namespace TDesu.Crypto.Tests

open System.Security.Cryptography
open NUnit.Framework
open TDesu.Crypto
open TDesu.Crypto.Tests

[<TestFixture>]
module RsaTests =

    [<Test>]
    let ``publicKeys list is non-empty`` () =
        Assert.That(Rsa.publicKeys.Length, Is.GreaterThan(0))

    /// Regression guard: a corrupted/truncated modulus or a mislabelled fingerprint
    /// (the prod DC silently rejects req_DH_params with transport error -404) must fail
    /// here, not in a live handshake.
    [<Test>]
    let ``every public key fingerprint matches its modulus and exponent`` () =
        for key in Rsa.publicKeys do
            equals key.Modulus.Length 256
            equals (Rsa.fingerprintOf key) key.Fingerprint

    /// `fingerprintOf` must reproduce the shipped RSA_PAD key's well-known
    /// fingerprint independently of the `Fingerprint` field transcribed alongside
    /// the modulus — the same transcription-independence
    /// `DiffieHellman`'s safe-prime primality test gives the pinned DH prime.
    [<Test>]
    let ``fingerprintOf reproduces the production RSA_PAD key's fingerprint`` () =
        let key = Rsa.publicKeys |> List.head
        equals (Rsa.fingerprintOf key) 0xd09d1d85de64fd85L

    [<Test>]
    let ``production key exponent is 65537`` () =
        let key = Rsa.publicKeys |> List.head
        equals key.Exponent [| 0x01uy; 0x00uy; 0x01uy |]

    [<Test>]
    let ``rawEncrypt produces output of modulus length`` () =
        let key = Rsa.publicKeys |> List.head
        let data = Array.zeroCreate 256
        RandomNumberGenerator.Fill(System.Span(data))
        // Ensure data < modulus by zeroing first byte
        data[0] <- 0uy
        let encrypted = Rsa.rawEncrypt data key
        equals encrypted.Length key.Modulus.Length

    [<Test>]
    let ``rawEncrypt with different data produces different output`` () =
        let key = Rsa.publicKeys |> List.head
        let data1 = Array.zeroCreate<byte> 256
        let data2 = Array.zeroCreate<byte> 256
        data1[0] <- 0uy; data1[1] <- 1uy
        data2[0] <- 0uy; data2[1] <- 2uy
        let enc1 = Rsa.rawEncrypt data1 key
        let enc2 = Rsa.rawEncrypt data2 key
        notEquals enc1 enc2

    /// The correctness fix the audit asked for: `encrypt` (now internal
    /// `rawEncrypt`) used to silently wrap `data mod n` for any `data >= n` --
    /// two different inputs at or above the modulus could then encrypt to the
    /// same ciphertext. It must refuse instead.
    [<Test>]
    let ``rawEncrypt rejects data at or above the modulus`` () =
        let key = Rsa.publicKeys |> List.head
        Assert.Throws<System.ArgumentException>(fun () -> Rsa.rawEncrypt key.Modulus key |> ignore)
        |> ignore

    [<Test>]
    let ``hexToBytes round-trip`` () =
        let hex = "DEADBEEF"
        let bytes = Rsa.hexToBytes hex
        equals bytes [| 0xDEuy; 0xADuy; 0xBEuy; 0xEFuy |]

    [<Test>]
    let ``hexToBytes with spaces`` () =
        let bytes = Rsa.hexToBytes "DE AD BE EF"
        equals bytes [| 0xDEuy; 0xADuy; 0xBEuy; 0xEFuy |]

    [<Test>]
    let ``encryptPad produces 256-byte output`` () =
        let key = Rsa.publicKeys |> List.head
        equals (Rsa.encryptPad (Array.zeroCreate 96) key).Length 256

    [<Test>]
    let ``encryptPad is randomized across calls`` () =
        let key = Rsa.publicKeys |> List.head
        let data = Array.zeroCreate 96
        notEquals (Rsa.encryptPad data key) (Rsa.encryptPad data key)

    [<Test>]
    let ``encryptPad rejects data over 144 bytes`` () =
        let key = Rsa.publicKeys |> List.head
        Assert.Throws<System.ArgumentException>(fun () -> Rsa.encryptPad (Array.zeroCreate 145) key |> ignore)
        |> ignore

    /// Independently decodes an `encryptPad` ciphertext with a freshly generated
    /// RSA-2048 keypair's own private exponent, undoing every step `Rsa.fs`'s
    /// `build` performs (Rsa.fs:129-145) in reverse: split temp_key_xor(32)|aes(224),
    /// recover temp_key = temp_key_xor XOR SHA256(aes), IGE-decrypt the aes block
    /// under a zero IV, verify the SHA-256 suffix, reverse the remaining 192 bytes,
    /// and compare the leading 144 bytes to the original payload. A refactor that
    /// gets any one of those seven steps wrong — a swapped XOR order, the wrong
    /// slice boundary, a missing reversal — fails this test even though
    /// `encryptPad produces 256-byte output` and `is randomized across calls` above
    /// would not notice, because neither one decodes anything.
    [<Test>]
    let ``encryptPad round-trips through independent RSA decryption and every RSA_PAD step`` () =
        use rsa = RSA.Create(2048)
        let rsaParams = rsa.ExportParameters(true)
        let key: Rsa.RsaPublicKey = {
            Fingerprint = 0L
            Modulus = rsaParams.Modulus
            Exponent = rsaParams.Exponent
        }

        let payload = Array.init 144 (fun i -> byte (i * 3 + 7))
        let ciphertext = Rsa.encryptPad payload key

        // Undo the outer raw RSA encryption: m = c^d mod n.
        let toUnsigned (be: byte[]) =
            System.Numerics.BigInteger(System.ReadOnlySpan<byte> be, isUnsigned = true, isBigEndian = true)

        let n = toUnsigned rsaParams.Modulus
        let d = toUnsigned rsaParams.D
        let c = toUnsigned ciphertext
        let m = System.Numerics.BigInteger.ModPow(c, d, n)

        let mBytes =
            let raw = m.ToByteArray(isUnsigned = true, isBigEndian = true)
            let padded = Array.zeroCreate<byte> 256
            System.Array.Copy(raw, 0, padded, 256 - raw.Length, raw.Length)
            padded

        // keyAesEncrypted = temp_key_xor(32) ++ aes(224)
        let tempKeyXor = mBytes[0..31]
        let aesEncrypted = mBytes[32..255]
        equals aesEncrypted.Length 224

        use sha256 = SHA256.Create()
        let tempKey = Array.map2 (^^^) tempKeyXor (sha256.ComputeHash aesEncrypted)
        equals tempKey.Length 32

        // dataWithHash = dataPadReversed(192) ++ SHA256(temp_key ++ dataWithPadding)(32)
        let dataWithHash = AesIge.decrypt aesEncrypted tempKey (Array.zeroCreate 32)
        equals dataWithHash.Length 224

        let dataPadReversed = dataWithHash[0..191]
        let hashSuffix = dataWithHash[192..223]

        let dataWithPadding = Array.rev dataPadReversed
        let expectedHashSuffix = sha256.ComputeHash(Array.append tempKey dataWithPadding)
        equals hashSuffix expectedHashSuffix

        equals dataWithPadding[0..143] payload
