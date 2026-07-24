namespace TDesu.Crypto.Tests

open System.Security.Cryptography
open NUnit.Framework
open TDesu.Crypto
open TDesu.Crypto.Tests

[<TestFixture>]
module RsaTests =

    /// TL serialize_bytes: length-prefixed, padded to a 4-byte boundary.
    let private serBytes (data: byte[]) : byte[] =
        let len = data.Length
        if len < 254 then
            let total = 1 + len
            Array.concat [ [| byte len |]; data; Array.zeroCreate ((4 - total % 4) % 4) ]
        else
            let header = [| 254uy; byte (len &&& 0xff); byte ((len >>> 8) &&& 0xff); byte ((len >>> 16) &&& 0xff) |]
            let total = 4 + len
            Array.concat [ header; data; Array.zeroCreate ((4 - total % 4) % 4) ]

    /// Telegram key fingerprint = low 64 bits of SHA1(serialize(n) ++ serialize(e)).
    let private computeFingerprint (key: Rsa.RsaPublicKey) : int64 =
        let payload = Array.append (serBytes key.Modulus) (serBytes key.Exponent)
        let h = SHA1.HashData(payload)
        System.BitConverter.ToInt64(h, h.Length - 8)

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
            equals (computeFingerprint key) key.Fingerprint

    [<Test>]
    let ``production keys cover the fingerprints prod DCs advertise`` () =
        let fps = Rsa.publicKeys |> List.map (fun k -> k.Fingerprint) |> Set.ofList
        Assert.That(fps.Contains 0x0bc35f3509f7b7a5L, Is.True)
        Assert.That(fps.Contains 0xc3b42b026ce86b21L, Is.True)
        Assert.That(fps.Contains 0xd09d1d85de64fd85L, Is.True)

    [<Test>]
    let ``production key exponent is 65537`` () =
        let key = Rsa.publicKeys |> List.head
        equals key.Exponent [| 0x01uy; 0x00uy; 0x01uy |]

    [<Test>]
    let ``allKeys includes production keys`` () =
        let all = Rsa.allKeys ()
        Assert.That(all.Length, Is.GreaterThanOrEqualTo(Rsa.publicKeys.Length))

    [<Test>]
    let ``addKey and clearAdditionalKeys`` () =
        let testKey: Rsa.RsaPublicKey = {
            Fingerprint = 123456L
            Modulus = Array.zeroCreate 256
            Exponent = [| 0x01uy; 0x00uy; 0x01uy |]
        }
        try
            Rsa.addKey testKey
            let all = Rsa.allKeys ()
            Assert.That(all |> List.exists (fun k -> k.Fingerprint = 123456L), Is.True)
        finally
            Rsa.clearAdditionalKeys ()

        let afterClear = Rsa.allKeys ()
        Assert.That(afterClear |> List.exists (fun k -> k.Fingerprint = 123456L), Is.False)

    [<Test>]
    let ``encrypt produces output of modulus length`` () =
        let key = Rsa.publicKeys |> List.head
        let data = Array.zeroCreate 256
        RandomNumberGenerator.Fill(System.Span(data))
        // Ensure data < modulus by zeroing first byte
        data[0] <- 0uy
        let encrypted = Rsa.encrypt data key
        equals encrypted.Length key.Modulus.Length

    [<Test>]
    let ``encrypt with different data produces different output`` () =
        let key = Rsa.publicKeys |> List.head
        let data1 = Array.zeroCreate<byte> 256
        let data2 = Array.zeroCreate<byte> 256
        data1[0] <- 0uy; data1[1] <- 1uy
        data2[0] <- 0uy; data2[1] <- 2uy
        let enc1 = Rsa.encrypt data1 key
        let enc2 = Rsa.encrypt data2 key
        notEquals enc1 enc2

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
