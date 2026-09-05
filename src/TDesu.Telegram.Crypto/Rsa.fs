namespace TDesu.Crypto

open System
open System.Buffers.Binary
open System.Numerics
open System.Security.Cryptography
open TDesu.FSharp
open TDesu.FSharp.Buffers

/// RSA for MTProto's DH handshake: the current RSA_PAD scheme (`encryptPad`), which
/// wraps `p_q_inner_data` so the rest of the exchange can be authenticated. There is
/// no PKCS#1 padding anywhere here — MTProto defines its own encoding.
[<RequireQualifiedAccess>]
module Rsa =

    /// An RSA public key as MTProto serves it: a fingerprint (for `resPQ`'s
    /// `server_public_key_fingerprints`) plus the raw big-endian modulus and
    /// exponent.
    type RsaPublicKey = {
        Fingerprint: int64
        Modulus: byte[]
        Exponent: byte[]
    }

    /// Converts a hex string (spaces/newlines allowed) to a byte array.
    let hexToBytes (hex: string) : byte[] =
        let hex = hex.Replace(" ", "").Replace("\n", "").Replace("\r", "")
        Array.init (hex.Length / 2) (fun i -> Convert.ToByte(hex.Substring(i * 2, 2), 16))

    /// Telegram's current production RSA_PAD key — the only one servers accept for
    /// the handshake this library implements (`encryptPad`). 0.3.0 also shipped two
    /// legacy keys for MTProto's classic `sha1(data)+data` raw-RSA scheme; nothing in
    /// this library, `TDesu.Telegram.MTProto`, or TeleEye ever implemented that
    /// scheme (the handshake always negotiates RSA_PAD), so those keys described
    /// production DCs in a way nothing here could ever act on — removed in 0.4.0.
    /// `fingerprintOf` reproduces this key's fingerprint independently of the
    /// transcribed constant below.
    let publicKeys: RsaPublicKey list =
        [
            {
                Fingerprint = 0xd09d1d85de64fd85L
                Modulus =
                    hexToBytes
                        "E8BB3305C0B52C6CF2AFDF7637313489E63E05268E5BADB601AF417786472E5F93B85438968E20E6729A301C0AFC121BF7151F834436F7FDA680847A66BF64ACCEC78EE21C0B316F0EDAFE2F41908DA7BD1F4A5107638EEB67040ACE472A14F90D9F7C2B7DEF99688BA3073ADB5750BB02964902A359FE745D8170E36876D4FD8A5D41B2A76CBFF9A13267EB9580B2D06D10357448D20D9DA2191CB5D8C93982961CDFDEDA629E37F1FB09A0722027696032FE61ED663DB7A37F6F263D370F69DB53A0DC0A1748BDAAFF6209D5645485E6E001D1953255757E4B8E42813347B11DA6AB500FD0ACE7E6DFA3736199CCAF9397ED0745A427DCFA6CD67BCB1ACFF3"
                Exponent = [| 0x01uy; 0x00uy; 0x01uy |] // 65537
            }
        ]

    /// Telegram's RSA key fingerprint: the low 64 bits of `SHA1` over the TL
    /// serialisation `rsa_public_key#7a19cb76 n:string e:string = RSAPublicKey`
    /// (core.telegram.org/mtproto/auth_key). Lets `publicKeys` be checked against a
    /// computed value instead of trusting the transcribed `Fingerprint` field alone —
    /// the same transcription risk `DiffieHellman`'s safe-prime primality test closes
    /// for the DH prime. `RsaTests.fs` asserts this reproduces `0xd09d1d85de64fd85`
    /// for the shipped key.
    let fingerprintOf (key: RsaPublicKey) : int64 =
        // TL serialize_bytes: single-byte length prefix under 254, else 0xFE
        // followed by a 3-byte little-endian length; the field is then padded to a
        // 4-byte boundary.
        let serializeBytes (data: byte[]) : byte[] =
            let len = data.Length

            if len < 254 then
                let total = 1 + len
                Bytes.concat3 [| byte len |] data (Array.zeroCreate ((4 - total % 4) % 4))
            else
                let header = [| 254uy; byte (len &&& 0xff); byte ((len >>> 8) &&& 0xff); byte ((len >>> 16) &&& 0xff) |]
                let total = 4 + len
                Bytes.concat3 header data (Array.zeroCreate ((4 - total % 4) % 4))

        let payload = Bytes.concat2 (serializeBytes key.Modulus) (serializeBytes key.Exponent)
        use sha1 = SHA1.Create()
        let hash = sha1.ComputeHash payload
        BinaryPrimitives.ReadInt64LittleEndian(ReadOnlySpan<byte>(hash, hash.Length - 8, 8))

    /// Raw textbook RSA: `data^e mod n`, big-endian in and out. Internal because the
    /// only remaining caller is `encryptPad` below — nothing in this library or a
    /// consumer implements MTProto's classic `sha1(data)+data` scheme that used to
    /// call this directly (see `publicKeys` above). `encryptPad`'s `build` already
    /// re-rolls its own output whenever it would land >= the modulus; every other
    /// caller must stay below it too, so this throws instead of silently wrapping.
    let internal rawEncrypt (data: byte[]) (key: RsaPublicKey) : byte[] =
        let dataBI = BigEndian.toBigInteger data
        let modulusBI = BigEndian.toBigInteger key.Modulus
        Guard.isTrue (nameof data) "RSA input must be less than the modulus" (dataBI < modulusBI)
        let exponentBI = BigEndian.toBigInteger key.Exponent

        let resultBI = BigInteger.ModPow(dataBI, exponentBI, modulusBI)
        BigEndian.toBytes key.Modulus.Length resultBI

    /// RSA_PAD encryption — MTProto's current, hardened scheme for `p_q_inner_data`
    /// (core.telegram.org/mtproto/auth_key#1-client-computes-encrypted-data): the
    /// payload length is hidden, the data is AES-IGE wrapped under a fresh random
    /// key, and the 256-byte block is re-rolled until it is below the RSA modulus.
    /// `data` (the serialized inner block) must be at most 144 bytes.
    let encryptPad (data: byte[]) (key: RsaPublicKey) : byte[] =
        if data.Length > 144 then
            invalidArg (nameof data) "RSA_PAD payload must be at most 144 bytes"

        let sha256 (b: byte[]) =
            use h = SHA256.Create()
            h.ComputeHash b

        let modulusBI = BigEndian.toBigInteger key.Modulus

        // data_with_padding (192) -> reversed -> + SHA256(temp_key+data_with_padding) (224) ->
        // AES-IGE(temp_key, 0) -> temp_key XOR SHA256(aes) ++ aes (256). Retry if >= modulus.
        let rec build () =
            let padding = Array.zeroCreate<byte> (192 - data.Length)
            RandomNumberGenerator.Fill(padding)
            let dataWithPadding = Bytes.concat2 data padding
            let dataPadReversed = Array.rev dataWithPadding

            let tempKey = Array.zeroCreate<byte> 32
            RandomNumberGenerator.Fill(tempKey)

            let dataWithHash =
                Bytes.concat2 dataPadReversed (sha256 (Bytes.concat2 tempKey dataWithPadding))

            let aesEncrypted = AesIge.encrypt dataWithHash tempKey (Array.zeroCreate 32)
            let tempKeyXor = Array.map2 (^^^) tempKey (sha256 aesEncrypted)
            let keyAesEncrypted = Bytes.concat2 tempKeyXor aesEncrypted

            if BigEndian.toBigInteger keyAesEncrypted >= modulusBI then build () else keyAesEncrypted

        rawEncrypt (build ()) key
