namespace TDesu.Crypto

open System
open System.Numerics
open System.Collections.Generic
open System.Security.Cryptography
open TDesu.FSharp
open TDesu.FSharp.Operators
open TDesu.FSharp.Buffers
[<RequireQualifiedAccess>]
module Rsa =

    type RsaPublicKey = {
        Fingerprint: int64
        Modulus: byte[]
        Exponent: byte[]
    }

    /// Convert a hex string to byte array
    let hexToBytes (hex: string) : byte[] =
        let hex = hex.Replace(" ", "").Replace("\n", "").Replace("\r", "")
        Array.init (hex.Length / 2) (fun i ->
            Convert.ToByte(hex.Substring(i * 2, 2), 16))

    /// Telegram production RSA public keys, in the order prod DCs advertise them in resPQ.
    /// The first key (0xd09d1d85de64fd85) is the current key the servers expect for the RSA_PAD
    /// scheme; the following two are legacy keys kept for the classic sha1(data)+data scheme.
    /// Each modulus is the canonical 256-byte value — verified by recomputing its fingerprint.
    let publicKeys: RsaPublicKey list =
        [
            {
                // 0xd09d1d85de64fd85 — RSA_PAD key
                Fingerprint = 0xd09d1d85de64fd85L
                Modulus =
                    hexToBytes
                        "E8BB3305C0B52C6CF2AFDF7637313489E63E05268E5BADB601AF417786472E5F93B85438968E20E6729A301C0AFC121BF7151F834436F7FDA680847A66BF64ACCEC78EE21C0B316F0EDAFE2F41908DA7BD1F4A5107638EEB67040ACE472A14F90D9F7C2B7DEF99688BA3073ADB5750BB02964902A359FE745D8170E36876D4FD8A5D41B2A76CBFF9A13267EB9580B2D06D10357448D20D9DA2191CB5D8C93982961CDFDEDA629E37F1FB09A0722027696032FE61ED663DB7A37F6F263D370F69DB53A0DC0A1748BDAAFF6209D5645485E6E001D1953255757E4B8E42813347B11DA6AB500FD0ACE7E6DFA3736199CCAF9397ED0745A427DCFA6CD67BCB1ACFF3"
                Exponent = [| 0x01uy; 0x00uy; 0x01uy |] // 65537
            }
            {
                // 0x0bc35f3509f7b7a5
                Fingerprint = 0x0bc35f3509f7b7a5L
                Modulus =
                    hexToBytes
                        "AEEC36C8FFC109CB099624685B97815415657BD76D8C9C3E398103D7AD16C9BBA6F525ED0412D7AE2C2DE2B44E77D72CBF4B7438709A4E646A05C43427C7F184DEBF72947519680E651500890C6832796DD11F772C25FF8F576755AFE055B0A3752C696EB7D8DA0D8BE1FAF38C9BDD97CE0A77D3916230C4032167100EDD0F9E7A3A9B602D04367B689536AF0D64B613CCBA7962939D3B57682BEB6DAE5B608130B2E52ACA78BA023CF6CE806B1DC49C72CF928A7199D22E3D7AC84E47BC9427D0236945D10DBD15177BAB413FBF0EDFDA09F014C7A7DA088DDE9759702CA760AF2B8E4E97CC055C617BD74C3D97008635B98DC4D621B4891DA9FB0473047927"
                Exponent = [| 0x01uy; 0x00uy; 0x01uy |] // 65537
            }
            {
                // 0xc3b42b026ce86b21
                Fingerprint = 0xc3b42b026ce86b21L
                Modulus =
                    hexToBytes
                        "C150023E2F70DB7985DED064759CFECF0AF328E69A41DAF4D6F01B538135A6F91F8F8B2A0EC9BA9720CE352EFCF6C5680FFC424BD634864902DE0B4BD6D49F4E580230E3AE97D95C8B19442B3C0A10D8F5633FECEDD6926A7F6DAB0DDB7D457F9EA81B8465FCD6FFFEED114011DF91C059CAEDAF97625F6C96ECC74725556934EF781D866B34F011FCE4D835A090196E9A5F0E4449AF7EB697DDB9076494CA5F81104A305B6DD27665722C46B60E5DF680FB16B210607EF217652E60236C255F6A28315F4083A96791D7214BF64C1DF4FD0DB1944FB26A2A57031B32EEE64AD15A8BA68885CDE74A5BFC920F6ABF59BA5C75506373E7130F9042DA922179251F"
                Exponent = [| 0x01uy; 0x00uy; 0x01uy |] // 65537
            }
        ]

    /// Additional keys registered at runtime (e.g. test server keys)
    let private additionalKeys = List<RsaPublicKey>()

    /// Register an additional RSA public key (e.g. for test servers)
    let addKey (key: RsaPublicKey) : unit =
        additionalKeys.Add(key)

    /// Get all known RSA keys (production + registered)
    let allKeys () : RsaPublicKey list =
        let extra = additionalKeys |> Seq.toList
        List.append publicKeys extra

    /// Clear all registered additional keys (for test teardown)
    let clearAdditionalKeys () : unit =
        additionalKeys.Clear()

    /// Encrypt data with RSA for DH exchange.
    /// Performs raw RSA: data^e mod n (big-endian, unsigned).
    let encrypt (data: byte[]) (key: RsaPublicKey) : byte[] =
        // MTProto uses big-endian for RSA, .NET BigInteger uses little-endian.
        // Append 0x00 sign byte to ensure unsigned interpretation.
        let toLEUnsigned (bigEndian: byte[]) =
            let le = Array.copy bigEndian
            Array.Reverse(le)
            Bytes.concat2 le [| 0uy |]

        let dataBI = BigInteger(toLEUnsigned data)
        let modulusBI = BigInteger(toLEUnsigned key.Modulus)
        let exponentBI = BigInteger(toLEUnsigned key.Exponent)

        let resultBI = BigInteger.ModPow(dataBI, exponentBI, modulusBI)

        // Convert back to big-endian, strip sign byte, pad to modulus length
        let resultBytes = resultBI.ToByteArray()
        // Remove trailing zero (sign byte) if present, then reverse to big-endian
        let trimmed =
            if resultBytes.Length > 1 && resultBytes[resultBytes.Length - 1] = 0uy then
                resultBytes[.. resultBytes.Length - 2]
            else
                resultBytes
        let be = Array.copy trimmed
        Array.Reverse(be)

        // Pad with leading zeros to match modulus length
        let modulusLen = key.Modulus.Length
        if be.Length < modulusLen then
            Bytes.concat2 (Array.zeroCreate (modulusLen - be.Length)) be
        else
            be

    /// RSA_PAD encryption — MTProto's current, hardened scheme for p_q_inner_data. The classic
    /// `encrypt` above (sha1(data)+data, raw RSA) is retained for callers that need it, but new
    /// code should prefer this: the payload length is hidden, the data is AES-IGE wrapped under a
    /// fresh random key, and the 256-byte block is re-rolled until it is below the RSA modulus.
    /// `data` (the serialized inner block) must be at most 144 bytes.
    let encryptPad (data: byte[]) (key: RsaPublicKey) : byte[] =
        if data.Length > 144 then
            invalidArg (nameof data) "RSA_PAD payload must be at most 144 bytes"

        let sha256 (b: byte[]) =
            use h = SHA256.Create()
            h.ComputeHash b

        let toUnsigned (be: byte[]) =
            let le = Array.copy be
            Array.Reverse(le)
            BigInteger(Bytes.concat2 le [| 0uy |])

        let modulusBI = toUnsigned key.Modulus

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

            if toUnsigned keyAesEncrypted >= modulusBI then build () else keyAesEncrypted

        encrypt (build ()) key
