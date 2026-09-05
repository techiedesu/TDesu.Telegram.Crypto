namespace TDesu.Crypto.Tests

open NUnit.Framework
open TDesu.Crypto
open TDesu.Crypto.Tests

[<TestFixture>]
type AesIgeTests() =

    [<Test>]
    member _.``Encrypt then decrypt recovers original data``() =
        let key = Array.init 32 (fun i -> byte i)
        let iv = Array.init 32 (fun i -> byte (i + 32))
        let plaintext = Array.init 64 (fun i -> byte (i * 3))

        let encrypted = AesIge.encrypt plaintext key iv
        notEquals encrypted plaintext

        let decrypted = AesIge.decrypt encrypted key iv
        equals decrypted plaintext

    [<Test>]
    member _.``Encrypt single block``() =
        let key = Array.init 32 (fun _ -> 0xAAuy)
        let iv = Array.init 32 (fun _ -> 0xBBuy)
        let plaintext = Array.init 16 (fun i -> byte i)

        let encrypted = AesIge.encrypt plaintext key iv
        equals encrypted.Length 16

        let decrypted = AesIge.decrypt encrypted key iv
        equals decrypted plaintext

    [<Test>]
    member _.``Encrypt multiple blocks``() =
        let key = Array.init 32 (fun i -> byte (i * 7))
        let iv = Array.init 32 (fun i -> byte (i * 11))
        let plaintext = Array.init 128 (fun i -> byte (i % 256))

        let encrypted = AesIge.encrypt plaintext key iv
        equals encrypted.Length 128

        let decrypted = AesIge.decrypt encrypted key iv
        equals decrypted plaintext

    [<Test>]
    member _.``Different keys produce different ciphertext``() =
        let key1 = Array.init 32 (fun i -> byte i)
        let key2 = Array.init 32 (fun i -> byte (i + 1))
        let iv = Array.init 32 (fun _ -> 0uy)
        let plaintext = Array.init 16 (fun i -> byte i)

        let encrypted1 = AesIge.encrypt plaintext key1 iv
        let encrypted2 = AesIge.encrypt plaintext key2 iv
        notEquals encrypted1 encrypted2

    /// Known-answer regression: computed once independently, driving the *platform*
    /// AES-256-ECB (`System.Security.Cryptography.Aes`, not this library) through the
    /// same IGE chaining by hand, then hardcoded here. `AesIge.encrypt`/`decrypt` route
    /// through `AesEcb`, which is the managed cipher whenever `AesEcb.isManaged` is
    /// true (e.g. browser-wasm) — pinning to an externally-computed answer, rather than
    /// just round-tripping through this library, is what would catch the managed path
    /// silently drifting from real AES-IGE.
    [<Test>]
    member _.``Known-answer vector matches the platform-computed reference``() =
        let key = Rsa.hexToBytes "01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3da"
        let iv = Rsa.hexToBytes "05121f2c394653606d7a8794a1aebbc8d5e2effc091623303d4a5764717e8b98"
        let plaintext =
            Rsa.hexToBytes
                "03284d7297bce1062b50759abfe4092e53789dc2e70c31567ba0c5ea0f34597ea3c8ed12375c81a6cbf0153a5f84a9ce"
        let expectedCiphertext =
            Rsa.hexToBytes
                "9d2556718dc33045547317c8e978e56eae3f4563249d857b5a472e115bb1b5e273fa87826c0ae00014695cf1d40e0fff"

        equals (AesIge.encrypt plaintext key iv) expectedCiphertext
        equals (AesIge.decrypt expectedCiphertext key iv) plaintext

    /// Telegram's own published auth_key generation example
    /// (core.telegram.org/mtproto/samples-auth_key, step 6 "Server responds with"):
    /// decrypting the server's `encrypted_answer` under the handshake's
    /// `tmp_aes_key`/`tmp_aes_iv` must reproduce `answer_with_hash` byte for byte.
    /// Independent of the vector above (which was derived by hand from the spec's
    /// chaining description): this one is Telegram's own worked example, so it
    /// pins the whole module — chaining direction, XOR order, and the platform vs.
    /// managed cipher dispatch — against an oracle this library did not produce.
    [<Test>]
    member _.``Telegram's published auth_key sample decrypts encrypted_answer to answer_with_hash``() =
        let tmpAesKey = Rsa.hexToBytes "16F548177058E8D39C41CBAD4D419446BEB12EB9B8F5AD28EA824B8015F17D81"
        let tmpAesIv = Rsa.hexToBytes "C4D14166C1378E35C698460047DBB6075441BE9984611C28837357EBBF8CB5BD"

        let encryptedAnswer =
            Rsa.hexToBytes
                "C334D313064174F443CE90E13C835FAEA6AE9677089A0781CC8C17ADC8FF5B5072934C1DFB1F2B9222197DE806186E6612E0CFA2593809B4B91B49F006FFBBD9EAAADE1EEDCA046F500A77BB538E3C2F02A4A6814DF0BC77993E493B7F2C98344F674455A90A541070740F4B811FFF4B80B161737E0E867FF20D03BE6B52BA66F7319D03B621732E1C880202EAF61DF31DE831E7AC97B0FFDBFFFFA7019D399553F37B645913238443F4C560A59A5BA6AA6BFAEB159FD2291FCDA49A23E8009196B8062DD424F45D3B43538C68B2C070A845C260052DD3C266659FA6C0C6A8FF36FBFF8DAB36E06BEB5E18AFE38027FDA45E65884A503402840E21C1869101F4C613E9EDA61C2EB0AA987046F8069C2C002EE48A95844DD62E0E4B612257391B014D3B043D7C193F936352F9D799CC4017CA544896BB09B3B5B8B70C2C5E48295A82CF13BCF5FB0BA52991EC5C25188AB783CBCED3573BABB255E82741EAF4941609AEFF960A4F2B41F92E78595141EBC73677E09104B8690D3E3C30FCA78BB0F97B4336E925BCB0C85A805458EE7B8DAD7599388C338394FB317C0C6BD5EC2CD564177EC059E9705EFAF2048ED0B014EA89C60EE48CC547FE51CE4D0F13DEA2ABEA9F2425B3FA2987D960EDEF619B67921B2E92219C81F709C2924414932257D5F3EEB12D0AAF2B29511988DACC966792D7E26F04EF5F78CC18F8A9C620668FD76A668AC6E6D43474BFB5CFC927C15B5D1FD531F50B7EDFFCD50F6F04A0884566CC858D05A2B846D69A8799D36022112ACCCA567D6B5EFE799AC93DE439A7D16CE61C16B02F89AD9ACBD045111BC5F1"

        let expectedAnswerWithHash =
            Rsa.hexToBytes
                "8BB20017894315B136AE5F4BAAD0F0BA20334342BA0D89B551A1143FC7A3666BE4BE54D6890A02DC63248F6748214EAB8A2F4CC876E1197403000000FE000100C71CAEB9C6B1C9048E6C522F70F13F73980D40238E3E21C14934D037563D930F48198A0AA7C14058229493D22530F4DBFA336F6E0AC925139543AED44CCE7C3720FD51F69458705AC68CD4FE6B6B13ABDC9746512969328454F18FAF8C595F642477FE96BB2A941D5BCD1D4AC8CC49880708FA9B378E3C4F3A9060BEE67CF9A4A4A695811051907E162753B56B0F6B410DBA74D8A84B2A14B3144E0EF1284754FD17ED950D5965B4B9DD46582DB1178D169C6BC465B0D6FF9CA3928FEF5B9AE4E418FC15E83EBEA0F87FA9FF5EED70050DED2849F47BF959D956850CE929851F0D8115F635B105EE2E4E15D04B2454BF6F4FADF034B10403119CD8E3B92FCC5BFE0001008539DB1E497692EE8BD112463F5F26699039792151BE8B575AA56D8914EDBAA242C2A8096FFAB06211B36291FC4994CB0FDFD37389DF8886F2C6B634C0D01B1C8EBD3E9BE1F49B4A8BD33C3952EF1CEC5E9425CD9C2136CA482A521F9ACC86BEA7D8E224F3D6D78A7F734961EED863EA52EC399C58AE94B733E4CB0AFC728926FB2F457D4AB89576D8067489E323DF8702DEC6EFA2EAF1D85548748D2DFA62925920563076F143D8AE852BCAE61553371BEDA580FEBD952AC7C7C1AFBB3F15934CE815716C6C362F9382BE91DC6F964E97C1A308D63FC1E4DFB2B8395A3E7B9A996C2DD3086488EB281301BEEC1ECEDD00296D76AC7EF7B786EA82F0FA7896DB6170466AA674223E982CE5E5"

        equals (AesIge.decrypt encryptedAnswer tmpAesKey tmpAesIv) expectedAnswerWithHash

    [<Test>]
    member _.``encryptTo and decryptTo match the byte[] wrappers``() =
        let key = Array.init 32 (fun i -> byte (i * 7))
        let iv = Array.init 32 (fun i -> byte (i * 11))
        let plaintext = Array.init 128 (fun i -> byte (i % 256))

        let expectedEncrypted = AesIge.encrypt plaintext key iv

        let encryptedViaSpan = Array.zeroCreate<byte> plaintext.Length
        AesIge.encryptTo (System.ReadOnlySpan<byte> plaintext) key iv (System.Span<byte> encryptedViaSpan)
        equals encryptedViaSpan expectedEncrypted

        let decryptedViaSpan = Array.zeroCreate<byte> plaintext.Length
        AesIge.decryptTo (System.ReadOnlySpan<byte> encryptedViaSpan) key iv (System.Span<byte> decryptedViaSpan)
        equals decryptedViaSpan plaintext

    /// `output` may alias `input` for `encryptTo`/`decryptTo`, per their docs.
    /// Encrypting and then decrypting a buffer over itself is exactly the case a
    /// naive "read this block after writing that one" ordering gets wrong,
    /// which is what the old-value-before-overwrite ordering in `AesIge.fs`
    /// guards against.
    [<Test>]
    member _.``encryptTo and decryptTo work in place``() =
        let key = Array.init 32 (fun i -> byte (i * 3 + 1))
        let iv = Array.init 32 (fun i -> byte (i * 13 + 2))
        let original = Array.init 96 (fun i -> byte (i * 5 + 3))

        let buffer = Array.copy original
        AesIge.encryptTo (System.ReadOnlySpan<byte> buffer) key iv (System.Span<byte> buffer)
        notEquals buffer original
        equals buffer (AesIge.encrypt original key iv)

        AesIge.decryptTo (System.ReadOnlySpan<byte> buffer) key iv (System.Span<byte> buffer)
        equals buffer original
