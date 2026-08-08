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
