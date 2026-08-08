namespace TDesu.Crypto.Tests

open System
open NUnit.Framework
open FsCheck
open FsCheck.NUnit
open TDesu.Crypto
open TDesu.Crypto.Tests

/// Validates the managed AES-256 block cipher (`ManagedAes.fs`) against published
/// third-party vectors, not against itself: a freshly written cipher that only agrees
/// with its own output proves nothing.
[<TestFixture>]
type ManagedAesTests() =

    /// Runs `ManagedAes.encryptBlock`/`decryptBlock` directly on a single block. Not
    /// `AesEcb.createEncryptor`: that dispatches to the platform cipher whenever one
    /// exists, and on any machine with hardware AES that would validate the platform,
    /// not the managed path this file exists to check.
    let managedEncryptBlock (roundKeys: byte[]) (block: byte[]) : byte[] =
        let dest = Array.zeroCreate<byte> ManagedAes.BlockSize
        ManagedAes.encryptBlock roundKeys block 0 dest 0
        dest

    let managedDecryptBlock (roundKeys: byte[]) (block: byte[]) : byte[] =
        let dest = Array.zeroCreate<byte> ManagedAes.BlockSize
        ManagedAes.decryptBlock roundKeys block 0 dest 0
        dest

    [<Test>]
    member _.``FIPS-197 Appendix C.3 AES-256 vector encrypts and decrypts``() =
        let key = Rsa.hexToBytes "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        let plaintext = Rsa.hexToBytes "00112233445566778899aabbccddeeff"
        let ciphertext = Rsa.hexToBytes "8ea2b7ca516745bfeafc49904b496089"
        let roundKeys = ManagedAes.expandKey key

        equals (managedEncryptBlock roundKeys plaintext) ciphertext
        equals (managedDecryptBlock roundKeys ciphertext) plaintext

    /// NIST SP 800-38A F.1.5/F.1.6 (ECB-AES256), all four published blocks under the
    /// same key, both directions. A single block can pass against a broken key
    /// schedule that happens to cancel out for that one input; four independent blocks
    /// make that far less likely.
    [<Test>]
    member _.``NIST SP800-38A ECB-AES256 vectors, all four blocks, both directions``() =
        let key = Rsa.hexToBytes "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
        let roundKeys = ManagedAes.expandKey key

        // F.1.5 (encrypt) / F.1.6 (decrypt), blocks 1-4, from the published standard.
        let blocks =
            [ "6bc1bee22e409f96e93d7e117393172a", "f3eed1bdb5d2a03c064b5a7e3db181f8"
              "ae2d8a571e03ac9c9eb76fac45af8e51", "591ccb10d410ed26dc5ba74a31362870"
              "30c81c46a35ce411e5fbc1191a0a52ef", "b6ed21b99ca6f4f9f153e7b1beafed1d"
              "f69f2445df4f9b17ad2b417be66c3710", "23304b7a39f9f3ff067d8d8f9e24ecc7" ]

        for plaintextHex, ciphertextHex in blocks do
            let plaintext = Rsa.hexToBytes plaintextHex
            let ciphertext = Rsa.hexToBytes ciphertextHex
            equals (managedEncryptBlock roundKeys plaintext) ciphertext
            equals (managedDecryptBlock roundKeys ciphertext) plaintext

    /// Round key 0 is definitionally the raw key (Nk=8 means the first two round keys
    /// are copied straight from the 256-bit cipher key). Round key 14 is not, and
    /// exercises the RotWord/SubWord/Rcon schedule fully; both values are read from
    /// FIPS-197 Appendix C.3's own worked trace (the inverse cipher's first
    /// AddRoundKey uses round key 14, and its last uses round key 0).
    [<Test>]
    member _.``expandKey produces the FIPS-197 C.3 first and last round key``() =
        let key = Rsa.hexToBytes "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        let roundKeys = ManagedAes.expandKey key

        let roundKey0 = roundKeys[0 .. ManagedAes.BlockSize - 1]
        let roundKey14 = roundKeys[14 * ManagedAes.BlockSize .. 15 * ManagedAes.BlockSize - 1]

        equals roundKey0 (Rsa.hexToBytes "000102030405060708090a0b0c0d0e0f")
        equals roundKey14 (Rsa.hexToBytes "24fc79ccbf0979e9371ac23c6d68de36")

    /// When this runtime has real AES, the managed cipher must agree with it byte for
    /// byte over random keys and blocks. There is nothing to compare against when it
    /// doesn't (`AesEcb.isManaged = true`, e.g. browser-wasm), so this is an explicit
    /// Ignore rather than a vacuous pass — the run should report it skipped, not green
    /// for a comparison that never happened. FsCheck drives the random inputs and
    /// shrinks any disagreement to a minimal reproducing case.
    [<Test>]
    member _.``managed cipher agrees with the platform on random blocks and keys``() =
        if AesEcb.isManaged then
            Assert.Ignore("AesEcb.isManaged = true on this runtime: no platform AES to compare the managed cipher against.")

        let agrees (seed: int) =
            let rng = Random(seed)
            let key = Array.zeroCreate<byte> 32
            rng.NextBytes(key)
            let block = Array.zeroCreate<byte> ManagedAes.BlockSize
            rng.NextBytes(block)

            let roundKeys = ManagedAes.expandKey key
            let managedCipher = managedEncryptBlock roundKeys block

            use platformEncryptor = AesEcb.createEncryptor key
            let platformCipher = Array.zeroCreate<byte> ManagedAes.BlockSize
            platformEncryptor.TransformBlock(block, 0, ManagedAes.BlockSize, platformCipher, 0) |> ignore

            let managedPlain = managedDecryptBlock roundKeys platformCipher

            use platformDecryptor = AesEcb.createDecryptor key
            let platformPlain = Array.zeroCreate<byte> ManagedAes.BlockSize
            platformDecryptor.TransformBlock(platformCipher, 0, ManagedAes.BlockSize, platformPlain, 0) |> ignore

            managedCipher = platformCipher && managedPlain = platformPlain

        Check.QuickThrowOnFailure(agrees)

    /// `decryptBlock (encryptBlock x) = x` for random 32-byte keys and random
    /// multi-block input, entirely within the managed cipher (no platform involved).
    [<Property>]
    member _.``decryptBlock inverts encryptBlock for random keys and multi-block input``(seed: int) =
        let rng = Random(seed)
        let key = Array.zeroCreate<byte> 32
        rng.NextBytes(key)
        let roundKeys = ManagedAes.expandKey key

        let blockCount = rng.Next(2, 9) // always multi-block: 2..8 blocks
        let data = Array.zeroCreate<byte> (blockCount * ManagedAes.BlockSize)
        rng.NextBytes(data)

        let encrypted = Array.zeroCreate<byte> data.Length
        for i in 0 .. blockCount - 1 do
            let offset = i * ManagedAes.BlockSize
            ManagedAes.encryptBlock roundKeys data offset encrypted offset

        let decrypted = Array.zeroCreate<byte> data.Length
        for i in 0 .. blockCount - 1 do
            let offset = i * ManagedAes.BlockSize
            ManagedAes.decryptBlock roundKeys encrypted offset decrypted offset

        decrypted = data
