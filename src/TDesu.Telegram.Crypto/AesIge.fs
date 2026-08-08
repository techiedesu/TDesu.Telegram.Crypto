namespace TDesu.Crypto

open System.Security.Cryptography
open TDesu.FSharp
open TDesu.FSharp.Operators
open TDesu.FSharp.Buffers

[<RequireQualifiedAccess>]
module AesIge =

    [<Literal>]
    let private BlockSize = 16

    let encrypt (data: byte[]) (key: byte[]) (iv: byte[]) : byte[] =
        Guard.isTrue (nameof data) "Data length must be a multiple of 16" (data.Length % BlockSize = 0)
        Guard.isTrue (nameof key) "Key must be 32 bytes" (key.Length = 32)
        Guard.isTrue (nameof iv) "IV must be 32 bytes" (iv.Length = 32)

        // Not `Aes.Create()` directly: browser-wasm has no AES, and this is the code
        // path every encrypted MTProto message takes.
        use encryptor = AesEcb.createEncryptor key
        let blockCount = data.Length / BlockSize
        let result = Array.zeroCreate<byte> data.Length
        let prevPlain = Array.zeroCreate<byte> BlockSize
        let prevCipher = Array.zeroCreate<byte> BlockSize
        let xored = Array.zeroCreate<byte> BlockSize
        let encrypted = Array.zeroCreate<byte> BlockSize

        // iv[0..15] = previous ciphertext, iv[16..31] = previous plaintext
        Bytes.copyTo iv 0 prevCipher 0 BlockSize
        Bytes.copyTo iv BlockSize prevPlain 0 BlockSize

        for i = 0 to blockCount - 1 do
            let offset = i * BlockSize

            // xored = plainBlock XOR prevCipher
            Bytes.xorBlock data offset prevCipher 0 xored 0 BlockSize

            // encrypted = AES_ECB_Encrypt(xored)
            %encryptor.TransformBlock(xored, 0, BlockSize, encrypted, 0)

            // cipherBlock = encrypted XOR prevPlain
            Bytes.xorBlock encrypted 0 prevPlain 0 result offset BlockSize

            // prevPlain = plainBlock
            Bytes.copyTo data offset prevPlain 0 BlockSize

            // prevCipher = cipherBlock
            Bytes.copyTo result offset prevCipher 0 BlockSize

        result

    let decrypt (data: byte[]) (key: byte[]) (iv: byte[]) : byte[] =
        Guard.isTrue (nameof data) "Data length must be a multiple of 16" (data.Length % BlockSize = 0)
        Guard.isTrue (nameof key) "Key must be 32 bytes" (key.Length = 32)
        Guard.isTrue (nameof iv) "IV must be 32 bytes" (iv.Length = 32)

        use decryptor = AesEcb.createDecryptor key
        let blockCount = data.Length / BlockSize
        let result = Array.zeroCreate<byte> data.Length
        let prevCipher = Array.zeroCreate<byte> BlockSize
        let prevPlain = Array.zeroCreate<byte> BlockSize
        let xored = Array.zeroCreate<byte> BlockSize
        let decrypted = Array.zeroCreate<byte> BlockSize

        // iv[0..15] = previous ciphertext, iv[16..31] = previous plaintext
        Bytes.copyTo iv 0 prevCipher 0 BlockSize
        Bytes.copyTo iv BlockSize prevPlain 0 BlockSize

        for i = 0 to blockCount - 1 do
            let offset = i * BlockSize

            // xored = cipherBlock XOR prevPlain
            Bytes.xorBlock data offset prevPlain 0 xored 0 BlockSize

            // decrypted = AES_ECB_Decrypt(xored)
            %decryptor.TransformBlock(xored, 0, BlockSize, decrypted, 0)

            // plainBlock = decrypted XOR prevCipher
            Bytes.xorBlock decrypted 0 prevCipher 0 result offset BlockSize

            // prevCipher = cipherBlock
            Bytes.copyTo data offset prevCipher 0 BlockSize

            // prevPlain = plainBlock
            Bytes.copyTo result offset prevPlain 0 BlockSize

        result
