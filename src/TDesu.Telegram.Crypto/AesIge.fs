namespace TDesu.Crypto

open System
open TDesu.FSharp
open TDesu.FSharp.Operators

/// AES-256-IGE (Infinite Garble Extension) mode — the non-standard block cipher mode
/// MTProto uses for message encryption. Unlike CBC, corrupting one ciphertext block
/// garbles every later plaintext block on decrypt rather than just the next one,
/// which is why MTProto layers its own `msg_key` integrity check on top instead of
/// relying on the chaining alone.
///
/// IGE chains each block's output into the next block's input, so it cannot be
/// parallelised or handed to the platform cipher as one multi-block call the way
/// CBC/CTR can — one `ICryptoTransform.TransformBlock` interop call per 16 bytes
/// (65,536 per MiB) is the accepted ceiling here, not an oversight. A
/// `System.Runtime.Intrinsics.X86.Aes` block path under `net8.0`/`netstandard2.1`
/// multi-targeting could still avoid the interop boundary itself; that is
/// follow-up work, not something `encryptTo`/`decryptTo`'s span-based signatures
/// preclude later.
[<RequireQualifiedAccess>]
module AesIge =

    [<Literal>]
    let private BlockSize = 16

    /// Encrypts `input` into `output`. `output` may alias `input` for an in-place
    /// encryption. Per 16-byte block, `prevPlain`/`prevCipher` are read (still
    /// holding the *previous* block's values) before being overwritten with this
    /// block's values, and this block's plaintext is copied out of `input` before
    /// `output` is written at the same index — so an aliased write can never
    /// clobber a value this or a later iteration still needs.
    let encryptTo (input: ReadOnlySpan<byte>) (key: byte[]) (iv: byte[]) (output: Span<byte>) : unit =
        Guard.isTrue (nameof input) "Data length must be a multiple of 16" (input.Length % BlockSize = 0)
        Guard.isTrue (nameof key) "Key must be 32 bytes" (key.Length = 32)
        Guard.isTrue (nameof iv) "IV must be 32 bytes" (iv.Length = 32)
        Guard.isTrue (nameof output) "Output length must equal input length" (output.Length = input.Length)

        // Not `Aes.Create()` directly: browser-wasm has no AES, and this is the code
        // path every encrypted MTProto message takes.
        use encryptor = AesEcb.createEncryptor key
        let blockCount = input.Length / BlockSize

        // Hoisted once for the whole call rather than allocated per block: IGE
        // chains one block's output into the next block's input, so these four
        // 16-byte buffers are exactly the running state the algorithm carries.
        let prevPlain = Array.zeroCreate<byte> BlockSize
        let prevCipher = Array.zeroCreate<byte> BlockSize
        let xored = Array.zeroCreate<byte> BlockSize
        let encrypted = Array.zeroCreate<byte> BlockSize

        // iv[0..15] = previous ciphertext, iv[16..31] = previous plaintext
        Array.blit iv 0 prevCipher 0 BlockSize
        Array.blit iv BlockSize prevPlain 0 BlockSize

        for i = 0 to blockCount - 1 do
            let offset = i * BlockSize

            // xored = plainBlock XOR prevCipher
            for j = 0 to BlockSize - 1 do
                xored[j] <- input[offset + j] ^^^ prevCipher[j]

            // encrypted = AES_ECB_Encrypt(xored)
            %encryptor.TransformBlock(xored, 0, BlockSize, encrypted, 0)

            // cipherBlock = encrypted XOR prevPlain, using prevPlain's *old* value
            // (the previous block's plaintext) before it is overwritten with this
            // block's plaintext -- read old prevPlain into `c`, then overwrite
            // prevPlain from `input` (still untouched at this index even if
            // `output` aliases it), then finally write `output`/prevCipher.
            for j = 0 to BlockSize - 1 do
                let c = encrypted[j] ^^^ prevPlain[j]
                prevPlain[j] <- input[offset + j]
                output[offset + j] <- c
                prevCipher[j] <- c

    /// Decrypts `input` into `output`, with the same in-place aliasing guarantee
    /// and old-value-before-overwrite ordering as `encryptTo`.
    let decryptTo (input: ReadOnlySpan<byte>) (key: byte[]) (iv: byte[]) (output: Span<byte>) : unit =
        Guard.isTrue (nameof input) "Data length must be a multiple of 16" (input.Length % BlockSize = 0)
        Guard.isTrue (nameof key) "Key must be 32 bytes" (key.Length = 32)
        Guard.isTrue (nameof iv) "IV must be 32 bytes" (iv.Length = 32)
        Guard.isTrue (nameof output) "Output length must equal input length" (output.Length = input.Length)

        use decryptor = AesEcb.createDecryptor key
        let blockCount = input.Length / BlockSize

        let prevCipher = Array.zeroCreate<byte> BlockSize
        let prevPlain = Array.zeroCreate<byte> BlockSize
        let xored = Array.zeroCreate<byte> BlockSize
        let decrypted = Array.zeroCreate<byte> BlockSize

        // iv[0..15] = previous ciphertext, iv[16..31] = previous plaintext
        Array.blit iv 0 prevCipher 0 BlockSize
        Array.blit iv BlockSize prevPlain 0 BlockSize

        for i = 0 to blockCount - 1 do
            let offset = i * BlockSize

            // xored = cipherBlock XOR prevPlain
            for j = 0 to BlockSize - 1 do
                xored[j] <- input[offset + j] ^^^ prevPlain[j]

            // decrypted = AES_ECB_Decrypt(xored)
            %decryptor.TransformBlock(xored, 0, BlockSize, decrypted, 0)

            // plainBlock = decrypted XOR prevCipher, using prevCipher's *old*
            // value (the previous block's ciphertext) before it is overwritten
            // with this block's ciphertext -- same read-old/overwrite/write
            // ordering as encryptTo, with plain and cipher swapped.
            for j = 0 to BlockSize - 1 do
                let p = decrypted[j] ^^^ prevCipher[j]
                prevCipher[j] <- input[offset + j]
                output[offset + j] <- p
                prevPlain[j] <- p

    /// `encryptTo` allocating its own output. Data length must be a multiple of 16.
    let encrypt (data: byte[]) (key: byte[]) (iv: byte[]) : byte[] =
        let result = Array.zeroCreate<byte> data.Length
        encryptTo (ReadOnlySpan<byte> data) key iv (Span<byte> result)
        result

    /// `decryptTo` allocating its own output. Data length must be a multiple of 16.
    let decrypt (data: byte[]) (key: byte[]) (iv: byte[]) : byte[] =
        let result = Array.zeroCreate<byte> data.Length
        decryptTo (ReadOnlySpan<byte> data) key iv (Span<byte> result)
        result
