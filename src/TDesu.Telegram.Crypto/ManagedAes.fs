namespace TDesu.Crypto

open System
open System.Security.Cryptography

/// AES-256 as a managed block cipher, for runtimes that do not provide one.
///
/// .NET has no AES on `browser-wasm` — `Aes.Create()` raises
/// `PlatformNotSupportedException`, and the BCL's own platform attributes say so, so
/// there is no cipher mode or padding that works around it. MTProto needs AES twice
/// on every connection (IGE for messages, CTR for transport obfuscation), which
/// leaves a WebAssembly client with no way to complete a handshake.
///
/// This is FIPS-197 with nothing on top: the plain byte-oriented cipher, no T-tables
/// and no bitslicing. It is slower than the platform implementation, which is why
/// nothing selects it while a platform one exists.
///
/// SIDE CHANNELS: the S-box lookups are data-dependent, so this is not constant-time
/// with respect to cache behaviour. That is the same tradeoff every managed AES makes,
/// and the deployment it exists for is a browser tab, where an attacker able to
/// observe this process's cache lines already has the page's memory.
module internal ManagedAes =

    [<Literal>]
    let BlockSize = 16

    /// Rounds for a 256-bit key.
    [<Literal>]
    let private Rounds = 14

    /// 32-bit words in a 256-bit key.
    [<Literal>]
    let private Nk = 8

    // ---- GF(2^8), modulus x^8 + x^4 + x^3 + x + 1 (0x11B) ----

    let private xtime (b: byte) =
        let shifted = b <<< 1
        if b &&& 0x80uy <> 0uy then shifted ^^^ 0x1Buy else shifted

    /// Multiplication in GF(2^8), by Russian-peasant doubling.
    let private gmul (a: byte) (b: byte) =
        let mutable result = 0uy
        let mutable x = a
        let mutable y = b

        while y <> 0uy do
            if y &&& 1uy <> 0uy then
                result <- result ^^^ x

            x <- xtime x
            y <- y >>> 1

        result

    // The S-box is derived rather than transcribed. A 256-entry literal table is a
    // transcription risk with no upside: the definition is short, it runs once, and a
    // single wrong nibble would produce a cipher that still encrypts and decrypts
    // consistently with itself while being incompatible with every other AES.
    let private sbox =
        // Inverses via the log/antilog tables of the field's generator 3, which is 512
        // steps. The obvious alternative — trying every pair until the product is 1 —
        // is 65k multiplications at type-initialisation time, and under a WebAssembly
        // interpreter that is a visible stall before the first byte is ever encrypted.
        let antilog = Array.zeroCreate<byte> 255
        let log = Array.zeroCreate<int> 256
        let mutable x = 1uy

        for i in 0..254 do
            antilog[i] <- x
            log[int x] <- i
            // Multiply by the generator 3 = x + 1.
            x <- x ^^^ xtime x

        let inverse (a: byte) =
            if a = 0uy then 0uy else antilog[(255 - log[int a]) % 255]

        Array.init 256 (fun i ->
            let x = inverse (byte i)

            let rotl (v: byte) n =
                (v <<< n) ||| (v >>> (8 - n))

            x ^^^ rotl x 1 ^^^ rotl x 2 ^^^ rotl x 3 ^^^ rotl x 4 ^^^ 0x63uy)

    let private invSbox =
        let table = Array.zeroCreate<byte> 256

        for i in 0..255 do
            table[int sbox[i]] <- byte i

        table

    /// Round constants, one per key-expansion round for a 256-bit key.
    let private rcon = [| 0x01uy; 0x02uy; 0x04uy; 0x08uy; 0x10uy; 0x20uy; 0x40uy |]

    /// Expands a 32-byte key into 15 round keys, flattened to 240 bytes.
    let expandKey (key: byte[]) : byte[] =
        if key.Length <> 32 then
            invalidArg (nameof key) "AES-256 key must be 32 bytes"

        let expanded = Array.zeroCreate<byte> ((Rounds + 1) * BlockSize)
        Array.blit key 0 expanded 0 key.Length

        let totalWords = (Rounds + 1) * 4

        for i in Nk .. totalWords - 1 do
            let prev = (i - 1) * 4
            let temp = Array.sub expanded prev 4

            if i % Nk = 0 then
                // RotWord, then SubWord, then the round constant on the top byte.
                let t0 = temp[0]
                temp[0] <- sbox[int temp[1]]
                temp[1] <- sbox[int temp[2]]
                temp[2] <- sbox[int temp[3]]
                temp[3] <- sbox[int t0]
                temp[0] <- temp[0] ^^^ rcon[i / Nk - 1]
            elif i % Nk = 4 then
                // The extra SubWord that only a 256-bit key schedule performs.
                for j in 0..3 do
                    temp[j] <- sbox[int temp[j]]

            let back = (i - Nk) * 4
            let current = i * 4

            for j in 0..3 do
                expanded[current + j] <- expanded[back + j] ^^^ temp[j]

        expanded

    let private addRoundKey (state: byte[]) (roundKeys: byte[]) (round: int) =
        let offset = round * BlockSize

        for i in 0 .. BlockSize - 1 do
            state[i] <- state[i] ^^^ roundKeys[offset + i]

    // The state is column-major: state[i] holds row (i % 4) of column (i / 4), which
    // is exactly the order the bytes arrive in.

    let private subBytes (state: byte[]) =
        for i in 0 .. BlockSize - 1 do
            state[i] <- sbox[int state[i]]

    let private invSubBytes (state: byte[]) =
        for i in 0 .. BlockSize - 1 do
            state[i] <- invSbox[int state[i]]

    /// Row r rotates left by r.
    let private shiftRows (state: byte[]) =
        let source = Array.copy state

        for r in 1..3 do
            for c in 0..3 do
                state[r + 4 * c] <- source[r + 4 * ((c + r) % 4)]

    /// Row r rotates right by r.
    let private invShiftRows (state: byte[]) =
        let source = Array.copy state

        for r in 1..3 do
            for c in 0..3 do
                state[r + 4 * c] <- source[r + 4 * ((c - r + 4) % 4)]

    // MixColumns multiplies by a fixed handful of constants, so the products are
    // tabulated once instead of running the doubling loop per byte per round. The
    // straightforward version cost roughly a thousand loop iterations per block, which
    // is invisible on a desktop and ruinous in WebAssembly: it turned an MTProto
    // handshake into minutes of blocked UI.
    let private mulTable (multiplier: byte) =
        Array.init 256 (fun i -> gmul (byte i) multiplier)

    let private mul2 = mulTable 2uy
    let private mul3 = mulTable 3uy
    let private mul9 = mulTable 9uy
    let private mul11 = mulTable 11uy
    let private mul13 = mulTable 13uy
    let private mul14 = mulTable 14uy

    let private mixColumns (state: byte[]) =
        for c in 0..3 do
            let o = 4 * c
            let a0, a1, a2, a3 = int state[o], int state[o + 1], int state[o + 2], int state[o + 3]
            state[o] <- mul2[a0] ^^^ mul3[a1] ^^^ byte a2 ^^^ byte a3
            state[o + 1] <- byte a0 ^^^ mul2[a1] ^^^ mul3[a2] ^^^ byte a3
            state[o + 2] <- byte a0 ^^^ byte a1 ^^^ mul2[a2] ^^^ mul3[a3]
            state[o + 3] <- mul3[a0] ^^^ byte a1 ^^^ byte a2 ^^^ mul2[a3]

    let private invMixColumns (state: byte[]) =
        for c in 0..3 do
            let o = 4 * c
            let a0, a1, a2, a3 = int state[o], int state[o + 1], int state[o + 2], int state[o + 3]
            state[o] <- mul14[a0] ^^^ mul11[a1] ^^^ mul13[a2] ^^^ mul9[a3]
            state[o + 1] <- mul9[a0] ^^^ mul14[a1] ^^^ mul11[a2] ^^^ mul13[a3]
            state[o + 2] <- mul13[a0] ^^^ mul9[a1] ^^^ mul14[a2] ^^^ mul11[a3]
            state[o + 3] <- mul11[a0] ^^^ mul13[a1] ^^^ mul9[a2] ^^^ mul14[a3]

    /// One block, in place from `source` into `destination`.
    let encryptBlock (roundKeys: byte[]) (source: byte[]) (sourceOffset: int) (destination: byte[]) (destinationOffset: int) =
        let state = Array.sub source sourceOffset BlockSize
        addRoundKey state roundKeys 0

        for round in 1 .. Rounds - 1 do
            subBytes state
            shiftRows state
            mixColumns state
            addRoundKey state roundKeys round

        // The last round omits MixColumns; without that, decryption cannot be inverted.
        subBytes state
        shiftRows state
        addRoundKey state roundKeys Rounds

        Array.blit state 0 destination destinationOffset BlockSize

    let decryptBlock (roundKeys: byte[]) (source: byte[]) (sourceOffset: int) (destination: byte[]) (destinationOffset: int) =
        let state = Array.sub source sourceOffset BlockSize
        addRoundKey state roundKeys Rounds

        for round in Rounds - 1 .. -1 .. 1 do
            invShiftRows state
            invSubBytes state
            addRoundKey state roundKeys round
            invMixColumns state

        invShiftRows state
        invSubBytes state
        addRoundKey state roundKeys 0

        Array.blit state 0 destination destinationOffset BlockSize

/// `ICryptoTransform` over the managed cipher, so callers that already drive
/// `Aes.CreateEncryptor()` need no second code path.
type internal ManagedAesTransform(key: byte[], encrypting: bool) =
    let roundKeys = ManagedAes.expandKey key

    interface ICryptoTransform with
        member _.CanReuseTransform = true
        member _.CanTransformMultipleBlocks = true
        member _.InputBlockSize = ManagedAes.BlockSize
        member _.OutputBlockSize = ManagedAes.BlockSize

        member _.TransformBlock(inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset) =
            if inputCount % ManagedAes.BlockSize <> 0 then
                invalidArg (nameof inputCount) "ECB input must be a whole number of 16-byte blocks"

            let blocks = inputCount / ManagedAes.BlockSize

            for i in 0 .. blocks - 1 do
                let offset = i * ManagedAes.BlockSize

                if encrypting then
                    ManagedAes.encryptBlock roundKeys inputBuffer (inputOffset + offset) outputBuffer (outputOffset + offset)
                else
                    ManagedAes.decryptBlock roundKeys inputBuffer (inputOffset + offset) outputBuffer (outputOffset + offset)

            inputCount

        member this.TransformFinalBlock(inputBuffer, inputOffset, inputCount) =
            if inputCount = 0 then
                Array.empty
            else
                let output = Array.zeroCreate<byte> inputCount
                (this :> ICryptoTransform).TransformBlock(inputBuffer, inputOffset, inputCount, output, 0) |> ignore
                output

    interface IDisposable with
        member _.Dispose() = Array.Clear(roundKeys, 0, roundKeys.Length)

/// AES-256-ECB single-block transforms, from the platform where it has them and from
/// the managed cipher where it does not.
///
/// ECB is never a mode to encrypt data in. It is here because AES-IGE and AES-CTR are
/// both built out of raw block operations, and this is how .NET exposes one.
[<RequireQualifiedAccess>]
module AesEcb =

    /// Whether the runtime supplies AES at all.
    ///
    /// Probed rather than sniffed by OS name: `netstandard2.1` has no
    /// `OperatingSystem.IsBrowser()`, and the question that matters is not which
    /// platform this is but whether a transform can actually be created on it.
    let private platformSupportsAes =
        lazy
            (try
                use aes = Aes.Create()
                aes.Mode <- CipherMode.ECB
                aes.Padding <- PaddingMode.None
                aes.Key <- Array.zeroCreate 32
                use transform = aes.CreateEncryptor()
                transform.TransformFinalBlock(Array.zeroCreate ManagedAes.BlockSize, 0, ManagedAes.BlockSize) |> ignore
                true
             with :? PlatformNotSupportedException ->
                 false)

    /// True when the managed cipher is in use, i.e. the platform has no AES.
    let isManaged = not platformSupportsAes.Value

    let private platformTransform (key: byte[]) (encrypting: bool) =
        let aes = Aes.Create()
        aes.Mode <- CipherMode.ECB
        aes.Padding <- PaddingMode.None
        aes.KeySize <- 256
        aes.Key <- key

        if encrypting then
            aes.CreateEncryptor()
        else
            aes.CreateDecryptor()

    let createEncryptor (key: byte[]) : ICryptoTransform =
        if platformSupportsAes.Value then
            platformTransform key true
        else
            new ManagedAesTransform(key, true) :> ICryptoTransform

    let createDecryptor (key: byte[]) : ICryptoTransform =
        if platformSupportsAes.Value then
            platformTransform key false
        else
            new ManagedAesTransform(key, false) :> ICryptoTransform
