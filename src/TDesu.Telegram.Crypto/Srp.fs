namespace TDesu.Crypto

open System
open System.Numerics
open System.Security.Cryptography
open System.Text
open TDesu.FSharp.Buffers

/// Client half of Telegram's SRP-6a variant for two-factor login
/// (core.telegram.org/api/srp), for the one KDF layer 228 advertises —
/// `passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow`.
/// `account.getPassword` hands back `(salt1, salt2, g, p, srp_B)`; `clientProof`
/// turns those plus the account's password into an `SrpProof` (`srp_A`, `M1`) for
/// `auth.checkPassword`'s `inputCheckPasswordSRP`. The password itself never
/// crosses the wire — only proof that the caller knows it.
///
/// Deliberately client-only: there is no `verifier`/`serverPublic`/`verify` here,
/// because nothing in this tree ever plays the server role. Checked against an
/// independent implementation's vectors for the far end — see `SrpTests.fs` for
/// the shared known-answer vectors both sides land on.
///
/// `clientProof` validates `g`/`p` with `DiffieHellman.validateDhParams` and
/// `serverPublicB` against `1 < B < p-1` before using either — SRP reuses the
/// exact DH group and public-value shape the MTProto handshake already validates,
/// so this is the same check, not a second one to keep in sync. A caller that has
/// already validated a group it intends to reuse across many proofs may call the
/// internal `clientProofWithSecret` directly to skip re-validating it.
[<RequireQualifiedAccess>]
module Srp =

    /// The two values `auth.checkPassword`'s `inputCheckPasswordSRP` needs: this
    /// client's own DH public value (`srp_A`) and the proof that it knows the
    /// account password (`M1`), without either one carrying the password itself.
    type SrpProof = { ClientPublic: byte[]; Proof: byte[] }

    /// Left-pads to `size` bytes. Every group element Telegram hashes is
    /// fixed-width, but TL `bytes` carries none and `BigInteger.ToByteArray`
    /// strips leading zeros, so a value that happens to be a byte short must
    /// still be re-padded before it is hashed, or it hashes to something the
    /// server never computed.
    let private toBytes (size: int) (value: BigInteger) : byte[] = BigEndian.toBytes size value

    /// SHA256 over the concatenation of `parts`, without materialising it.
    let private h (parts: byte[] list) : byte[] =
        use hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256)

        for part in parts do
            hasher.AppendData part

        hasher.GetHashAndReset()

    /// SH(data, salt) = SHA256(salt | data | salt).
    let private sh (data: byte[]) (salt: byte[]) : byte[] = h [ salt; data; salt ]

    /// PBKDF2-HMAC-SHA512 producing exactly 64 bytes — one HMAC-SHA512 block, so
    /// the general PBKDF2 block-index-and-truncate machinery collapses to a
    /// single U-chain (`U1 = HMAC(salt | be32(1))`, `Ti = U1 xor .. xor Uc`).
    /// Written by hand rather than via `Rfc2898DeriveBytes` because every ctor
    /// that BCL type offers for a keyed hash other than SHA-1 is obsolete on
    /// current .NET in favour of a static `Pbkdf2` helper that does not exist on
    /// `netstandard2.1`, the TFM this library targets for WASM.
    ///
    /// Writes each of the 100,000 HMAC outputs into one reused 64-byte buffer via
    /// `TryComputeHash` (ping-ponged against a second buffer) instead of letting
    /// `ComputeHash` allocate a fresh 64-byte array per call — 6.4 MB of digest
    /// garbage for one password check before this, now four fixed buffers.
    let private pbkdf2Sha512Block64 (password: byte[]) (salt: byte[]) (iterations: int) : byte[] =
        use hmac = new HMACSHA512(password)
        let mutable bytesWritten = 0

        let mutable u = Array.zeroCreate<byte> 64
        let mutable next = Array.zeroCreate<byte> 64

        let seed = Bytes.concat2 salt [| 0uy; 0uy; 0uy; 1uy |]
        hmac.TryComputeHash(ReadOnlySpan<byte> seed, Span<byte> u, &bytesWritten) |> ignore

        let t = Array.copy u

        for _ in 2..iterations do
            hmac.TryComputeHash(ReadOnlySpan<byte> u, Span<byte> next, &bytesWritten) |> ignore
            let swap = u
            u <- next
            next <- swap

            for i in 0..63 do
                t[i] <- t[i] ^^^ u[i]

        t

    /// x = PH2(password, salt1, salt2), the client-side password hash:
    ///   PH1 = SH(SH(password, salt1), salt2)
    ///   PH2 = SH(pbkdf2(sha512, PH1, salt1, 100000, 64 bytes), salt2)
    /// The server never sees the password or x — only ever `g^x mod p`, the
    /// verifier `account.updatePasswordSettings` uploaded and `clientProof`
    /// below proves knowledge of without sending either.
    ///
    /// Clears the UTF-8 encoding of `password` once it has been hashed: the
    /// `string` itself cannot be scrubbed (.NET strings are immutable and may be
    /// interned), but the byte buffer this function creates from it can be, and
    /// otherwise would be the one copy of the password's raw bytes left sitting
    /// in managed memory after this returns.
    let passwordHash (password: string) (salt1: byte[]) (salt2: byte[]) : byte[] =
        let passwordBytes = Encoding.UTF8.GetBytes password

        try
            let ph1 = sh (sh passwordBytes salt1) salt2
            sh (pbkdf2Sha512Block64 ph1 salt1 100_000) salt2
        finally
            Array.Clear(passwordBytes, 0, passwordBytes.Length)

    /// Computes `(srp_A, M1)` for an explicitly supplied client secret `a`.
    /// `internal`: the known-answer vectors in `SrpTests.fs` must reproduce an
    /// exact, previously-published `srp_A`, which requires supplying the same
    /// fixed secret the vectors were computed with — something the public
    /// `clientProof` deliberately does not accept, since a fixed secret across
    /// calls is exactly what SRP must not do in production. `secretA` is sized
    /// for the group (e.g. `DiffieHellman.generateA ()`, 256 bytes for this
    /// 2048-bit group).
    let internal clientProofWithSecret
        (password: string)
        (salt1: byte[])
        (salt2: byte[])
        (g: int)
        (p: byte[])
        (serverPublicB: byte[])
        (secretA: byte[])
        : byte[] * byte[] =
        let size = p.Length
        let pi = BigEndian.toBigInteger p
        let gInt = BigInteger g
        let gPad = toBytes size gInt
        let x = BigEndian.toBigInteger (passwordHash password salt1 salt2)
        let v = BigInteger.ModPow(gInt, x, pi)
        let k = BigEndian.toBigInteger (h [ p; gPad ])
        let a = BigEndian.toBigInteger secretA
        let clientPublic = toBytes size (BigInteger.ModPow(gInt, a, pi))
        // Re-pad B: TL `bytes` carries no fixed width, so it must hash at the
        // full group width regardless of how the server happened to serialize it.
        let serverPublic = toBytes size (BigEndian.toBigInteger serverPublicB)
        let u = BigEndian.toBigInteger (h [ clientPublic; serverPublic ])

        let kv = (k * v) % pi
        let t0 = (BigEndian.toBigInteger serverPublic - kv) % pi
        let t = if t0.Sign < 0 then t0 + pi else t0
        let s = BigInteger.ModPow(t, a + (u * x), pi)

        let hp = h [ p ]
        let hg = h [ gPad ]
        let hpXorHg = Array.map2 (^^^) hp hg

        let m1 =
            h [
                hpXorHg
                h [ salt1 ]
                h [ salt2 ]
                clientPublic
                serverPublic
                h [ toBytes size s ]
            ]

        clientPublic, m1

    /// Proves knowledge of `password` to a server holding `g^x mod p`, without
    /// sending the password or x. `g`/`p`/`serverPublicB` come from
    /// `account.getPassword`'s `current_algo`/`srp_B`.
    ///
    /// Before computing anything, this validates the group the same way the
    /// MTProto handshake validates its own `g`/`dh_prime`
    /// (`DiffieHellman.validateDhParams`), refuses a server public value outside
    /// `1 < B < p-1`, and refuses the degenerate case `B - k*v ≡ 0 (mod p)` — a
    /// server able to force that could solve for the password verifier directly
    /// instead of merely checking a proof against it. Checking the last one needs
    /// `x`/`v`, which duplicates the one expensive step (100,000-round PBKDF2)
    /// `clientProofWithSecret` performs again below; accepted because this
    /// function runs once per login attempt a human is already waiting on, not
    /// once per message the way `KeyDerivation`/`AesIge` do.
    ///
    /// Draws its own client secret from a CSPRNG and redraws it until `g^a`
    /// itself passes `DiffieHellman.validateGARange` — the same margin the
    /// handshake requires of its own `g_a`/`g_b`, reused here because SRP shares
    /// the identical group. These are the checks core.telegram.org/api/srp lists
    /// and TeleEye's own `SrpHelper` had to add because this library did not
    /// perform them.
    let clientProof
        (password: string)
        (salt1: byte[])
        (salt2: byte[])
        (g: int)
        (p: byte[])
        (serverPublicB: byte[])
        : Result<SrpProof, string> =
        if not (DiffieHellman.validateDhParams g p) then
            Error "SRP group parameters (g, p) failed DiffieHellman.validateDhParams"
        else
            let pi = BigEndian.toBigInteger p
            let bInt = BigEndian.toBigInteger serverPublicB

            if bInt <= BigInteger.One || bInt >= pi - BigInteger.One then
                Error "SRP server public value B is outside the required range 1 < B < p-1"
            else
                let size = p.Length
                let gInt = BigInteger g
                let k = BigEndian.toBigInteger (h [ p; toBytes size gInt ])
                let x = BigEndian.toBigInteger (passwordHash password salt1 salt2)
                let v = BigInteger.ModPow(gInt, x, pi)
                let kv = (k * v) % pi
                let t0 = (bInt - kv) % pi
                let t = if t0.Sign < 0 then t0 + pi else t0

                if t.IsZero then
                    Error "SRP server public value B is degenerate (B - k*v = 0 mod p)"
                else
                    let rec drawValidSecret () =
                        let secretA = DiffieHellman.generateA ()
                        let clientPublic = toBytes size (BigInteger.ModPow(gInt, BigEndian.toBigInteger secretA, pi))

                        if DiffieHellman.validateGARange clientPublic p then
                            secretA
                        else
                            drawValidSecret ()

                    let secretA = drawValidSecret ()
                    let clientPublic, proof = clientProofWithSecret password salt1 salt2 g p serverPublicB secretA
                    Array.Clear(secretA, 0, secretA.Length)
                    Ok { ClientPublic = clientPublic; Proof = proof }
