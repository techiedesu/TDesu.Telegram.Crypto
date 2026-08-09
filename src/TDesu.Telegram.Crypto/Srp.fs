namespace TDesu.Crypto

open System
open System.Numerics
open System.Security.Cryptography
open System.Text

/// Client half of Telegram's SRP-6a variant for two-factor login
/// (core.telegram.org/api/srp), for the one KDF layer 228 advertises —
/// `passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow`.
/// `account.getPassword` hands back `(salt1, salt2, g, p, srp_B)`; `clientProof`
/// turns those plus the account's password into `(srp_A, M1)` for
/// `auth.checkPassword`'s `inputCheckPasswordSRP`. The password itself never
/// crosses the wire — only proof that the caller knows it.
///
/// Deliberately client-only: there is no `verifier`/`serverPublic`/`verify` here,
/// because nothing in this tree ever plays the server role. Checked against
/// Altergram's own reference implementation of the far end
/// (`src/Altergram.Server/Crypto/Srp.cs`) — see `SrpTests.fs` for the shared
/// known-answer vectors both sides land on.
///
/// `g`/`p`/`srp_B` are taken as given: this module does not re-validate them as a
/// safe DH group / in-range public value. Callers should run them through
/// `DiffieHellman.validateDhParams`/`validateGARange` first — the exact checks
/// the MTProto handshake already applies to its own `g`/`p`/`g_a`/`g_b`. SRP
/// reuses the identical group, so there is one implementation of that check to
/// call, not a second one to keep in sync.
[<RequireQualifiedAccess>]
module Srp =

    let private toInt (bigEndian: byte[]) : BigInteger =
        BigInteger(ReadOnlySpan<byte> bigEndian, isUnsigned = true, isBigEndian = true)

    /// Left-pads to `size` bytes. Every group element Telegram hashes is
    /// fixed-width, but TL `bytes` carries none and `BigInteger.ToByteArray`
    /// strips leading zeros, so a value that happens to be a byte short must
    /// still be re-padded before it is hashed, or it hashes to something the
    /// server never computed.
    let private toBytes (size: int) (value: BigInteger) : byte[] =
        let raw = value.ToByteArray(isUnsigned = true, isBigEndian = true)

        if raw.Length > size then
            invalidArg (nameof value) "SRP value wider than the group modulus"

        let out = Array.zeroCreate<byte> size
        Array.blit raw 0 out (size - raw.Length) raw.Length
        out

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
    let private pbkdf2Sha512Block64 (password: byte[]) (salt: byte[]) (iterations: int) : byte[] =
        use hmac = new HMACSHA512(password)
        let mutable u = hmac.ComputeHash(Array.append salt [| 0uy; 0uy; 0uy; 1uy |])
        let t = Array.copy u

        for _ in 2..iterations do
            u <- hmac.ComputeHash u

            for i in 0 .. t.Length - 1 do
                t[i] <- t[i] ^^^ u[i]

        t

    /// x = PH2(password, salt1, salt2), the client-side password hash:
    ///   PH1 = SH(SH(password, salt1), salt2)
    ///   PH2 = SH(pbkdf2(sha512, PH1, salt1, 100000, 64 bytes), salt2)
    /// The server never sees the password or x — only ever `g^x mod p`, the
    /// verifier `account.updatePasswordSettings` uploaded and `clientProof`
    /// below proves knowledge of without sending either.
    let passwordHash (password: string) (salt1: byte[]) (salt2: byte[]) : byte[] =
        let ph1 = sh (sh (Encoding.UTF8.GetBytes password) salt1) salt2
        sh (pbkdf2Sha512Block64 ph1 salt1 100_000) salt2

    /// Proves knowledge of `password` to a server holding `g^x mod p`, without
    /// sending the password or x. `secretA` is this exchange's private client
    /// exponent — fresh randomness per attempt, sized for the group (e.g.
    /// `DiffieHellman.generateA ()`, which already produces the right width for
    /// this same 2048-bit group). `g`/`p`/`serverPublicB` come from
    /// `account.getPassword`'s `current_algo`/`srp_B`.
    ///
    /// Returns `(srp_A, M1)` ready for `inputCheckPasswordSRP`.
    let clientProof
        (password: string)
        (salt1: byte[])
        (salt2: byte[])
        (g: int)
        (p: byte[])
        (serverPublicB: byte[])
        (secretA: byte[])
        : byte[] * byte[] =
        let size = p.Length
        let pi = toInt p
        let gInt = BigInteger g
        let gPad = toBytes size gInt
        let x = toInt (passwordHash password salt1 salt2)
        let v = BigInteger.ModPow(gInt, x, pi)
        let k = toInt (h [ p; gPad ])
        let a = toInt secretA
        let clientPublic = toBytes size (BigInteger.ModPow(gInt, a, pi))
        // Re-pad B: TL `bytes` carries no fixed width, so it must hash at the
        // full group width regardless of how the server happened to serialize it.
        let serverPublic = toBytes size (toInt serverPublicB)
        let u = toInt (h [ clientPublic; serverPublic ])

        let kv = (k * v) % pi
        let t0 = (toInt serverPublic - kv) % pi
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
