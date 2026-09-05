namespace TDesu.Crypto

open System
open System.Numerics
open System.Security.Cryptography

/// 2048-bit Diffie-Hellman key exchange as used in MTProto
/// (core.telegram.org/mtproto/auth_key): generating this client's own exponent,
/// computing `g^a mod p` and the shared `auth_key`, and validating a server's
/// offered `(g, dh_prime)` and public values against the spec's safety margins.
[<RequireQualifiedAccess>]
module DiffieHellman =

    /// Generate random 256-byte value for DH
    let generateA () : byte[] =
        let bytes = Array.zeroCreate<byte> 256
        RandomNumberGenerator.Fill(bytes)
        bytes

    /// Compute g^a mod p
    let computeGA (g: int) (a: byte[]) (p: byte[]) : byte[] =
        let gBI = BigInteger(g)
        let aBI = BigEndian.toBigInteger a
        let pBI = BigEndian.toBigInteger p
        let result = BigInteger.ModPow(gBI, aBI, pBI)
        BigEndian.toBytes p.Length result

    /// Compute g_b^a mod p (shared secret / auth_key)
    let computeAuthKey (gB: byte[]) (a: byte[]) (p: byte[]) : byte[] =
        let gBBI = BigEndian.toBigInteger gB
        let aBI = BigEndian.toBigInteger a
        let pBI = BigEndian.toBigInteger p
        let result = BigInteger.ModPow(gBBI, aBI, pBI)
        BigEndian.toBytes 256 result

    /// Validate that g_a or g_b lies within [2^{2048-64}, p - 2^{2048-64}], the stricter range
    /// recommended by the MTProto 2.0 security guidelines. This rejects the degenerate
    /// small-subgroup values (0, 1, p-1) and any value close enough to the bounds to leak the
    /// exponent; the minimal 1 < g_a < p-1 rule alone is not sufficient.
    let validateGARange (ga: byte[]) (p: byte[]) : bool =
        let gaInt = BigEndian.toBigInteger ga
        let pInt = BigEndian.toBigInteger p
        let margin = BigInteger.One <<< (2048 - 64)
        gaInt >= margin && gaInt <= (pInt - margin)

    // Cryptographically secure RNG for Miller-Rabin witnesses.
    let private rng = RandomNumberGenerator.Create()

    /// Uniform BigInteger in [0, m).
    let private randomBelow (m: BigInteger) : BigInteger =
        let mBytes = m.ToByteArray() // little-endian, two's complement
        let buf = Array.zeroCreate<byte> (mBytes.Length + 1)
        rng.GetBytes(buf)
        buf[buf.Length - 1] <- 0uy // force a non-negative interpretation
        BigInteger(buf) % m

    /// Miller-Rabin probabilistic primality test with cryptographically random bases.
    /// Random bases (not fixed witnesses) are required because dh_prime is attacker-chosen;
    /// the adversarial error probability is 4^-rounds.
    ///
    /// `internal` (not `private`) rather than only reachable through `isSafePrime`'s
    /// equality fast path below, so `DhValidationTests.fs` can run it directly on
    /// `knownSafePrime` — proving the pinned bytes actually are prime, not just that
    /// they equal themselves.
    let internal isProbablePrime (n: BigInteger) (rounds: int) : bool =
        if n < BigInteger 2 then false
        elif n = BigInteger 2 || n = BigInteger 3 then true
        elif n.IsEven then false
        else
            let nm1 = n - BigInteger.One
            let mutable d = nm1
            let mutable r = 0
            while d.IsEven do
                d <- d >>> 1
                r <- r + 1

            let mutable probablyPrime = true
            let mutable round = 0
            while probablyPrime && round < rounds do
                let a = BigInteger 2 + randomBelow (n - BigInteger 3) // base in [2, n-2]
                let mutable x = BigInteger.ModPow(a, d, n)
                if x <> BigInteger.One && x <> nm1 then
                    let mutable j = 1
                    let mutable sawMinusOne = false
                    while not sawMinusOne && j < r do
                        x <- BigInteger.ModPow(x, BigInteger 2, n)
                        if x = nm1 then sawMinusOne <- true
                        j <- j + 1
                    if not sawMinusOne then probablyPrime <- false
                round <- round + 1

            probablyPrime

    /// Telegram's canonical 2048-bit safe prime — the value official clients ship and
    /// servers offer in practice.
    ///
    /// Recognising it is not a shortcut around the check, it is a stronger form of it:
    /// a fixed value verified once and pinned beats re-deriving the same answer
    /// probabilistically on every connection. What it buys is the difference between a
    /// usable client and an unusable one — the two Miller-Rabin passes below are 128
    /// modular exponentiations, which cost milliseconds on a desktop and about three and
    /// a half minutes under a WebAssembly interpreter, where one 2048-bit `ModPow`
    /// measures 1.7 seconds.
    ///
    /// `internal` so `DhValidationTests.fs` can run `isProbablePrime` on these exact
    /// bytes directly — see `isProbablePrime`'s doc comment.
    let internal knownSafePrime =
        Rsa.hexToBytes (
            "C71CAEB9C6B1C9048E6C522F70F13F73980D40238E3E21C14934D037563D930F"
            + "48198A0AA7C14058229493D22530F4DBFA336F6E0AC925139543AED44CCE7C37"
            + "20FD51F69458705AC68CD4FE6B6B13ABDC9746512969328454F18FAF8C595F64"
            + "2477FE96BB2A941D5BCD1D4AC8CC49880708FA9B378E3C4F3A9060BEE67CF9A4"
            + "A4A695811051907E162753B56B0F6B410DBA74D8A84B2A14B3144E0EF1284754"
            + "FD17ED950D5965B4B9DD46582DB1178D169C6BC465B0D6FF9CA3928FEF5B9AE4"
            + "E418FC15E83EBEA0F87FA9FF5EED70050DED2849F47BF959D956850CE929851F"
            + "0D8115F635B105EE2E4E15D04B2454BF6F4FADF034B10403119CD8E3B92FCC5B"
        )

    // Safe-prime verification is expensive, so successful results are memoised by prime.
    // Only positive results are cached (a tiny set in practice), so a malicious server cannot
    // fill memory with distinct rejected primes. The cache is per-process, so a browser tab
    // pays for an unrecognised prime again on every reload.
    let private safePrimeCache =
        System.Collections.Concurrent.ConcurrentDictionary<string, bool>()

    let private isSafePrime (p: BigInteger) (pBytes: byte[]) : bool =
        if System.Linq.Enumerable.SequenceEqual(pBytes, knownSafePrime) then
            true
        else
            let key =
                use sha = SHA256.Create()
                System.Convert.ToBase64String(sha.ComputeHash pBytes)

            match safePrimeCache.TryGetValue key with
            | true, cached -> cached
            | _ ->
                let ok = isProbablePrime p 64 && isProbablePrime ((p - BigInteger.One) >>> 1) 64
                if ok then safePrimeCache[key] <- true
                ok

    /// The residue condition MTProto attaches to each permitted generator, verbatim from
    /// core.telegram.org/mtproto/auth_key: it is what makes `g` generate the whole quadratic-residue
    /// subgroup of a safe prime rather than a smaller one. `g = 7` requires `p mod 7 = 3, 5 or 6`;
    /// this accepted 4 as well until 0.3.3 — read off the wrong table — and a server offering
    /// `g = 7` with such a prime would have passed validation the spec says to refuse.
    let generatorResidueOk (g: int) (p: BigInteger) : bool =
        match g with
        | 2 -> int (p % BigInteger 8) = 7
        | 3 -> int (p % BigInteger 3) = 2
        | 4 -> true
        | 5 -> let m = int (p % BigInteger 5) in m = 1 || m = 4
        | 6 -> let m = int (p % BigInteger 24) in m = 19 || m = 23
        | 7 -> let m = int (p % BigInteger 7) in m = 3 || m = 5 || m = 6
        | _ -> false

    /// Validate the server's DH parameters (g, dh_prime). Enforces that g is one of the six
    /// generators Telegram permits (2..7) with its residue condition, that dh_prime is exactly
    /// 2048 bits, and that dh_prime is a safe prime (both p and (p-1)/2 are prime). A malicious
    /// server that skipped any of these could otherwise force a recoverable auth key.
    let validateDhParams (g: int) (p: byte[]) : bool =
        if g < 2 || g > 7 then
            false
        elif p.Length <> 256 then
            false
        else
            let pBI = BigEndian.toBigInteger p

            if pBI < (BigInteger.One <<< 2047) || pBI >= (BigInteger.One <<< 2048) then
                false
            else
                generatorResidueOk g pBI && isSafePrime pBI p
