namespace TDesu.Crypto

open System
open System.Numerics
open System.Security.Cryptography
open TDesu.FSharp
open TDesu.FSharp.Operators
open TDesu.FSharp.Buffers
[<RequireQualifiedAccess>]
module DiffieHellman =

    /// Convert big-endian byte array to unsigned BigInteger (little-endian + sign byte)
    let private toBigInteger (bigEndian: byte[]) : BigInteger =
        let le = Array.copy bigEndian
        Array.Reverse(le)
        BigInteger(Bytes.concat2 le [| 0uy |])

    /// Convert BigInteger back to big-endian byte array of specified length
    let private fromBigInteger (bi: BigInteger) (length: int) : byte[] =
        let bytes = bi.ToByteArray()
        let trimmed =
            if bytes.Length > 1 && bytes[bytes.Length - 1] = 0uy then
                bytes[.. bytes.Length - 2]
            else
                bytes
        let be = Array.copy trimmed
        Array.Reverse(be)
        if be.Length < length then
            Bytes.concat2 (Array.zeroCreate (length - be.Length)) be
        elif be.Length > length then
            be[be.Length - length ..]
        else
            be

    /// Generate random 256-byte value for DH
    let generateA () : byte[] =
        let bytes = Array.zeroCreate<byte> 256
        RandomNumberGenerator.Fill(bytes)
        bytes

    /// Compute g^a mod p
    let computeGA (g: int) (a: byte[]) (p: byte[]) : byte[] =
        let gBI = BigInteger(g)
        let aBI = toBigInteger a
        let pBI = toBigInteger p
        let result = BigInteger.ModPow(gBI, aBI, pBI)
        fromBigInteger result p.Length

    /// Compute g_b^a mod p (shared secret / auth_key)
    let computeAuthKey (gB: byte[]) (a: byte[]) (p: byte[]) : byte[] =
        let gBBI = toBigInteger gB
        let aBI = toBigInteger a
        let pBI = toBigInteger p
        let result = BigInteger.ModPow(gBBI, aBI, pBI)
        fromBigInteger result 256

    /// Validate that g_a or g_b lies within [2^{2048-64}, p - 2^{2048-64}], the stricter range
    /// recommended by the MTProto 2.0 security guidelines. This rejects the degenerate
    /// small-subgroup values (0, 1, p-1) and any value close enough to the bounds to leak the
    /// exponent; the minimal 1 < g_a < p-1 rule alone is not sufficient.
    let validateGARange (ga: byte[]) (p: byte[]) : bool =
        let gaInt = toBigInteger ga
        let pInt = toBigInteger p
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
    let private isProbablePrime (n: BigInteger) (rounds: int) : bool =
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

    // Safe-prime verification is expensive, so successful results are memoised by prime.
    // Only positive results are cached (a tiny set in practice), so a malicious server cannot
    // fill memory with distinct rejected primes.
    let private safePrimeCache =
        System.Collections.Concurrent.ConcurrentDictionary<string, bool>()

    let private isSafePrime (p: BigInteger) (pBytes: byte[]) : bool =
        let key =
            use sha = SHA256.Create()
            System.Convert.ToBase64String(sha.ComputeHash pBytes)

        match safePrimeCache.TryGetValue key with
        | true, cached -> cached
        | _ ->
            let ok = isProbablePrime p 64 && isProbablePrime ((p - BigInteger.One) >>> 1) 64
            if ok then safePrimeCache[key] <- true
            ok

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
            let pBI = toBigInteger p

            if pBI < (BigInteger.One <<< 2047) || pBI >= (BigInteger.One <<< 2048) then
                false
            else
                let gOk =
                    match g with
                    | 2 -> int (pBI % BigInteger 8) = 7
                    | 3 -> int (pBI % BigInteger 3) = 2
                    | 4 -> true
                    | 5 -> let m = int (pBI % BigInteger 5) in m = 1 || m = 4
                    | 6 -> let m = int (pBI % BigInteger 24) in m = 19 || m = 23
                    | 7 -> let m = int (pBI % BigInteger 7) in m = 3 || m = 4 || m = 5 || m = 6
                    | _ -> false

                gOk && isSafePrime pBI p
