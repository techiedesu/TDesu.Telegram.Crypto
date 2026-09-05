namespace TDesu.Crypto.Tests

open NUnit.Framework
open TDesu.Crypto

[<TestFixture>]
type DhValidationTests() =

    // Real Telegram dh_prime (a safe 2048-bit prime; generator 3), from core.telegram.org.
    let realPrime =
        Rsa.hexToBytes
            "C7 1C AE B9 C6 B1 C9 04 8E 6C 52 2F 70 F1 3F 73 98 0D 40 23 8E 3E 21 C1 49 34 D0 37 56 3D 93 0F 48 19 8A 0A A7 C1 40 58 22 94 93 D2 25 30 F4 DB FA 33 6F 6E 0A C9 25 13 95 43 AE D4 4C CE 7C 37 20 FD 51 F6 94 58 70 5A C6 8C D4 FE 6B 6B 13 AB DC 97 46 51 29 69 32 84 54 F1 8F AF 8C 59 5F 64 24 77 FE 96 BB 2A 94 1D 5B CD 1D 4A C8 CC 49 88 07 08 FA 9B 37 8E 3C 4F 3A 90 60 BE E6 7C F9 A4 A4 A6 95 81 10 51 90 7E 16 27 53 B5 6B 0F 6B 41 0D BA 74 D8 A8 4B 2A 14 B3 14 4E 0E F1 28 47 54 FD 17 ED 95 0D 59 65 B4 B9 DD 46 58 2D B1 17 8D 16 9C 6B C4 65 B0 D6 FF 9C A3 92 8F EF 5B 9A E4 E4 18 FC 15 E8 3E BE A0 F8 7F A9 FF 5E ED 70 05 0D ED 28 49 F4 7B F9 59 D9 56 85 0C E9 29 85 1F 0D 81 15 F6 35 B1 05 EE 2E 4E 15 D0 4B 24 54 BF 6F 4F AD F0 34 B1 04 03 11 9C D8 E3 B9 2F CC 5B"

    [<Test>]
    member _.``validateDhParams rejects small p``() =
        let smallP = [| 23uy |]
        Assert.That(DiffieHellman.validateDhParams 2 smallP, Is.False)

    [<Test>]
    member _.``validateDhParams rejects even p``() =
        let evenP = Array.zeroCreate<byte> 256
        evenP[255] <- 4uy  // even number
        Assert.That(DiffieHellman.validateDhParams 2 evenP, Is.False)

    [<Test>]
    member _.``validateDhParams rejects g less than 2``() =
        // Use a valid-looking p but invalid g
        let p = Array.init 256 (fun _ -> 0xFFuy)
        Assert.That(DiffieHellman.validateDhParams 1 p, Is.False)
        Assert.That(DiffieHellman.validateDhParams 0 p, Is.False)

    [<Test>]
    member _.``validateDhParams rejects p equal to 1``() =
        let p = Array.zeroCreate<byte> 256
        p[255] <- 1uy
        Assert.That(DiffieHellman.validateDhParams 2 p, Is.False)

    [<Test>]
    member _.``validateDhParams rejects generators above 7``() =
        // The library must reject g outside {2..7}; a lenient catch-all here would let a
        // malicious server slip a weak generator past the check.
        Assert.That(DiffieHellman.validateDhParams 8 realPrime, Is.False)
        Assert.That(DiffieHellman.validateDhParams 9 realPrime, Is.False)

    [<Test>]
    member _.``validateDhParams accepts the real Telegram safe prime``() =
        // g=3 is the generator for this prime; g=4 has no extra condition; g=2 must fail
        // its residue condition (p mod 8 <> 7).
        Assert.That(DiffieHellman.validateDhParams 3 realPrime, Is.True)
        Assert.That(DiffieHellman.validateDhParams 4 realPrime, Is.True)
        Assert.That(DiffieHellman.validateDhParams 2 realPrime, Is.False)

    [<Test>]
    member _.``validateDhParams rejects a non-prime of the right size``() =
        // 256 bytes, odd, correct residue for g=3, but composite (2^2048 - 1 is not prime).
        let composite = Array.create 256 0xFFuy
        Assert.That(DiffieHellman.validateDhParams 3 composite, Is.False)

    [<Test>]
    member _.``validateGARange rejects values outside the 2^(2048-64) margin``() =
        // 0 and 1 are far below the margin.
        Assert.That(DiffieHellman.validateGARange (Array.zeroCreate 256) realPrime, Is.False)
        let one = Array.zeroCreate 256 in one[255] <- 1uy
        Assert.That(DiffieHellman.validateGARange one realPrime, Is.False)
        // 2^1984 - 1 is just below the lower margin.
        let belowMargin = Array.append (Array.zeroCreate 8) (Array.create 248 0xFFuy)
        Assert.That(DiffieHellman.validateGARange belowMargin realPrime, Is.False)
        // p itself is above the upper margin (p - 2^1984 < p).
        Assert.That(DiffieHellman.validateGARange realPrime realPrime, Is.False)

    [<Test>]
    member _.``validateGARange accepts a value inside the margin``() =
        // Exactly 2^1984 sits on the lower margin and well below p - 2^1984.
        let atMargin = Array.zeroCreate 256 in atMargin[7] <- 1uy
        Assert.That(DiffieHellman.validateGARange atMargin realPrime, Is.True)

    [<Test>]
    member _.``generatorResidueOk follows the spec's table for every generator``() =
        // core.telegram.org/mtproto/auth_key: g=2 needs p mod 8 = 7; g=3 p mod 3 = 2; g=4 nothing;
        // g=5 p mod 5 = 1 or 4; g=6 p mod 24 = 19 or 23; g=7 p mod 7 = 3, 5 or 6.
        let ok g (p: int) = DiffieHellman.generatorResidueOk g (System.Numerics.BigInteger p)
        Assert.That(ok 2 15, Is.True)
        Assert.That(ok 2 11, Is.False)
        Assert.That(ok 3 11, Is.True)
        Assert.That(ok 3 10, Is.False)
        Assert.That(ok 4 10, Is.True)
        Assert.That(ok 5 11, Is.True)
        Assert.That(ok 5 14, Is.True)
        Assert.That(ok 5 12, Is.False)
        Assert.That(ok 6 43, Is.True)
        Assert.That(ok 6 47, Is.True)
        Assert.That(ok 6 25, Is.False)
        Assert.That(ok 7 10, Is.True)
        Assert.That(ok 7 12, Is.True)
        Assert.That(ok 7 13, Is.True)
        // p mod 7 = 4 was accepted before 0.3.3; the spec never listed it.
        Assert.That(ok 7 11, Is.False)
        Assert.That(ok 7 8, Is.False)
        Assert.That(ok 8 10, Is.False)

    /// The audit's own point: `validateDhParams accepts the real Telegram safe
    /// prime` above only proves `isSafePrime`'s equality fast path recognises
    /// `realPrime` as itself — a mistyped constant in either transcription would
    /// still pass that test as long as both happened to agree with each other.
    /// This bypasses the fast path and runs the actual Miller-Rabin test
    /// (`DiffieHellman.isProbablePrime`, `internal` via `InternalsVisibleTo`)
    /// directly on the library's own pinned `knownSafePrime` and `(p-1)/2`, at
    /// the same 64 rounds production uses — proving the shipped bytes really are
    /// a safe prime, not just that they equal themselves.
    [<Test>]
    member _.``the pinned safe prime and (p-1)/2 are actually prime, fast path bypassed``() =
        let p = BigEndian.toBigInteger DiffieHellman.knownSafePrime
        Assert.That(DiffieHellman.isProbablePrime p 64, Is.True)
        Assert.That(DiffieHellman.isProbablePrime ((p - System.Numerics.BigInteger.One) >>> 1) 64, Is.True)

    /// Belt-and-suspenders alongside the primality test above: this file's own
    /// `realPrime`, hand-transcribed from core.telegram.org with spaces, and
    /// `DiffieHellman.knownSafePrime`, transcribed separately without them,
    /// should be the exact same bytes.
    [<Test>]
    member _.``the pinned safe prime matches this test's own independent transcription``() =
        equals DiffieHellman.knownSafePrime realPrime
