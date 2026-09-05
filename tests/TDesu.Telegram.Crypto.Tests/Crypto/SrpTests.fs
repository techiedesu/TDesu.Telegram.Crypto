namespace TDesu.Crypto.Tests

open System.Numerics
open System.Security.Cryptography
open NUnit.Framework
open TDesu.Crypto
open TDesu.Crypto.Tests

/// Known-answer vectors ported from an independent implementation's own tests,
/// which cross-check its own SRP implementation — the server this client's
/// auth.checkPassword actually talks to — against a second, independent
/// implementation. Reproducing the same (password, salt1, salt2, secret) inputs
/// here and landing on the same A/M1 checks this module against both of those,
/// not just against itself.
[<TestFixture>]
type SrpTests() =

    // Telegram's canonical 2048-bit safe prime, g = 3 — the same group
    // account.getPassword serves in practice (see DhValidationTests.realPrime).
    let p =
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

    let g = 3
    let password = "correct horse battery staple"
    let salt1 = Array.init 32 byte
    let salt2 = Array.init 32 (fun i -> byte (i + 32))
    let clientSecret = Array.init 256 (fun i -> byte ((i * 7 + 1) % 256))

    // account.getPassword's srp_B for this exchange. A known-answer value from an
    // independent implementation's own test suite (there, derived from a server
    // secret this module never needs — a real client only ever receives B over
    // the wire).
    let serverPublicB =
        Rsa.hexToBytes (
            "2041ED7B9CFC9A691A9C018A4862A997FD7EBB8539B1AAE6A43989CF9354B1C9"
            + "0BA89165C5A3BA86552A81C0515C72C137521A8BE1223B663AF7BE9E910970ED"
            + "A3C961EE5E070883C93E4A76EA544BCCF187EE41B4884E8207A58C342FED5ED0"
            + "7D6D9C313824AECBE2D6E61326A703A3D6AD179C1DD8E953D4C5FAA380D92977"
            + "4AA9F40C862D445E4E7BA880CCFE3E359055298A9509F852245AFFA818D63088"
            + "37AAECCAF8FA88F0366B8370954944D3A10572C867CC038E7A5ED9FBE3C70DC2"
            + "10372E7A2A5479BFE5EBE52F7A7E00856F68C45E811A04AC9D00E16BA80449F3"
            + "3577CDB428467922526ABDAC17252F3305A6626FD46A4C10B234F7F8E84B4FE3"
        )

    let expectedX =
        Rsa.hexToBytes "61D61042D18B562E64931F9842F01443F96A844E9CF471E10C46B7DAC9301B64"

    let expectedA =
        Rsa.hexToBytes (
            "474D4BD10A65BD5DCF1743D9F6B14FC459D68E60AD11B32D09BCAED0590C0F18"
            + "761D79310A16D78E1C91531C55329F42502A16B765B8861089892CA4E8A36397"
            + "DBBE888F402425ECF636A7070AADBBAFE7FC54947D45B6AB355E5BEDDA78F43E"
            + "EC8DCE6BDA653B28EB444B13A94C75E8BCD9493076CB20EDC2FDD9EAEA7A25E2"
            + "15987D60EDC9D437BC3A5C3E86253228BDF4E1FF8AF49828BC9245B279C61B2B"
            + "58F6E549FAC6711309FEE7C05855AF38D8D9360436F88E032A7E46C092CEC50F"
            + "6530151348C2F3D01F1F1D8A6EEDC7087426292570743E22D92610B53BEF4F86"
            + "38F630849A465B50EE866C5EC938396320109F234085CDD913C4BD042B386E11"
        )

    let expectedM1 =
        Rsa.hexToBytes "776F5F7CBCCCCED7064263F4DEC04951505D932CE84B8D60D93803F06E10F6CD"

    [<Test>]
    member _.``passwordHash matches the reference vector``() =
        equals (Srp.passwordHash password salt1 salt2) expectedX

    [<Test>]
    member _.``clientProofWithSecret matches the reference A and M1``() =
        let a, m1 = Srp.clientProofWithSecret password salt1 salt2 g p serverPublicB clientSecret
        equals a expectedA
        equals m1 expectedM1

    [<Test>]
    member _.``clientProofWithSecret returns a full-width srp_A``() =
        let a, _ = Srp.clientProofWithSecret password salt1 salt2 g p serverPublicB clientSecret
        equals a.Length p.Length

    [<Test>]
    member _.``a wrong password produces a different M1``() =
        let _, m1 =
            Srp.clientProofWithSecret "correct horse battery stapl" salt1 salt2 g p serverPublicB clientSecret

        notEquals m1 expectedM1

    [<Test>]
    member _.``clientProof succeeds for a valid group and server public value``() =
        match Srp.clientProof password salt1 salt2 g p serverPublicB with
        | Ok proof ->
            equals proof.ClientPublic.Length p.Length
            equals proof.Proof.Length 32
        | Error e -> Assert.Fail($"expected Ok, got Error \"{e}\"")

    /// `clientProof` draws its own client secret via a CSPRNG (unlike
    /// `clientProofWithSecret`, which is pinned to a fixed one for the
    /// known-answer vectors above), so two calls with identical inputs must not
    /// agree on `srp_A` — a fixed secret across attempts is exactly what SRP must
    /// not do in production.
    [<Test>]
    member _.``clientProof draws a fresh secret each call, so srp_A varies``() =
        match Srp.clientProof password salt1 salt2 g p serverPublicB,
              Srp.clientProof password salt1 salt2 g p serverPublicB with
        | Ok first, Ok second -> notEquals first.ClientPublic second.ClientPublic
        | results -> Assert.Fail($"expected both calls to succeed, got {results}")

    [<Test>]
    member _.``clientProof rejects an invalid DH group``() =
        let notASafePrime = Array.create 256 0xFFuy // 2^2048 - 1: odd, right size, composite

        match Srp.clientProof password salt1 salt2 g notASafePrime serverPublicB with
        | Error _ -> ()
        | Ok _ -> Assert.Fail("expected the invalid group to be rejected")

    [<Test>]
    member _.``clientProof rejects a server public value outside 1 < B < p-1``() =
        match Srp.clientProof password salt1 salt2 g p (Array.zeroCreate 256) with
        | Error _ -> ()
        | Ok _ -> Assert.Fail("expected B = 0 to be rejected")

        let pMinusOne = Array.copy p
        pMinusOne[pMinusOne.Length - 1] <- pMinusOne[pMinusOne.Length - 1] - 1uy

        match Srp.clientProof password salt1 salt2 g p pMinusOne with
        | Error _ -> ()
        | Ok _ -> Assert.Fail("expected B = p - 1 to be rejected")

    /// A server that could force `B ≡ k*v (mod p)` would let an attacker solve for
    /// the password verifier directly instead of merely checking a proof against
    /// it — the one condition core.telegram.org/api/srp calls out by name.
    /// Constructed independently of `Srp.fs`'s own `h`/padding helpers via the
    /// internal `BigEndian` module, so this does not just re-run the
    /// implementation's own arithmetic back at itself.
    [<Test>]
    member _.``clientProof rejects a degenerate B where B - k*v = 0 (mod p)``() =
        let size = p.Length
        let pi = BigEndian.toBigInteger p
        let gInt = BigInteger g
        let gPad = BigEndian.toBytes size gInt

        use sha256 = SHA256.Create()
        let k = BigEndian.toBigInteger (sha256.ComputeHash(Array.append p gPad))
        let x = BigEndian.toBigInteger (Srp.passwordHash password salt1 salt2)
        let v = BigInteger.ModPow(gInt, x, pi)
        let degenerateB = BigEndian.toBytes size ((k * v) % pi)

        match Srp.clientProof password salt1 salt2 g p degenerateB with
        | Error _ -> ()
        | Ok _ -> Assert.Fail("expected a degenerate B (B = k*v mod p) to be rejected")
