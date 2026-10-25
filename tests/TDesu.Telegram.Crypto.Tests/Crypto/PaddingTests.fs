namespace TDesu.Crypto.Tests

open NUnit.Framework
open TDesu.Crypto
open TDesu.Crypto.Tests

[<TestFixture>]
type PaddingTests() =

    [<Test>]
    member _.``randomBytes returns correct length``() =
        let bytes = Padding.randomBytes 32
        equals bytes.Length 32

    [<Test>]
    member _.``randomBytes returns different values``() =
        let a = Padding.randomBytes 32
        let b = Padding.randomBytes 32
        // Extremely unlikely to be equal
        notEquals a b

    [<Test>]
    member _.``addPadding result length is divisible by 16``() =
        for dataLen in [ 1; 10; 16; 32; 48; 100; 255; 500 ] do
            let data = Array.zeroCreate<byte> dataLen
            let padded = Padding.addPadding data
            equals (padded.Length % 16) 0

    [<Test>]
    member _.``addPadding adds at least 12 bytes``() =
        for dataLen in [ 0; 1; 16; 32; 100 ] do
            let data = Array.zeroCreate<byte> dataLen
            let padded = Padding.addPadding data
            let paddingLen = padded.Length - dataLen
            Assert.That(paddingLen, Is.GreaterThanOrEqualTo(12), $"Failed for data length %d{dataLen}")

    [<Test>]
    member _.``addPadding preserves original data``() =
        let data = Array.init 50 (fun i -> byte i)
        let padded = Padding.addPadding data
        equals padded[..49] data

    [<Test>]
    member _.``addHandshakePadding result length is divisible by 16``() =
        for dataLen in [ 0; 1; 10; 16; 17; 31; 32; 48; 100; 255; 500 ] do
            let data = Array.zeroCreate<byte> dataLen
            let padded = Padding.addHandshakePadding data
            equals (padded.Length % 16) 0

    [<Test>]
    member _.``addHandshakePadding adds 0 to 15 bytes``() =
        for dataLen in [ 0; 1; 15; 16; 17; 31; 32; 100 ] do
            let data = Array.zeroCreate<byte> dataLen
            let padded = Padding.addHandshakePadding data
            let paddingLen = padded.Length - dataLen
            Assert.That(paddingLen, Is.GreaterThanOrEqualTo(0), $"Failed for data length %d{dataLen}")
            Assert.That(paddingLen, Is.LessThanOrEqualTo(15), $"Failed for data length %d{dataLen}")

    [<Test>]
    member _.``addHandshakePadding zero bytes when already aligned``() =
        for dataLen in [ 0; 16; 32; 48; 256 ] do
            let data = Array.zeroCreate<byte> dataLen
            let padded = Padding.addHandshakePadding data
            equals padded.Length dataLen

    [<Test>]
    member _.``addHandshakePadding preserves original data``() =
        let data = Array.init 50 (fun i -> byte i)
        let padded = Padding.addHandshakePadding data
        equals padded[..49] data

    // paddedLength is the rule a caller sizes its own buffer with, so it has to agree with
    // what addPadding actually produces for every length -- otherwise the two drift and the
    // caller writes a frame the server reads as malformed.
    [<Test>]
    member _.``paddedLength agrees with addPadding over a full period``() =
        for dataLen in 0..96 do
            let padded = Padding.addPadding (Array.zeroCreate<byte> dataLen)
            equals (Padding.paddedLength dataLen) padded.Length

    [<Test>]
    member _.``handshakePaddedLength agrees with addHandshakePadding over a full period``() =
        for dataLen in 0..96 do
            let padded = Padding.addHandshakePadding (Array.zeroCreate<byte> dataLen)
            equals (Padding.handshakePaddedLength dataLen) padded.Length

    [<Test>]
    member _.``paddedLength keeps padding inside 12 to 27 and a 16-byte total``() =
        for dataLen in 0..512 do
            let total = Padding.paddedLength dataLen
            let padding = total - dataLen
            equals (total % 16) 0
            Assert.That(padding, Is.InRange(12, 27), $"Failed for data length %d{dataLen}")

    [<Test>]
    member _.``fill writes random bytes only inside the destination``() =
        let buffer = Array.zeroCreate<byte> 64
        Padding.fill (System.Span(buffer, 16, 32))

        // The untouched ends stay zero; the filled window is not left as zeros.
        equals buffer[..15] (Array.zeroCreate<byte> 16)
        equals buffer[48..] (Array.zeroCreate<byte> 16)
        notEquals buffer[16..47] (Array.zeroCreate<byte> 32)

    [<Test>]
    member _.``fill accepts an empty destination``() =
        let buffer = Array.zeroCreate<byte> 8
        Padding.fill (System.Span(buffer, 8, 0))
        equals buffer (Array.zeroCreate<byte> 8)

    [<Test>]
    member _.``paddedLength rejects a negative length``() =
        Assert.Throws<System.ArgumentException>(fun () -> Padding.paddedLength -1 |> ignore)
        |> ignore
