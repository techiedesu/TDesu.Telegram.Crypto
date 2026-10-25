namespace TDesu.Crypto

open System
open System.Security.Cryptography
open TDesu.FSharp

[<RequireQualifiedAccess>]
module Padding =

    /// Generate random bytes
    let randomBytes (count: int) : byte[] =
        let bytes = Array.zeroCreate<byte> count
        RandomNumberGenerator.Fill(bytes)
        bytes

    /// Fills `destination` with cryptographic random bytes. The span counterpart of
    /// `randomBytes`, for a caller that already owns the buffer the padding belongs in —
    /// a message frame writing its own plaintext in place, say — and would otherwise
    /// allocate an array only to copy it away and drop it.
    let fill (destination: Span<byte>) : unit =
        if not destination.IsEmpty then
            RandomNumberGenerator.Fill destination

    /// Total length `addPadding` produces for `dataLength` bytes: 12 bytes minimum plus
    /// whatever rounds the total up to the next multiple of 16, so the padding itself is
    /// always in 12..27.
    ///
    /// Exists so a caller can size a buffer for the padded plaintext *before* writing into
    /// it, and still get the length from the same arithmetic `addPadding` uses rather than
    /// from a second copy of the rule.
    let paddedLength (dataLength: int) : int =
        Guard.isTrue (nameof dataLength) "Data length cannot be negative" (dataLength >= 0)
        let minTotal = dataLength + 12
        let rem = minTotal % 16

        if rem = 0 then
            minTotal
        else
            minTotal + (16 - rem)

    /// Total length `addHandshakePadding` produces: 0..15 bytes, enough to reach the next
    /// multiple of 16. Separate from `paddedLength` because the handshake rule is a
    /// different one — see `addHandshakePadding`.
    let handshakePaddedLength (dataLength: int) : int =
        Guard.isTrue (nameof dataLength) "Data length cannot be negative" (dataLength >= 0)
        let rem = dataLength % 16
        if rem = 0 then dataLength else dataLength + (16 - rem)

    /// Add random padding (always 12..27 bytes; result length divisible by 16).
    /// Used for auth_key-encrypted MTProto 2.0 messages — the post-auth wire
    /// format requires padding >= 12 bytes to mask plaintext length.
    /// For pre-auth handshake messages (server_DH_inner_data,
    /// client_DH_inner_data), use `addHandshakePadding` instead — TDLib's
    /// strict parser rejects > 15 bytes there with "Too much pad".
    ///
    /// The result is always in 12..27: 12 bytes minimum, plus whatever 0..15
    /// extra bytes round the total up to the next multiple of 16, and 12 + 15
    /// never exceeds 27. A previous version also clamped a `paddingLen > 1024`
    /// case that this arithmetic can never reach — dead code removed in 0.4.0.
    let addPadding (data: byte[]) : byte[] =
        let result = Array.zeroCreate<byte> (paddedLength data.Length)
        Buffer.BlockCopy(data, 0, result, 0, data.Length)
        fill (result.AsSpan data.Length)
        result

    /// Add 0..15 bytes random padding so the result length is divisible by 16.
    /// Used for the MTProto 2.0 handshake `answer_with_hash` envelope:
    ///   answer_with_hash := SHA1(answer) + answer + (0..15 random bytes)
    /// where the result is then AES-IGE-256 encrypted. TDLib's
    /// `AuthKeyHandshake::on_server_dh_params` rejects > 15 padding bytes
    /// with "Too much pad" (Handshake.cpp:204) — distinct from the post-auth
    /// `addPadding` (12..27) rule.
    let addHandshakePadding (data: byte[]) : byte[] =
        let total = handshakePaddedLength data.Length

        if total = data.Length then
            data
        else
            let result = Array.zeroCreate<byte> total
            Buffer.BlockCopy(data, 0, result, 0, data.Length)
            fill (result.AsSpan data.Length)
            result
