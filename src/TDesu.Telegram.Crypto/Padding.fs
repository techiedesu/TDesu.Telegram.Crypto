namespace TDesu.Crypto

open System.Security.Cryptography

[<RequireQualifiedAccess>]
module Padding =

    /// Generate random bytes
    let randomBytes (count: int) : byte[] =
        let bytes = Array.zeroCreate<byte> count
        RandomNumberGenerator.Fill(bytes)
        bytes

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
        let minPadding = 12
        let dataLen = data.Length

        // Minimum total length with 12 bytes padding
        let minTotal = dataLen + minPadding

        // Round up to next multiple of 16
        let totalLen =
            let rem = minTotal % 16
            if rem = 0 then minTotal
            else minTotal + (16 - rem)

        let paddingLen = totalLen - dataLen

        let result = Array.zeroCreate<byte> (dataLen + paddingLen)
        System.Buffer.BlockCopy(data, 0, result, 0, dataLen)
        let padding = randomBytes paddingLen
        System.Buffer.BlockCopy(padding, 0, result, dataLen, paddingLen)
        result

    /// Add 0..15 bytes random padding so the result length is divisible by 16.
    /// Used for the MTProto 2.0 handshake `answer_with_hash` envelope:
    ///   answer_with_hash := SHA1(answer) + answer + (0..15 random bytes)
    /// where the result is then AES-IGE-256 encrypted. TDLib's
    /// `AuthKeyHandshake::on_server_dh_params` rejects > 15 padding bytes
    /// with "Too much pad" (Handshake.cpp:204) — distinct from the post-auth
    /// `addPadding` (12..27) rule.
    let addHandshakePadding (data: byte[]) : byte[] =
        let rem = data.Length % 16
        if rem = 0 then
            data
        else
            let paddingLen = 16 - rem
            let result = Array.zeroCreate<byte> (data.Length + paddingLen)
            System.Buffer.BlockCopy(data, 0, result, 0, data.Length)
            let padding = randomBytes paddingLen
            System.Buffer.BlockCopy(padding, 0, result, data.Length, paddingLen)
            result
