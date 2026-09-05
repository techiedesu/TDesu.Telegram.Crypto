namespace TDesu.Crypto

open System.Security.Cryptography
open TDesu.FSharp
open TDesu.FSharp.Buffers

/// MTProto 2.0 key derivation: turns `auth_key` plus a per-message `msg_key` into
/// the AES-256-IGE key and IV for that message
/// (core.telegram.org/mtproto/description#defining-aes-key-and-initialization-vector),
/// and computes `msg_key` itself from `auth_key` and the padded plaintext.
[<RequireQualifiedAccess>]
module KeyDerivation =

    type AesKeyIv = { Key: byte[]; Iv: byte[] }

    /// x = 0 for client->server, x = 8 for server->client.
    ///
    /// Appends the two hash inputs to one reused `IncrementalHash` instead of
    /// slicing `auth_key`/`msg_key` into fresh arrays and concatenating them before
    /// hashing, and writes the two output halves directly from the two SHA-256
    /// results instead of slicing those into fresh arrays too: 4 byte[] allocations
    /// total (the two hashes and the two 32-byte results) instead of 16 on the
    /// pre-refactor code (three slices plus a concat per hash, three slices plus a
    /// concat per output half). `KeyDerivationTests.fs` pins a vector computed with
    /// the old implementation to prove the two are equivalent.
    let deriveAesKeyIv (authKey: byte[]) (msgKey: byte[]) (x: int) : AesKeyIv =
        Guard.isTrue (nameof authKey) "auth_key must be 256 bytes" (authKey.Length = 256)
        Guard.isTrue (nameof msgKey) "msg_key must be 16 bytes" (msgKey.Length = 16)

        use hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256)

        // sha256_a = SHA256(msg_key + auth_key[x..x+35])
        hasher.AppendData(msgKey)
        hasher.AppendData(authKey, x, 36)
        let sha256A = hasher.GetHashAndReset()

        // sha256_b = SHA256(auth_key[40+x..40+x+35] + msg_key)
        hasher.AppendData(authKey, 40 + x, 36)
        hasher.AppendData(msgKey)
        let sha256B = hasher.GetHashAndReset()

        // aes_key = sha256_a[0..7] + sha256_b[8..23] + sha256_a[24..31]   (32 bytes)
        let aesKey = Array.zeroCreate<byte> 32
        Bytes.copyTo sha256A 0 aesKey 0 8
        Bytes.copyTo sha256B 8 aesKey 8 16
        Bytes.copyTo sha256A 24 aesKey 24 8

        // aes_iv = sha256_b[0..7] + sha256_a[8..23] + sha256_b[24..31]    (32 bytes)
        let aesIv = Array.zeroCreate<byte> 32
        Bytes.copyTo sha256B 0 aesIv 0 8
        Bytes.copyTo sha256A 8 aesIv 8 16
        Bytes.copyTo sha256B 24 aesIv 24 8

        { Key = aesKey; Iv = aesIv }

    /// msg_key = SHA256(auth_key[88+x..119+x] ++ plaintext)[8..23]  (16 bytes).
    ///
    /// Appends the key slice, then the plaintext, directly to an `IncrementalHash`
    /// instead of concatenating them into one fresh array first — plaintext is the
    /// one input here that scales with message size, so this is the allocation the
    /// audit's "copies the whole plaintext to prepend 32 bytes" finding was about.
    let computeMsgKey (authKey: byte[]) (plaintext: byte[]) (x: int) : byte[] =
        Guard.isTrue (nameof authKey) "auth_key must be 256 bytes" (authKey.Length = 256)

        use hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256)
        hasher.AppendData(authKey, 88 + x, 32)
        hasher.AppendData(plaintext)
        let hash = hasher.GetHashAndReset()
        hash[8..23]
