namespace TDesu.Crypto

open System
open System.Buffers.Binary
open System.Security.Cryptography

[<RequireQualifiedAccess>]
module AuthKeyId =

    /// SHA1 hash helper
    let sha1 (data: byte[]) : byte[] =
        use hasher = SHA1.Create()
        hasher.ComputeHash(data)

    /// SHA256 hash helper
    let sha256 (data: byte[]) : byte[] =
        use hasher = SHA256.Create()
        hasher.ComputeHash(data)

    /// auth_key_id = SHA1(auth_key)[12..19], read as a little-endian int64 —
    /// MTProto's own wire byte order (core.telegram.org/mtproto/description),
    /// which is also what every consumer's comment on this value already
    /// assumes. `BitConverter.ToInt64` used to read this host-endian instead,
    /// which only agreed with the spec because every host this library has
    /// actually run on so far is itself little-endian.
    let compute (authKey: byte[]) : int64 =
        let hash = sha1 authKey
        BinaryPrimitives.ReadInt64LittleEndian(ReadOnlySpan<byte>(hash, 12, 8))
