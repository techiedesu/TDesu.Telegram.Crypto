namespace TDesu.Crypto

open System
open System.Numerics
open TDesu.FSharp

/// Unsigned big-endian byte-string <-> `BigInteger` conversions, shared by every
/// module that speaks MTProto's wire format (`Rsa`, `DiffieHellman`, `Srp`): TL never
/// carries a sign, only fixed- or length-prefixed byte strings, and MTProto always
/// treats them as big-endian while `BigInteger` stores its bytes little-endian.
///
/// `Rsa` and `DiffieHellman` used to each hand-roll this conversion (reverse the
/// bytes, append a zero sign byte, reverse the result back) at four call sites
/// between them, none sharing code with the others. `Srp` already used the
/// framework's own `BigInteger(ReadOnlySpan<byte>, isUnsigned, isBigEndian)` /
/// `ToByteArray(isUnsigned, isBigEndian)` overloads, which netstandard2.1 provides
/// for exactly this; this module is that same approach, promoted so the other two
/// no longer duplicate it.
module internal BigEndian =

    /// Reads an unsigned big-endian byte string as a non-negative `BigInteger`.
    let toBigInteger (bigEndian: byte[]) : BigInteger =
        BigInteger(ReadOnlySpan<byte> bigEndian, isUnsigned = true, isBigEndian = true)

    /// Writes a non-negative `BigInteger` as an unsigned big-endian byte string of
    /// exactly `size` bytes, left-padding with zeros. Throws rather than silently
    /// truncating a value that does not fit: every caller in this library already
    /// bounds its inputs so the value fits in `size` bytes (a modular-exponentiation
    /// result taken mod an n-byte modulus or prime never needs more than n bytes),
    /// so overflow here means a caller's assumption broke, not a normal case to clamp.
    let toBytes (size: int) (value: BigInteger) : byte[] =
        let raw = value.ToByteArray(isUnsigned = true, isBigEndian = true)
        Guard.isTrue (nameof value) $"value needs {raw.Length} bytes, wider than the requested {size}" (raw.Length <= size)

        let out = Array.zeroCreate<byte> size
        Array.blit raw 0 out (size - raw.Length) raw.Length
        out
