# TDesu.Telegram.Crypto

[![NuGet](https://img.shields.io/nuget/v/TDesu.Telegram.Crypto.svg)](https://www.nuget.org/packages/TDesu.Telegram.Crypto)
[![License: Unlicense](https://img.shields.io/badge/License-Unlicense-blue.svg)](https://unlicense.org)

Cryptographic primitives for [Telegram MTProto 2.0](https://core.telegram.org/mtproto/description). AES-IGE, Diffie-Hellman key exchange, RSA_PAD, SRP-6a (2FA), and key derivation — all in pure F# with `System.Security.Cryptography`.

No BouncyCastle. No OpenSSL bindings. Just .NET crypto APIs and `BigInteger`.

## Install

```
dotnet add package TDesu.Telegram.Crypto
```

## Modules

### AesIge

AES-256-IGE (Infinite Garble Extension) mode — the non-standard block cipher mode used by MTProto for message encryption.

```fsharp
open TDesu.Crypto

// Encrypt (data length must be a multiple of 16)
let encrypted = AesIge.encrypt plaintext key iv

// Decrypt
let decrypted = AesIge.decrypt ciphertext key iv
```

- Key: 32 bytes (AES-256)
- IV: 32 bytes (split into two 16-byte halves internally)
- Data: must be aligned to 16 bytes (use `Padding.addPadding` first)
- Validates input lengths, throws `ArgumentException` on mismatch

For a caller that already owns its buffers, `encryptTo`/`decryptTo` write into a
caller-supplied `Span<byte>` instead of allocating a new array — `encrypt`/`decrypt`
above are thin wrappers over them:

```fsharp
open System

// output may alias input: encrypting/decrypting in place is safe and supported.
let buffer: byte[] = getBuffer ()
AesIge.encryptTo (ReadOnlySpan buffer) key iv (Span buffer)
AesIge.decryptTo (ReadOnlySpan buffer) key iv (Span buffer)
```

Each 16-byte block still costs one `ICryptoTransform.TransformBlock` interop call —
IGE chains each block's output into the next block's input, so blocks cannot be
batched into one multi-block platform call the way CBC/CTR can.

### KeyDerivation

MTProto 2.0 key derivation — derives AES key + IV from `auth_key` and `msg_key` per the [specification](https://core.telegram.org/mtproto/description#defining-aes-key-and-initialization-vector).

```fsharp
open TDesu.Crypto

// x = 0 for client->server, x = 8 for server->client
let { Key = aesKey; Iv = aesIv } = KeyDerivation.deriveAesKeyIv authKey msgKey x

// msg_key = SHA256(auth_key[88+x..119+x] ++ plaintext)[8..23]
let msgKey = KeyDerivation.computeMsgKey authKey plaintext x
```

Internally computes `sha256_a` and `sha256_b` from slices of `auth_key` and `msg_key` via one reused `IncrementalHash`, then interleaves the hashes to produce a 32-byte key and 32-byte IV. `authKey` must be 256 bytes and (for `deriveAesKeyIv`) `msgKey` must be 16 bytes — both are validated and throw `ArgumentException` otherwise.

### DiffieHellman

2048-bit Diffie-Hellman key exchange as used in MTProto [authorization key creation](https://core.telegram.org/mtproto/auth_key).

```fsharp
open TDesu.Crypto

// Generate this client's own 256-byte exponent
let a = DiffieHellman.generateA ()

// Compute g^a mod p to send to the server
let gA = DiffieHellman.computeGA g a p

// Compute the shared secret / auth_key from the server's g^b and this client's a
let authKey = DiffieHellman.computeAuthKey gB a p

// Validate the server's (g, dh_prime) before using either
let isValid = DiffieHellman.validateDhParams g p

// Validate a received g_a/g_b against the recommended margin
let inRange = DiffieHellman.validateGARange gA p
```

`validateDhParams g p` checks:
- `g` is one of the six generators MTProto permits (2..7), each with its own residue condition on `p`
- `p` is exactly 2048 bits
- `p` is a safe prime (both `p` and `(p-1)/2` are prime — Miller-Rabin, 64 rounds, cryptographically random bases; Telegram's own canonical prime is recognised directly and independently verified prime by `DhValidationTests.fs`)

`validateGARange ga p` checks `2^{2048-64} <= g_a <= p - 2^{2048-64}`, the stricter range the MTProto 2.0 security guidelines recommend over the minimal `1 < g_a < p-1`.

All arithmetic uses `System.Numerics.BigInteger` with big-endian ↔ little-endian conversion (MTProto uses big-endian, .NET's `BigInteger` is little-endian).

### Rsa

RSA_PAD encryption for the initial DH key exchange — MTProto's current, hardened encoding for `p_q_inner_data`.

```fsharp
open TDesu.Crypto

// The current production RSA_PAD key
let key = Rsa.publicKeys |> List.head

// Encrypt data (at most 144 bytes) with RSA_PAD: hides the payload length, wraps it
// in AES-IGE under a fresh random key, and re-rolls the 256-byte block until it is
// below the RSA modulus.
let encrypted = Rsa.encryptPad data key    // byte[] -> byte[] (modulus length)

// Recompute a key's fingerprint independently of a transcribed constant --
// the low 64 bits of SHA1 over the TL rsa_public_key serialisation.
let fingerprint = Rsa.fingerprintOf key    // 0xd09d1d85de64fd85L for the key above
```

`publicKeys` holds only the current production RSA_PAD key: the handshake this library
implements always negotiates RSA_PAD, so there is no code path that would ever pick a
different key. The raw `data^e mod n` operation RSA_PAD is built on is internal
(`rawEncrypt`) — nothing outside `encryptPad` needs it, and it throws `ArgumentException`
rather than silently wrapping when `data >= n`.

### Srp

Client half of Telegram's SRP-6a variant for two-factor login ([`account.getPassword`](https://core.telegram.org/api/srp)).

```fsharp
open TDesu.Crypto

// account.getPassword gives (salt1, salt2, g, p, srp_B); this proves knowledge of
// the account password without ever sending it or the derived x.
match Srp.clientProof password salt1 salt2 g p srpB with
| Ok { ClientPublic = srpA; Proof = m1 } ->
    // -> auth.checkPassword's inputCheckPasswordSRP(srp_A = srpA, M1 = m1)
    ()
| Error reason ->
    // g/p failed DiffieHellman.validateDhParams, B was outside 1 < B < p-1, or B
    // was degenerate (B - k*v = 0 mod p) -- never send a proof built from this B.
    ()
```

`clientProof` validates the group and the server's public value before computing
anything, draws its own client secret from a CSPRNG (redrawing until `g^a` passes
`DiffieHellman.validateGARange`), and clears the password's UTF-8 bytes once hashed.
There is no `verifier`/`server`/`verify` half here — this library only ever plays the
client role.

`Srp.passwordHash password salt1 salt2` exposes the client-side password hash (`x`)
on its own, for callers that need it independently of a full proof.

### Padding

Random padding for MTProto message encryption. Ensures ciphertext length is a multiple of 16 bytes.

```fsharp
open TDesu.Crypto

// Add 12-27 bytes of random padding, result aligned to 16 (post-auth messages)
let padded = Padding.addPadding plaintext

// Add 0-15 bytes of random padding (pre-auth handshake messages: TDLib rejects more)
let handshakePadded = Padding.addHandshakePadding plaintext

// Generate random bytes
let nonce = Padding.randomBytes 16
```

### AuthKeyId

Compute `auth_key_id` — the 8-byte identifier derived from SHA1 of the authorization key.

```fsharp
open TDesu.Crypto

// auth_key_id = SHA1(auth_key)[12..19], read as a little-endian int64
let keyId = AuthKeyId.compute authKey

// Hash helpers
let sha1Hash = AuthKeyId.sha1 data
let sha256Hash = AuthKeyId.sha256 data
```

## How these fit together

A typical MTProto message encryption flow:

```
1. Serialize message body        → TDesu.Telegram.Serialization
2. Add random padding            → Padding.addPadding
3. Compute msg_key (SHA-256)     → KeyDerivation.computeMsgKey
4. Derive AES key + IV           → KeyDerivation.deriveAesKeyIv
5. Encrypt with AES-IGE          → AesIge.encrypt / AesIge.encryptTo
6. Prepend auth_key_id + msg_key → AuthKeyId.compute
```

For the initial DH handshake:

```
1. Generate nonce                → Padding.randomBytes
2. Encrypt PQ inner data         → Rsa.encryptPad
3. Generate this client's a      → DiffieHellman.generateA
4. Compute g^a mod p             → DiffieHellman.computeGA
5. Validate server's (g, p)      → DiffieHellman.validateDhParams
6. Derive auth_key               → DiffieHellman.computeAuthKey
7. Compute auth_key_id           → AuthKeyId.compute
```

For 2FA login (`auth.checkPassword`):

```
1. account.getPassword           → (salt1, salt2, g, p, srp_B) from the server
2. Prove knowledge of password   → Srp.clientProof
3. auth.checkPassword            → inputCheckPasswordSRP(srp_A, M1)
```

## Security notes

- **AES prefers the platform implementation.** `AesEcb.createEncryptor`/`createDecryptor`
  (used by `AesIge`) use `System.Security.Cryptography.Aes` whenever the runtime provides
  one, and fall back to a pure-F# managed AES-256 (internal `ManagedAes`) only when it
  doesn't — today, that means `browser-wasm`, where `Aes.Create()` throws
  `PlatformNotSupportedException`. The managed cipher is validated against FIPS-197 and
  SP 800-38A known-answer vectors, but its S-box lookups are data-dependent array indices,
  so it is **not constant-time with respect to cache behaviour**. That is the tradeoff every
  portable managed AES makes, and the one deployment that ever selects it — a browser tab —
  is a context where an attacker able to observe this process's cache timing already has the
  page's memory.
- **`BigInteger.ModPow` is not constant-time either.** `Rsa`, `DiffieHellman`, and `Srp` all
  do their modular exponentiation through `System.Numerics.BigInteger`, whose implementation
  makes no constant-time guarantee. This is an accepted tradeoff for a client-side MTProto
  implementation built on a general-purpose bignum type rather than a dedicated constant-time
  bignum library, which would be a much larger dependency than "nothing but
  `System.Security.Cryptography`/`System.Numerics`" affords.
- **`auth_key` has no expiry or rotation logic here.** Once `DiffieHellman.computeAuthKey`
  produces one, persisting, expiring, and rotating it is the caller's responsibility —
  `TDesu.Telegram.MTProto`'s session store owns that lifetime, not this library.

## Dependencies

- [TDesu.FSharp](https://github.com/techiedesu/TDesu.FSharp) (>= 2.0.0) — `Guard`, `TDesu.FSharp.Buffers.Bytes`
- No other dependencies (uses only `System.Security.Cryptography` and `System.Numerics`)

## Building

```sh
dotnet build
dotnet test
```

## References

- [MTProto 2.0 Description](https://core.telegram.org/mtproto/description)
- [Authorization Key Creation](https://core.telegram.org/mtproto/auth_key)
- [Auth Key Generation Example](https://core.telegram.org/mtproto/samples-auth_key)
- [SRP two-factor authentication](https://core.telegram.org/api/srp)
- [Security Guidelines](https://core.telegram.org/mtproto/security_guidelines)

## License

[Unlicense](LICENSE)
