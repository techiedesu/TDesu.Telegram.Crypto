## 0.4.0

Follows the cross-library audit dated 2026-09-05 (`docs/tdesu-libraries-audit.md` in the
TeleEye repository) — its "TDesu.Telegram.Crypto (0.3.3)" section is the source for every
finding below.

### Known-answer tests, so a refactor of any of this has an oracle

Before this release, nothing but a live handshake exercised `deriveAesKeyIv`/`computeMsgKey`'s
six slice offsets, the RSA_PAD block layout's seven ordered steps, or the IGE chaining
direction — `KeyDerivationTests`/`RsaTests` checked sizes and randomisation, not correctness.
Added:

- Telegram's own published [`samples-auth_key`](https://core.telegram.org/mtproto/samples-auth_key)
  vector: `AesIge.decrypt` reproduces `answer_with_hash` from `encrypted_answer` under the
  handshake's `tmp_aes_key`/`tmp_aes_iv`, and `DiffieHellman.computeGA`/`computeAuthKey`
  reproduce the published `g_b` and `auth_key` from `b`, `g_a`, and `dh_prime`.
- A generated RSA-2048 keypair that `encryptPad`s a fixed 144-byte payload, then decodes it
  with the private exponent and undoes every step of `Rsa.fs`'s `build` — the `temp_key_xor`/
  `aes` split, `temp_key` recovery, the IGE decrypt under a zero IV, the SHA-256 suffix check,
  and the reversal — checked individually, not just the round trip.
- One pinned `deriveAesKeyIv`/`computeMsgKey` vector, computed once against the pre-refactor
  implementation and asserted forever: a regression pin, not an independent oracle, since no
  smaller published vector for this construction exists than a full DC handshake.
- `DiffieHellman.isProbablePrime` (now `internal`, reachable from the test project via
  `InternalsVisibleTo`) run directly on the pinned `knownSafePrime` and `(p-1)/2`, bypassing
  `isSafePrime`'s equality fast path — the previous test only proved the pinned bytes equal
  themselves, not that they are prime.
- `encryptTo`/`decryptTo` exercised in place (`output` aliasing `input`), the one case a naive
  implementation of either gets wrong.

This paid for itself immediately: reordering `AesIge`'s per-block state update during the
refactor below broke the encrypt/decrypt round trip, and Telegram's own sample vector caught it
in the same test run that introduced the bug, before anything shipped.

### Performance

**`KeyDerivation` — 4 allocations instead of 16.** `computeMsgKey` and `deriveAesKeyIv` used to
slice `auth_key`/`msg_key` into fresh arrays and concatenate them before hashing
(`Bytes.concat2`), then slice each SHA-256 output into fresh arrays again to assemble the final
key/IV (`Bytes.concat3`) — 14 array allocations plus two `SHA256.Create()` instances per call.
Both now append their inputs directly to one reused `IncrementalHash` and copy each hash's
relevant bytes straight into the output arrays: 4 byte[] allocations total (the two SHA-256
outputs and the two 32-byte results), regardless of plaintext size. `computeMsgKey` was the one
that scaled with message size — the audit's "copies the whole plaintext to prepend 32 bytes"
finding.

**`Srp`'s PBKDF2 — 4 fixed buffers instead of 100,000 digest allocations.** The
PBKDF2-HMAC-SHA512 loop called `HMACSHA512.ComputeHash`, which allocates a fresh 64-byte array
every call, 100,000 times per password check (6.4 MB of digest garbage per check). It now writes
each HMAC output into one of two reused 64-byte buffers via `TryComputeHash`, ping-ponging
between them across iterations.

**`AesIge`/`ManagedAes` — the platform `Aes` instance no longer leaks.**
`AesEcb.createEncryptor`/`createDecryptor` created a platform `Aes` per call and returned only
its `ICryptoTransform`; callers correctly disposed the transform (`use encryptor = ...`), but the
`Aes` object — holding a copy of the key — was never disposed and lived for the rest of the
process. A `KeyOwningTransform` wrapper now disposes both from the one handle callers already
hold.

### API changes (breaking)

**`Rsa.publicKeys` now holds only the current production RSA_PAD key.** The two legacy keys
shipped in 0.3.0 were for MTProto's classic `sha1(data)+data` raw-RSA scheme, which no code in
this library, `TDesu.Telegram.MTProto`, or TeleEye has ever implemented — the handshake this
library supports always negotiates RSA_PAD. Removed rather than left to describe production DCs
in a way nothing here could act on. New `Rsa.fingerprintOf: RsaPublicKey -> int64` recomputes a
key's fingerprint (SHA1 over the TL `rsa_public_key` serialisation) independently of the
transcribed `Fingerprint` field, and reproduces `0xd09d1d85de64fd85` for the remaining key.

**`Rsa.encrypt` is gone; the raw RSA primitive is now `internal rawEncrypt`, and it validates
its input.** It used to be public raw `data^e mod n` with no `data < n` check — documented (this
README, the 0.3.0 notes below, and `Rsa.fs`) as the "classic" scheme kept alongside `encryptPad`,
when in fact nothing implements or calls it except `encryptPad` itself. It is internal now, and
throws `ArgumentException` instead of silently wrapping when `data >= n` — two different inputs
at or above the modulus could otherwise encrypt to the same ciphertext. `encryptPad`, the actual
public encryption entry point, is unaffected: it always supplied data already below the modulus
via its own re-roll loop.

**`Rsa.addKey`, `Rsa.allKeys`, `Rsa.clearAdditionalKeys` are gone.** This was a process-global
mutable registry meant for test server keys, with no real consumer and no fingerprint validation
against what was registered. Callers that need a specific key should hold a `Rsa.RsaPublicKey`
value directly; there is no replacement registry.

**`Srp.clientProof` no longer takes a client secret and now returns `Result<SrpProof, string>`
instead of a bare `(byte[] * byte[])` tuple.** Previously it trusted `g`/`p`/`serverPublicB`
completely and left the caller to supply its own "random" exponent — TeleEye shipped a parallel
`SrpHelper` with the checks this library lacked (`1 < B < p-1`, regenerate the exponent until
`g^a` is in range, refuse `B - k*v ≡ 0 (mod p)`) because of exactly this gap. `clientProof` now
performs all of those checks (via `DiffieHellman.validateDhParams`/`validateGARange`) and draws
its own secret from a CSPRNG, returning `Error` instead of computing a proof from parameters that
failed validation. The previous signature — an explicit secret, an unconditional
`(byte[] * byte[])` — survives as `internal Srp.clientProofWithSecret`, needed so the pinned
known-answer vectors can still reproduce an exact, previously-published `srp_A`. New public type
`Srp.SrpProof = { ClientPublic: byte[]; Proof: byte[] }` replaces the tuple.

**`AuthKeyId.compute` now reads `auth_key_id` as an explicit little-endian `int64`
(`System.Buffers.Binary.BinaryPrimitives`) instead of host-endian (`BitConverter.ToInt64`).**
Every consumer's comment on this value already assumed little-endian, per
core.telegram.org/mtproto/description; the two only ever agreed because every host this library
has actually shipped to is itself little-endian, so this is not an observable behavioural change
on any of them — it removes an assumption the code never actually depended on being true.

### Correctness

**`Padding.addPadding` no longer carries an unreachable `paddingLen > 1024` branch.** The
padding length is always `12..27` (12 bytes minimum, plus 0..15 bytes to round the total up to
the next multiple of 16 — the two can never sum past 27), so the `> 1024` clamp this function
also had could never execute. Documented and removed rather than left as dead code implying a
case that does not exist.

### Housekeeping

- Bumped `TDesu.FSharp` to 2.0.0 (`Guard`, `TDesu.FSharp.Buffers.Bytes` — unaffected by that
  release's own removals, which were `Result` functions FSharp.Core itself now provides).
- Added an internal `BigEndian` module (`toBigInteger`/`toBytes`) shared by `Rsa`,
  `DiffieHellman`, and `Srp`, replacing four hand-rolled big-endian ↔ `BigInteger` conversions
  (reverse the bytes, append a zero sign byte, reverse back) with netstandard2.1's own
  `BigInteger(ReadOnlySpan<byte>, isUnsigned, isBigEndian)`/`ToByteArray(isUnsigned, isBigEndian)`
  overloads, which `Srp` already used.
- `Srp.fs`/`SrpTests.fs` referred to the known-answer vectors' source as a specific third-party
  project by name; reworded to "an independent implementation's vectors" throughout.
- README rewritten for the current API (`generateA`, the two-argument `validateDhParams`,
  `encryptPad`, `publicKeys`, `fingerprintOf`, `Srp.clientProof`) plus a new security section:
  platform AES preferred with a managed fallback and its S-box caveat, `BigInteger.ModPow` not
  being constant-time, and `auth_key` lifetime being the caller's responsibility.

## 0.3.3

### Security

**`g = 7` no longer accepts `p mod 7 = 4`.** MTProto's table for the permitted generators
(core.telegram.org/mtproto/auth_key) gives `p mod 7 = 3, 5 or 6` for `g = 7`; the check accepted
4 as well, so a server offering `g = 7` with such a prime passed validation the spec says to refuse.
The five other generators were already correct. The residue table is now its own function,
`DiffieHellman.generatorResidueOk g p`, so it can be tested on small integers without minting a
2048-bit safe prime per case — the new test covers every row of the table, including the one that
was wrong.

## 0.3.0

### Security

**RSA_PAD encryption (`Rsa.encryptPad`).** Adds MTProto's current OAEP+-style RSA
padding scheme for `p_q_inner_data`, alongside the classic `Rsa.encrypt` (kept for
callers that need it). Ships the current production RSA key
(fingerprint `0xd09d1d85de64fd85`) that the servers require for RSA_PAD; the two
legacy keys remain for the classic scheme.

**Hardened DH parameter validation.** `DiffieHellman.validateDhParams` now enforces
`g ∈ {2..7}` with its residue condition, a 2048-bit `dh_prime`, and a real
Miller-Rabin safe-prime test — both `p` and `(p-1)/2` prime, 64 cryptographically
random-base rounds, positive results memoised. Previously the "safe prime" check was
only a parity test and the generator bound accepted any `g > 7`, so a malicious
server could have supplied a weak prime and recovered the auth key.
`DiffieHellman.validateGARange` now enforces the recommended
`2^{2048-64} ≤ g_a ≤ dh_prime − 2^{2048-64}` margin instead of the minimal
`1 < g_a < p−1` bound.

## 0.1.0

Initial release. Extracted from a Telegram MTProto server implementation.

### Modules
- AesIge: AES-256-IGE encryption/decryption (MTProto message encryption)
- KeyDerivation: MTProto 2.0 AES key+IV derivation from auth_key and msg_key
- DiffieHellman: 2048-bit DH key exchange (generate g^b, compute auth_key, validate params)
- Rsa: Raw RSA encryption for DH handshake (production key included)
- Padding: Random padding (12-1024 bytes, aligned to 16)
- AuthKeyId: auth_key_id computation (SHA1-based)
