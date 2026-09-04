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

Initial release. Extracted from SedBot MTProto server.

### Modules
- AesIge: AES-256-IGE encryption/decryption (MTProto message encryption)
- KeyDerivation: MTProto 2.0 AES key+IV derivation from auth_key and msg_key
- DiffieHellman: 2048-bit DH key exchange (generate g^b, compute auth_key, validate params)
- Rsa: Raw RSA encryption for DH handshake (production key included)
- Padding: Random padding (12-1024 bytes, aligned to 16)
- AuthKeyId: auth_key_id computation (SHA1-based)
