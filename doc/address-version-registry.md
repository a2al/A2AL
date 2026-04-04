# A2AL Address Version Registry

> **Status: Draft**

This document defines the A2AL address version byte space, the current registry of assigned values, and the process for requesting new assignments.

---

## 1. Address Structure

An A2AL `Address` is a fixed 21-byte value:

```
[ version_byte (1 byte) ] [ hash (20 bytes) ]
```

The version byte encodes the cryptographic key algorithm and the method used to derive the 20-byte hash from a public key. It does not identify a specific blockchain — multiple chains that share the same key algorithm and derivation method map to the same version byte.

The DHT `NodeID` is derived as:

```
NodeID = SHA-256(version_byte || hash_20bytes)
```

---

## 2. Version Byte Space

The A2AL address version byte space is `0xA0`–`0xAF` (16 values).

| Range | Status | Policy |
|-------|--------|--------|
| `0xA0`–`0xA7` | Official | Expert Review required (see §4) |
| `0xA8`–`0xAD` | Reserved | Frozen; future standards use only |
| `0xAE` | Experimental | No registration required; no uniqueness guarantee |
| `0xAF` | Private Use | No registration required; no uniqueness guarantee |

---

## 3. Current Assignments

| Version Byte | Name | Key Algorithm | 20-byte Derivation | Representative Uses |
|-------------|------|--------------|-------------------|---------------------|
| `0xA0` | `Ed25519` | Ed25519 | `SHA-256(pubkey)[0:20]` | A2AL native identity |
| `0xA1` | `P256` | P-256 (NIST) | `SHA-256(pubkey)[0:20]` | A2AL native P-256 identity |
| `0xA2` | `Paralism` | secp256k1 | `RIPEMD160(SHA-256(pubkey))` | Paralism, Bitcoin P2PKH, Cosmos SDK, Litecoin |
| `0xA3` | `Ethereum` | secp256k1 | `Keccak-256(pubkey)[12:32]` | Ethereum and all EVM-compatible chains |
| `0xA4`–`0xA7` | — | — | — | Unassigned |

> **Note on `0xA2` (Paralism):** Paralism is the named representative of the `secp256k1 + HASH160` derivation family. Any chain using the same key algorithm and derivation is compatible with this version byte. The name reflects the first formally integrated chain; it does not imply exclusivity.

---

## 4. Assignment Process

To request assignment of an unassigned version byte, open a GitHub Issue using the **Address Version Request** template. The request must include:

1. **Name** — a short identifier for the version byte (typically the primary chain or algorithm name)
2. **Key algorithm** — the public key algorithm (e.g., Ed25519, secp256k1, P-256, Sr25519)
3. **20-byte derivation** — the exact function mapping a public key to 20 bytes, with a normative reference
4. **Signature verification** — how a signature over arbitrary bytes is verified using this key type
5. **Rationale** — why an existing version byte does not cover this use case
6. **Representative chain or implementation** — at least one concrete user of this version byte

Requests are reviewed by the A2AL maintainers (**Expert Review** policy). Approval criteria:

- The key algorithm and derivation are not already covered by an existing assignment
- The derivation is deterministic and produces exactly 20 bytes
- A normative public specification exists for the key algorithm
- The request is not duplicative or speculative

Approved assignments are merged into this document and reflected in the codebase constants.

---

## 5. Experimental and Private Use

- **`0xAE` (Experimental):** May be used freely for prototyping and testing. Values are not unique across implementations. Do not use in production.
- **`0xAF` (Private Use):** For closed or internal deployments where global uniqueness is not required. Implementations may assign this byte to any scheme at their discretion.

---

## 6. Reserved Range

`0xA8`–`0xAD` are frozen and will only be allocated through a future standards process, should the Expert Review pool (`0xA0`–`0xA7`) approach exhaustion. Requests targeting this range will not be accepted under the current policy.

---

## 7. Relationship to Chain Identity

The version byte identifies a **cryptographic scheme**, not a blockchain. Two chains sharing the same key algorithm and derivation (e.g., Paralism and Bitcoin SDK) produce identical A2AL addresses from the same public key. Chain-specific context (if needed by an application) is carried at the endpoint record or application layer, not in the address itself.

---

*This registry is maintained by The A2AL Authors. To propose a change to this document or its process, open a GitHub Issue or Pull Request.*
