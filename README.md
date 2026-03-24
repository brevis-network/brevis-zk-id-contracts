# IdentityRegistry

On-chain identity registry for the BNB ZK ID framework. Binds Web2 identities to Web3 wallets via ZK-attested proofs, and provides lock/unlock semantics for downstream apps to consume verified identity data.

## Table of Contents

1. [Architecture](#1-architecture)
2. [Roles and Access Control](#2-roles-and-access-control)
3. [Key Concepts](#3-key-concepts)
4. [Flows](#4-flows)
5. [Events and Observability](#5-events-and-observability)
6. [Toolchain](#6-toolchain)

---

## 1. Architecture

A single `IdentityRegistry` contract handles all identity lifecycle operations:

- **Provider lifecycle** — register and update providers (permanently active once registered).
- **App lifecycle** — register, update, and deactivate apps.
- **Identity attestation** — verify ZK proofs inline (decode public inputs, look up verification key, call Pico verifier) and store latest attestation per tuple.
- **Approval** — users approve apps for lock operations, directly or via EIP-712 relayer signatures.
- **Lock/Unlock** — apps lock identity properties they consume; locks gate unbinding.
- **Query** — apps read the latest attestation data blob for a given wallet/provider/property.

### References
- **Product requirement:** [`docs/requirements.md`](docs/requirements.md)

---

## 2. Roles and Access Control

The registry inherits from [`PauserControl`](https://github.com/brevis-network/security-contracts) (`Ownable → AccessControl → Pausable`).

| Role | Scope | Key Functions |
|------|-------|---------------|
| **Owner** | Core security | `setPicoVerifier`, `setVerifierKey`, `removeVerifierKey`, `transferOwnership` |
| **GOVERNANCE_ROLE** | Provider/App lifecycle | `registerProvider`, `updateProvider`, `registerApp`, `updateApp`, `deactivateApp` |
| **PAUSER_ROLE** | Emergency | `pause`, `unpause` |
| **User** | Own identity | `approveApp`, `approveAppWithSig`, `revokeApp`, `unbindIdentity`, queries |
| **App contract** | Lock/unlock | `lockIdentityProperty`, `unlockIdentityProperty` (must be registered `appContract`) |
| **Relayer** | Submission | `submitIdentityAttestation`, `approveAppWithSig` (on behalf of wallet) |

Owner grants `GOVERNANCE_ROLE` and `PAUSER_ROLE` post-deployment.

**Pause model:** `whenNotPaused` guards all state-mutating user operations, including `unbindIdentity` and `revokeApp`. A paused registry therefore also blocks user recovery actions (exit bindings, revoke approvals) until governance unpauses.

---

## 3. Key Concepts

**Provider** — A Web2 service (e.g., Binance, GitHub). Permanently active once registered. Names are unique on-chain.

**App** — A downstream service that consumes identity data. Has a designated `appContract` address for lock/unlock calls. Can be deactivated (and reactivated) by governance.

The trust model is **appId-anchored**: user approval and lock ownership are both tied to the logical `appId`, not to a specific contract address. When governance updates `appContract`, the new address inherits full lock/unlock authority over all existing locks for that `appId`. The old contract can no longer call `unlockIdentityProperty` once replaced. This is intentional — governance is trusted to manage the app's contract lifecycle under a stable identity.

**Web2IDNullifier** — Privacy-preserving identifier derived from a Web2 account. One-to-one binding with a wallet per provider. Released on unbind.

**IdentityProperty** — A provider-scoped attribute (e.g., account age, balance). Recognized on first successful attestation.

**Tuple** — The unit of attestation state: `(wallet, providerId, web2IdNullifier, identityProperty)`. Each tuple stores the latest `timestamp` and `dataBlob`.

**Lock** — Apps lock identity properties they rely on. Locks are counter-based (N locks require N unlocks). Locks gate unbinding at the provider scope.

A lock **only** prevents the user from unbinding that provider identity while the lock is held. It does **not** prevent: new attestations for the same property, reads of the latest attestation value, or other apps holding concurrent locks on the same property.

### Binding Hierarchy

```
Wallet → Provider → Web2IDNullifier → IdentityProperty → Attestation
```

- One wallet can bind to multiple providers.
- Per provider, a wallet has at most one active Web2IDNullifier.
- Per (provider, nullifier), exactly one wallet can own it at any time.
- Per tuple, only the latest attestation is stored.

### Existence Conventions

No `exists` flags. Existence is inferred from required fields:
- Provider registered: non-empty `name`.
- App registered: non-zero `appContract`.
- Attestation exists: non-zero `timestamp`.

### Composite Keys

State indexed beyond 2-layer mapping depth uses flattened composite keys:

| Key | Encoding |
|-----|----------|
| Tuple | `keccak256(abi.encode("TUPLE_V1", wallet, providerId, web2IdNullifier, identityProperty))` |
| App+Tuple | `keccak256(abi.encode("APP_TUPLE_V1", appId, wallet, providerId, web2IdNullifier, identityProperty))` |
| Wallet+Provider | `keccak256(abi.encode("WALLET_PROVIDER_V1", wallet, providerId))` |

Rules: `abi.encode` only (never `abi.encodePacked`). Version tags (`*_V1`) are mandatory key material.

### Key Invariants

1. **Nullifier ownership** — one wallet per `(providerId, nullifier)` at any time. Released on unbind.
2. **Active nullifier uniqueness** — one active nullifier per `(wallet, provider)`.
3. **Timestamp monotonicity** — strictly increasing per tuple. Sole replay protection.
4. **Lock-gated unbind** — blocked while any app holds locks under the provider binding.
5. **Unlock independence** — apps can release their own locks regardless of user approval state.
6. **Soft-delete unbind** — clears binding maps, preserves attestation data. Old constraints apply on re-bind.

---

## 4. Flows

### 4.1 Attestation Submission

Anyone (user or relayer) calls `submitIdentityAttestation(publicValues, proof)`.

1. Decode `publicValues` and verify the ZK proof via Pico verifier.
2. Validate provider is registered and timestamp is positive.
3. Enforce binding invariants: one wallet per nullifier, one active nullifier per (wallet, provider).
4. Enforce replay protection: timestamp must strictly increase per tuple.
5. Write latest attestation and mark property as recognized.

### 4.2 Approval

- **Direct:** User calls `approveApp(appId)` for an active app.
- **Delegated:** Relayer submits `approveAppWithSig(wallet, appId, deadline, nonce, signature)` with an EIP-712 typed data signature from the wallet owner.
- **Revoke:** User calls `revokeApp(appId)`. Prevents future locks but does not affect existing ones.

### 4.3 Lock and Unlock

- **Lock:** App's designated contract calls `lockIdentityProperty`. Requires active app, user approval, and an existing attestation for the resolved tuple.
- **Unlock:** App's designated contract calls `unlockIdentityProperty`. Does **not** require user approval — apps can always release their own locks.
- **Deactivated app unlock:** Anyone can call `unlockIdentityPropertyForDeactivatedApp` to release locks held by deactivated apps.

Lock counting:
- Per-app-tuple count enforces N-lock/N-unlock parity.
- Per-tuple aggregate count determines locked/unlocked state.
- Per-provider effective count (increments on 0→1, decrements on 1→0) gates unbinding.

### 4.4 Unbind

User calls `unbindIdentity(providerId, web2IdNullifier)`.

- Blocked while any app holds locks on the provider binding.
- Soft-delete: clears binding maps but preserves attestation data in storage.
- After unbind, the nullifier is released and can be rebound to any wallet.

### 4.5 Query

- `getLatestIdentityDataBlob(wallet, providerId, identityProperty)` — returns opaque data blob for app-side parsing.
- `getLatestIdentityProperty(wallet, providerId, identityProperty)` — returns `(timestamp, dataBlob)`.

Queries revert if the provider is unregistered, property is unrecognized, no active binding exists, or no attestation has been stored.

---

## 5. Events and Observability

The registry emits events for all state-mutating operations:

| Event | Trigger |
|-------|---------|
| `ProviderRegistered`, `ProviderUpdated` | Provider lifecycle |
| `AppRegistered`, `AppUpdated`, `AppDeactivated` | App lifecycle |
| `PicoVerifierUpdated`, `VerifierKeySet`, `VerifierKeyRemoved` | Verifier config |
| `AppApproved`, `AppRevoked` | User approval |
| `IdentityAttestationAccepted` | Successful attestation |
| `IdentityPropertyLocked`, `IdentityPropertyUnlocked` | Lock/unlock |
| `IdentityUnbound` | Identity unbinding |

Ownership, role, and pause events come from the inherited security library.

---

## 6. Toolchain

| Item | Value |
|------|-------|
| Framework | Foundry |
| Config | `foundry.toml` |
| Solidity | `0.8.28` |
| Build | `forge build` |
| Test | `forge test -vv` |
| Proxy | TransparentUpgradeableProxy (OZ v4) |
