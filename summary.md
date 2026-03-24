# Onchain Implementation Summary

Review of this standalone on-chain package (`src/`, `scripts/`, `test/`) against `docs/requirement/requirement_onchain.md` in the parent framework repository.

**Result**: Fully implemented and aligned with the product requirement. All design decisions have been incorporated into the requirement.

---

## Requirement Coverage

### Identity Binding

| Requirement | Status | Evidence |
|---|---|---|
| One Web2IDNullifier bound to one wallet, vice versa | Covered | `nullifierOwner` + `activeNullifierByWalletProvider` invariants |
| Prevent replay | Covered | Timestamp monotonicity (nonce removed by decision) |
| Prevent tampered attestation | Covered | Pico verifier proof check |
| Anyone can submit | Covered | No `msg.sender == wallet` check |
| Maintain only latest per tuple | Covered | `latestAttestationByTuple` overwritten each time |
| Timestamp strictly greater | Covered | `TimestampNotIncreasing` check |
| Reject unregistered provider | Covered | `ProviderNotRegistered` check |
| Reject nullifier bound to another wallet | Covered | `NullifierOwnershipMismatch` check |
| Events for off-chain indexing | Covered | `IdentityAttestationAccepted` event |

### Identity Provider Registration

| Requirement | Status | Evidence |
|---|---|---|
| Register only once | Covered | `EntityAlreadyExists` check |
| Metadata (name + unique ID) | Covered | `providerId` as unique ID, `name` + `metadata` |
| Governance approval | Covered | `onlyRole(GOVERNANCE_ROLE)` |
| No sybil on names | Covered | `providerNameHash` on-chain uniqueness |
| Events | Covered | `ProviderRegistered`, `ProviderUpdated` |

### App Registration

| Requirement | Status | Evidence |
|---|---|---|
| Register only once | Covered | `EntityAlreadyExists` check |
| Metadata + contract address (updatable) | Covered | `registerApp` + `updateApp` |
| Governance approval | Covered | `onlyRole(GOVERNANCE_ROLE)` |
| Events | Covered | `AppRegistered`, `AppUpdated` |

### App Deactivation

| Requirement | Status | Evidence |
|---|---|---|
| Governance approval | Covered | `onlyRole(GOVERNANCE_ROLE)` on `deactivateApp` |
| User protection | Covered | Anyone can unlock deactivated app's locks |
| Events | Covered | `AppDeactivated` |

### App Approval

| Requirement | Status | Evidence |
|---|---|---|
| Only registered apps | Covered | `AppNotActive` check |
| Cross-provider locking after approval | Covered | `appApproval` is not provider-scoped |
| Events | Covered | `AppApproved` |

### App Approval Revocation

| Requirement | Status | Evidence |
|---|---|---|
| Only registered apps' approval can be revoked | Covered | `EntityNotFound` check (allows inactive apps — intentional) |
| Events | Covered | `AppRevoked` |

### Identity Locking

| Requirement | Status | Evidence |
|---|---|---|
| Only registered + approved apps | Covered | `AppNotActive` + `AppApprovalMissing` checks |
| ZK events provide signals | Covered | `IdentityAttestationAccepted` has wallet, nullifier, property |
| Multi-property per provider | Covered | Lock is per-tuple, not per-provider |
| Multi-app multi-lock | Covered | `appLockCountByAppTuple` tracks per-app |
| Events | Covered | `IdentityPropertyLocked` |

### Identity Unlocking

| Requirement | Status | Evidence |
|---|---|---|
| Designated contract (no re-check of approval) | Covered | Unlock checks app identity and lock ownership; approval not re-checked at unlock time |
| Deactivated app: anyone can unlock | Covered | `unlockIdentityPropertyForDeactivatedApp` |
| Cannot unlock without prior lock | Covered | `AppTupleLockMissing` check |
| App responsibility to unlock | Covered | App can always unlock (no approval gate) |
| Events | Covered | `IdentityPropertyUnlocked` |

### Identity Unbinding

| Requirement | Status | Evidence |
|---|---|---|
| Only if no locks | Covered | `UnbindBlockedByProviderLocks` |
| Cannot unbind before binding | Covered | `CallerNotBindingOwner` (owner is zero if not bound) |
| Properties removed / not queryable | Covered | Binding maps cleared; data unreachable via queries |
| Events | Covered | `IdentityUnbound` |

### Query

| Requirement | Status | Evidence |
|---|---|---|
| Query by (wallet, providerId, property) | Covered | `getLatestIdentityProperty` / `getLatestIdentityDataBlob` |
| Only registered providers | Covered | `ProviderNotRegistered` in `_resolveLatest` |
| Reject unrecognized property | Covered | `PropertyNotRecognized` in `_resolveLatest` |
| Raw blob, app decodes | Covered | Returns opaque `dataBlob` |
