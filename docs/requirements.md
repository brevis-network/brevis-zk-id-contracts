# On-chain Identity Registry

## Introduction

We are building a BNB ZK ID framework that enables users to bind their Web2 identity and related attributes to their Web3 wallet address on BNB Chain. With this binding in place, services and applications can leverage verified identity data to deliver more personalized experiences.

The framework is designed to be end-to-end trustless, powered by zero-knowledge proofs of users’ TLS sessions (ZKTLS) as well as zero-knowledge computation proofs derived from the raw data collected during the TLS process.

Because this is intended to be a general-purpose framework, the supporting on-chain smart contracts should be reusable across multiple applications, cover common use cases, and remain highly extensible. This document focuses on the functional requirements that this smart contract standard should support.

## Glossaries and key concepts

**IdentityProvider**: The identifier representing a Web 2 service, such as Binance, Github, and others. Each IdentityProvider’s unique user can only be bound once to a wallet address. A wallet address can be bound to only one unique user for each IdentityProvider. The user can bind different IdentityProviders at the same time. **Binding occurs strictly at the provider layer.**

**IdentityProperty**: The unique identifier that represents a specific attribute or trait of a user as recognized by a given provider. Examples of such attributes include account age, user balance, or transaction history. This identifier is **provider-scoped** — even if two providers expose the same type of attribute (e.g., *account age*), they are assigned distinct identifiers — and is globally unique across all providers.

**App**: An App is a downstream service or application that consumes a user’s IdentityProperty attributes to deliver personalized experiences or enforce service-specific policies.

**Web2IDNullifier**: The Web2IDNullifier is a deterministic, privacy-preserving identifier derived from a Web2 provider’s unique user reference (e.g., GitHub ID, Binance UID, Amazon account email) combined with the provider’s identifier. Ownership of a Web2 user identity property is enforced at the **Web2IDNullifier level** to guarantee that only a single wallet address can bind to a given Web2 identity.

**Wallet address**: User’s wallet address on BNB Chain.

**IdentityAttestation**: A zero-knowledge (ZK) attestation output that encapsulates verified identity information in a privacy-preserving format. It contains IdentityProvider, Web2IDNullifier, IdentityProperty, Wallet address, timestamp, and an unstructured data blob which will be interpreted and parsed by each application. It enables relayer-based proof submission and a binding between Web2 identity and Web3 wallet address.

**Identity Registry**: A smart contract that verifies ZK proofs of identity attestations, maintains the association of user identity, and enables queries and operations for external apps and users.

## Key Functions of the system:

### Identity Binding

It is the process by which a user or relayer submits an IdentityAttestation to the Identity Registry. Once the attestation is successfully verified, a binding relationship is established that links the user’s Web2 identity to their Web3 wallet.

The binding structure will be:
Wallet Address → Identity Provider → Web2IDNullifier → Identity Property → IdentityAttestation

Requirements:

- One Web2IDNullifier can only be bound to one wallet address, vice versa.
- We should prevent any replay of the same IdentityAttestation.
- We should prevent any tampered IdentityAttestation.
- Anyone can submit identity attestation after a ZK proof is generated. It does not have to be the user.
- The Identity Registry will maintain only the latest attestation result for each (Wallet Address, Web2IDNullifier, IdentityProperty) tuple.
- An IdentityAttestation will only be accepted if its timestamp is strictly greater than the latest on-chain maintained timestamp for the same (Wallet Address, Web2IDNullifier, IdentityProperty) tuple.
- An IdentityAttestation should be rejected if there is no registration for IdentityProvider.
- An IdentityAttestation should be rejected if Web2IDNullifier has been bound to another wallet.
- The binding process should allow off-chain services to create a complete view of all historical attestation results through event indexing.

### Identity Provider Registration

It is the process by which the Identity Registry formally declares that a Web2 service (e.g., Binance, GitHub, Amazon) is recognized and available for use by users and applications.

Requirements:

- Each IdentityProvider can be registered only once in the Identity Registry.
- During registration, each IdentityProvider must provide a set of metadata to the Identity Registry, including Provider Name and Provider Unique ID.
- Provider names must be unique within the registry.
- Registration is executed through governance approval through an admin role, ensuring that only vetted providers are added to the registry and no sybil attack on the provider names can be carried out.
- There is no explicit deregistration process for a provider. Deregistering a provider while apps hold locks on its identity properties would leave users unable to unbind with no resolution path.
- All update and registration processes should allow off-chain services to create a complete view of all available providers through event indexing.


### App Registration

It is the process by which the Identity Registry formally declares that an App (e.g., Listadao) is recognized and available for interaction with user identities.

Requirements:

- Each App can be registered only once in the Identity Registry.
- During registration, each App must provide a set of metadata to the Identity Registry, including App Name and App Unique ID and contract address of the app (can be updated) used to lock user resources.
- Registration is executed through governance approval through an admin role, ensuring that only vetted apps are added to the registry.
- All update and registration processes should allow off-chain services to create a complete view of all available apps through event indexing.


### App Deactivation

It is the process by which the Identity Registry suspends an App’s ability to interact with user identities. Deactivation is reversible: governance may reactivate a previously deactivated App.

Requirements:

- Deactivation is executed through governance approval through an admin role, ensuring the protection of users when an App is found malicious, compromised, or violating policies.
- The deactivation process should allow off-chain services to create a complete view of all app deactivations through event indexing.

### App Approval

It is a **user-driven action** that grants an App authorization to lock the user’s attestation results across all providers. A user (or a relayer acting on their behalf) grants or revokes this authorization at the wallet level. Once approved, the App may apply its own logic or policies based on the locked/unlocked state.

Requirements:

- Only registered Apps can be approved.
- Approval is wallet-wide: a single approval covers the App’s access to all of the user’s identity properties across all providers.
- Once an App has been approved in the Identity Registry, it may lock the user’s attestation results across different providers.
- The approval process should allow off-chain services to create a complete view of all app approvals through event indexing.

### App Approval Revocation

It is the user-initiated process by which a user revokes an App’s wallet-wide authorization to interact with attestation results.

Requirements:

- Only registered Apps’ approval can be revoked.
- The revocation process should allow off-chain services to create a complete view of all app revocations through event indexing.

### Identity Locking

It is the process by which an App explicitly notifies the Identity Registry that it will use a user’s IdentityProperty attributes as part of its business logic. Then the user cannot unbind the associated Web2IDNullifier for this IdentityProvider.

Requirements:

- Only registered Apps with the user’s approval can use and lock the user’s IdentityProperty.
- On-chain ZK-attestation events provide the necessary signals, including the user, Web2IDNullifier, and the specific IdentityProperty being attested.
- An App or multiple apps can lock multiple identity properties on the same IdentityProvider for a user.
- One or multiple Apps can apply multiple locks on the same IdentityProperty’s attestation value.
- The Identity Locking process should allow off-chain services to create a complete view of all identity locking through event indexing.

### Identity Unlocking

Once an App finishes using a user’s IdentityProperty attributes, it must explicitly unlock the IdentityProperty by notifying the Identity Registry.

Requirements:

- Only registered Apps’ designated smart contract can unlock the user’s IdentityProperty. Unlocking does not require the user’s approval.
- If an App is deactivated through the admin/governance process, anyone can unlock the lock created by that app.
- An App cannot unlock an IdentityProperty unless it has previously locked that property.
- It is the App’s responsibility to unlock the user’s IdentityProperty unless it is deactivated. After deactivation, the user can unlock their IdentityProperty locked by the app.

### Identity Unbinding

It is the user-initiated process by which a user detaches a bound IdentityProvider (via Web2IDNullifier) from their wallet.

Requirements:

- The user can unbind only if no app locks their IdentityProperty.
- A user cannot unbind before binding.
- After unbinding, all of the user’s IdentityProperties associated with the provider are no longer queryable. The released Web2IDNullifier may be rebound to any wallet.
- The Identity Unbinding process should allow off-chain services to create a complete view of all identity unbinding through event indexing.

### IdentityProperty Attributes Query and Usage

After an IdentityAttestation is verified, its result is stored in the Identity Registry according to a layered structure: User → ProviderId → IdentityProperty → Attestation Results.

When an App wants to use a user’s IdentityProperty attributes, it must explicitly provide the following identifiers to the Identity Registry: User Address, ProviderId, IdentityProperty. The Identity Registry will return the **latest attestation result** for the requested IdentityProperty. Meanwhile, the **App** carries full responsibility for how the data is processed and when locks are applied.

Requirements:

- By providing ProviderId, the Web2 provider user is uniquely identified because the system enforces a one-to-one policy between a user and a Web2IDNullifier.
- Only registered Providers are available for querying attestation results.
- The Identity Registry must reject queries that reference random or unrecognized IdentityProperty values.
- The Identity Registry provides a data blob in an attestation result. It is the App’s responsibility to decode and parse this blob into meaningful business logic. The Registry does not interpret or transform the attestation data; Apps must handle this themselves.
