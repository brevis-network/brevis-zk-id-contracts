// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IIdentityRegistry
 * @author Brevis Network
 * @notice Interface for the on-chain identity registry that binds Web2 identities to Web3 wallets
 *         via ZK-attested proofs. Manages provider/app lifecycle, attestations, lock/unlock, and queries.
 */
interface IIdentityRegistry {
    // =========================================================================
    // STRUCTS
    // =========================================================================

    struct Provider {
        string name; // display name; non-empty indicates registered
        bytes metadata; // opaque metadata payload
    }

    struct App {
        string name; // display name
        address appContract; // designated caller for lock/unlock; non-zero indicates registered
        bytes metadata; // opaque metadata payload
        bool active; // false after deactivation
    }

    struct LatestAttestation {
        uint64 timestamp; // non-zero indicates attestation exists
        bytes dataBlob; // opaque payload for app-side business logic
    }

    struct AttestationPublicInputs {
        address wallet; // attested wallet address
        bytes32 providerId; // provider identifier
        bytes32 web2IdNullifier; // privacy-preserving Web2 identity nullifier
        bytes32 identityProperty; // provider-scoped identity property
        uint64 timestamp; // attestation timestamp, must be > 0
        bytes dataBlob; // opaque attestation payload
    }

    // =========================================================================
    // EVENTS
    // =========================================================================

    event ProviderRegistered(bytes32 indexed providerId, string name, bytes metadata);
    event ProviderUpdated(bytes32 indexed providerId, string name, bytes metadata);
    event AppRegistered(bytes32 indexed appId, string name, address indexed appContract, bytes metadata);
    event AppUpdated(bytes32 indexed appId, string name, address indexed appContract, bytes metadata, bool active);
    event AppDeactivated(bytes32 indexed appId);
    event PicoVerifierUpdated(address indexed picoVerifier);
    event VerifierKeySet(bytes32 indexed identityProperty, bytes32 indexed riscvVkey);
    event VerifierKeyRemoved(bytes32 indexed identityProperty);
    event AppApproved(address indexed wallet, bytes32 indexed appId);
    event AppRevoked(address indexed wallet, bytes32 indexed appId);
    event IdentityAttestationAccepted(
        address indexed wallet,
        bytes32 indexed providerId,
        bytes32 indexed web2IdNullifier,
        bytes32 identityProperty,
        uint64 timestamp,
        bytes dataBlob
    );
    event IdentityPropertyLocked(
        bytes32 indexed appId, address indexed wallet, bytes32 indexed providerId,
        bytes32 web2IdNullifier, bytes32 identityProperty
    );
    event IdentityPropertyUnlocked(
        bytes32 indexed appId, address indexed wallet, bytes32 indexed providerId,
        bytes32 web2IdNullifier, bytes32 identityProperty
    );
    event IdentityUnbound(address indexed wallet, bytes32 indexed providerId, bytes32 indexed web2IdNullifier);

    // =========================================================================
    // ERRORS
    // =========================================================================

    error InvalidPicoVerifierAddress(address picoVerifier);
    error VerifierKeyMissing(bytes32 identityProperty);
    error ProviderNotRegistered(bytes32 providerId);
    error ProviderNameAlreadyTaken(string name);
    error InvalidProviderName();
    error InvalidTimestamp();
    error AppNotActive(bytes32 appId);
    error AppApprovalMissing(address wallet, bytes32 appId);
    error AppContractCallerMismatch(bytes32 appId, address caller, address expectedAppContract);
    error ActiveBindingMissing(address wallet, bytes32 providerId);
    error NullifierOwnershipMismatch(bytes32 providerId, bytes32 web2IdNullifier);
    error TimestampNotIncreasing(bytes32 tupleKey, uint64 previousTs, uint64 incomingTs);
    error AppTupleLockMissing(bytes32 appTupleKey);
    error UnbindBlockedByProviderLocks(bytes32 walletProviderKey, uint256 effectiveCount);
    error PropertyNotRecognized(bytes32 providerId, bytes32 identityProperty);
    error EntityAlreadyExists(bytes32 entityId);
    error EntityNotFound(bytes32 entityId);
    error AppNotDeactivated(bytes32 appId);
    error CallerNotBindingOwner(address caller, bytes32 providerId, bytes32 web2IdNullifier);
    error ActiveNullifierConflict(
        address wallet, bytes32 providerId, bytes32 currentNullifier, bytes32 incomingNullifier
    );
    error InvalidAppName();
    error InvalidAppId();
    error InvalidAppContract(address appContract);
    error LockTargetTupleMissing(bytes32 tupleKey);
    error DeactivatedUnlockAppMissing(bytes32 appId);
    error LatestAttestationMissing(bytes32 tupleKey);
    error ApprovalSignatureExpired(uint256 deadline, uint256 currentTimestamp);
    error ApprovalNonceMismatch(address wallet, uint256 expectedNonce, uint256 providedNonce);
    error InvalidApprovalSignature(address wallet);

    // =========================================================================
    // OWNER-ONLY CONTROLS
    // =========================================================================

    /// @notice Sets or replaces the Pico proof verifier contract
    /// @param picoVerifier_ New Pico verifier contract address
    function setPicoVerifier(address picoVerifier_) external;

    /// @notice Sets a RISC-V verification key for an identity property
    /// @param identityProperty Provider-scoped identity property identifier
    /// @param riscvVkey RISC-V verification key for this property's ZK program
    function setVerifierKey(bytes32 identityProperty, bytes32 riscvVkey) external;

    /// @notice Removes a verification key, disabling attestation for this property
    /// @param identityProperty Provider-scoped identity property identifier
    function removeVerifierKey(bytes32 identityProperty) external;

    // =========================================================================
    // PROVIDER / APP LIFECYCLE
    // =========================================================================

    /// @notice Registers a new provider (permanently active once registered)
    /// @param providerId Provider identifier
    /// @param name Provider display name (must be non-empty and globally unique)
    /// @param metadata Opaque provider metadata payload
    function registerProvider(bytes32 providerId, string calldata name, bytes calldata metadata) external;

    /// @notice Updates provider name and metadata
    /// @param providerId Provider identifier
    /// @param name New provider display name (must be non-empty)
    /// @param metadata New opaque provider metadata payload
    function updateProvider(bytes32 providerId, string calldata name, bytes calldata metadata) external;

    /// @notice Registers an app and its designated calling contract
    /// @param appId App identifier
    /// @param name App display name
    /// @param appContract Designated caller address for lock/unlock (must be non-zero)
    /// @param metadata Opaque app metadata payload
    function registerApp(bytes32 appId, string calldata name, address appContract, bytes calldata metadata) external;

    /// @notice Updates app metadata, designated contract, and active status
    /// @param appId App identifier
    /// @param name App display name
    /// @param appContract New designated caller contract (must be non-zero)
    /// @param metadata Opaque app metadata payload
    /// @param active New active status
    function updateApp(
        bytes32 appId, string calldata name, address appContract, bytes calldata metadata, bool active
    ) external;

    /// @notice Marks app inactive. Locks by deactivated apps can be unlocked by anyone.
    /// @param appId App identifier
    function deactivateApp(bytes32 appId) external;

    // =========================================================================
    // USER APPROVALS
    // =========================================================================

    /// @notice Approves an active app for lock operations on caller's identity properties
    /// @param appId App identifier (must be registered and active)
    function approveApp(bytes32 appId) external;

    /// @notice Approves an active app via relayer-submitted EIP-712 signature
    /// @param wallet Wallet owner granting approval
    /// @param appId App identifier (must be registered and active)
    /// @param deadline Signature expiry timestamp
    /// @param nonce Sequential nonce for this wallet
    /// @param signature ECDSA signature over the EIP-712 approval digest
    function approveAppWithSig(
        address wallet, bytes32 appId, uint256 deadline, uint256 nonce, bytes calldata signature
    ) external;

    /// @notice Revokes app approval. Prevents future locks but does not affect existing locks.
    /// @param appId App identifier
    function revokeApp(bytes32 appId) external;

    // =========================================================================
    // ATTESTATION SUBMISSION
    // =========================================================================

    /// @notice Verifies a ZK proof and updates the latest attestation for the resolved tuple.
    ///         Anyone can submit (relayer-friendly); sender does not need to equal attested wallet.
    /// @param publicValues ABI-encoded AttestationPublicInputs committed in the proof
    /// @param proof Pico ZK proof array (8 uint256 values)
    function submitIdentityAttestation(bytes calldata publicValues, uint256[8] calldata proof) external;

    // =========================================================================
    // LOCKING / UNLOCKING
    // =========================================================================

    /// @notice Adds one lock unit on the active binding. Requires active app, designated caller, and user approval.
    /// @param appId App identifier
    /// @param wallet User wallet whose identity property is being locked
    /// @param providerId Provider identifier
    /// @param identityProperty Provider-scoped identity property to lock
    function lockIdentityProperty(bytes32 appId, address wallet, bytes32 providerId, bytes32 identityProperty) external;

    /// @notice Removes one lock unit owned by an active app. No approval check.
    /// @param appId App identifier
    /// @param wallet User wallet
    /// @param providerId Provider identifier
    /// @param identityProperty Provider-scoped identity property to unlock
    function unlockIdentityProperty(
        bytes32 appId, address wallet, bytes32 providerId, bytes32 identityProperty
    ) external;

    /// @notice Removes one lock unit for a deactivated app. Callable by anyone.
    /// @param appId App identifier (must exist and be inactive)
    /// @param wallet User wallet
    /// @param providerId Provider identifier
    /// @param identityProperty Provider-scoped identity property to unlock
    function unlockIdentityPropertyForDeactivatedApp(
        bytes32 appId, address wallet, bytes32 providerId, bytes32 identityProperty
    ) external;

    /// @notice Unbinds a Web2 identity from caller's wallet (soft-delete).
    ///         Blocked while any app holds locks on this provider binding.
    /// @param providerId Provider identifier
    /// @param web2IdNullifier Provider-scoped nullifier to unbind
    function unbindIdentity(bytes32 providerId, bytes32 web2IdNullifier) external;

    // =========================================================================
    // QUERY
    // =========================================================================

    /// @notice Returns full attestation metadata for wallet's current active binding
    /// @param wallet User wallet
    /// @param providerId Provider identifier
    /// @param identityProperty Provider-scoped identity property
    /// @return timestamp Latest attestation timestamp
    /// @return dataBlob Latest opaque attestation payload
    function getLatestIdentityProperty(
        address wallet, bytes32 providerId, bytes32 identityProperty
    ) external view returns (uint64 timestamp, bytes memory dataBlob);

    /// @notice Returns only the data blob for app-side business logic evaluation
    /// @param wallet User wallet
    /// @param providerId Provider identifier
    /// @param identityProperty Provider-scoped identity property
    /// @return dataBlob Latest opaque attestation payload
    function getLatestIdentityDataBlob(
        address wallet, bytes32 providerId, bytes32 identityProperty
    ) external view returns (bytes memory dataBlob);
}
