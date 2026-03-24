// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@security/access/PauserControl.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "./pico/IPicoVerifier.sol";
import "./IIdentityRegistry.sol";

/**
 * @title IdentityRegistry
 * @notice On-chain registry that binds Web2 identities to Web3 wallets via ZK-attested proofs.
 *
 * @dev Access control tiers (inherited from PauserControl -> AccessControl -> Ownable):
 *      - Owner: core security functions (Pico verifier, verification keys)
 *      - GOVERNANCE_ROLE: provider/app lifecycle operations
 *      - PAUSER_ROLE: emergency pause/unpause
 */
contract IdentityRegistry is IIdentityRegistry, PauserControl, EIP712 {
    // =========================================================================
    // CONSTANTS
    // =========================================================================

    // 71840dc4906352362b0cdaf79870196c8e42acafade72d5d5a6d59291253ceb1
    bytes32 public constant GOVERNANCE_ROLE = keccak256("GOVERNANCE_ROLE");

    // EIP-712 typehash for delegated app approval signatures.
    // c00079495475d1d758d0e3c2a788c0733ca667cc062a2dc8a365adc623fa3704
    bytes32 public constant APPROVE_APP_TYPEHASH =
        keccak256("ApproveApp(address wallet,bytes32 appId,uint256 deadline,uint256 nonce)");

    // Structs, events, and errors are defined in IIdentityRegistry.

    // =========================================================================
    // STORAGE
    // =========================================================================

    // --- Verification ---

    /// Pico proof verifier contract for ZK proof validation.
    address public picoVerifier;
    /// RISC-V verification keys indexed by identity property.
    mapping(bytes32 => bytes32) public riscvVkeyByIdentityProperty;

    // --- Provider / App ---

    /// Provider records keyed by providerId. Non-empty name = registered.
    mapping(bytes32 => Provider) public providers;
    /// On-chain provider name uniqueness guard: keccak256(name) -> taken.
    mapping(bytes32 => bool) public providerNameHash;
    /// App records keyed by appId. Non-zero appContract = registered.
    mapping(bytes32 => App) public apps;

    // --- User Approvals ---

    /// User approval gate for app lock operations: appApproval[wallet][appId].
    mapping(address => mapping(bytes32 => bool)) public appApproval;
    /// Delegated-approval replay guard: each signed approval consumes one sequential nonce.
    mapping(address => uint256) public approvalNonceByWallet;

    // --- Binding ---

    /// Nullifier ownership: one wallet per (providerId, web2IdNullifier).
    mapping(bytes32 => mapping(bytes32 => address)) public nullifierOwner;
    /// Active binding: one active nullifier per (wallet, providerId).
    mapping(address => mapping(bytes32 => bytes32)) public activeNullifierByWalletProvider;

    // --- Attestation State ---

    /// Latest attestation keyed by composite tupleKey. Non-zero timestamp = attestation exists.
    mapping(bytes32 => LatestAttestation) public latestAttestationByTuple;
    /// Provider-scoped property recognition: set to true on first successful attestation.
    mapping(bytes32 => mapping(bytes32 => bool)) public recognizedProperty;

    // --- Lock Counters ---

    /// Aggregate lock count per tuple across all apps.
    mapping(bytes32 => uint256) public lockCountByTuple;
    /// Per-app lock count per tuple, enforces N-lock/N-unlock parity.
    mapping(bytes32 => uint256) public appLockCountByAppTuple;
    /// Provider-scope effective lock count per (wallet, providerId).
    /// Increments on tuple 0->1 transition, decrements on 1->0. Gates unbind.
    mapping(bytes32 => uint256) public effectiveProviderLockCountByWalletProvider;

    // Storage gap for future upgrades. Reserves 40 slots.
    uint256[40] private __gap;

    // =========================================================================
    // CONSTRUCTOR & INITIALIZATION
    // =========================================================================

    /**
     * @notice Deploys registry. Supports both direct and proxy deployment.
     * @dev For direct deployment: pass real picoVerifier address.
     *      For proxy deployment: pass address(0), then call init() via proxy.
     *      Ownable constructor sets msg.sender as owner for direct deployment.
     *      EIP712 name "IdentityRegistry" is 16 bytes, fits in ShortString (no storage fallback needed).
     * @param picoVerifier_ Pico proof verifier contract address (or address(0) for proxy)
     */
    constructor(address picoVerifier_) EIP712("IdentityRegistry", "1") {
        // Only initialize if non-zero value is provided (direct deployment)
        if (picoVerifier_ != address(0)) {
            _init(picoVerifier_);
            // Note: Ownable constructor automatically sets msg.sender as owner
        }
        // For proxy deployment, pass address(0) and call init() separately
    }

    /**
     * @notice Initializer for proxy deployment. Sets up state and claims ownership.
     * @dev Can only be called once — initOwner() reverts if owner is already set.
     *      In proxy context (delegateCall), _owner is address(0) because the
     *      Ownable constructor ran on the implementation, not the proxy.
     * @param picoVerifier_ Pico proof verifier contract address
     */
    function init(address picoVerifier_) external {
        _init(picoVerifier_);
        initOwner(); // sets msg.sender as owner; reverts if already set
    }

    /**
     * @dev Shared initialization logic for constructor and init().
     */
    function _init(address picoVerifier_) internal {
        if (picoVerifier_ == address(0)) revert InvalidPicoVerifierAddress(address(0));
        picoVerifier = picoVerifier_;
        emit PicoVerifierUpdated(picoVerifier_);
    }

    // =========================================================================
    // OWNER-ONLY CONTROLS
    // =========================================================================

    /**
     * @notice Sets or replaces the Pico proof verifier contract
     * @param picoVerifier_ New Pico verifier contract address
     */
    function setPicoVerifier(address picoVerifier_) external onlyOwner {
        if (picoVerifier_ == address(0)) revert InvalidPicoVerifierAddress(picoVerifier_);
        picoVerifier = picoVerifier_;
        emit PicoVerifierUpdated(picoVerifier_);
    }

    /**
     * @notice Sets a RISC-V verification key for an identity property
     * @param identityProperty Provider-scoped identity property identifier
     * @param riscvVkey RISC-V verification key for this property's ZK program
     */
    function setVerifierKey(
        bytes32 identityProperty,
        bytes32 riscvVkey
    ) external onlyOwner {
        riscvVkeyByIdentityProperty[identityProperty] = riscvVkey;
        emit VerifierKeySet(identityProperty, riscvVkey);
    }

    /**
     * @notice Removes a verification key, effectively disabling attestation for this property
     * @param identityProperty Provider-scoped identity property identifier
     */
    function removeVerifierKey(bytes32 identityProperty) external onlyOwner {
        delete riscvVkeyByIdentityProperty[identityProperty];
        emit VerifierKeyRemoved(identityProperty);
    }

    // =========================================================================
    // PROVIDER / APP LIFECYCLE (GOVERNANCE_ROLE)
    // =========================================================================

    /**
     * @notice Registers a new provider. Providers are permanently active once registered.
     * @dev Name must be non-empty and unique on-chain (prevents sybil attacks on provider names).
     * @param providerId Provider identifier
     * @param name Provider display name (must be non-empty and globally unique)
     * @param metadata Opaque provider metadata payload
     */
    function registerProvider(
        bytes32 providerId,
        string calldata name,
        bytes calldata metadata
    ) external onlyRole(GOVERNANCE_ROLE) whenNotPaused {
        // Validate name is non-empty
        if (bytes(name).length == 0) revert InvalidProviderName();

        // Check provider not already registered
        if (bytes(providers[providerId].name).length > 0) revert EntityAlreadyExists(providerId);

        // Enforce on-chain name uniqueness
        bytes32 nameHash = keccak256(bytes(name));
        if (providerNameHash[nameHash]) revert ProviderNameAlreadyTaken(name);

        // Store provider record
        providers[providerId] = Provider({
            name: name,
            metadata: metadata
        });
        providerNameHash[nameHash] = true;

        emit ProviderRegistered(providerId, name, metadata);
    }

    /**
     * @notice Updates provider name and metadata
     * @dev If the name changes, the old name hash is released and the new one is claimed.
     *      Reverts if the new name is already taken by another provider.
     * @param providerId Provider identifier
     * @param name New provider display name (must be non-empty)
     * @param metadata New opaque provider metadata payload
     */
    function updateProvider(
        bytes32 providerId,
        string calldata name,
        bytes calldata metadata
    ) external onlyRole(GOVERNANCE_ROLE) whenNotPaused {
        // Validate name is non-empty
        if (bytes(name).length == 0) revert InvalidProviderName();

        // Check provider exists
        Provider storage p = providers[providerId];
        if (bytes(p.name).length == 0) revert EntityNotFound(providerId);

        // Release old name hash and claim new one (skip if name unchanged)
        bytes32 oldNameHash = keccak256(bytes(p.name));
        bytes32 newNameHash = keccak256(bytes(name));
        if (oldNameHash != newNameHash) {
            if (providerNameHash[newNameHash]) revert ProviderNameAlreadyTaken(name);
            providerNameHash[oldNameHash] = false;
            providerNameHash[newNameHash] = true;
        }

        // Update provider record
        p.name = name;
        p.metadata = metadata;

        emit ProviderUpdated(providerId, name, metadata);
    }

    /**
     * @notice Registers an app and its designated calling contract
     * @param appId App identifier
     * @param name App display name
     * @param appContract Designated caller address for lock/unlock (must be non-zero)
     * @param metadata Opaque app metadata payload
     */
    function registerApp(
        bytes32 appId,
        string calldata name,
        address appContract,
        bytes calldata metadata
    ) external onlyRole(GOVERNANCE_ROLE) whenNotPaused {
        // Validate inputs
        if (appId == bytes32(0)) revert InvalidAppId();
        if (bytes(name).length == 0) revert InvalidAppName();
        if (appContract == address(0)) revert InvalidAppContract(appContract);

        // Check app not already registered
        if (apps[appId].appContract != address(0)) revert EntityAlreadyExists(appId);

        // Store app record
        apps[appId] = App({
            name: name,
            appContract: appContract,
            metadata: metadata,
            active: true
        });

        emit AppRegistered(appId, name, appContract, metadata);
    }

    /**
     * @notice Updates app metadata, designated contract, and active status.
     * @dev Trust model: appId is the persistent logical identity of the app. User approval and lock
     *      ownership are both anchored to appId. Updating appContract is a normal lifecycle operation —
     *      the new contract inherits lock/unlock authority over all existing locks for this appId.
     *      The old contract loses unlock access immediately upon update.
     * @param appId App identifier
     * @param name App display name
     * @param appContract New designated caller contract (must be non-zero)
     * @param metadata Opaque app metadata payload
     * @param active New active status
     */
    function updateApp(
        bytes32 appId,
        string calldata name,
        address appContract,
        bytes calldata metadata,
        bool active
    ) external onlyRole(GOVERNANCE_ROLE) whenNotPaused {
        if (bytes(name).length == 0) revert InvalidAppName();
        App storage a = apps[appId];
        if (a.appContract == address(0)) revert EntityNotFound(appId);
        if (appContract == address(0)) revert InvalidAppContract(appContract);

        a.name = name;
        a.appContract = appContract;
        a.metadata = metadata;
        a.active = active;

        emit AppUpdated(appId, name, appContract, metadata, active);
    }

    /**
     * @notice Marks app inactive. Locks created by deactivated apps can be unlocked by anyone.
     *         Deactivation is reversible: governance may reactivate via updateApp.
     * @param appId App identifier
     */
    function deactivateApp(bytes32 appId) external onlyRole(GOVERNANCE_ROLE) whenNotPaused {
        App storage a = apps[appId];
        if (a.appContract == address(0)) revert EntityNotFound(appId);
        a.active = false;
        emit AppDeactivated(appId);
    }

    // =========================================================================
    // USER APPROVALS
    // =========================================================================

    /**
     * @notice Approves an active app for lock operations on caller's identity properties
     * @param appId App identifier (must be registered and active)
     */
    function approveApp(bytes32 appId) external whenNotPaused {
        App storage a = apps[appId];
        if (a.appContract == address(0) || !a.active) revert AppNotActive(appId);
        appApproval[msg.sender][appId] = true;
        emit AppApproved(msg.sender, appId);
    }

    /**
     * @notice Approves an active app via relayer-submitted ECDSA signature
     * @dev Validation order: app active -> deadline -> nonce -> signature validity.
     *      Digest is domain-bound to (contract address, chainId) to prevent cross-contract/chain replay.
     * @param wallet Wallet owner granting approval
     * @param appId App identifier (must be registered and active)
     * @param deadline Signature expiry timestamp (block.timestamp must be <= deadline)
     * @param nonce Sequential nonce for this wallet (must match approvalNonceByWallet[wallet])
     * @param signature ECDSA signature over the approval digest, must recover to wallet
     */
    function approveAppWithSig(
        address wallet,
        bytes32 appId,
        uint256 deadline,
        uint256 nonce,
        bytes calldata signature
    ) external whenNotPaused {
        // Check app is registered and active
        App storage a = apps[appId];
        if (a.appContract == address(0) || !a.active) revert AppNotActive(appId);

        // Check signature has not expired
        if (block.timestamp > deadline) revert ApprovalSignatureExpired(deadline, block.timestamp);

        // Check nonce matches expected value (prevents replay)
        uint256 expectedNonce = approvalNonceByWallet[wallet];
        if (nonce != expectedNonce) {
            revert ApprovalNonceMismatch(wallet, expectedNonce, nonce);
        }

        // EIP-712 typed data digest (domain separator includes contract address and chainId)
        bytes32 structHash = keccak256(abi.encode(APPROVE_APP_TYPEHASH, wallet, appId, deadline, nonce));
        bytes32 digest = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(digest, signature);
        if (signer != wallet) {
            revert InvalidApprovalSignature(wallet);
        }

        // Consume nonce and set approval
        approvalNonceByWallet[wallet] = expectedNonce + 1;
        appApproval[wallet][appId] = true;

        emit AppApproved(wallet, appId);
    }

    /**
     * @notice Revokes app approval. Prevents future locks but does not affect existing locks.
     * @dev Revoke is valid for any registered app (active or deactivated).
     * @param appId App identifier
     */
    function revokeApp(bytes32 appId) external whenNotPaused {
        App storage a = apps[appId];
        if (a.appContract == address(0)) revert EntityNotFound(appId);
        appApproval[msg.sender][appId] = false;
        emit AppRevoked(msg.sender, appId);
    }

    // =========================================================================
    // ATTESTATION SUBMISSION
    // =========================================================================

    /**
     * @notice Verifies a ZK proof and updates the latest attestation for the resolved tuple.
     *         Anyone can submit (relayer-friendly); sender does not need to equal attested wallet.
     * @dev Validation order: paused -> proof verification -> provider -> binding -> replay -> state write.
     * @param publicValues ABI-encoded AttestationPublicInputs committed in the proof
     * @param proof Pico ZK proof array (8 uint256 values)
     */
    function submitIdentityAttestation(
        bytes calldata publicValues,
        uint256[8] calldata proof
    ) external whenNotPaused {
        // Step 1: Decode public inputs and verify proof
        AttestationPublicInputs memory a = abi.decode(publicValues, (AttestationPublicInputs));
        bytes32 vkey = riscvVkeyByIdentityProperty[a.identityProperty];
        if (vkey == bytes32(0)) revert VerifierKeyMissing(a.identityProperty);
        IPicoVerifier(picoVerifier).verifyPicoProof(vkey, publicValues, proof);

        // Step 2: Validate provider is registered (providers are permanently active once registered)
        if (bytes(providers[a.providerId].name).length == 0) revert ProviderNotRegistered(a.providerId);

        // Step 3: Validate timestamp is positive (zero is reserved as "no attestation" sentinel)
        if (a.timestamp == 0) revert InvalidTimestamp();

        // Step 4: Enforce nullifier ownership — one wallet per (providerId, nullifier).
        // First bind claims ownership; subsequent submissions for same pair must match.
        address currentOwner = nullifierOwner[a.providerId][a.web2IdNullifier];
        if (currentOwner == address(0)) {
            nullifierOwner[a.providerId][a.web2IdNullifier] = a.wallet;
        } else if (currentOwner != a.wallet) {
            revert NullifierOwnershipMismatch(a.providerId, a.web2IdNullifier);
        }

        // Step 5: Enforce one active nullifier per (wallet, providerId).
        // Prevents cross-nullifier writes within the same wallet/provider scope.
        bytes32 currentNullifier = activeNullifierByWalletProvider[a.wallet][a.providerId];
        if (currentNullifier == bytes32(0)) {
            activeNullifierByWalletProvider[a.wallet][a.providerId] = a.web2IdNullifier;
        } else if (currentNullifier != a.web2IdNullifier) {
            revert ActiveNullifierConflict(a.wallet, a.providerId, currentNullifier, a.web2IdNullifier);
        }

        // Step 6: Replay protection — timestamp must strictly increase per tuple
        bytes32 tupleKey = _tupleKey(a.wallet, a.providerId, a.web2IdNullifier, a.identityProperty);
        LatestAttestation storage latest = latestAttestationByTuple[tupleKey];
        if (latest.timestamp != 0 && a.timestamp <= latest.timestamp) {
            revert TimestampNotIncreasing(tupleKey, latest.timestamp, a.timestamp);
        }

        // Step 7: Write latest attestation state
        latest.timestamp = a.timestamp;
        latest.dataBlob = a.dataBlob;

        // Mark property as recognized on first successful attestation (gates future queries)
        recognizedProperty[a.providerId][a.identityProperty] = true;

        emit IdentityAttestationAccepted(
            a.wallet,
            a.providerId,
            a.web2IdNullifier,
            a.identityProperty,
            a.timestamp,
            a.dataBlob
        );
    }

    // =========================================================================
    // LOCKING / UNLOCKING
    // =========================================================================

    /**
     * @notice Adds one lock unit for (appId, wallet, providerId, property) on the active binding.
     *         Only the app's designated contract can lock, and the user must have approved the app.
     * @dev Validation order: app active -> designated caller -> user approval -> active binding -> tuple exists.
     *      A lock ONLY prevents the user from unbinding while it is held. It does NOT prevent new
     *      attestations for the same property, reads of the latest attestation value, or concurrent
     *      locks by other apps on the same property.
     * @param appId App identifier
     * @param wallet User wallet whose identity property is being locked
     * @param providerId Provider identifier
     * @param identityProperty Provider-scoped identity property to lock
     */
    function lockIdentityProperty(
        bytes32 appId,
        address wallet,
        bytes32 providerId,
        bytes32 identityProperty
    ) external whenNotPaused {
        // Validate app is registered and active
        App storage a = apps[appId];
        if (a.appContract == address(0) || !a.active) revert AppNotActive(appId);

        // Validate caller is the app's designated contract
        if (msg.sender != a.appContract) {
            revert AppContractCallerMismatch(appId, msg.sender, a.appContract);
        }

        // Validate user has approved this app for lock operations
        if (!appApproval[wallet][appId]) revert AppApprovalMissing(wallet, appId);

        // Resolve active nullifier — lock path never accepts caller-supplied nullifier
        bytes32 resolvedNullifier = activeNullifierByWalletProvider[wallet][providerId];
        if (resolvedNullifier == bytes32(0)) revert ActiveBindingMissing(wallet, providerId);

        // Derive composite keys
        bytes32 tupleKey = _tupleKey(wallet, providerId, resolvedNullifier, identityProperty);
        bytes32 appTupleKey = _appTupleKey(appId, wallet, providerId, resolvedNullifier, identityProperty);
        bytes32 walletProviderKey = _walletProviderKey(wallet, providerId);

        // Require attestation exists for this tuple
        if (latestAttestationByTuple[tupleKey].timestamp == 0) revert LockTargetTupleMissing(tupleKey);

        // Increment lock counters
        uint256 previousTupleCount = lockCountByTuple[tupleKey];
        appLockCountByAppTuple[appTupleKey] += 1;
        lockCountByTuple[tupleKey] = previousTupleCount + 1;

        // Effective provider lock count tracks "how many tuples are locked" (not total lock ops).
        // Only the first lock on a tuple (0->1) increments the provider-level count.
        if (previousTupleCount == 0) {
            effectiveProviderLockCountByWalletProvider[walletProviderKey] += 1;
        }

        emit IdentityPropertyLocked(appId, wallet, providerId, resolvedNullifier, identityProperty);
    }

    /**
     * @notice Removes one lock unit owned by an active app.
     *         No approval check — app proved authorization at lock time and must be able to
     *         release its own locks even if the user later revokes approval.
     * @dev Validation order: app active -> designated caller -> active binding -> positive lock count.
     * @param appId App identifier
     * @param wallet User wallet
     * @param providerId Provider identifier
     * @param identityProperty Provider-scoped identity property to unlock
     */
    function unlockIdentityProperty(
        bytes32 appId,
        address wallet,
        bytes32 providerId,
        bytes32 identityProperty
    ) external whenNotPaused {
        App storage a = apps[appId];
        if (a.appContract == address(0) || !a.active) revert AppNotActive(appId);
        if (msg.sender != a.appContract) {
            revert AppContractCallerMismatch(appId, msg.sender, a.appContract);
        }
        _unlock(appId, wallet, providerId, identityProperty);
    }

    /**
     * @notice Removes one lock unit for a deactivated (inactive) app. Callable by anyone.
     *         Allows users to recover from locks held by apps that have been deactivated.
     * @dev Rejects both missing app IDs and still-active apps.
     * @param appId App identifier (must exist and be inactive)
     * @param wallet User wallet
     * @param providerId Provider identifier
     * @param identityProperty Provider-scoped identity property to unlock
     */
    function unlockIdentityPropertyForDeactivatedApp(
        bytes32 appId,
        address wallet,
        bytes32 providerId,
        bytes32 identityProperty
    ) external whenNotPaused {
        App storage a = apps[appId];
        if (a.appContract == address(0)) revert DeactivatedUnlockAppMissing(appId);
        if (a.active) revert AppNotDeactivated(appId);
        _unlock(appId, wallet, providerId, identityProperty);
    }

    /**
     * @notice Unbinds a Web2 identity from caller's wallet. Soft-delete: clears binding maps
     *         but does not delete attestation data (queries fail because resolution path is broken).
     *         After unbind, the nullifier is released and can be rebound to any wallet.
     * @dev CRITICAL: Unbind is blocked while any app holds locks on this provider binding.
     *      The effective lock count must be zero for unbind to succeed.
     * @param providerId Provider identifier
     * @param web2IdNullifier Provider-scoped nullifier to unbind
     */
    function unbindIdentity(bytes32 providerId, bytes32 web2IdNullifier) external whenNotPaused {
        // Verify caller owns this binding
        address bindingOwner = nullifierOwner[providerId][web2IdNullifier];
        if (bindingOwner != msg.sender) {
            revert CallerNotBindingOwner(msg.sender, providerId, web2IdNullifier);
        }

        // Check no apps hold locks on any tuple under this provider binding
        bytes32 walletProviderKey = _walletProviderKey(msg.sender, providerId);
        uint256 effectiveCount = effectiveProviderLockCountByWalletProvider[walletProviderKey];
        if (effectiveCount != 0) {
            revert UnbindBlockedByProviderLocks(walletProviderKey, effectiveCount);
        }

        // Clear binding maps (soft-delete: tuple data and nonce history are preserved)
        delete nullifierOwner[providerId][web2IdNullifier];
        delete activeNullifierByWalletProvider[msg.sender][providerId];

        emit IdentityUnbound(msg.sender, providerId, web2IdNullifier);
    }

    // =========================================================================
    // QUERY APIS
    // =========================================================================

    /**
     * @notice Returns full attestation metadata for wallet's current active binding
     * @dev Reverts if any precondition fails (provider not registered, property not recognized,
     *      no active binding, or no attestation for resolved tuple).
     * @param wallet User wallet
     * @param providerId Provider identifier
     * @param identityProperty Provider-scoped identity property
     * @return timestamp Latest attestation timestamp
     * @return dataBlob Latest opaque attestation payload
     */
    function getLatestIdentityProperty(
        address wallet,
        bytes32 providerId,
        bytes32 identityProperty
    ) external view returns (uint64 timestamp, bytes memory dataBlob) {
        LatestAttestation storage latest = _resolveLatest(wallet, providerId, identityProperty);
        return (latest.timestamp, latest.dataBlob);
    }

    /**
     * @notice Returns only the data blob for app-side business logic evaluation
     * @dev Same preconditions as getLatestIdentityProperty.
     * @param wallet User wallet
     * @param providerId Provider identifier
     * @param identityProperty Provider-scoped identity property
     * @return dataBlob Latest opaque attestation payload
     */
    function getLatestIdentityDataBlob(
        address wallet,
        bytes32 providerId,
        bytes32 identityProperty
    ) external view returns (bytes memory dataBlob) {
        LatestAttestation storage latest = _resolveLatest(wallet, providerId, identityProperty);
        return latest.dataBlob;
    }

    // =========================================================================
    // INTERNAL HELPERS
    // =========================================================================

    /**
     * @dev Resolves the latest attestation for a wallet/provider/property tuple.
     *      Deterministic check order: provider registered -> property recognized ->
     *      active binding exists -> attestation exists.
     */
    function _resolveLatest(
        address wallet,
        bytes32 providerId,
        bytes32 identityProperty
    ) internal view returns (LatestAttestation storage latest) {
        // 1. Provider must be registered
        if (bytes(providers[providerId].name).length == 0) revert ProviderNotRegistered(providerId);

        // 2. Property must have been recognized (at least one successful attestation)
        if (!recognizedProperty[providerId][identityProperty]) {
            revert PropertyNotRecognized(providerId, identityProperty);
        }

        // 3. Active binding must exist for (wallet, providerId)
        bytes32 resolvedNullifier = activeNullifierByWalletProvider[wallet][providerId];
        if (resolvedNullifier == bytes32(0)) revert ActiveBindingMissing(wallet, providerId);

        // 4. Attestation must exist for the resolved tuple
        bytes32 tupleKey = _tupleKey(wallet, providerId, resolvedNullifier, identityProperty);
        latest = latestAttestationByTuple[tupleKey];
        if (latest.timestamp == 0) revert LatestAttestationMissing(tupleKey);
    }

    /**
     * @dev Shared unlock logic for both normal and deactivated-app unlock paths.
     *      Enforces N-lock/N-unlock parity per app-tuple and manages provider-level
     *      effective lock count transitions.
     */
    function _unlock(
        bytes32 appId,
        address wallet,
        bytes32 providerId,
        bytes32 identityProperty
    ) internal {
        // Resolve active nullifier
        bytes32 resolvedNullifier = activeNullifierByWalletProvider[wallet][providerId];
        if (resolvedNullifier == bytes32(0)) revert ActiveBindingMissing(wallet, providerId);

        // Derive composite keys
        bytes32 tupleKey = _tupleKey(wallet, providerId, resolvedNullifier, identityProperty);
        bytes32 appTupleKey = _appTupleKey(appId, wallet, providerId, resolvedNullifier, identityProperty);
        bytes32 walletProviderKey = _walletProviderKey(wallet, providerId);

        // Require this app has at least one lock on this tuple
        uint256 appCount = appLockCountByAppTuple[appTupleKey];
        if (appCount == 0) revert AppTupleLockMissing(appTupleKey);

        // Decrement lock counters
        appLockCountByAppTuple[appTupleKey] = appCount - 1;
        uint256 tupleCount = lockCountByTuple[tupleKey];
        lockCountByTuple[tupleKey] = tupleCount - 1;

        // Provider effective count decreases only on tuple 1->0 transition (symmetric to 0->1 on lock).
        // This keeps the unbind gate accurate even when the same app locks a tuple multiple times.
        if (tupleCount == 1) {
            effectiveProviderLockCountByWalletProvider[walletProviderKey] -= 1;
        }

        emit IdentityPropertyUnlocked(appId, wallet, providerId, resolvedNullifier, identityProperty);
    }

    /**
     * @dev Canonical tuple identity key. Version tag is part of key material;
     *      changing it would be a storage-layout migration.
     */
    function _tupleKey(
        address wallet,
        bytes32 providerId,
        bytes32 web2IdNullifier,
        bytes32 identityProperty
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode("TUPLE_V1", wallet, providerId, web2IdNullifier, identityProperty));
    }

    /**
     * @dev Canonical app+tuple key for per-app lock parity tracking.
     */
    function _appTupleKey(
        bytes32 appId,
        address wallet,
        bytes32 providerId,
        bytes32 web2IdNullifier,
        bytes32 identityProperty
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode("APP_TUPLE_V1", appId, wallet, providerId, web2IdNullifier, identityProperty)
        );
    }

    /**
     * @dev Canonical wallet+provider key for the effective lock gate that controls unbind.
     */
    function _walletProviderKey(
        address wallet,
        bytes32 providerId
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode("WALLET_PROVIDER_V1", wallet, providerId));
    }
}
