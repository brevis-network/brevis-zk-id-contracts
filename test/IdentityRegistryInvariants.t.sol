// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IdentityRegistry} from "../src/IdentityRegistry.sol";
import {IIdentityRegistry} from "../src/IIdentityRegistry.sol";

contract MockPicoVerifier {
    bool public shouldRevert;

    function setShouldRevert(bool v) external {
        shouldRevert = v;
    }

    function verifyPicoProof(
        bytes32,
        bytes calldata,
        uint256[8] calldata
    ) external view {
        if (shouldRevert) revert("MOCK_PROOF_FAILED");
    }
}

contract RegistryCaller {
    function callTarget(
        address target,
        bytes calldata data
    ) external returns (bool ok, bytes memory returndata) {
        (ok, returndata) = target.call(data);
    }
}

contract IdentityRegistryInvariantTest {
    IdentityRegistry internal registry;
    MockPicoVerifier internal pico;
    RegistryCaller internal appCaller;
    RegistryCaller internal walletA;
    RegistryCaller internal walletB;

    bytes32 internal constant PROVIDER_ID = keccak256("provider");
    bytes32 internal constant APP_ID = keccak256("app");
    bytes32 internal constant PROPERTY_A = keccak256("property_a");
    bytes32 internal constant PROPERTY_B = keccak256("property_b");
    bytes32 internal constant NULLIFIER_A = keccak256("nullifier_a");
    bytes32 internal constant NULLIFIER_B = keccak256("nullifier_b");
    bytes32 internal constant VKEY = keccak256("test_vkey");

    function setUp() public {
        pico = new MockPicoVerifier();
        registry = new IdentityRegistry(address(pico));
        appCaller = new RegistryCaller();
        walletA = new RegistryCaller();
        walletB = new RegistryCaller();

        // Grant GOVERNANCE_ROLE to this test contract (owner) for provider/app lifecycle
        registry.grantRole(registry.GOVERNANCE_ROLE(), address(this));

        registry.registerProvider(PROVIDER_ID, "provider", bytes("meta"));
        registry.registerApp(APP_ID, "app", address(appCaller), bytes("meta"));

        _callFrom(
            walletA,
            abi.encodeCall(IdentityRegistry.approveApp, (APP_ID))
        );
    }

    function testBindingUniquenessRejectsSecondWalletSameNullifier() public {
        _submit(address(walletA), NULLIFIER_A, PROPERTY_A, 100, bytes("d1"));

        bytes memory pkg = _buildPublicValues(address(walletB), PROVIDER_ID, NULLIFIER_A, PROPERTY_A, 101, bytes("d2"));
        _assertSelectorRevert(
            _callAsSelf(abi.encodeCall(IdentityRegistry.submitIdentityAttestation, (pkg, ZERO_PROOF))),
            IIdentityRegistry.NullifierOwnershipMismatch.selector
        );
    }

    function testActiveNullifierConflictRejectsSecondNullifierForWalletProvider() public {
        _submit(address(walletA), NULLIFIER_A, PROPERTY_A, 100, bytes("d1"));

        bytes memory pkg = _buildPublicValues(address(walletA), PROVIDER_ID, NULLIFIER_B, PROPERTY_A, 101, bytes("d2"));
        _assertSelectorRevert(
            _callAsSelf(abi.encodeCall(IdentityRegistry.submitIdentityAttestation, (pkg, ZERO_PROOF))),
            IIdentityRegistry.ActiveNullifierConflict.selector
        );
    }

    function testReplayTimestampMonotonicity() public {
        _submit(address(walletA), NULLIFIER_A, PROPERTY_A, 100, bytes("d1"));
        _submit(address(walletA), NULLIFIER_A, PROPERTY_A, 101, bytes("d2"));

        bytes memory pkg = _buildPublicValues(address(walletA), PROVIDER_ID, NULLIFIER_A, PROPERTY_A, 101, bytes("d3"));
        _assertSelectorRevert(
            _callAsSelf(abi.encodeCall(IdentityRegistry.submitIdentityAttestation, (pkg, ZERO_PROOF))),
            IIdentityRegistry.TimestampNotIncreasing.selector
        );
    }

    function testPropertyRecognitionAndQueryGate() public {
        _submit(address(walletA), NULLIFIER_A, PROPERTY_A, 100, bytes("d1"));

        _assertSelectorRevert(
            _callAsSelf(
                abi.encodeCall(
                    IdentityRegistry.getLatestIdentityProperty,
                    (address(walletA), PROVIDER_ID, PROPERTY_B)
                )
            ),
            IIdentityRegistry.PropertyNotRecognized.selector
        );

        (uint64 ts, bytes memory blob) = registry.getLatestIdentityProperty(
            address(walletA),
            PROVIDER_ID,
            PROPERTY_A
        );
        require(ts == 100, "timestamp mismatch");
        require(keccak256(blob) == keccak256(bytes("d1")), "blob mismatch");
    }

    function testBlobQueryIsAppPrimaryReadPath() public {
        _submit(address(walletA), NULLIFIER_A, PROPERTY_A, 100, bytes("d1"));

        bytes memory blob = registry.getLatestIdentityDataBlob(
            address(walletA),
            PROVIDER_ID,
            PROPERTY_A
        );
        require(keccak256(blob) == keccak256(bytes("d1")), "blob mismatch");
    }

    function testQueryLatestPropertyRejectsMissingLatestAttestation() public {
        _submit(address(walletA), NULLIFIER_A, PROPERTY_A, 100, bytes("d1"));

        _callFrom(
            appCaller,
            abi.encodeCall(
                IdentityRegistry.lockIdentityProperty,
                (APP_ID, address(walletA), PROVIDER_ID, PROPERTY_A)
            )
        );
        _callFrom(
            appCaller,
            abi.encodeCall(
                IdentityRegistry.unlockIdentityProperty,
                (APP_ID, address(walletA), PROVIDER_ID, PROPERTY_A)
            )
        );
        (bool unbindOk, ) = walletA.callTarget(
            address(registry),
            abi.encodeCall(IdentityRegistry.unbindIdentity, (PROVIDER_ID, NULLIFIER_A))
        );
        require(unbindOk, "expected unbind");

        _submit(address(walletA), NULLIFIER_B, PROPERTY_B, 101, bytes("d2"));

        _assertSelectorRevert(
            _callAsSelf(
                abi.encodeCall(
                    IdentityRegistry.getLatestIdentityProperty,
                    (address(walletA), PROVIDER_ID, PROPERTY_A)
                )
            ),
            IIdentityRegistry.LatestAttestationMissing.selector
        );
    }

    function testQueryBlobRejectsMissingLatestAttestation() public {
        _submit(address(walletA), NULLIFIER_A, PROPERTY_A, 100, bytes("d1"));

        _callFrom(
            appCaller,
            abi.encodeCall(
                IdentityRegistry.lockIdentityProperty,
                (APP_ID, address(walletA), PROVIDER_ID, PROPERTY_A)
            )
        );
        _callFrom(
            appCaller,
            abi.encodeCall(
                IdentityRegistry.unlockIdentityProperty,
                (APP_ID, address(walletA), PROVIDER_ID, PROPERTY_A)
            )
        );
        (bool unbindOk, ) = walletA.callTarget(
            address(registry),
            abi.encodeCall(IdentityRegistry.unbindIdentity, (PROVIDER_ID, NULLIFIER_A))
        );
        require(unbindOk, "expected unbind");

        _submit(address(walletA), NULLIFIER_B, PROPERTY_B, 101, bytes("d2"));

        _assertSelectorRevert(
            _callAsSelf(
                abi.encodeCall(
                    IdentityRegistry.getLatestIdentityDataBlob,
                    (address(walletA), PROVIDER_ID, PROPERTY_A)
                )
            ),
            IIdentityRegistry.LatestAttestationMissing.selector
        );
    }

    function testLockRequiresExistingTupleForProperty() public {
        _submit(address(walletA), NULLIFIER_A, PROPERTY_A, 100, bytes("d1"));

        _assertSelectorRevert(
            _callFrom(
                appCaller,
                abi.encodeCall(
                    IdentityRegistry.lockIdentityProperty,
                    (APP_ID, address(walletA), PROVIDER_ID, PROPERTY_B)
                )
            ),
            IIdentityRegistry.LockTargetTupleMissing.selector
        );
    }

    function testDeactivatedUnlockRejectsMissingApp() public {
        _submit(address(walletA), NULLIFIER_A, PROPERTY_A, 100, bytes("d1"));

        _assertSelectorRevert(
            _callAsSelf(
                abi.encodeCall(
                    IdentityRegistry.unlockIdentityPropertyForDeactivatedApp,
                    (keccak256("missing_app"), address(walletA), PROVIDER_ID, PROPERTY_A)
                )
            ),
            IIdentityRegistry.DeactivatedUnlockAppMissing.selector
        );
    }

    function testUnlockForDeactivatedRejectsActiveApp() public {
        _submit(address(walletA), NULLIFIER_A, PROPERTY_A, 100, bytes("d1"));
        _assertSelectorRevert(
            _callAsSelf(
                abi.encodeCall(
                    IdentityRegistry.unlockIdentityPropertyForDeactivatedApp,
                    (APP_ID, address(walletA), PROVIDER_ID, PROPERTY_A)
                )
            ),
            IIdentityRegistry.AppNotDeactivated.selector
        );
    }

    function testLockRejectsMissingUserApproval() public {
        _submit(address(walletB), NULLIFIER_A, PROPERTY_A, 100, bytes("d1"));
        _assertSelectorRevert(
            _callFrom(
                appCaller,
                abi.encodeCall(
                    IdentityRegistry.lockIdentityProperty,
                    (APP_ID, address(walletB), PROVIDER_ID, PROPERTY_A)
                )
            ),
            IIdentityRegistry.AppApprovalMissing.selector
        );
    }

    function testLockRejectsMissingActiveBinding() public {
        _callFrom(walletB, abi.encodeCall(IdentityRegistry.approveApp, (APP_ID)));
        _assertSelectorRevert(
            _callFrom(
                appCaller,
                abi.encodeCall(
                    IdentityRegistry.lockIdentityProperty,
                    (APP_ID, address(walletB), PROVIDER_ID, PROPERTY_A)
                )
            ),
            IIdentityRegistry.ActiveBindingMissing.selector
        );
    }

    function testUnlockRejectsWithoutAppTupleLock() public {
        _submit(address(walletA), NULLIFIER_A, PROPERTY_A, 100, bytes("d1"));
        _assertSelectorRevert(
            _callFrom(
                appCaller,
                abi.encodeCall(
                    IdentityRegistry.unlockIdentityProperty,
                    (APP_ID, address(walletA), PROVIDER_ID, PROPERTY_A)
                )
            ),
            IIdentityRegistry.AppTupleLockMissing.selector
        );
    }

    function testLockParityAndUnbindGate() public {
        _submit(address(walletA), NULLIFIER_A, PROPERTY_A, 100, bytes("d1"));

        _callFrom(
            appCaller,
            abi.encodeCall(
                IdentityRegistry.lockIdentityProperty,
                (APP_ID, address(walletA), PROVIDER_ID, PROPERTY_A)
            )
        );
        _callFrom(
            appCaller,
            abi.encodeCall(
                IdentityRegistry.lockIdentityProperty,
                (APP_ID, address(walletA), PROVIDER_ID, PROPERTY_A)
            )
        );

        _callFrom(
            appCaller,
            abi.encodeCall(
                IdentityRegistry.unlockIdentityProperty,
                (APP_ID, address(walletA), PROVIDER_ID, PROPERTY_A)
            )
        );
        _assertSelectorRevert(
            _callFrom(
                walletA,
                abi.encodeCall(IdentityRegistry.unbindIdentity, (PROVIDER_ID, NULLIFIER_A))
            ),
            IIdentityRegistry.UnbindBlockedByProviderLocks.selector
        );

        _callFrom(
            appCaller,
            abi.encodeCall(
                IdentityRegistry.unlockIdentityProperty,
                (APP_ID, address(walletA), PROVIDER_ID, PROPERTY_A)
            )
        );
        (bool ok, ) = walletA.callTarget(
            address(registry),
            abi.encodeCall(IdentityRegistry.unbindIdentity, (PROVIDER_ID, NULLIFIER_A))
        );
        require(ok, "unbind should succeed after full unlock");
    }

    function testUnbindRejectsNonOwner() public {
        _submit(address(walletA), NULLIFIER_A, PROPERTY_A, 100, bytes("d1"));
        _assertSelectorRevert(
            _callFrom(
                walletB,
                abi.encodeCall(IdentityRegistry.unbindIdentity, (PROVIDER_ID, NULLIFIER_A))
            ),
            IIdentityRegistry.CallerNotBindingOwner.selector
        );
    }

    function testProofVerificationFailureReverts() public {
        registry.setVerifierKey(PROPERTY_A, VKEY);
        pico.setShouldRevert(true);
        bytes memory pkg = _buildPublicValues(address(walletA), PROVIDER_ID, NULLIFIER_A, PROPERTY_A, 100, bytes("d1"));
        // Pico verifier reverts directly; the registry does not wrap it.
        (bool ok, ) = abi.decode(
            _callAsSelf(abi.encodeCall(IdentityRegistry.submitIdentityAttestation, (pkg, ZERO_PROOF))),
            (bool, bytes)
        );
        require(!ok, "expected revert from pico verifier");
    }

    function testFuzz_LockUnlockParity(uint8 count) public {
        uint8 n = uint8((count % 8) + 1);
        _submit(address(walletA), NULLIFIER_A, PROPERTY_A, 100, bytes("d1"));

        for (uint8 i = 0; i < n; i++) {
            _callFrom(
                appCaller,
                abi.encodeCall(
                    IdentityRegistry.lockIdentityProperty,
                    (APP_ID, address(walletA), PROVIDER_ID, PROPERTY_A)
                )
            );
        }
        for (uint8 j = 0; j + 1 < n; j++) {
            _callFrom(
                appCaller,
                abi.encodeCall(
                    IdentityRegistry.unlockIdentityProperty,
                    (APP_ID, address(walletA), PROVIDER_ID, PROPERTY_A)
                )
            );
        }

        _assertSelectorRevert(
            _callFrom(
                walletA,
                abi.encodeCall(IdentityRegistry.unbindIdentity, (PROVIDER_ID, NULLIFIER_A))
            ),
            IIdentityRegistry.UnbindBlockedByProviderLocks.selector
        );

        _callFrom(
            appCaller,
            abi.encodeCall(
                IdentityRegistry.unlockIdentityProperty,
                (APP_ID, address(walletA), PROVIDER_ID, PROPERTY_A)
            )
        );
        (bool ok, ) = walletA.callTarget(
            address(registry),
            abi.encodeCall(IdentityRegistry.unbindIdentity, (PROVIDER_ID, NULLIFIER_A))
        );
        require(ok, "unbind should succeed");
    }

    function testFuzz_ReplayTimestampNotIncreasing(uint64 baseTs, bytes memory blob1, bytes memory blob2) public {
        if (baseTs == 0) baseTs = 1;
        if (blob1.length == 0) blob1 = bytes("a");
        if (blob2.length == 0) blob2 = bytes("b");

        _submit(address(walletA), NULLIFIER_A, PROPERTY_A, baseTs, blob1);
        bytes memory pkg = _buildPublicValues(address(walletA), PROVIDER_ID, NULLIFIER_A, PROPERTY_A, baseTs, blob2);
        _assertSelectorRevert(
            _callAsSelf(abi.encodeCall(IdentityRegistry.submitIdentityAttestation, (pkg, ZERO_PROOF))),
            IIdentityRegistry.TimestampNotIncreasing.selector
        );
    }

    function testFuzz_QueryOrderProviderFirst(bytes32 randomProvider, bytes32 property) public {
        if (randomProvider == bytes32(0) || randomProvider == PROVIDER_ID) {
            randomProvider = keccak256("random_provider");
        }
        _assertSelectorRevert(
            _callAsSelf(
                abi.encodeCall(
                    IdentityRegistry.getLatestIdentityDataBlob,
                    (address(walletA), randomProvider, property)
                )
            ),
            IIdentityRegistry.ProviderNotRegistered.selector
        );
    }

    // =========================================================================
    // Unlock does not require approval
    // =========================================================================

    function testUnlockSucceedsAfterApprovalRevoked() public {
        _submit(address(walletA), NULLIFIER_A, PROPERTY_A, 100, bytes("d1"));

        // Lock while approved
        _callFrom(
            appCaller,
            abi.encodeCall(
                IdentityRegistry.lockIdentityProperty,
                (APP_ID, address(walletA), PROVIDER_ID, PROPERTY_A)
            )
        );

        // User revokes approval
        _callFrom(walletA, abi.encodeCall(IdentityRegistry.revokeApp, (APP_ID)));
        require(!registry.appApproval(address(walletA), APP_ID), "approval should be revoked");

        // App can still unlock after approval revoked
        (bool ok, ) = appCaller.callTarget(
            address(registry),
            abi.encodeCall(
                IdentityRegistry.unlockIdentityProperty,
                (APP_ID, address(walletA), PROVIDER_ID, PROPERTY_A)
            )
        );
        require(ok, "unlock should succeed without approval");

        // User can now unbind
        (bool unbindOk, ) = walletA.callTarget(
            address(registry),
            abi.encodeCall(IdentityRegistry.unbindIdentity, (PROVIDER_ID, NULLIFIER_A))
        );
        require(unbindOk, "unbind should succeed after unlock");
    }

    // =========================================================================
    // T-06: Deactivated app unlock success path
    // =========================================================================

    function testDeactivatedAppUnlockSuccessAndUnbind() public {
        _submit(address(walletA), NULLIFIER_A, PROPERTY_A, 100, bytes("d1"));

        // Lock
        _callFrom(
            appCaller,
            abi.encodeCall(
                IdentityRegistry.lockIdentityProperty,
                (APP_ID, address(walletA), PROVIDER_ID, PROPERTY_A)
            )
        );

        // Governance deactivates app
        registry.deactivateApp(APP_ID);

        // Anyone (walletB) can unlock deactivated app's locks
        (bool ok, ) = walletB.callTarget(
            address(registry),
            abi.encodeCall(
                IdentityRegistry.unlockIdentityPropertyForDeactivatedApp,
                (APP_ID, address(walletA), PROVIDER_ID, PROPERTY_A)
            )
        );
        require(ok, "deactivated app unlock should succeed");

        // User can now unbind
        (bool unbindOk, ) = walletA.callTarget(
            address(registry),
            abi.encodeCall(IdentityRegistry.unbindIdentity, (PROVIDER_ID, NULLIFIER_A))
        );
        require(unbindOk, "unbind should succeed after deactivated unlock");
    }

    // =========================================================================
    // Attestation happy path — verify stored state
    // =========================================================================

    function testAttestationStoresStateCorrectly() public {
        _submit(address(walletA), NULLIFIER_A, PROPERTY_A, 100, bytes("hello"));

        // Verify binding state
        require(
            registry.nullifierOwner(PROVIDER_ID, NULLIFIER_A) == address(walletA),
            "nullifier owner should be walletA"
        );
        require(
            registry.activeNullifierByWalletProvider(address(walletA), PROVIDER_ID) == NULLIFIER_A,
            "active nullifier should be set"
        );
        require(registry.recognizedProperty(PROVIDER_ID, PROPERTY_A), "property should be recognized");

        // Verify query returns correct data
        (uint64 ts, bytes memory blob) = registry.getLatestIdentityProperty(
            address(walletA), PROVIDER_ID, PROPERTY_A
        );
        require(ts == 100, "timestamp mismatch");
        require(keccak256(blob) == keccak256(bytes("hello")), "blob mismatch");
    }

    // =========================================================================
    // Attestation update — second overwrites first
    // =========================================================================

    function testSecondAttestationOverwritesFirst() public {
        _submit(address(walletA), NULLIFIER_A, PROPERTY_A, 100, bytes("first"));
        _submit(address(walletA), NULLIFIER_A, PROPERTY_A, 200, bytes("second"));

        (uint64 ts, bytes memory blob) = registry.getLatestIdentityProperty(
            address(walletA), PROVIDER_ID, PROPERTY_A
        );
        require(ts == 200, "timestamp should be updated");
        require(keccak256(blob) == keccak256(bytes("second")), "blob should be overwritten");
    }

    // =========================================================================
    // Invalid timestamp rejection
    // =========================================================================

    function testAttestationRejectsZeroTimestamp() public {
        registry.setVerifierKey(PROPERTY_A, VKEY);
        bytes memory pv = _buildPublicValues(address(walletA), PROVIDER_ID, NULLIFIER_A, PROPERTY_A, 0, bytes("d1"));
        _assertSelectorRevert(
            _callAsSelf(abi.encodeCall(IdentityRegistry.submitIdentityAttestation, (pv, ZERO_PROOF))),
            IIdentityRegistry.InvalidTimestamp.selector
        );
    }

    // =========================================================================
    // Empty provider name rejection
    // =========================================================================

    function testRegisterProviderRejectsEmptyName() public {
        _assertSelectorRevert(
            _callAsSelf(
                abi.encodeCall(IdentityRegistry.registerProvider, (keccak256("new"), "", bytes("m")))
            ),
            IIdentityRegistry.InvalidProviderName.selector
        );
    }

    function testUpdateProviderRejectsEmptyName() public {
        _assertSelectorRevert(
            _callAsSelf(
                abi.encodeCall(IdentityRegistry.updateProvider, (PROVIDER_ID, "", bytes("m")))
            ),
            IIdentityRegistry.InvalidProviderName.selector
        );
    }

    // =========================================================================
    // Multiple providers per wallet
    // =========================================================================

    function testWalletCanBindMultipleProviders() public {
        bytes32 PROVIDER_B = keccak256("provider_b");
        registry.registerProvider(PROVIDER_B, "ProviderB", bytes("meta"));
        registry.setVerifierKey(PROPERTY_A, VKEY);

        // Bind walletA to PROVIDER_ID
        _submit(address(walletA), NULLIFIER_A, PROPERTY_A, 100, bytes("d1"));

        // Bind same walletA to PROVIDER_B with a different nullifier
        bytes memory pv = _buildPublicValues(address(walletA), PROVIDER_B, NULLIFIER_B, PROPERTY_A, 100, bytes("d2"));
        registry.submitIdentityAttestation(pv, ZERO_PROOF);

        // Both should be queryable
        (, bytes memory blob1) = registry.getLatestIdentityProperty(address(walletA), PROVIDER_ID, PROPERTY_A);
        (, bytes memory blob2) = registry.getLatestIdentityProperty(address(walletA), PROVIDER_B, PROPERTY_A);
        require(keccak256(blob1) == keccak256(bytes("d1")), "provider A blob mismatch");
        require(keccak256(blob2) == keccak256(bytes("d2")), "provider B blob mismatch");
    }

    // =========================================================================
    // Multiple apps locking the same tuple
    // =========================================================================

    function testMultipleAppsCanLockSameTuple() public {
        _submit(address(walletA), NULLIFIER_A, PROPERTY_A, 100, bytes("d1"));

        // Register a second app
        bytes32 APP_B = keccak256("app_b");
        RegistryCaller appCallerB = new RegistryCaller();
        registry.registerApp(APP_B, "appB", address(appCallerB), bytes("meta"));
        _callFrom(walletA, abi.encodeCall(IdentityRegistry.approveApp, (APP_B)));

        // Both apps lock the same property
        _callFrom(appCaller, abi.encodeCall(
            IdentityRegistry.lockIdentityProperty, (APP_ID, address(walletA), PROVIDER_ID, PROPERTY_A)
        ));
        _callFrom(appCallerB, abi.encodeCall(
            IdentityRegistry.lockIdentityProperty, (APP_B, address(walletA), PROVIDER_ID, PROPERTY_A)
        ));

        // Unbind should be blocked
        _assertSelectorRevert(
            _callFrom(walletA, abi.encodeCall(IdentityRegistry.unbindIdentity, (PROVIDER_ID, NULLIFIER_A))),
            IIdentityRegistry.UnbindBlockedByProviderLocks.selector
        );

        // Unlock app A — still blocked (app B still has lock)
        _callFrom(appCaller, abi.encodeCall(
            IdentityRegistry.unlockIdentityProperty, (APP_ID, address(walletA), PROVIDER_ID, PROPERTY_A)
        ));
        _assertSelectorRevert(
            _callFrom(walletA, abi.encodeCall(IdentityRegistry.unbindIdentity, (PROVIDER_ID, NULLIFIER_A))),
            IIdentityRegistry.UnbindBlockedByProviderLocks.selector
        );

        // Unlock app B — now unbind succeeds
        _callFrom(appCallerB, abi.encodeCall(
            IdentityRegistry.unlockIdentityProperty, (APP_B, address(walletA), PROVIDER_ID, PROPERTY_A)
        ));
        (bool ok, ) = walletA.callTarget(
            address(registry),
            abi.encodeCall(IdentityRegistry.unbindIdentity, (PROVIDER_ID, NULLIFIER_A))
        );
        require(ok, "unbind should succeed after all apps unlock");
    }

    // =========================================================================
    // Unbind happy path — releases nullifier for rebinding
    // =========================================================================

    function testUnbindReleasesNullifierForRebinding() public {
        _submit(address(walletA), NULLIFIER_A, PROPERTY_A, 100, bytes("d1"));

        // Unbind
        (bool unbindOk, ) = walletA.callTarget(
            address(registry),
            abi.encodeCall(IdentityRegistry.unbindIdentity, (PROVIDER_ID, NULLIFIER_A))
        );
        require(unbindOk, "unbind should succeed");

        // Query should fail
        _assertSelectorRevert(
            _callAsSelf(abi.encodeCall(
                IdentityRegistry.getLatestIdentityProperty, (address(walletA), PROVIDER_ID, PROPERTY_A)
            )),
            IIdentityRegistry.ActiveBindingMissing.selector
        );

        // Different wallet can now claim the same nullifier
        bytes memory pv = _buildPublicValues(address(walletB), PROVIDER_ID, NULLIFIER_A, PROPERTY_A, 200, bytes("d2"));
        registry.submitIdentityAttestation(pv, ZERO_PROOF);

        (, bytes memory blob) = registry.getLatestIdentityProperty(address(walletB), PROVIDER_ID, PROPERTY_A);
        require(keccak256(blob) == keccak256(bytes("d2")), "walletB should own the nullifier now");
    }

    // =========================================================================
    // Deactivate app then approve fails
    // =========================================================================

    function testDeactivatedAppCannotBeApproved() public {
        registry.deactivateApp(APP_ID);
        _assertSelectorRevert(
            _callFrom(walletA, abi.encodeCall(IdentityRegistry.approveApp, (APP_ID))),
            IIdentityRegistry.AppNotActive.selector
        );
    }

    // =========================================================================
    // Submit rejects unregistered provider
    // =========================================================================

    function testSubmitRejectsUnregisteredProvider() public {
        bytes32 unknownProvider = keccak256("unknown_provider");
        registry.setVerifierKey(PROPERTY_A, VKEY);
        bytes memory pv = _buildPublicValues(address(walletA), unknownProvider, NULLIFIER_A, PROPERTY_A, 100, bytes("d1"));
        _assertSelectorRevert(
            _callAsSelf(abi.encodeCall(IdentityRegistry.submitIdentityAttestation, (pv, ZERO_PROOF))),
            IIdentityRegistry.ProviderNotRegistered.selector
        );
    }

    // =========================================================================
    // App registration validation
    // =========================================================================

    function testRegisterAppRejectsEmptyName() public {
        _assertSelectorRevert(
            _callAsSelf(
                abi.encodeCall(IdentityRegistry.registerApp, (keccak256("app2"), "", address(0x1234), bytes("m")))
            ),
            IIdentityRegistry.InvalidAppName.selector
        );
    }

    function testRegisterAppRejectsZeroAppId() public {
        _assertSelectorRevert(
            _callAsSelf(
                abi.encodeCall(IdentityRegistry.registerApp, (bytes32(0), "app", address(0x1234), bytes("m")))
            ),
            IIdentityRegistry.InvalidAppId.selector
        );
    }

    // =========================================================================
    // T-07: updateApp contract change while locks exist
    // =========================================================================

    function testUpdateAppContractWhileLocksExist() public {
        _submit(address(walletA), NULLIFIER_A, PROPERTY_A, 100, bytes("d1"));

        // Lock via original appCaller
        _callFrom(
            appCaller,
            abi.encodeCall(IdentityRegistry.lockIdentityProperty, (APP_ID, address(walletA), PROVIDER_ID, PROPERTY_A))
        );

        // Governance updates appContract to a new caller
        RegistryCaller newAppCaller = new RegistryCaller();
        registry.updateApp(APP_ID, "app", address(newAppCaller), bytes("meta"), true);

        // Old caller can no longer unlock
        (bool oldOk, ) = appCaller.callTarget(
            address(registry),
            abi.encodeCall(IdentityRegistry.unlockIdentityProperty, (APP_ID, address(walletA), PROVIDER_ID, PROPERTY_A))
        );
        require(!oldOk, "old contract should not be able to unlock after appContract update");

        // New caller inherits unlock authority over existing lock
        (bool newOk, ) = newAppCaller.callTarget(
            address(registry),
            abi.encodeCall(IdentityRegistry.unlockIdentityProperty, (APP_ID, address(walletA), PROVIDER_ID, PROPERTY_A))
        );
        require(newOk, "new contract should inherit unlock authority");
    }

    // =========================================================================
    // T-08: deactivate, reactivate, unlock old locks through reactivated contract
    // =========================================================================

    function testDeactivateReactivateUnlockOldLocks() public {
        _submit(address(walletA), NULLIFIER_A, PROPERTY_A, 100, bytes("d1"));

        // Lock via appCaller
        _callFrom(
            appCaller,
            abi.encodeCall(IdentityRegistry.lockIdentityProperty, (APP_ID, address(walletA), PROVIDER_ID, PROPERTY_A))
        );

        // Governance deactivates app — lock still exists
        registry.deactivateApp(APP_ID);

        // appCaller can no longer unlock (app is inactive)
        (bool deactivatedOk, ) = appCaller.callTarget(
            address(registry),
            abi.encodeCall(IdentityRegistry.unlockIdentityProperty, (APP_ID, address(walletA), PROVIDER_ID, PROPERTY_A))
        );
        require(!deactivatedOk, "deactivated app contract should not be able to unlock via normal path");

        // Governance reactivates the app
        registry.updateApp(APP_ID, "app", address(appCaller), bytes("meta"), true);

        // appCaller can now unlock again through the normal path
        (bool reactivatedOk, ) = appCaller.callTarget(
            address(registry),
            abi.encodeCall(IdentityRegistry.unlockIdentityProperty, (APP_ID, address(walletA), PROVIDER_ID, PROPERTY_A))
        );
        require(reactivatedOk, "reactivated app contract should be able to unlock");
    }

    // =========================================================================
    // T-09: Same-wallet rebind after unbind — tuple timestamp must still increase
    // =========================================================================

    function testRebindSameWalletTimestampMustIncrease() public {
        _submit(address(walletA), NULLIFIER_A, PROPERTY_A, 100, bytes("d1"));

        // Unbind
        walletA.callTarget(
            address(registry),
            abi.encodeCall(IdentityRegistry.unbindIdentity, (PROVIDER_ID, NULLIFIER_A))
        );

        // Rebind same wallet+nullifier with a higher timestamp — should succeed
        _submit(address(walletA), NULLIFIER_A, PROPERTY_A, 101, bytes("d2"));
        (, bytes memory blob) = registry.getLatestIdentityProperty(address(walletA), PROVIDER_ID, PROPERTY_A);
        require(keccak256(blob) == keccak256(bytes("d2")), "rebind attestation should be stored");

        // Rebind again with a non-increasing timestamp — should fail
        bytes memory pv = _buildPublicValues(address(walletA), PROVIDER_ID, NULLIFIER_A, PROPERTY_A, 101, bytes("d3"));
        _assertSelectorRevert(
            _callAsSelf(abi.encodeCall(IdentityRegistry.submitIdentityAttestation, (pv, ZERO_PROOF))),
            IIdentityRegistry.TimestampNotIncreasing.selector
        );
    }

    // =========================================================================
    // T-10: Re-attestation while locked does not revert
    // =========================================================================

    function testReattestationWhileLockedSucceeds() public {
        _submit(address(walletA), NULLIFIER_A, PROPERTY_A, 100, bytes("d1"));

        // Lock
        _callFrom(
            appCaller,
            abi.encodeCall(IdentityRegistry.lockIdentityProperty, (APP_ID, address(walletA), PROVIDER_ID, PROPERTY_A))
        );

        // Re-attest with a higher timestamp — should succeed despite active lock
        _submit(address(walletA), NULLIFIER_A, PROPERTY_A, 200, bytes("d2"));
        (uint64 ts, ) = registry.getLatestIdentityProperty(address(walletA), PROVIDER_ID, PROPERTY_A);
        require(ts == 200, "re-attestation while locked should update the stored timestamp");

        // Unbind is still blocked
        (bool unbindOk, ) = walletA.callTarget(
            address(registry),
            abi.encodeCall(IdentityRegistry.unbindIdentity, (PROVIDER_ID, NULLIFIER_A))
        );
        require(!unbindOk, "unbind should still be blocked while lock is held");
    }

    // =========================================================================
    // T-11: Verifier key removal — existing query succeeds, new attestation fails
    // =========================================================================

    function testVerifierKeyRemovalBlocksNewAttestationButNotQuery() public {
        _submit(address(walletA), NULLIFIER_A, PROPERTY_A, 100, bytes("d1"));

        // Remove the verifier key for PROPERTY_A
        registry.removeVerifierKey(PROPERTY_A);

        // Existing stored attestation is still queryable
        (, bytes memory blob) = registry.getLatestIdentityProperty(address(walletA), PROVIDER_ID, PROPERTY_A);
        require(keccak256(blob) == keccak256(bytes("d1")), "existing attestation should still be queryable after key removal");

        // New attestation for the same property is rejected
        bytes memory pv = _buildPublicValues(address(walletA), PROVIDER_ID, NULLIFIER_A, PROPERTY_A, 200, bytes("d2"));
        _assertSelectorRevert(
            _callAsSelf(abi.encodeCall(IdentityRegistry.submitIdentityAttestation, (pv, ZERO_PROOF))),
            IIdentityRegistry.VerifierKeyMissing.selector
        );
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    uint256[8] internal ZERO_PROOF = [uint256(0), 0, 0, 0, 0, 0, 0, 0];

    function _submit(
        address wallet,
        bytes32 nullifier,
        bytes32 property,
        uint64 ts,
        bytes memory blob
    ) internal {
        // Set verification key for property if not already set.
        if (registry.riscvVkeyByIdentityProperty(property) == bytes32(0)) {
            registry.setVerifierKey(property, VKEY);
        }
        bytes memory publicValues = _buildPublicValues(wallet, PROVIDER_ID, nullifier, property, ts, blob);
        registry.submitIdentityAttestation(publicValues, ZERO_PROOF);
    }

    function _buildPublicValues(
        address wallet,
        bytes32 providerId,
        bytes32 nullifier,
        bytes32 property,
        uint64 ts,
        bytes memory blob
    ) internal pure returns (bytes memory) {
        return abi.encode(IIdentityRegistry.AttestationPublicInputs({
            wallet: wallet,
            providerId: providerId,
            web2IdNullifier: nullifier,
            identityProperty: property,
            timestamp: ts,
            dataBlob: blob
        }));
    }

    function _callAsSelf(bytes memory callData) internal returns (bytes memory) {
        (bool ok, bytes memory returndata) = address(registry).call(callData);
        return abi.encode(ok, returndata);
    }

    function _callFrom(RegistryCaller caller, bytes memory callData) internal returns (bytes memory) {
        (bool ok, bytes memory returndata) = caller.callTarget(address(registry), callData);
        return abi.encode(ok, returndata);
    }

    function _assertSelectorRevert(bytes memory packed, bytes4 selector) internal pure {
        (bool ok, bytes memory returndata) = abi.decode(packed, (bool, bytes));
        require(!ok, "expected revert");
        _assertSelector(returndata, selector);
    }

    function _assertSelector(bytes memory returndata, bytes4 selector) internal pure {
        require(returndata.length >= 4, "missing selector");
        bytes4 actual;
        assembly ("memory-safe") {
            actual := mload(add(returndata, 0x20))
        }
        require(actual == selector, "wrong selector");
    }
}
