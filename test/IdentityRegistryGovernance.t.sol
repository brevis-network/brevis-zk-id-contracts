// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IdentityRegistry} from "../src/IdentityRegistry.sol";
import {IIdentityRegistry} from "../src/IIdentityRegistry.sol";
import {IAccessControl} from "@security/access/interfaces/IAccessControl.sol";
import {IPauserControl} from "@security/access/interfaces/IPauserControl.sol";
import {IOwnable} from "@security/access/interfaces/IOwnable.sol";

interface Vm {
    function addr(uint256 privateKey) external returns (address);
    function sign(
        uint256 privateKey,
        bytes32 digest
    ) external returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 newTimestamp) external;
}

contract NonGovernanceCaller {
    function callTarget(
        address target,
        bytes calldata data
    ) external returns (bool ok, bytes memory returndata) {
        (ok, returndata) = target.call(data);
    }
}

contract MockPicoVerifierGov {
    function verifyPicoProof(bytes32, bytes calldata, uint256[8] calldata) external pure {}
}

contract IdentityRegistryGovernanceTest {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    IdentityRegistry internal registry;
    NonGovernanceCaller internal nonGov;
    MockPicoVerifierGov internal pico;

    bytes32 internal constant PROVIDER_ID = keccak256("provider");
    bytes32 internal constant APP_ID = keccak256("app");
    uint256 internal constant WALLET_A_PK = 0xA11CE;
    uint256 internal constant WALLET_B_PK = 0xB0B;

    function setUp() public {
        pico = new MockPicoVerifierGov();
        registry = new IdentityRegistry(address(pico));
        nonGov = new NonGovernanceCaller();

        // Grant GOVERNANCE_ROLE and PAUSER_ROLE to this test contract (owner)
        registry.grantRole(registry.GOVERNANCE_ROLE(), address(this));
        registry.grantRole(registry.PAUSER_ROLE(), address(this));
    }

    // =========================================================================
    // Pause tests
    // =========================================================================

    function testPauseBlocksStateMutationPaths() public {
        registry.pause();

        // Paused error comes from OZ Pausable
        _assertSelectorRevert(
            _callAsSelf(
                abi.encodeCall(
                    IdentityRegistry.registerProvider,
                    (PROVIDER_ID, "p", bytes("m"))
                )
            ),
            bytes4(keccak256("EnforcedPause()"))
        );
        _assertSelectorRevert(
            _callAsSelf(
                abi.encodeCall(
                    IdentityRegistry.registerApp,
                    (APP_ID, "a", address(0x1234), bytes("m"))
                )
            ),
            bytes4(keccak256("EnforcedPause()"))
        );
        uint256[8] memory zeroProof;
        _assertSelectorRevert(
            _callAsSelf(
                abi.encodeCall(IdentityRegistry.submitIdentityAttestation, (bytes("x"), zeroProof))
            ),
            bytes4(keccak256("EnforcedPause()"))
        );
    }

    // =========================================================================
    // Approval tests
    // =========================================================================

    function testApproveRejectsMissingOrInactiveApp() public {
        _assertSelectorRevert(
            _callAsSelf(abi.encodeCall(IdentityRegistry.approveApp, (APP_ID))),
            IIdentityRegistry.AppNotActive.selector
        );

        registry.registerApp(APP_ID, "a", address(0x1234), bytes("m"));
        registry.deactivateApp(APP_ID);
        _assertSelectorRevert(
            _callAsSelf(abi.encodeCall(IdentityRegistry.approveApp, (APP_ID))),
            IIdentityRegistry.AppNotActive.selector
        );
    }

    function testApproveWithSigSucceeds() public {
        registry.registerApp(APP_ID, "a", address(0x1234), bytes("m"));
        address wallet = vm.addr(WALLET_A_PK);
        uint256 deadline = block.timestamp + 1 days;
        uint256 nonce = registry.approvalNonceByWallet(wallet);
        bytes memory signature = _signApproval(WALLET_A_PK, wallet, APP_ID, deadline, nonce);

        (bool ok, ) = address(registry).call(
            abi.encodeCall(
                IdentityRegistry.approveAppWithSig,
                (wallet, APP_ID, deadline, nonce, signature)
            )
        );
        require(ok, "approve with sig should succeed");
        require(registry.appApproval(wallet, APP_ID), "approval not set");
        require(registry.approvalNonceByWallet(wallet) == nonce + 1, "nonce not consumed");
    }

    function testApproveWithSigRejectsExpiredSignature() public {
        registry.registerApp(APP_ID, "a", address(0x1234), bytes("m"));
        address wallet = vm.addr(WALLET_A_PK);
        uint256 deadline = block.timestamp + 1;
        uint256 nonce = registry.approvalNonceByWallet(wallet);
        bytes memory signature = _signApproval(WALLET_A_PK, wallet, APP_ID, deadline, nonce);
        vm.warp(deadline + 1);

        _assertSelectorRevert(
            _callAsSelf(
                abi.encodeCall(
                    IdentityRegistry.approveAppWithSig,
                    (wallet, APP_ID, deadline, nonce, signature)
                )
            ),
            IIdentityRegistry.ApprovalSignatureExpired.selector
        );
    }

    function testApproveWithSigRejectsNonceMismatchAndReplay() public {
        registry.registerApp(APP_ID, "a", address(0x1234), bytes("m"));
        address wallet = vm.addr(WALLET_A_PK);
        uint256 deadline = block.timestamp + 1 days;

        _assertSelectorRevert(
            _callAsSelf(
                abi.encodeCall(
                    IdentityRegistry.approveAppWithSig,
                    (wallet, APP_ID, deadline, 7, _signApproval(WALLET_A_PK, wallet, APP_ID, deadline, 7))
                )
            ),
            IIdentityRegistry.ApprovalNonceMismatch.selector
        );

        uint256 nonce = registry.approvalNonceByWallet(wallet);
        bytes memory signature = _signApproval(WALLET_A_PK, wallet, APP_ID, deadline, nonce);
        (bool ok, ) = address(registry).call(
            abi.encodeCall(
                IdentityRegistry.approveAppWithSig,
                (wallet, APP_ID, deadline, nonce, signature)
            )
        );
        require(ok, "first delegated approval should succeed");

        _assertSelectorRevert(
            _callAsSelf(
                abi.encodeCall(
                    IdentityRegistry.approveAppWithSig,
                    (wallet, APP_ID, deadline, nonce, signature)
                )
            ),
            IIdentityRegistry.ApprovalNonceMismatch.selector
        );
    }

    function testApproveWithSigRejectsInvalidSigner() public {
        registry.registerApp(APP_ID, "a", address(0x1234), bytes("m"));
        address wallet = vm.addr(WALLET_A_PK);
        uint256 deadline = block.timestamp + 1 days;
        uint256 nonce = registry.approvalNonceByWallet(wallet);
        bytes memory signature = _signApproval(WALLET_B_PK, wallet, APP_ID, deadline, nonce);

        _assertSelectorRevert(
            _callAsSelf(
                abi.encodeCall(
                    IdentityRegistry.approveAppWithSig,
                    (wallet, APP_ID, deadline, nonce, signature)
                )
            ),
            IIdentityRegistry.InvalidApprovalSignature.selector
        );
    }

    function testApproveWithSigFailureOrder_ExpiredBeforeNonceAndSignature() public {
        registry.registerApp(APP_ID, "a", address(0x1234), bytes("m"));
        address wallet = vm.addr(WALLET_A_PK);
        uint256 deadline = block.timestamp + 1;
        bytes memory signature = _signApproval(WALLET_B_PK, wallet, APP_ID, deadline, 7);
        vm.warp(deadline + 1);

        _assertSelectorRevert(
            _callAsSelf(
                abi.encodeCall(
                    IdentityRegistry.approveAppWithSig,
                    (wallet, APP_ID, deadline, 7, signature)
                )
            ),
            IIdentityRegistry.ApprovalSignatureExpired.selector
        );
    }

    // =========================================================================
    // Revoke tests
    // =========================================================================

    function testRevokeAllowsInactiveButExistingApp() public {
        registry.registerApp(APP_ID, "a", address(0x1234), bytes("m"));
        (bool okApprove, ) = address(registry).call(
            abi.encodeCall(IdentityRegistry.approveApp, (APP_ID))
        );
        require(okApprove, "approve should succeed");

        registry.deactivateApp(APP_ID);

        (bool okRevoke, ) = address(registry).call(
            abi.encodeCall(IdentityRegistry.revokeApp, (APP_ID))
        );
        require(okRevoke, "revoke should succeed for existing inactive app");
        require(!registry.appApproval(address(this), APP_ID), "approval should be false");
    }

    function testRevokeRejectsMissingApp() public {
        _assertSelectorRevert(
            _callAsSelf(abi.encodeCall(IdentityRegistry.revokeApp, (keccak256("missing_app")))),
            IIdentityRegistry.EntityNotFound.selector
        );
    }

    // =========================================================================
    // Constructor tests
    // =========================================================================

    function testConstructorWithZeroIsProxyPath() public {
        // address(0) is the proxy deployment path — should not revert
        IdentityRegistry impl = new IdentityRegistry(address(0));
        // Implementation has no owner set (Ownable constructor ran but init was skipped)
        // picoVerifier should be address(0) since _init was not called
        require(impl.picoVerifier() == address(0), "picoVerifier should be zero for proxy impl");
    }

    function testInitRejectsZeroPicoVerifier() public {
        IdentityRegistry impl = new IdentityRegistry(address(0));
        (bool ok, bytes memory returndata) = address(impl).call(
            abi.encodeWithSignature("init(address)", address(0))
        );
        require(!ok, "init with zero must fail");
        _assertSelector(returndata, IIdentityRegistry.InvalidPicoVerifierAddress.selector);
    }

    function testInitRevertsOnDirectDeployment() public {
        // On direct deployment, Ownable constructor already set owner,
        // so init() → initOwner() reverts (owner already set).
        IdentityRegistry impl = new IdentityRegistry(address(0));
        (bool ok, ) = address(impl).call(
            abi.encodeWithSignature("init(address)", address(pico))
        );
        require(!ok, "init should fail on direct deployment (owner already set)");
    }

    // =========================================================================
    // Access control: GOVERNANCE_ROLE required for provider/app lifecycle
    // =========================================================================

    function testGovernanceRoleRequired() public {
        // nonGov has no GOVERNANCE_ROLE
        _assertSelectorRevert(
            _callAsNonGov(
                abi.encodeCall(
                    IdentityRegistry.registerProvider,
                    (PROVIDER_ID, "p", bytes("m"))
                )
            ),
            IAccessControl.AccessControlUnauthorizedRole.selector
        );
        _assertSelectorRevert(
            _callAsNonGov(
                abi.encodeCall(
                    IdentityRegistry.updateProvider,
                    (PROVIDER_ID, "p2", bytes("m2"))
                )
            ),
            IAccessControl.AccessControlUnauthorizedRole.selector
        );
        _assertSelectorRevert(
            _callAsNonGov(
                abi.encodeCall(
                    IdentityRegistry.registerApp,
                    (APP_ID, "a", address(0x1234), bytes("m"))
                )
            ),
            IAccessControl.AccessControlUnauthorizedRole.selector
        );
        _assertSelectorRevert(
            _callAsNonGov(
                abi.encodeCall(
                    IdentityRegistry.updateApp,
                    (APP_ID, "a2", address(0x5678), bytes("m2"), true)
                )
            ),
            IAccessControl.AccessControlUnauthorizedRole.selector
        );
        _assertSelectorRevert(
            _callAsNonGov(
                abi.encodeCall(IdentityRegistry.deactivateApp, (APP_ID))
            ),
            IAccessControl.AccessControlUnauthorizedRole.selector
        );
    }

    // =========================================================================
    // Access control: onlyOwner for core security functions
    // =========================================================================

    function testOwnerOnlyForCoreSecurityFunctions() public {
        _assertSelectorRevert(
            _callAsNonGov(
                abi.encodeCall(IdentityRegistry.setPicoVerifier, (address(0x8888)))
            ),
            IOwnable.OwnerUnauthorized.selector
        );
        _assertSelectorRevert(
            _callAsNonGov(
                abi.encodeCall(IdentityRegistry.setVerifierKey, (bytes32("k"), bytes32("v")))
            ),
            IOwnable.OwnerUnauthorized.selector
        );
        _assertSelectorRevert(
            _callAsNonGov(
                abi.encodeCall(IdentityRegistry.removeVerifierKey, (bytes32("k")))
            ),
            IOwnable.OwnerUnauthorized.selector
        );
    }

    // =========================================================================
    // Access control: pause requires PAUSER_ROLE
    // =========================================================================

    function testPauseRequiresPauserRole() public {
        _assertSelectorRevert(
            _callAsNonGov(abi.encodeWithSignature("pause()")),
            IPauserControl.PauserUnauthorized.selector
        );
        _assertSelectorRevert(
            _callAsNonGov(abi.encodeWithSignature("unpause()")),
            IPauserControl.PauserUnauthorized.selector
        );
    }

    // =========================================================================
    // Entity lifecycle validation
    // =========================================================================

    function testRegisterAppRejectsZeroContractAddress() public {
        _assertSelectorRevert(
            _callAsSelf(
                abi.encodeCall(
                    IdentityRegistry.registerApp,
                    (APP_ID, "a", address(0), bytes("m"))
                )
            ),
            IIdentityRegistry.InvalidAppContract.selector
        );
    }

    function testUpdateAppRejectsZeroContractAddress() public {
        registry.registerApp(APP_ID, "a", address(0x1234), bytes("m"));
        _assertSelectorRevert(
            _callAsSelf(
                abi.encodeCall(
                    IdentityRegistry.updateApp,
                    (APP_ID, "a", address(0), bytes("m2"), true)
                )
            ),
            IIdentityRegistry.InvalidAppContract.selector
        );
    }

    function testSetPicoVerifierRejectsZeroAddress() public {
        _assertSelectorRevert(
            _callAsSelf(abi.encodeCall(IdentityRegistry.setPicoVerifier, (address(0)))),
            IIdentityRegistry.InvalidPicoVerifierAddress.selector
        );
    }

    function testLockRejectsCallerMismatchWithDesignatedAppContract() public {
        registry.registerApp(APP_ID, "a", address(0x1234), bytes("m"));
        _assertSelectorRevert(
            _callAsSelf(
                abi.encodeCall(
                    IdentityRegistry.lockIdentityProperty,
                    (APP_ID, address(0x9999), PROVIDER_ID, bytes32("p"))
                )
            ),
            IIdentityRegistry.AppContractCallerMismatch.selector
        );
    }

    function testRegisterRejectsExistingEntity() public {
        registry.registerProvider(PROVIDER_ID, "p", bytes("m"));
        _assertSelectorRevert(
            _callAsSelf(
                abi.encodeCall(
                    IdentityRegistry.registerProvider,
                    (PROVIDER_ID, "p2", bytes("m2"))
                )
            ),
            IIdentityRegistry.EntityAlreadyExists.selector
        );

        registry.registerApp(APP_ID, "a", address(0x1234), bytes("m"));
        _assertSelectorRevert(
            _callAsSelf(
                abi.encodeCall(
                    IdentityRegistry.registerApp,
                    (APP_ID, "a2", address(0x5678), bytes("m2"))
                )
            ),
            IIdentityRegistry.EntityAlreadyExists.selector
        );
    }

    function testUpdateRejectsMissingEntity() public {
        _assertSelectorRevert(
            _callAsSelf(
                abi.encodeCall(
                    IdentityRegistry.updateProvider,
                    (PROVIDER_ID, "p2", bytes("m2"))
                )
            ),
            IIdentityRegistry.EntityNotFound.selector
        );
        _assertSelectorRevert(
            _callAsSelf(
                abi.encodeCall(
                    IdentityRegistry.updateApp,
                    (APP_ID, "a2", address(0x5678), bytes("m2"), true)
                )
            ),
            IIdentityRegistry.EntityNotFound.selector
        );
    }

    // =========================================================================
    // Fuzz tests
    // =========================================================================

    function testFuzz_NonOwnerCannotSetPicoVerifier(address picoVerifier_) public {
        if (picoVerifier_ == address(0)) {
            picoVerifier_ = address(0x7777);
        }
        _assertSelectorRevert(
            _callAsNonGov(abi.encodeCall(IdentityRegistry.setPicoVerifier, (picoVerifier_))),
            IOwnable.OwnerUnauthorized.selector
        );
    }

    function testFuzz_NonGovernanceCannotRegisterProvider(bytes32 providerId) public {
        _assertSelectorRevert(
            _callAsNonGov(
                abi.encodeCall(
                    IdentityRegistry.registerProvider,
                    (providerId, "p", bytes("m"))
                )
            ),
            IAccessControl.AccessControlUnauthorizedRole.selector
        );
    }

    function testFuzz_NonGovernanceCannotRegisterApp(
        bytes32 appId,
        address appContract
    ) public {
        _assertSelectorRevert(
            _callAsNonGov(
                abi.encodeCall(
                    IdentityRegistry.registerApp,
                    (appId, "a", appContract, bytes("m"))
                )
            ),
            IAccessControl.AccessControlUnauthorizedRole.selector
        );
    }

    // =========================================================================
    // Provider name uniqueness
    // =========================================================================

    function testRegisterProviderRejectsDuplicateName() public {
        registry.registerProvider(PROVIDER_ID, "SameName", bytes("m1"));
        bytes32 providerId2 = keccak256("provider2");
        _assertSelectorRevert(
            _callAsSelf(
                abi.encodeCall(
                    IdentityRegistry.registerProvider,
                    (providerId2, "SameName", bytes("m2"))
                )
            ),
            IIdentityRegistry.ProviderNameAlreadyTaken.selector
        );
    }

    function testUpdateProviderRejectsDuplicateName() public {
        registry.registerProvider(PROVIDER_ID, "NameA", bytes("m1"));
        bytes32 providerId2 = keccak256("provider2");
        registry.registerProvider(providerId2, "NameB", bytes("m2"));
        _assertSelectorRevert(
            _callAsSelf(
                abi.encodeCall(
                    IdentityRegistry.updateProvider,
                    (providerId2, "NameA", bytes("m3"))
                )
            ),
            IIdentityRegistry.ProviderNameAlreadyTaken.selector
        );
    }

    function testUpdateProviderAllowsSameName() public {
        registry.registerProvider(PROVIDER_ID, "KeepName", bytes("m1"));
        (bool ok, ) = address(registry).call(
            abi.encodeCall(
                IdentityRegistry.updateProvider,
                (PROVIDER_ID, "KeepName", bytes("m2"))
            )
        );
        require(ok, "update with same name should succeed");
    }

    function testUpdateProviderReleasesOldName() public {
        registry.registerProvider(PROVIDER_ID, "OldName", bytes("m1"));
        registry.updateProvider(PROVIDER_ID, "NewName", bytes("m2"));
        bytes32 providerId2 = keccak256("provider2");
        (bool ok, ) = address(registry).call(
            abi.encodeCall(
                IdentityRegistry.registerProvider,
                (providerId2, "OldName", bytes("m3"))
            )
        );
        require(ok, "old name should be available after release");
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    function _callAsSelf(bytes memory callData) internal returns (bytes memory) {
        (bool ok, bytes memory returndata) = address(registry).call(callData);
        return abi.encode(ok, returndata);
    }

    function _callAsNonGov(bytes memory callData) internal returns (bytes memory) {
        (bool ok, bytes memory returndata) = nonGov.callTarget(address(registry), callData);
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

    function _signApproval(
        uint256 privateKey,
        address wallet,
        bytes32 appId,
        uint256 deadline,
        uint256 nonce
    ) internal returns (bytes memory signature) {
        bytes32 digest = _approvalDigest(wallet, appId, deadline, nonce);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _approvalDigest(
        address wallet,
        bytes32 appId,
        uint256 deadline,
        uint256 nonce
    ) internal view returns (bytes32) {
        // Must match the EIP-712 typed data hash used by the contract
        bytes32 APPROVE_APP_TYPEHASH = keccak256("ApproveApp(address wallet,bytes32 appId,uint256 deadline,uint256 nonce)");
        bytes32 structHash = keccak256(abi.encode(APPROVE_APP_TYPEHASH, wallet, appId, deadline, nonce));

        // Build EIP-712 domain separator matching EIP712("IdentityRegistry", "1")
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("IdentityRegistry"),
                keccak256("1"),
                block.chainid,
                address(registry)
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }
}
