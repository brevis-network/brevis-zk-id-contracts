// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IdentityRegistry} from "../src/IdentityRegistry.sol";
import {IIdentityRegistry} from "../src/IIdentityRegistry.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts-v4/proxy/transparent/TransparentUpgradeableProxy.sol";

interface Vm {
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
}

contract MockPicoVerifierProxy {
    function verifyPicoProof(bytes32, bytes calldata, uint256[8] calldata) external pure {}
}

contract IdentityRegistryProxyTest {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    IdentityRegistry internal registry; // proxy cast to IdentityRegistry
    MockPicoVerifierProxy internal pico;
    address internal proxyAdmin;
    uint256 internal constant WALLET_PK = 0xA11CE;

    function setUp() public {
        pico = new MockPicoVerifierProxy();
        proxyAdmin = address(0xAD);

        // Deploy implementation with zero address (proxy path)
        IdentityRegistry impl = new IdentityRegistry(address(0));

        // Prepare init calldata
        bytes memory initData = abi.encodeWithSignature("init(address)", address(pico));

        // Deploy proxy with init calldata — init() runs in proxy context
        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
            address(impl),
            proxyAdmin,
            initData
        );

        registry = IdentityRegistry(address(proxy));
    }

    function testProxyOwnerIsDeployer() public view {
        require(registry.owner() == address(this), "owner should be deployer");
    }

    function testProxyPicoVerifierIsSet() public view {
        require(registry.picoVerifier() == address(pico), "picoVerifier should be set");
    }

    function testProxyCanGrantRolesAndOperate() public {
        // Grant GOVERNANCE_ROLE to this test contract
        registry.grantRole(registry.GOVERNANCE_ROLE(), address(this));

        // Register a provider through the proxy
        bytes32 providerId = keccak256("test_provider");
        registry.registerProvider(providerId, "TestProvider", bytes("meta"));

        // Verify state is on the proxy
        (string memory name, ) = registry.providers(providerId);
        require(bytes(name).length > 0, "provider should be registered on proxy");
    }

    function testProxyEIP712DomainUsesProxyAddress() public view {
        (, , , , address verifyingContract, , ) = registry.eip712Domain();
        require(verifyingContract == address(registry), "EIP712 domain should use proxy address");
    }

    function testProxyInitCannotBeCalledAgain() public {
        // init() already called during proxy deployment; calling again should revert
        (bool ok, ) = address(registry).call(
            abi.encodeWithSignature("init(address)", address(pico))
        );
        require(!ok, "init should fail on already-initialized proxy");
    }

    function testProxyAttestationFlow() public {
        // Grant roles
        registry.grantRole(registry.GOVERNANCE_ROLE(), address(this));
        registry.grantRole(registry.PAUSER_ROLE(), address(this));

        // Register provider
        bytes32 providerId = keccak256("provider");
        registry.registerProvider(providerId, "Provider", bytes("meta"));

        // Set verifier key
        bytes32 property = keccak256("property");
        registry.setVerifierKey(property, keccak256("vkey"));

        // Submit attestation
        IIdentityRegistry.AttestationPublicInputs memory inputs = IIdentityRegistry.AttestationPublicInputs({
            wallet: address(this),
            providerId: providerId,
            web2IdNullifier: keccak256("nullifier"),
            identityProperty: property,
            timestamp: 100,
            dataBlob: bytes("data")
        });
        bytes memory publicValues = abi.encode(inputs);
        uint256[8] memory proof;
        registry.submitIdentityAttestation(publicValues, proof);

        // Query through proxy
        (, bytes memory dataBlob) = registry.getLatestIdentityProperty(address(this), providerId, property);
        require(keccak256(dataBlob) == keccak256(bytes("data")), "data should match");
    }

    function testProxyApproveAppWithSig() public {
        // Setup: register an app
        registry.grantRole(registry.GOVERNANCE_ROLE(), address(this));
        bytes32 appId = keccak256("app");
        registry.registerApp(appId, "TestApp", address(0x1234), bytes("meta"));

        address wallet = vm.addr(WALLET_PK);
        uint256 deadline = block.timestamp + 1 days;

        // Build EIP-712 digest and sign
        bytes memory signature = _signApproval(WALLET_PK, wallet, appId, deadline, 0);

        // Submit delegated approval through proxy
        registry.approveAppWithSig(wallet, appId, deadline, 0, signature);

        // Verify approval was set and nonce consumed
        require(registry.appApproval(wallet, appId), "approval should be set");
        require(registry.approvalNonceByWallet(wallet) == 1, "nonce should be consumed");
    }

    function _signApproval(
        uint256 privateKey,
        address wallet,
        bytes32 appId,
        uint256 deadline,
        uint256 nonce
    ) internal returns (bytes memory) {
        bytes32 typehash = keccak256("ApproveApp(address wallet,bytes32 appId,uint256 deadline,uint256 nonce)");
        bytes32 structHash = keccak256(abi.encode(typehash, wallet, appId, deadline, nonce));

        // Build domain separator using the proxy address
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("IdentityRegistry"),
                keccak256("1"),
                block.chainid,
                address(registry)
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }
}
