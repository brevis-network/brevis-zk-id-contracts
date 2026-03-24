// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "forge-std/StdJson.sol";
import {ProxyAdmin} from "@openzeppelin/contracts-v4/proxy/transparent/ProxyAdmin.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts-v4/proxy/transparent/TransparentUpgradeableProxy.sol";
import {IdentityRegistry} from "../src/IdentityRegistry.sol";

/// @title DeployIdentityRegistry
/// @notice Deploys IdentityRegistry as a TransparentUpgradeableProxy.
///         Supports both full proxy deployment and implementation-only deployment (for upgrades).
///
/// @dev Config JSON schema:
///   {
///     "proxyAdmin": { "address": "0x..." },
///     "registry": {
///       "picoVerifier": "0x...",
///       "implementationOnly": false
///     }
///   }
///
/// usage: DEPLOY_CONFIG=config.json forge script scripts/DeployIdentityRegistry.s.sol \
///        --rpc-url $RPC_URL --broadcast --verify -vv
contract DeployIdentityRegistry is Script {
    using stdJson for string;

    function run() external {
        // Load config
        string memory json = _loadConfig();

        uint256 pk = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(pk);

        // Deploy implementation with zero address (proxy path)
        address implementation = address(new IdentityRegistry(address(0)));
        console.log("IdentityRegistry implementation:", implementation);

        // Check if implementation-only deployment
        bool implementationOnly = json.keyExists("$.registry.implementationOnly")
            ? json.readBool("$.registry.implementationOnly")
            : false;

        if (implementationOnly) {
            console.log("implementationOnly=true: Skipping proxy deployment");
            vm.stopBroadcast();
            return;
        }

        // Read proxy admin address
        ProxyAdmin proxyAdmin = _loadOrDeployProxyAdmin(json);

        // Read picoVerifier address
        require(json.keyExists("$.registry.picoVerifier"), "config.registry.picoVerifier missing");
        address picoVerifier = json.readAddress("$.registry.picoVerifier");
        require(picoVerifier != address(0), "config.registry.picoVerifier is zero");

        // Prepare init calldata
        bytes memory initData = abi.encodeWithSignature("init(address)", picoVerifier);

        // Deploy proxy with init calldata
        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
            implementation,
            address(proxyAdmin),
            initData
        );

        vm.stopBroadcast();

        // Print summary
        IdentityRegistry registry = IdentityRegistry(address(proxy));
        console.log("---");
        console.log("IdentityRegistry proxy:", address(proxy));
        console.log("ProxyAdmin:", address(proxyAdmin));
        console.log("Owner:", registry.owner());
        console.log("PicoVerifier:", registry.picoVerifier());
    }

    function _loadConfig() internal view returns (string memory) {
        string memory inlineJson = vm.envOr("DEPLOY_CONFIG_JSON", string(""));
        if (bytes(inlineJson).length != 0) {
            return inlineJson;
        }
        string memory configPath = vm.envString("DEPLOY_CONFIG");
        require(bytes(configPath).length != 0, "DEPLOY_CONFIG not set");
        return vm.readFile(configPath);
    }

    function _loadOrDeployProxyAdmin(string memory json) internal returns (ProxyAdmin) {
        address existing = address(0);
        if (json.keyExists("$.proxyAdmin.address")) {
            string memory configuredAddress = json.readString("$.proxyAdmin.address");
            if (bytes(configuredAddress).length != 0) {
                existing = vm.parseAddress(configuredAddress);
            }
        }
        if (existing != address(0)) {
            console.log("Using existing ProxyAdmin:", existing);
            return ProxyAdmin(existing);
        }

        // Deploy new ProxyAdmin if not provided
        ProxyAdmin proxyAdmin = new ProxyAdmin();
        console.log("Deployed new ProxyAdmin:", address(proxyAdmin));
        return proxyAdmin;
    }
}
