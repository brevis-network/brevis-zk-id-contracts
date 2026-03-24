// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {ProxyAdmin} from "@openzeppelin/contracts-v4/proxy/transparent/ProxyAdmin.sol";

/// @title DeploySharedProxyAdmin
/// @notice Deploys a shared ProxyAdmin for managing all TransparentUpgradeableProxy instances.
/// @dev usage: forge script scripts/DeploySharedProxyAdmin.s.sol --rpc-url $RPC_URL --broadcast --verify -vv
contract DeploySharedProxyAdmin is Script {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(pk);

        ProxyAdmin proxyAdmin = new ProxyAdmin();

        vm.stopBroadcast();

        console.log("ProxyAdmin deployed:", address(proxyAdmin));
        console.log("Owner:", proxyAdmin.owner());
    }
}
