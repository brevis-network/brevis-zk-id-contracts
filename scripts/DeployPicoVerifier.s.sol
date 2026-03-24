// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/pico/PicoVerifier.sol";

/// @title DeployPicoVerifier
/// @notice Deploys the production PicoVerifier (Groth16-based ZK proof verification).
/// @dev usage: forge script scripts/DeployPicoVerifier.s.sol --rpc-url $RPC_URL --broadcast --verify -vv
contract DeployPicoVerifier is Script {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(pk);

        PicoVerifier verifier = new PicoVerifier();

        vm.stopBroadcast();

        console.log("PicoVerifier deployed:", address(verifier));
    }
}
