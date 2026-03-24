// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/pico/MockPicoVerifier.sol";

/// @title DeployMockPicoVerifier
/// @notice Deploys the mock PicoVerifier for testing and devnet environments.
/// @dev usage: forge script scripts/DeployMockPicoVerifier.s.sol --rpc-url $RPC_URL --broadcast --verify -vv
contract DeployMockPicoVerifier is Script {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(pk);

        MockPicoVerifier verifier = new MockPicoVerifier();

        vm.stopBroadcast();

        console.log("MockPicoVerifier deployed:", address(verifier));
    }
}
