// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {FlareVtpmAttestation} from "../contracts/FlareVtpmAttestation.sol";
import {OidcSignatureVerification} from "../contracts/verifiers/OidcSignatureVerification.sol";
import {Upgrades} from "@openzeppelin/foundry-upgrades/Upgrades.sol";
import {Script, console} from "forge-std/Script.sol";

contract FlareVtpmAttestationScript is Script {
    uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
    string hwmodel = vm.envString("HWMODEL");
    string swname = vm.envString("SWNAME");
    string imageDigest = vm.envString("IMAGE_DIGEST");
    string iss = vm.envString("ISS");
    bool secboot = vm.envBool("SECBOOT");

    function deploy() public {
        // Starting the broadcast of transactions from the deployer account
        vm.startBroadcast(deployerPrivateKey);

        address deployer = vm.addr(deployerPrivateKey);

        // Deploy the FlareVtpmAttestation proxy
        address flareVtpm = Upgrades.deployUUPSProxy(
            "FlareVtpmAttestation.sol",
            abi.encodeCall(FlareVtpmAttestation.initialize, (deployer, hwmodel, swname, imageDigest, iss, secboot))
        );
        console.log("FlareVtpmAttestation proxy deployed at:", flareVtpm);

        // Log that the base configuration has been set during initialization
        console.log("Base quote configuration set with:");
        console.log("  Hardware Model:", hwmodel);
        console.log("  Software Name:", swname);
        console.log("  Image Digest:", imageDigest);
        console.log("  Issuer:", iss);
        console.log("  Secure Boot:", secboot);

        // Deploy the OidcSignatureVerification proxy
        address oidcVerifier = Upgrades.deployUUPSProxy(
            "OidcSignatureVerification.sol", abi.encodeCall(OidcSignatureVerification.initialize, (deployer))
        );
        console.log("OidcSignatureVerification proxy deployed at:", oidcVerifier);

        // Set the token type verifier to the OidcSignatureVerification contract
        FlareVtpmAttestation(flareVtpm).setTokenTypeVerifier(oidcVerifier);
        console.log("FlareVtpmAttestation token type verifier set to OidcSignatureVerification");

        vm.stopBroadcast();
    }
}
