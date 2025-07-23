// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {FlareVtpmAttestation} from "../contracts/FlareVtpmAttestation.sol";
import {OidcSignatureVerification} from "../contracts/verifiers/OidcSignatureVerification.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Script, console} from "forge-std/Script.sol";

contract FlareVtpmAttestationScript is Script {
    uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
    string hwmodel = vm.envString("HWMODEL");
    string swname = vm.envString("SWNAME");
    string imageDigest = vm.envString("IMAGE_DIGEST");
    string iss = vm.envString("ISS");
    bool secboot = vm.envBool("SECBOOT");

    FlareVtpmAttestation flareVtpmImpl;
    FlareVtpmAttestation flareVtpmProxy;
    OidcSignatureVerification oidcVerifierImpl;
    OidcSignatureVerification oidcVerifierProxy;

    function deploy() public {
        address deployer = vm.addr(deployerPrivateKey);
        
        // Starting the broadcast of transactions from the deployer account
        vm.startBroadcast(deployerPrivateKey);

        // Deploy the FlareVtpmAttestation implementation
        flareVtpmImpl = new FlareVtpmAttestation();
        console.log("FlareVtpmAttestation implementation deployed at:", address(flareVtpmImpl));

        // Deploy the OidcSignatureVerification implementation
        oidcVerifierImpl = new OidcSignatureVerification();
        console.log("OidcSignatureVerification implementation deployed at:", address(oidcVerifierImpl));

        // Deploy OIDC verifier proxy with initialization
        bytes memory oidcInitData = abi.encodeWithSelector(
            OidcSignatureVerification.initialize.selector,
            deployer
        );
        ERC1967Proxy oidcProxy = new ERC1967Proxy(address(oidcVerifierImpl), oidcInitData);
        oidcVerifierProxy = OidcSignatureVerification(address(oidcProxy));
        console.log("OidcSignatureVerification proxy deployed at:", address(oidcVerifierProxy));

        // Deploy FlareVtpmAttestation proxy with configuration initialization
        bytes memory flareInitData = abi.encodeWithSelector(
            FlareVtpmAttestation.initializeWithConfig.selector,
            deployer,
            hwmodel,
            swname,
            imageDigest,
            iss,
            secboot
        );
        ERC1967Proxy flareProxy = new ERC1967Proxy(address(flareVtpmImpl), flareInitData);
        flareVtpmProxy = FlareVtpmAttestation(address(flareProxy));
        console.log("FlareVtpmAttestation proxy deployed at:", address(flareVtpmProxy));

        // Log that the base configuration has been set
        console.log("Base quote configuration initialized with:");
        console.log("  Hardware Model:", hwmodel);
        console.log("  Software Name:", swname);
        console.log("  Image Digest:", imageDigest);
        console.log("  Issuer:", iss);
        console.log("  Secure Boot:", secboot);

        // Set the token type verifier to the OidcSignatureVerification proxy
        flareVtpmProxy.setTokenTypeVerifier(address(oidcVerifierProxy));
        console.log("FlareVtpmAttestation token type verifier set to OidcSignatureVerification proxy");

        vm.stopBroadcast();
    }
}
