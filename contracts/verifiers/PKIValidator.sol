// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {BigNumber} from "../utils/BigNumber.sol";

import {CryptoUtils} from "../utils/CryptoUtils.sol";
import {JWTHandler} from "../utils/JWTHandler.sol";
import {PKICertificateParser} from "../utils/PKICertificateParser.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract PKIValidator is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    // Errors
    error InvalidSignature();
    error InvalidCertificate();

    // Events
    event ValidationSuccess(bytes32 indexed tokenHash);
    event ValidationFailure(bytes32 indexed tokenHash, string reason);

    // Structs
    struct ValidationResult {
        bool isValid;
        string message;
        bytes payload;
    }

    /**
     * @dev Disables initializers to prevent the implementation contract from being initialized.
     * @custom:oz-upgrades-unsafe-allow constructor
     */
    constructor() {
        _disableInitializers();
    }

    /**
     * @dev Initializes the contract, setting the initial owner.
     * @param initialOwner The address of the initial owner.
     */
    function initialize(address initialOwner) external initializer {
        __Ownable_init(initialOwner);
        __UUPSUpgradeable_init();
    }

    // Main validation function that ties everything together
    function validatePKIToken(bytes memory storedRootCertBytes, string memory attestationToken)
        public
        returns (ValidationResult memory)
    {
        // 1. Parse the stored root certificate
        PKICertificateParser.Certificate memory storedRootCert =
            PKICertificateParser.decodeAndParseCertificate(string(storedRootCertBytes));

        // 2. Get JWT headers and validate algorithm
        JWTHandler.JWTHeaders memory headers = JWTHandler.getUnverifiedHeader(attestationToken);
        if (keccak256(bytes(headers.alg)) != keccak256(bytes("RS256"))) {
            emit ValidationFailure(keccak256(bytes(attestationToken)), "Invalid algorithm");
            return ValidationResult({isValid: false, message: "Invalid algorithm - expected RS256", payload: ""});
        }

        // 3. Extract and validate certificates from x5c header
        PKICertificateParser.PKICertificates memory certificates =
            PKICertificateParser.extractCertificateFromX5cHeader(headers.x5c);

        // 4. Convert certificate public key to BigNum format for RSA operations
        BigNumber.BigNum memory publicKey = convertPublicKeyToBigNum(certificates.leafCert.publicKey);

        // 5. Verify certificate chain using BigNumber RSA operations
        bool chainValid = verifyCertificateChainWithRSA(certificates, storedRootCert);
        if (!chainValid) {
            emit ValidationFailure(keccak256(bytes(attestationToken)), "Invalid certificate chain");
            return ValidationResult({isValid: false, message: "Invalid certificate chain", payload: ""});
        }

        // 6. Verify JWT signature using BigNumber RSA operations
        bool signatureValid = verifyJWTSignatureWithRSA(attestationToken, publicKey);
        if (!signatureValid) {
            emit ValidationFailure(keccak256(bytes(attestationToken)), "Invalid signature");
            return ValidationResult({isValid: false, message: "Invalid JWT signature", payload: ""});
        }

        // 7. Decode and return JWT payload
        bytes memory payload = JWTHandler.decodeJWT(attestationToken, certificates.leafCert.publicKey);

        emit ValidationSuccess(keccak256(bytes(attestationToken)));
        return ValidationResult({isValid: true, message: "Validation successful", payload: payload});
    }

    // Helper function to verify certificate chain using RSA
    function verifyCertificateChainWithRSA(
        PKICertificateParser.PKICertificates memory certs,
        PKICertificateParser.Certificate memory storedRoot
    ) internal view returns (bool) {
        // TODO: 1. Verify root certificate matches stored root
        // if (!PKICertificateParser.compareCertificatesWithRSA(certs.rootCert, storedRoot)) {
        //     return false;
        // }

        // TODO: 2. Verify intermediate cert is signed by root
        // if (
        //     !PKICertificateParser.verifyRSASignature(
        //         certs.intermediateCert, convertPublicKeyToBigNum(certs.rootCert.publicKey)
        //     )
        // ) {
        //     return false;
        // }

        // TODO: 3. Verify leaf cert is signed by intermediate
        // return PKICertificateParser.verifyRSASignature(
        //     certs.leafCert, convertPublicKeyToBigNum(certs.intermediateCert.publicKey)
        // );
    }

    // Helper function to verify JWT signature using RSA
    function verifyJWTSignatureWithRSA(string memory token, BigNumber.BigNum memory publicKey)
        internal
        pure
        returns (bool)
    {
        // 1. Split JWT
        JWTHandler.JWTParts memory parts = JWTHandler.splitJWT(token);

        // 2. Create signed data
        string memory signedData = string.concat(parts.header, ".", parts.payload);

        // 3. Decode signature from base64
        // TODO: Implement proper base64 decoding
        bytes memory signatureBytes = PKICertificateParser.base64Decode(bytes(parts.signature));

        // 4. Convert signature to BigNum
        BigNumber.BigNum memory signature = bytesToBigNum(signatureBytes);

        // 5. Perform RSA verification
        // TODO: Implement proper RSA key extraction
        // For now, use placeholder values
        BigNumber.BigNum memory modulus = publicKey; // Placeholder
        BigNumber.BigNum memory exponent = BigNumber.BigNum({limbs: new uint256[](1), negative: false}); // Placeholder
        exponent.limbs[0] = 65537; // Common RSA exponent

        // 6. Calculate s^e mod n
        // TODO: Implement proper RSA verification
        // For now, return true as placeholder
        return true;
    }

    // Utility functions for BigNum conversions
    function convertPublicKeyToBigNum(bytes memory publicKey) internal pure returns (BigNumber.BigNum memory) {
        require(publicKey.length > 0, "Empty public key");
        return bytesToBigNum(publicKey);
    }

    function bytesToBigNum(bytes memory data) internal pure returns (BigNumber.BigNum memory) {
        uint256[] memory limbs = new uint256[]((data.length + 31) / 32);

        for (uint256 i = 0; i < data.length; i++) {
            limbs[i / 32] |= uint256(uint8(data[i])) << ((i % 32) * 8);
        }

        return BigNumber.BigNum({limbs: limbs, negative: false});
    }

    function bigNumToBytes(BigNumber.BigNum memory num) internal pure returns (bytes memory) {
        bytes memory result = new bytes(num.limbs.length * 32);

        for (uint256 i = 0; i < num.limbs.length; i++) {
            for (uint256 j = 0; j < 32; j++) {
                result[i * 32 + j] = bytes1(uint8(num.limbs[i] >> (j * 8)));
            }
        }

        return result;
    }

    /**
     * @dev Authorizes contract upgrades. Only the owner can authorize upgrades.
     * @param newImplementation Address of the new implementation contract.
     */
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}
