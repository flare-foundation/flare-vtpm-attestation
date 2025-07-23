// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {SignatureVerificationFailed} from "../types/Common.sol";
import {Header, RSAPubKey} from "../types/OidcStructs.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {RSA} from "@openzeppelin/contracts/utils/cryptography/RSA.sol";

/**
 * @title OidcSignatureVerification
 * @dev Contract for managing and verifying RSA public keys associated with OIDC (OpenID Connect) JWT signatures.
 * Allows adding, removing, and verifying RSA public keys by `kid` (Key ID).
 */
contract OidcSignatureVerification is Initializable, Ownable, UUPSUpgradeable {
    /// @notice Event emitted when a new OIDC RSA public key is added
    /// @param kid Key ID associated with the RSA public key
    /// @param e The exponent of the RSA public key
    /// @param n The modulus of the RSA public key
    event PubKeyAdded(bytes indexed kid, bytes e, bytes n);

    /// @notice Event emitted when an OIDC RSA public key is removed
    /// @param kid Key ID associated with the RSA public key that was removed
    event PubKeyRemoved(bytes indexed kid);

    /// @notice Mapping of RSA public keys by Key ID (`kid`)
    /// Each `kid` maps to an RSAPubKey struct containing the RSA public key parameters
    mapping(bytes kid => RSAPubKey) internal pubKeys;

    /**
     * @dev Constructor required by Ownable but disabled for upgradeable contracts
     */
    constructor() Ownable(msg.sender) {
        _disableInitializers();
    }

    /**
     * @dev Initializes the contract with the specified owner.
     * This replaces the constructor for upgradeable contracts.
     * @param initialOwner The address that will be set as the contract owner
     */
    function initialize(address initialOwner) public initializer {
        _transferOwnership(initialOwner);
    }

    /**
     * @dev Returns the token type handled by this verifier, which is `"OIDC"`.
     * @return The token type identifier as bytes ("OIDC").
     */
    function tokenType() external pure returns (bytes memory) {
        return bytes("OIDC");
    }

    /**
     * @dev Adds an OIDC RSA public key, identified by its Key ID (`kid`), to the contract.
     * This key will be used to verify JWT signatures associated with the `kid`.
     * Only the contract owner can call this function.
     * @param kid The Key ID (identifier) for the RSA public key.
     * @param e The exponent component of the RSA public key.
     * @param n The modulus component of the RSA public key.
     */
    function addPubKey(bytes memory kid, bytes memory e, bytes memory n) external onlyOwner {
        pubKeys[kid] = RSAPubKey({e: e, n: n});
        emit PubKeyAdded(kid, e, n);
    }

    /**
     * @dev Removes an OIDC RSA public key from the contract by its Key ID (`kid`).
     * This action can only be performed by the contract owner.
     * @param kid The Key ID (identifier) for the RSA public key to be removed.
     */
    function removePubKey(bytes memory kid) external onlyOwner {
        // Check if the key exists in the mapping
        if (pubKeys[kid].n.length == 0) {
            revert("Public key does not exist");
        }

        // Remove the RSA public key
        delete pubKeys[kid];

        // Emit an event indicating the public key has been removed
        emit PubKeyRemoved(kid);
    }

    /**
     * @dev Verifies the RSA signature of a JWT.
     * Constructs the signing input from the JWT header and payload, computes its SHA256 hash, and verifies
     * the signature using the RSA public key associated with the `kid` in the JWT header.
     * @param rawHeader The JWT header as a Base64URL-decoded byte array.
     * @param rawPayload The JWT payload as a Base64URL-decoded byte array.
     * @param rawSignature The RSA signature associated with the JWT, provided as a Base64URL-decoded byte array.
     * @param header The parsed JWT header, containing the `kid` (Key ID).
     * @return verified Boolean indicating whether the signature is valid.
     * @return digest The SHA256 hash of the signing input (the concatenation of the Base64URL-encoded header and payload).
     */
    function verifySignature(
        bytes calldata rawHeader,
        bytes calldata rawPayload,
        bytes calldata rawSignature,
        Header calldata header
    ) public view returns (bool verified, bytes32 digest) {
        // Encode the header and payload using Base64URL as per JWT standards
        string memory headerB64URL = Base64.encodeURL(rawHeader);
        string memory payloadB64URL = Base64.encodeURL(rawPayload);

        // Construct the signing input (header.payload)
        bytes memory signingInput = abi.encodePacked(headerB64URL, ".", payloadB64URL);

        // Compute the SHA256 hash of the signing input
        digest = sha256(signingInput);

        // Retrieve the RSA public key associated with the `kid`
        RSAPubKey storage rsaPublicKey = pubKeys[header.kid];
        if (rsaPublicKey.n.length == 0) {
            revert SignatureVerificationFailed("Public key not found");
        }

        // Verify the RSA signature using the RSA public key
        verified = RSA.pkcs1Sha256(digest, rawSignature, rsaPublicKey.e, rsaPublicKey.n);
    }

    /**
     * @dev Authorizes an upgrade to a new implementation.
     * Only the contract owner can authorize upgrades.
     * @param newImplementation Address of the new implementation contract
     */
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    /**
     * @dev Returns the current implementation version.
     * @return Version string for this implementation
     */
    function version() public pure virtual returns (string memory) {
        return "1.0.0";
    }
}
