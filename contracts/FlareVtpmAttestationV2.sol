// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {FlareVtpmAttestation} from "./FlareVtpmAttestation.sol";
import {IVerification} from "./interfaces/IVerification.sol";
import {Header, QuoteConfig} from "./types/Common.sol";
import {InvalidVerifier, SignatureVerificationFailed} from "./types/Common.sol";

/**
 * @title FlareVtpmAttestationV2
 * @dev Version 2 of FlareVtpmAttestation for testing upgrade functionality.
 * Adds new features while maintaining existing storage layout.
 */
contract FlareVtpmAttestationV2 is FlareVtpmAttestation {
    /// @notice Counter for total number of attestations processed
    uint256 public totalAttestations;
    
    /// @notice Event emitted when attestation statistics are updated
    event AttestationStatsUpdated(uint256 totalAttestations);

    /**
     * @dev Constructor required by parent but disabled for upgradeable contracts
     */
    constructor() {
        _disableInitializers();
    }

    /**
     * @dev Override verifyAndAttest to include statistics tracking
     */
    function verifyAndAttest(bytes calldata header, bytes calldata payload, bytes calldata signature)
        external
        override
        returns (bool success)
    {
        // Parse the JWT header to obtain the token type
        Header memory parsedHeader = parseHeader(header);

        // Retrieve the verifier based on the token type
        IVerification verifier = tokenTypeVerifiers[parsedHeader.tokenType];
        if (address(verifier) == address(0)) {
            revert InvalidVerifier();
        }

        // Verify the JWT signature
        (bool verified, bytes32 digest) = verifier.verifySignature(header, payload, signature, parsedHeader);
        if (!verified) {
            revert SignatureVerificationFailed("Signature does not match");
        }

        // Parse the JWT payload to obtain the vTPM configuration
        QuoteConfig memory payloadConfig = parsePayload(payload);

        // Validate the configuration in the payload
        validatePayload(payloadConfig);

        // Assign the verified digest to the configuration for record-keeping
        payloadConfig.digest = digest;

        // Register the vTPM attestation for the sender
        registeredQuotes[msg.sender] = payloadConfig;

        emit QuoteRegistered(msg.sender, payloadConfig);
        
        success = true;
        
        if (success) {
            totalAttestations++;
            emit AttestationStatsUpdated(totalAttestations);
        }
        
        return success;
    }

    /**
     * @dev New function added in V2 to demonstrate upgrade functionality
     * @return The total number of successful attestations
     */
    function getAttestationStats() external view returns (uint256) {
        return totalAttestations;
    }

    /**
     * @dev Reset attestation statistics (only owner)
     */
    function resetStats() external onlyOwner {
        totalAttestations = 0;
        emit AttestationStatsUpdated(0);
    }

    /**
     * @dev Returns the current implementation version.
     * @return Version string for this implementation
     */
    function version() public pure override returns (string memory) {
        return "2.0.0";
    }
}