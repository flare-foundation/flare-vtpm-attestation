// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { FlareVtpmAttestation } from "../FlareVtpmAttestation.sol";

/**
 * @title FlareVtpmAttestationV2
 * @dev Version 2 of FlareVtpmAttestation contract with additional functionality for testing upgrades.
 * This contract adds a new function to demonstrate that state is preserved during upgrades.
 */
contract FlareVtpmAttestationV2 is FlareVtpmAttestation {
    /// @notice Version number for this contract
    uint256 public constant VERSION = 2;

    /// @notice New storage variable added in V2
    string public newFeature;

    /**
     * @dev Sets a new feature string to test that new functionality works after upgrade.
     * @param _newFeature The string to set for the new feature.
     */
    function setNewFeature(string calldata _newFeature) external onlyOwner {
        newFeature = _newFeature;
    }

    /**
     * @dev Returns the version of this contract.
     * @return The version number.
     */
    function getVersion() external pure returns (uint256) {
        return VERSION;
    }

    /**
     * @dev Returns information about the contract upgrade.
     * @return version The contract version.
     * @return feature The new feature string.
     */
    function getUpgradeInfo() external view returns (uint256 version, string memory feature) {
        return (VERSION, newFeature);
    }
}
