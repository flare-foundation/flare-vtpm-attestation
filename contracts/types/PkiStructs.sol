// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "./Common.sol";

/// @dev Struct representing an PKI Certificate
struct PKICertificates {
    bytes rootCert;
    bytes intermediateCert;
    bytes leafCert;
}
