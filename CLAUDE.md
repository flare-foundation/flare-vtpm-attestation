# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Solidity-based implementation for verifying Virtual Trusted Platform Module (vTPM) quotes generated within Google Cloud Platform's Confidential Space. The system enables permissionless onboarding of Trusted Execution Environments (TEEs) on Flare through JWT-based attestation verification.

## Development Commands

### Solidity (Primary codebase)
- **Build contracts**: `forge build`
- **Run tests**: `forge test -vv` (use `-vv` for verbose output)
- **Generate gas report**: `forge test --gas-report`
- **Format code**: `forge fmt`
- **Deploy contracts**: `forge script script/FlareVtpmAttestation.s.sol:FlareVtpmAttestationScript --rpc-url ${FLARE_RPC_URL} --private-key ${DEPLOYER_PRIVATE_KEY}`

### Python (Example implementations)
- **Setup environment**: `cd py/ && uv sync --all-extras`
- **Test PKI validation**: `uv run pki_attestation_validation.py`
- **Test OIDC validation**: `uv run oidc_attestation_validation.py`
- **Lint Python code**: `uv run ruff check`
- **Format Python code**: `uv run ruff format`
- **Type check**: `uv run pyright`

## Architecture Overview

### Core Contracts

**FlareVtpmAttestation** (`contracts/FlareVtpmAttestation.sol`): Main attestation contract that:
- Manages vTPM quote configurations via `BaseQuoteConfig` requirements
- Delegates signature verification to pluggable verifier contracts via `IVerification` interface
- Validates JWT payload against required vTPM specifications
- Registers successful attestations in `registeredQuotes` mapping

**Verification System**: Modular verification through two main verifiers:
- **OidcSignatureVerification** (`contracts/verifiers/OidcSignatureVerification.sol`): Handles OIDC JWT tokens with RSA public key management
- **PKIValidator** (`contracts/verifiers/PKIValidator.sol`): Handles PKI certificate chain validation (work in progress)

### Key Data Structures

- **QuoteConfig**: Complete vTPM configuration including digest, base config, expiry, and issuance times
- **BaseQuoteConfig**: Required vTPM specifications (hardware model, software name, image digest, issuer, secure boot)
- **Header**: JWT header containing key ID and token type detection

### Gas Costs

Verification operations cost approximately 2M gas per attestation.

## Configuration

### Foundry Configuration
- Solidity version: 0.8.27
- Optimizer enabled with 200 runs
- EVM version: London
- Source directory: `contracts/`
- Test directory: `test/`

### Network Configuration
Environment variables for deployment:
- `FLARE_RPC_URL`: Flare mainnet RPC
- `COSTON2_RPC_URL`: Coston2 testnet RPC
- `DEPLOYER_PRIVATE_KEY`: Deployment account private key
- `FLARESCAN_API_KEY`: API key for contract verification

## Testing Strategy

Main test file: `test/FlareVtpmAttestation.t.sol`

Tests cover:
- RSA signature verification with real attestation tokens
- Full verification and attestation flow
- Edge cases: expired tokens, invalid signatures, missing keys
- Payload validation against required configuration

Example test data includes decoded JWT components from actual Google Confidential Space attestation tokens.

## Dependencies

- **OpenZeppelin Contracts**: Standard library for Ownable, RSA verification, Base64 encoding
- **Forge Standard Library**: Testing utilities and development tools

## Important Notes

- PKI validator implementation is currently incomplete (contains TODO sections)
- Python examples may fail validation due to outdated attestation tokens
- The system supports pluggable verifiers through the `IVerification` interface
- All JWT components must be provided as Base64URL-decoded byte arrays