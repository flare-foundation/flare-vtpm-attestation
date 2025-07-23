# Flare vTPM Attestation - Agent Guide

## Build/Test Commands
- `forge build` - Compile contracts
- `forge test -vv` - Run all tests with verbose output
- `forge test -vvv` - Run tests with maximum verbosity
- `forge test --gas-report` - Run tests with gas usage report
- `forge test --match-test <test_name>` - Run specific test function
- `forge fmt` - Format Solidity code
- `forge fmt --check` - Check formatting without modifying files

## Python Commands
- `cd py/ && uv sync --all-extras` - Install Python dependencies
- `uv run pki_attestation_validation.py` - Run PKI attestation validation
- `uv run oidc_attestation_validation.py` - Run OIDC attestation validation

## Architecture
- **Main Contract**: `contracts/FlareVtpmAttestation.sol` - Core vTPM attestation verification
- **Verifiers**: `contracts/verifiers/` - Token type verification implementations
- **Types**: `contracts/types/Common.sol` - Shared types and error definitions
- **Utils**: `contracts/utils/ParserUtils.sol` - JWT parsing utilities
- **Interfaces**: `contracts/interfaces/` - Contract interfaces
- **Python**: `py/` - Reference implementation and validation examples
- **Deploy**: `script/FlareVtpmAttestation.s.sol` - Deployment script
- **Config**: Gas limit 15M, Solc 0.8.27, optimizer enabled (200 runs)

## Code Style
- SPDX license required, pragma ^0.8.27
- Use OpenZeppelin imports for standard contracts
- NatSpec comments required for public functions
- Import organization: interfaces, types, utils, external libs
- Follow solhint:recommended rules with func-visibility exceptions
- Use `forge fmt` with sort_imports=true for consistent formatting
