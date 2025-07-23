# AGENT.md - Development Guide for Flare vTPM Attestation

## Build/Test Commands
- **Build contracts**: `forge build`
- **Run all tests**: `forge test -vv` (verbose output)
- **Run single test**: `forge test --match-test [TEST_NAME] -vv`
- **Run specific test file**: `forge test test/FlareVtpmAttestation.t.sol -vv`
- **Format code**: `forge fmt`
- **Gas report**: `forge test --gas-report`
- **Deploy**: `forge script script/FlareVtpmAttestation.s.sol:FlareVtpmAttestationScript --rpc-url ${FLARE_RPC_URL} --private-key ${DEPLOYER_PRIVATE_KEY}`

## Python Testing (optional)
- **Setup**: `cd py/ && uv sync --all-extras`
- **Run attestation tests**: `uv run pki_attestation_validation.py` or `uv run oidc_attestation_validation.py`

## Architecture
- **Main contract**: `contracts/FlareVtpmAttestation.sol` - Core vTPM attestation verification
- **Interfaces**: `contracts/interfaces/` - IAttestation, IVerification
- **Verifiers**: `contracts/verifiers/` - Token signature verification implementations
- **Types**: `contracts/types/` - Common data structures and errors
- **Utils**: `contracts/utils/` - Parser utilities
- **Tests**: Single test file `test/FlareVtpmAttestation.t.sol`
- **Python reference**: `py/` - Example validation logic with dependencies

## Code Style
- **Solidity version**: 0.8.27+ (as per foundry.toml)
- **Imports**: Use relative paths within project, OpenZeppelin for external
- **Formatting**: Use `forge fmt` (sort_imports=true)
- **Comments**: Natspec format (@notice, @dev, @param, @return)
- **Linting**: Uses solhint with recommended rules + custom func-visibility rule
- **Error handling**: Custom errors defined in types/Common.sol
- **Gas optimization**: 200 optimizer runs, London EVM version
