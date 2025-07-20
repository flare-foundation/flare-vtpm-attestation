# Flare vTPM Attestation

Flare vTPM Attestation is a Solidity-based implementation designed to verify Virtual Trusted Platform Module (vTPM) quotes generated within Google Cloud Platform’s (GCP) Confidential Space. 
This solution enables the permissionless onboarding of multiple Trusted Execution Environments (TEEs) on Flare, establishing a verifiable chain of trust across the network.

Verification cost: Approx. 2M gas

## Requirements

- [Solidity](https://soliditylang.org) v0.8.27 or higher
- [Foundry](https://getfoundry.sh)
- [uv](https://docs.astral.sh/uv/) (for example scripts)

## Usage

Start by cloning the repository:

```bash
git clone https://github.com/dineshpinto/flare-vtpm-attestation
```

To compile the contracts, run:

```bash
forge build
```

To run the contract tests:

```bash
forge test -vv
```

- The `-vv` flag provides verbose output, useful for detailed test logging.
- To generate a gas report for the contract functions, use the `--gas-report` flag.

### Deploying the contracts

To deploy the contracts, you can use a Foundry script along with your preferred RPC URL and private key:

```bash
forge script script/FlareVtpmAttestation.s.sol:FlareVtpmAttestationScript --rpc-url ${FLARE_RPC_URL} --private-key ${DEPLOYER_PRIVATE_KEY}
```

To maintain code consistency and adhere to Solidity style guidelines, format the code with:

```bash
forge fmt
```

# Python

The example logic is already written out in Python. To run it:

```bash
cd py/
uv sync --all-extras
```

Example attestation tokens are stored in `py/data/`, to test them:

```bash
uv run pki_attestation_validation.py
uv run oidc_attestation_validation.py
```

Note these actual validation may fail as the attestation tokens may be outdated.
