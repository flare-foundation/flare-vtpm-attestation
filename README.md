# Flare vTPM Attestation

A Solidity-based framework for verifying Virtual Trusted Platform Module (vTPM) quotes generated in Google Cloud Platform’s (GCP) Confidential Space.
This permissionless solution streamlines the onboarding of multiple Trusted Execution Environments (TEEs) on Flare, establishing a provable chain of trust across the network.

> [!WARNING]
>
> This project is in alpha and under active development. Breaking changes may occur.

## Requirements

- [Solidity](https://soliditylang.org) v0.8.27 or higher
- [Foundry](https://getfoundry.sh)
- [Slither](https://github.com/marketplace/actions/slither-action) for static analysis
- [uv](https://docs.astral.sh/uv/) (for example scripts)

## 📦 Getting Started

1. Clone the repo:

   ```bash
   git clone https://github.com/dineshpinto/flare-vtpm-attestation
   ```

2. Configure your `.env`:

   ```
   # Copy the template and add your PKs etc.
   cp .env.example .env
   ```

3. To compile the contracts, run:

   ```bash
   forge build
   ```

4. To run the contract tests:

   ```bash
   forge test -vv
   ```

   - To generate a gas report for the contract functions, use the `--gas-report` flag.

### ✅ Development checks

Run the following commands to format, lint, type-check, and test your code before committing.

```bash
# Format
forge fmt

# Run slither
slither contracts/ --config-file .github/slither.config.json
```

### ☁️ Deploying the contracts

Deploy contracts using a Foundry script.
Ensure the environment variables `FLARE_RPC_URL` and `DEPLOYER_PRIVATE_KEY` are set.

```bash
forge script \
    script/FlareVtpmAttestation.s.sol:FlareVtpmAttestationScript \
    --rpc-url ${FLARE_RPC_URL} \
    --private-key ${DEPLOYER_PRIVATE_KEY}
```

Format your code to adhere to Solidity style guidelines:

```bash
forge fmt
```

## Repo structure

```plaintext
flare-foundation/flare-vtpm-attestation
├── .github/
│   └── scripts/
│       └── slither_comment.js    # Bot integration for Slither reports
├── contracts/                    # Solidity code
│   ├── interfaces/
│   ├── types/
│   ├── utils/
│   ├── verifiers/
│   └── FlareVtpmAttestation.sol
├── py/                           # Python examples & validation scripts
├── script/                       # Foundry deployment scripts
├── test/                         # Solidity test suite
├── .env.example                  # Sample environment variables
├── foundry.toml                  # Build & formatting configuration
├── README.md
└── CONTRIBUTING.md
```

## Python

The `py/` directory contains sample validation scripts for attestation tokens.

1. Install dependencies:
   ```bash
   cd py/
   uv sync --all-extras
   ```
2. Validate example attestation tokens stored in `py/data/`:
   ```bash
   uv run pki_attestation_validation.py
   uv run oidc_attestation_validation.py
   ```

**Note:** Tokens in `py/data/` may expire and fail validation.
