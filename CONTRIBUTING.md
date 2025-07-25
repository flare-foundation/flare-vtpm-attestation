# Contributing to Flare vTPM Attestation

First off, thank you for considering contributing to Flare vTPM Attestation

We welcome contributions from the community to help make this library robust, feature-rich, and easy to use.

## How to Contribute

- **Pull Requests (PRs)** for bug fixes, features, and documentation updates.
- **Bug Reports** for issues you encounter.

## ✨ Write High-Quality Code

We strive for high-quality, maintainable code. Please adhere to the following principles:

- **NatSpec Documentation**

  - Document all public and external functions using NatSpec tags:

    ```solidity
    /// @notice Short description of the function's purpose
    /// @param  foo    Description of parameter `foo`
    /// @return bar    Description of the return value
    function example(uint256 foo) external returns (uint256 bar) { ... }
    ```

  - Include `@dev` for implementation details and `@custom:error` for custom errors if needed.

- **Visibility and Mutability**

  - Explicitly declare visibility for all state variables and functions (`public`, `external`, `internal`, `private`).
  - Use `view` and `pure` modifiers where applicable to indicate read-only operations.
  - Favor `immutable` for constructor-set variables and `constant` for compile-time constants.

- **Custom Errors and Reverts**

  - Use custom errors for gas-efficient revert reasons:

    ```solidity
    error Unauthorized(address caller);
    ```

  - Replace `require` with custom errors when reverting:

    ```solidity
    if (msg.sender != owner) revert Unauthorized(msg.sender);
    ```

- **Gas Efficiency**

  - Favor short-circuiting and early returns to minimize gas usage.
  - Pack state variables to reduce storage slots: declare smaller types together.
  - Cache repeated state reads in memory variables.
  - Avoid unbounded loops and external calls within loops.

- **Security & Patterns**

  - Follow the **Checks-Effects-Interactions** pattern for state changes and external calls.
  - Use [OpenZeppelin Contracts](https://github.com/OpenZeppelin/openzeppelin-contracts) for battle-tested implementations (e.g., access control, ERC standards).
  - Avoid inline assembly unless absolutely necessary and document its use clearly.
  - Validate all external inputs and casting operations.

- **Interfaces and Modularity**

  - Keep interfaces minimal and purpose-specific (`IAttestation`, `IVerification`).
  - Split large contracts into smaller components (e.g., `utils/`, `verifiers/`).
  - Leverage libraries for shared logic (`ParserUtils`, `CryptoUtils`, etc.).

## 🧪 Test Extensively

**Ensure robust coverage and reliability of Solidity code:**

- **Unit Tests**

  - Place all tests under the `test/` directory. Name your test contracts `<ContractName>.t.sol` for clarity.
  - New features **must** include unit tests covering both success and failure (revert) scenarios.
  - Bug fixes **should** include tests that demonstrate the failure before the fix and the pass after.
  - Use `setUp()` in your test contract to initialize common fixtures.

- **Integration & Edge Cases**

  - For cross-contract flows, write integration-style tests in Foundry as additional test files.
  - Mock external calls or dependencies as needed (e.g., use custom or stub verifier contracts).

- **Gas & Performance**

  - Include gas-reporting tests to monitor regressions:

    ```bash
    forge test --gas-report
    ```

  - Review gas usage in your tests and optimize hotspots if necessary.

- **Running Tests Locally**

  - **All tests must pass** before submitting a pull request:

    ```bash
    forge test -vv
    ```

  - The `-vv` flag provides verbose logs for debugging.

- **Coverage & Quality**

  - Aim for comprehensive coverage across public and external functions.
  - If gaps exist, add targeted tests to cover edge cases and error branches.

## 🚨 CI Checks Must Pass

- We use Continuous Integration (CI) pipelines (e.g., GitHub Actions) to automatically run linters, type checkers, and tests.
- **Pull requests will only be considered for merging if all CI checks pass.** Ensure your code meets all quality gates before submitting.

## ✅ Use Conventional Commits

- All commit messages **MUST** adhere to the **Conventional Commits** specification. This helps automate changelog generation and provides a clear commit history.
- Please read the specification: [https://www.conventionalcommits.org/](https://www.conventionalcommits.org/)
- **Format:** `<type>[optional scope]: <description>`
- **Examples:**
  - `feat(contracts): add PKIValidator chain verification logic`
  - `fix(utils): correct extractUintValue parsing in ParserUtils`
  - `docs(interfaces): update NatSpec comments in IAttestation.sol`
  - `test(FlareVtpmAttestation): cover expired-token revert case`
  - `chore(foundry): bump Solidity compiler to ^0.8.27 in foundry.toml`

## 📜 License

By contributing to Flare vTPM Attestation, you agree that your contributions will be licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for more information.

Thank you for contributing!
