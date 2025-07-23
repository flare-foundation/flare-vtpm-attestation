Refactor `FlareVtpmAttestation` (and its verifier contracts) to support on‑chain upgrades via OpenZeppelin’s UUPS proxy pattern. As requirements evolve (new token types, bug fixes, performance optimizations), we need the ability to patch or extend logic without redeploying fresh contracts and losing existing state. UUPS proxies provide a lightweight, permissioned upgrade mechanism.

**Proposed Changes**

* Inherit Upgradeable Base Contracts
  
  * Replace `Ownable` with `OwnableUpgradeable`
  * In verifiers (e.g. `OidcSignatureVerification`) and `FlareVtpmAttestation`, inherit from `UUPSUpgradeable` in addition to `OwnableUpgradeable`.
* Initialize Instead of Constructor
  
  * Add an `initialize(...) initializer` function to each contract that:
    
    * Calls `__Ownable_init()`
    * Sets any necessary initial state (e.g. `requiredConfig`, initial verifiers)
  * Remove logic from constructors.
* Implement `_authorizeUpgrade(address newImpl) internal override onlyOwner` in each contract.
* Update `FlareVtpmAttestation.s.sol` to deploy an `ERC1967Proxy` pointing to the logic implementation and call `initialize` with env vars.
* Write a Forge test that:
  
  1. Deploys via proxy
  2. Calls `verifyAndAttest` to register a quote
  3. Upgrades the implementation to a dummy “v2” contract that adds a new function
  4. Verifies state (registered quote) is preserved and new function is callable.

**Acceptance Criteria**

* Contracts compile with OpenZeppelin Upgradeable imports.
* Proxy deployment script successfully initializes state.
* Owner can call `upgradeTo(...)` via proxy.
* Existing storage (registered quotes, pubKeys) remains intact after upgrade.
* Forge tests demonstrate upgrade flow and state preservation.