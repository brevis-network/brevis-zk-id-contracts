# Identity Registry Deployment Scripts

## 1) Quick setup

1. Copy templates:
   ```bash
   cp scripts/.env.example .env
   cp scripts/example_config.json config.json
   ```

2. Edit `.env` and `config.json`:
   - `.env` must include `RPC_URL`, `PRIVATE_KEY`, and `DEPLOY_CONFIG=config.json`.
   - `config.json` holds addresses and parameters. See `scripts/example_config.json` for the schema.

Notes:
- The deployer is the initial owner of ProxyAdmin and IdentityRegistry.
- For production, transfer ProxyAdmin ownership to a multisig after deployment.

## 2) Deploy

### Step 1: Deploy ProxyAdmin (one-time per network)

```bash
forge script scripts/DeploySharedProxyAdmin.s.sol --rpc-url $RPC_URL --broadcast --verify -vv
```

Copy the printed address into `config.json` under `proxyAdmin.address`.

### Step 2: Deploy PicoVerifier

For production (Groth16 verification):
```bash
forge script scripts/DeployPicoVerifier.s.sol --rpc-url $RPC_URL --broadcast --verify -vv
```

For devnet/testing (mock verification):
```bash
forge script scripts/DeployMockPicoVerifier.s.sol --rpc-url $RPC_URL --broadcast --verify -vv
```

Copy the printed address into `config.json` under `registry.picoVerifier`.

### Step 3: Deploy IdentityRegistry (upgradeable via TransparentProxy)

```bash
forge script scripts/DeployIdentityRegistry.s.sol --rpc-url $RPC_URL --broadcast --verify -vv
```

This deploys the implementation, then wraps it in a `TransparentUpgradeableProxy` with `init()` calldata. The deployer becomes the registry owner.

Where to find addresses:
- The script prints all addresses at the end.
- They're also saved to `broadcast/DeployIdentityRegistry.s.sol/<chainId>/run-latest.json`.

### Implementation-only deployment (for upgrades)

To deploy only a new implementation without creating a proxy (for use with `ProxyAdmin.upgrade()`):

Set in `config.json`:
```json
{ "registry": { "implementationOnly": true } }
```

Then run the same script — it will deploy and print the implementation address without creating a proxy.

## 3) Post-deployment setup

After deploying the registry proxy, the owner should:

1. **Grant roles:**
   - `grantRole(GOVERNANCE_ROLE, governanceAddress)` — for provider/app lifecycle
   - `grantRole(PAUSER_ROLE, pauserAddress)` — for emergency pause

2. **Set verification keys:**
   - `setVerifierKey(identityProperty, riscvVkey)` — for each supported identity property

3. **Register providers:**
   - `registerProvider(providerId, name, metadata)` — requires GOVERNANCE_ROLE

## 4) After deployment

- **Verification**: `--verify` usually handles all contracts. If anything remains unverified, use the block explorer's "Verify & Publish" UI.
- **Proxy ABI**: Verify both the proxy and implementation. Explorers auto-link them.
- **Transfer ownership**: Call `transferOwnership(multisig)` on the registry and `transferOwnership(multisig)` on the ProxyAdmin via the explorer UI.
- **Upgrades**: Deploy a new implementation with `implementationOnly: true`, then call `ProxyAdmin.upgrade(proxy, newImpl)` via the explorer.

## 5) Config reference

`example_config.json`:

| Field | Required | Description |
|-------|----------|-------------|
| `proxyAdmin.address` | Optional | Shared ProxyAdmin address. Auto-deployed if empty. |
| `registry.picoVerifier` | Yes | PicoVerifier (or MockPicoVerifier) contract address |
| `registry.implementationOnly` | Optional | Set `true` to skip proxy deployment (for upgrades) |
