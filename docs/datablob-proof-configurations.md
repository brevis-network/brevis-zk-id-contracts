# Datablob Proof Configurations

This document defines data source proof output formats and IdentityProperty references for app services.

Scope notes:
- Product requirement source of truth remains docs/requirements.md.
- Numeric outputs are documented as integer types (uint256).
- String type is used only for non-numeric labels/enums.
- Threshold parameters are configurable at request time and may vary by business scenario.

## IdentityProperty Convention

IdentityProperty is a provider-scoped identifier used by app services and verifier-key management.

Format:
- providerId: bytes32 provider identifier (already registered on-chain)
- identityProperty: bytes32 property identifier

Rationale:
- Avoids collisions across providers.
- Keeps property assignment deterministic for off-chain and on-chain systems.
- Supports additive growth without renumbering.

## Provider-Centric Datablob Structure

Use the following hierarchy for app-service references:

- ProviderName (ProviderId)
- IdentityDescription (IdentityProperty)
- Datablob structure (Solidity struct)

### Binance (0x099e8cf4d817a6e4eec62bff4cdef05faa4a00fcde8d7e99f5090708d23ad9b2)

Suggested provider blob name: `BinanceKycTradingProfileV1`

IdentityDescription: Binance_KYC_Trading_Profile (IdentityProperty)
- identityProperty: `0xa8b86ba89172f269976e3ef2dafed6de381b92a6d19a2ab848273b6f8db69c7c` (KYC trade count route)
- output schema:
    - `kycLevel`: `"intermediate"`, `"advanced"`, `"advanced_pro"`, `"none"`
    - `spotTradeHistoryLast6Months`: numeric count (e.g. `53`, `0`)

```solidity
struct BinanceKycTradingProfileV1 {
    string kycLevel;
    uint256 spotTradeHistoryLast6Months;
}
```

### OKX (0xd6b6d5e0aacce0469a313983d889ed10d0bb7c9545af0285a19b4ff094b4041d)

Suggested provider blob name: `OkxKycTradingProfileV1`

IdentityDescription: OKX_KYC_Trading_Profile (IdentityProperty)
- identityProperty: `0x289d4fed0b3ecb26e711e6d1200b46f1d67f2da4847b03f99aa8584706933195` (KYC trade count route)
- output schema:
    - `kycLevel`: `"Level 1"`, `"Level 2"`, `"Level 3"`, `"none"`
    - `tradeHistoryLast6Months`: numeric count (e.g. `53`, `0`)

```solidity
struct OkxKycTradingProfileV1 {
    string kycLevel;
    uint256 tradeHistoryLast6Months;
}
```

### GitHub (0x07a17bd3c7c8d7b88e93a4d9007e3bc230b0a586a434de0bed6500e9f343deb7)

Suggested provider blob name: `GithubAccountContributionProfileV1`

IdentityDescription: GitHub_Account_Contribution_Profile (IdentityProperty)
- identityProperty: `0x0e5adf3535913ff915e7f062801a0f3a165711cb26709ec9574a9c45e091c7ff` (Creation contribution route)
- output schema:
    - `accountEarliestYear`: year (e.g. `2024`, `0`)
    - `contributionsLastYear`: numeric count (e.g. `17`, `0`)

```solidity
struct GithubAccountContributionProfileV1 {
    uint256 accountEarliestYear;
    uint256 contributionsLastYear;
}
```

### Steam (0x916a4e1d9663cd29f23da1f15fdd5a0908ceed01f5fe580407b2aa4509077dda)

Suggested provider blob name: `SteamAccountValueProfileV1`

IdentityDescription: Steam_Account_Value_Profile (IdentityProperty)
- identityProperty: `0xab7ca68fb0d5fb64b53a938930b00a040af3d9a819756883d9bea6367ab84c08` (Special score route)
- output schema:
    - `accountEarliestYear`: year (e.g. `2023`, `0`)
    - `limitedAccountStatus`: `"Limited Account"` or `"Not Limited Account"`
    - `gameLibraryValue`: numeric net value (e.g. `80`, `0`)

```solidity
struct SteamAccountValueProfileV1 {
    uint256 accountEarliestYear;
    string limitedAccountStatus;
    uint256 gameLibraryValue;
}
```

### Amazon (0xb5cc0e0322dd67209d90babc2c95e7c381be7d675597a0d03e9dd4b60cfa8758)

Suggested provider blob name: `AmazonMembershipOrderProfileV1`

IdentityDescription: Amazon_Membership_Order_Profile (IdentityProperty)
- identityProperty: `0xc8e54ecd3ffce098897c6ed6f58d818d83ef46ecb043158d8929433b505ba944` (Prime status years route)
- output schema:
    - `accountEarliestYear`: year (e.g. `2024`, `0`)
    - `primeMemberStatus`: `"Prime"` or `"Not Prime"`
    - `ordersCountByYear`: `[{ year: 2026, count: 3 }, { year: 2025, count: 0 }]`

```solidity
struct AmazonOrderCountByYear {
    uint256 year;
    uint256 count;
}

struct AmazonMembershipOrderProfileV1 {
    uint256 accountEarliestYear;
    string primeMemberStatus;
    AmazonOrderCountByYear[] ordersCountByYear;
}
```

## App Service Decoding Rules

- Decode numeric values as uint256.
- Decode label/status outputs as string.
- For year-count data, decode as tuple(uint256 year, uint256 count)[] and avoid comma-delimited strings.
- If no data exists, use the sentinel values listed above.
