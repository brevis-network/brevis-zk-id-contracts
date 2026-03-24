# Agent Instructions

## Source of Truth
- Product source-of-truth for requirements lives in the parent framework repository under `docs/requirement/` (not in this standalone package).
- Canonical requirement file for this project:
  - `docs/requirement/requirement_onchain.md` (parent framework repo)
- For any design or implementation task in this project, read the on-chain requirement file first.
- Do not modify files under `docs/requirement/` in the parent framework repository. Requirement updates are user-owned.

## Domains
- `onchain` only

## Canonical Domain Documents
- For this standalone on-chain package, `README.md` is the canonical architecture/flows/toolchain document.
- Do not maintain separate `REQUIREMENTS.md` or `SPEC.md` files.

## Workflow
- For any domain change:
  1. Read the scoped requirement file.
  2. Update `Design.md` if the design is affected.
  3. Implement.
- If `Design.md` is missing or stale, flag it before implementing.

## Code Comments
- Solidity comments must be self-contained.
- Public/external functions: NatSpec (`@notice`, `@dev`, `@param`, `@return`).
- Non-trivial logic: inline `//` comments (invariants, failure ordering, key derivation, counter transitions).
- Interface files: file-level NatSpec header (`@title`, `@author`, `@notice`) plus per-function `@notice`, `@param`, `@return`.

## Change Tracking
- No changelog files.
- When `AGENTS.md` changes, check downstream docs for stale references.
