---
anvil: major
foundry-primitives: major
foundry-evm-core: major
foundry-cheatcodes: minor
---

Replaced the obsolete FrameTx devnet envelope with EIP-8250's nested fees, current nonce selectors and first-use state gas. Added EIP-8272 verifier-frame encoding and removed the legacy native root shortcut. Removed the declined EIP-7819 and EIP-7851 flags and execution support; EIP-7702 and opt-in EIP-8151 remain supported.
