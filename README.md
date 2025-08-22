# Universal NFT - Solana Cross-Chain NFT DApp

## Project Overview

Universal NFT is a Solana-based decentralized application (dApp) that enables minting, sending, and receiving non-fungible tokens (NFTs) across blockchains using ZetaChain’s cross-chain messaging protocol. Built with the Anchor framework, this program integrates with ZetaChain’s Solana gateway (program ID: `ZETAjseVjuFsxdRxo6MmTCvqFwb3ZHUx56Co3vCmGis`) to support seamless NFT transfers between Solana, ZetaChain, Ethereum, and BNB Chain, replicating the functionality of ZetaChain’s EVM Universal NFT. It addresses Solana-specific challenges like compute budget, rent exemptions, and token account creation, and ensures security through Threshold Signature Scheme (TSS) authentication, nonce-based replay protection, and chain ID commitments.

This project fulfills the requirements of [zeta-chain/standard-contracts issue #72](https://github.com/zeta-chain/standard-contracts/issues/72), providing a secure, open-source solution for cross-chain NFT interoperability with comprehensive documentation and developer-friendly examples.

## Features
- **Mint NFTs**: Create SPL Token-based NFTs with Metaplex metadata on Solana.
- **Send NFTs**: Burn NFTs on Solana and send cross-chain messages to ZetaChain for minting on destination chains (e.g., Ethereum, BNB Chain).
- **Receive NFTs**: Mint or transfer NFTs on Solana based on ZetaChain’s cross-chain messages, verified via TSS ECDSA signatures.
- **Security**: Implements nonce replay protection, TSS authentication, and chain ID commitments to prevent cross-chain replays.
- **Solana Optimization**: Handles compute budget limits, rent-exempt accounts, and Associated Token Account (ATA) creation.

## Setup Instructions

### Prerequisites
- **Rust**: Version 1.81.0 or later
- **Solana CLI**: Version 2.1.0
- **Anchor CLI**: Version 0.31.0
- **Node.js**: Version 16 or later
- **Yarn**: Latest version
- **Git**: For cloning the repository

### Installation
```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Install Solana CLI
sh -c "$(curl -sSfL https://release.anza.xyz/v2.1.0/install)"

# Install Anchor CLI
cargo install --git https://github.com/coral-xyz/anchor avm --force
avm install 0.31.0
avm use 0.31.0

# Install Node.js dependencies
npm install -g yarn
cd ZetaSolNFT
yarn install
```

### Build
```bash
# Build the program
anchor build
```

### Test
Run tests on a local Solana validator to verify minting, sending, and receiving NFTs:
```bash
# Start local validator
solana-test-validator --reset &

# Run tests
anchor test
```

**Note**: If you encounter errors on macOS (e.g., "Unable to get latest blockhash" or "Archive error"), install GNU tar:
```bash
# For Apple Silicon
brew install gnu-tar
echo 'export PATH="/opt/homebrew/opt/gnu-tar/libexec/gnubin:$PATH"' >> ~/.zshrc

# For Intel-based Mac
brew install gnu-tar
echo 'export PATH="/usr/local/opt/gnu-tar/libexec/gnubin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

### Generate Go Bindings
For development environments (localnet):
```bash
make generate-dev
```

For production (mainnet, testnet):
```bash
make generate-prod
```

## Deployment
Deploy the program to Solana devnet:
```bash
anchor deploy --provider.cluster devnet
```

**Program ID**: `<YourProgramID>` (replace with the actual ID from `anchor deploy`)

**Devnet Transaction Hash**: `<YourTransactionHash>` (replace with the hash of a cross-chain NFT transfer, verifiable on ZetaChain explorer)

## Usage
Interact with the program using Anchor CLI or a client SDK. Below are example commands for each instruction.

### Initialize
Set up the program’s configuration with admin, chain ID, and TSS address.
```bash
anchor run initialize --admin <admin-pubkey> --chain-id 90 --tss-address <20-byte-tss-address>
```

### Mint NFT
Mint an NFT with Metaplex metadata.
```bash
anchor run mint_nft --uri "https://example.com/nft.json" --name "MyNFT" --symbol "NFT"
```

### Send NFT
Burn an NFT and send a cross-chain message to ZetaChain.
```bash
anchor run send_nft --destination-chain 1 --recipient <32-byte-recipient-address>
```

### Receive NFT
Mint or transfer an NFT based on a ZetaChain cross-chain message (called by the gateway with TSS signature).
```bash
# Handled by ZetaChain gateway (not directly invoked)
```

## API Reference
### Instructions
- **`initialize(admin: Pubkey, chain_id: u16, tss_address: [u8; 20])`**
  - Initializes the program’s `Config` account with admin, Solana chain ID (e.g., 90 for mainnet-beta), and ZetaChain TSS address.
  - Accounts:
    - `config`: PDA (`seeds = [b"config"]`), stores state.
    - `payer`: Signer, pays for account creation.
    - `system_program`: Solana system program.
- **`mint_nft(uri: String, name: String, symbol: String)`**
  - Mints an SPL Token NFT (supply 1, decimals 0) with Metaplex metadata.
  - Accounts:
    - `payer`: Signer, pays for minting.
    - `mint`: SPL Token mint account.
    - `token_account`: User’s ATA for the NFT.
    - `metadata`: Metaplex metadata account.
    - `mint_authority`: PDA (`seeds = [b"mint_authority"]`).
    - `token_program`, `metadata_program`, `system_program`, `rent`.
- **`send_nft(destination_chain: u16, recipient: [u8; 32])`**
  - Burns the NFT and sends a cross-chain payload to ZetaChain via the gateway.
  - Accounts:
    - `owner`: Signer, NFT owner.
    - `user_token_account`: Owner’s ATA.
    - `mint`: NFT mint account.
    - `nonce`: PDA (`seeds = [b"nonce"]`) for replay protection.
    - `gateway_program`: ZetaChain gateway program.
    - `gateway_pda`: Gateway’s meta PDA.
    - `token_program`.
- **`receive_nft(payload: Vec<u8>, proof: VerificationProof)`**
  - Mints an NFT to the recipient after verifying the TSS signature and nonce.
  - Accounts:
    - `recipient`: NFT recipient.
    - `mint`: NFT mint account.
    - `mint_authority`: PDA for minting.
    - `recipient_token_account`: Recipient’s ATA.
    - `nonce`: PDA for replay protection.
    - `config`: Program config for TSS address and chain ID.
    - `token_program`.

### Accounts
- **`Config`**: Stores `admin` (Pubkey), `chain_id` (u16), `nonce` (u64), `tss_address` ([u8; 20]).
- **`NonceAccount`**: Stores `nonce` (u64) for replay protection.
- **PDA Seeds**:
  - `config`: `b"config"`
  - `mint_authority`: `b"mint_authority"`
  - `nonce`: `b"nonce"`

### Events
- **`MintEvent`**: Emitted on NFT minting (`mint: Pubkey`, `owner: Pubkey`).
- **`SendEvent`**: Emitted on NFT send (`mint: Pubkey`, `destination_chain: u16`, `recipient: [u8; 32]`).
- **`ReceiveEvent`**: Emitted on NFT receipt (`mint: Pubkey`, `recipient: Pubkey`).

## Security
- **TSS Authentication**: Uses ECDSA secp256k1 signatures verified via `recover_eth_address`, ensuring only ZetaChain’s TSS can authorize `receive_nft`.
- **Replay Protection**: Increments and checks nonces in `send_nft` and `receive_nft` to prevent message replays.
- **Chain ID Commitment**: Includes Solana chain ID in message hashes to prevent cross-chain replays.
- **Access Control**: Only the admin can initialize; anyone can mint or send NFTs; only TSS-signed messages can trigger receiving.

## Cross-Chain Demo
To demonstrate cross-chain functionality:
1. Deploy the program to Solana devnet.
2. Initialize with a valid TSS address.
3. Mint an NFT on Solana.
4. Send the NFT to ZetaChain (destination chain: 1 for Ethereum, 56 for BNB Chain).
5. Verify the NFT mint on the destination chain via ZetaChain explorer.
6. Send an NFT from ZetaChain back to Solana, triggering `receive_nft`.

**Devnet Transaction Hash**: `<YourTransactionHash>` (replace with actual hash)

## Testing
Unit tests are in `tests/zetasolnft.ts`, covering:
- Initialization of config.
- Minting NFTs with Metaplex metadata.
- Sending NFTs with gateway CPI.
- Receiving NFTs with mock TSS signatures.

Run:
```bash
anchor test
```

## Troubleshooting
- **Build Errors**: Ensure Anchor 0.31.0 and Solana CLI 2.1.0 are installed.
- **Test Validator Errors**: Check `test-ledger/validator.log` and increase `[test.startup_wait]` in `Anchor.toml` if needed.
- **macOS Tar Issues**: Install GNU tar as shown above.

## Bonus: Developer Onboarding
### Quickstart Guide
1. Clone the repository: `git clone https://github.com/rainman456/ZetaSolNFT`
2. Install dependencies and build as above.
3. Deploy to devnet and run the cross-chain demo.
4. Use the provided CLI commands to interact with the program.

### Reusable Components
- **Anchor Macro**: A planned macro for simplifying ZetaChain gateway CPIs.
- **Client SDK**: Example JavaScript client in `client/` for interacting with the program.

## Resources
- [ZetaChain Solana Docs](https://www.zetachain.com/docs/developers/chains/solana/)
- [ZetaChain Gateway](https://github.com/zeta-chain/protocol-contracts-solana)
- [Issue #72](https://github.com/zeta-chain/standard-contracts/issues/72)
- [Example Connected Program](https://github.com/zeta-chain/protocol-contracts-solana/blob/main/programs/examples/connected/src/lib.rs)

## About
A Solana program for cross-chain NFT transfers, built for ZetaChain interoperability.  
Website: [zetachain.com](https://zetachain.com)  
Topics: Solana, ZetaChain, NFT, cross-chain, Anchor

## License
MIT License
