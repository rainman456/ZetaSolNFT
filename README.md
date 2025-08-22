# Universal NFT - Solana Cross-Chain NFT DApp

## Project Overview

Universal NFT is a Solana-based decentralized application (dApp) enabling minting and seamless cross-chain transfer of NFTs using the ZetaChain cross-chain messaging protocol. This project demonstrates minting NFTs on Solana, sending them across chains, and receiving them on a destination chain with secure verification and nonce replay protection.

---

## Setup Instructions

### Prerequisites

- Rust (latest stable)
- Solana CLI (>=1.14)
- Anchor CLI (v0.24.2)
- Node.js (>=16)
- Yarn or NPM

### Installation

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install Solana CLI
sh -c "$(curl -sSfL https://release.solana.com/v1.14.17/install)"

# Install Anchor CLI
cargo install --git https://github.com/project-serum/anchor anchor-cli --locked --version 0.24.2

# Install Node.js dependencies
npm install -g yarn
yarn install