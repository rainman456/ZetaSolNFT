// programs/universal-nft/src/state.rs

use anchor_lang::prelude::*;

#[account]
#[derive(InitSpace)]
pub struct ProgramConfig {
    pub tss_address: [u8; 20],      // TSS ECDSA address (Ethereum format)
    pub authority: Pubkey,          // Program authority (can update config)
    pub nonce: u64,                 // Current nonce for replay protection
    pub paused: bool,               // Emergency pause switch
    #[max_len(10)]
    pub supported_chains: Vec<String>, // Supported blockchain networks
}

#[account]
#[derive(InitSpace)]
pub struct NFTMetadata {
    #[max_len(32)]
    pub name: String,
    #[max_len(10)]
    pub symbol: String,
    #[max_len(200)]
    pub uri: String,
    pub mint: Pubkey,
    #[max_len(20)]
    pub original_chain: String,
    #[max_len(66)]
    pub original_token_id: String,
    pub owner: Pubkey,
}

#[account]
#[derive(InitSpace)]
pub struct CrossChainState {
    pub nft_mint: Pubkey,
    #[max_len(20)]
    pub source_chain: String,
    #[max_len(20)]
    pub destination_chain: String,
    #[max_len(66)]
    pub destination_address: String,
    pub nonce: u64,
    pub status: u8,        // 0: Pending, 1: Completed, 2: Failed
    pub timestamp: i64,
    pub processed: bool,   // Flag to prevent replay attacks
}

// Constants for the program
pub mod constants {
    pub const SOLANA_CHAIN_ID: u64 = 90;
    pub const META_SEED: &[u8] = b"meta";
    pub const NFT_SEED: &[u8] = b"nft";
    pub const CROSS_CHAIN_SEED: &[u8] = b"cross_chain";
    pub const CONFIG_SEED: &[u8] = b"config";
    pub const NONCE_SEED: &[u8] = b"nonce";
    
    // Compute budget constants
    pub const MAX_COMPUTE_UNITS: u32 = 200_000;
    
    // Gateway PDAs
    pub const GATEWAY_META_ADDRESS: &str = "2f9SLuUNb7TNeM6gzBwT4ZjbL5ZyKzzHg1Ce9yiquEjj";
    pub const GATEWAY_RENT_PAYER_ADDRESS: &str = "Am1aA3XQciu3vMG6E9yLa2Y9TcTf2XB3D3akLtjVzu3L";
}

// Error codes for the program
#[error_code]
pub enum ErrorCode {
    #[msg("The provided gateway address is invalid")]
    InvalidGateway,
    
    #[msg("The signer is not authorized to perform this action")]
    InvalidSigner,
    
    #[msg("The provided nonce is invalid or has been used")]
    InvalidNonce,
    
    #[msg("The NFT is invalid or does not exist")]
    InvalidNFT,
    
    #[msg("An error occurred during cross-chain communication")]
    CrossChainError,
    
    #[msg("The program is currently paused")]
    ProgramPaused,
    
    #[msg("The specified chain is not supported")]
    UnsupportedChain,
    
    #[msg("Too many chains specified (max 10)")]
    TooManyChains,
    
    #[msg("Invalid TSS signature")]
    InvalidTssSignature,
    
    #[msg("Message already processed (replay attempt)")]
    ReplayAttempt,
    
    #[msg("Compute budget exceeded")]
    ComputeBudgetExceeded,
    
    #[msg("Invalid message format")]
    InvalidMessageFormat,
    
    #[msg("Invalid chain ID")]
    InvalidChainId,
}
