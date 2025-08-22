// programs/universal-nft/src/lib.rs

use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    program::{invoke, invoke_signed},
    system_instruction,
};
use anchor_spl::{
    associated_token::AssociatedToken,
    token::{Mint, Token, TokenAccount},
    token_2022::{Token2022, mint_to, burn, initialize_mint2, set_authority},
};
use std::str::FromStr;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod universal_nft {
    use super::*;

    /// Initialize the Universal NFT program with the ZetaChain gateway
    pub fn initialize(
        ctx: Context<Initialize>,
        supported_chains: Vec<String>,
    ) -> Result<()> {
        let config = &mut ctx.accounts.config;
        
        // Initialize program config
        config.gateway_address = ctx.accounts.gateway_address.key();
        config.admin = ctx.accounts.admin.key();
        config.paused = false;
        
        // Store supported chains
        require!(supported_chains.len() <= 10, ErrorCode::TooManyChains);
        config.supported_chains = supported_chains;
        
        msg!("Universal NFT program initialized");
        Ok(())
    }

    /// Update the program configuration
    pub fn update_config(
        ctx: Context<UpdateConfig>,
        new_gateway_address: Option<Pubkey>,
        new_admin: Option<Pubkey>,
        paused: Option<bool>,
        supported_chains: Option<Vec<String>>,
    ) -> Result<()> {
        let config = &mut ctx.accounts.config;
        
        // Verify the admin is the signer
        require!(
            ctx.accounts.admin.key() == config.admin,
            ErrorCode::InvalidSigner
        );
        
        // Update gateway address if provided
        if let Some(gateway) = new_gateway_address {
            config.gateway_address = gateway;
        }
        
        // Update admin if provided
        if let Some(admin) = new_admin {
            config.admin = admin;
        }
        
        // Update paused state if provided
        if let Some(pause_state) = paused {
            config.paused = pause_state;
        }
        
        // Update supported chains if provided
        if let Some(chains) = supported_chains {
            require!(chains.len() <= 10, ErrorCode::TooManyChains);
            config.supported_chains = chains;
        }
        
        msg!("Program configuration updated");
        Ok(())
    }

    /// Mint a new NFT from a cross-chain message
    pub fn mint_nft(
        ctx: Context<MintNft>,
        name: String,
        symbol: String,
        uri: String,
        original_chain: String,
        original_token_id: String,
        nonce: u64,
    ) -> Result<()> {
        // Check if program is paused
        require!(!ctx.accounts.config.paused, ErrorCode::ProgramPaused);
        
        // Verify the gateway account
        require!(
            ctx.accounts.gateway.key() == ctx.accounts.config.gateway_address,
            ErrorCode::InvalidGateway
        );
        
        // Verify the chain is supported
        let is_supported = ctx.accounts.config.supported_chains.iter()
            .any(|chain| chain == &original_chain);
        require!(is_supported, ErrorCode::UnsupportedChain);
        
        // Initialize the mint account
        let cpi_accounts = anchor_spl::token_2022::InitializeMint2 {
            mint: ctx.accounts.mint.to_account_info(),
            rent: ctx.accounts.rent.to_account_info(),
        };
        
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_context = CpiContext::new(cpi_program, cpi_accounts);
        
        // Initialize mint with 0 decimals (NFT standard)
        initialize_mint2(cpi_context, 0, &ctx.accounts.payer.key(), Some(&ctx.accounts.payer.key()))?;
        
        // Create associated token account if it doesn't exist
        let cpi_accounts = anchor_spl::associated_token::Create {
            payer: ctx.accounts.payer.to_account_info(),
            associated_token: ctx.accounts.token_account.to_account_info(),
            authority: ctx.accounts.recipient.to_account_info(),
            mint: ctx.accounts.mint.to_account_info(),
            system_program: ctx.accounts.system_program.to_account_info(),
            token_program: ctx.accounts.token_program.to_account_info(),
            rent: ctx.accounts.rent.to_account_info(),
        };
        
        let cpi_program = ctx.accounts.associated_token_program.to_account_info();
        let cpi_context = CpiContext::new(cpi_program, cpi_accounts);
        
        anchor_spl::associated_token::create(cpi_context)?;
        
        // Mint token to recipient
        let cpi_accounts = anchor_spl::token_2022::MintTo {
            mint: ctx.accounts.mint.to_account_info(),
            to: ctx.accounts.token_account.to_account_info(),
            authority: ctx.accounts.payer.to_account_info(),
        };
        
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_context = CpiContext::new(cpi_program, cpi_accounts);
        
        // Mint exactly 1 token (NFT standard)
        mint_to(cpi_context, 1)?;
        
        // Store NFT metadata
        let metadata = &mut ctx.accounts.metadata;
        metadata.name = name;
        metadata.symbol = symbol;
        metadata.uri = uri;
        metadata.mint = ctx.accounts.mint.key();
        metadata.original_chain = original_chain;
        metadata.original_token_id = original_token_id;
        metadata.owner = ctx.accounts.recipient.key();
        
        msg!("NFT minted successfully");
        Ok(())
    }

    /// Send an NFT to another chain via ZetaChain
    pub fn send_nft(
        ctx: Context<SendNft>,
        destination_chain: String,
        destination_address: String,
        nonce: u64,
    ) -> Result<()> {
        // Check if program is paused
        require!(!ctx.accounts.config.paused, ErrorCode::ProgramPaused);
        
        // Verify the gateway account
        require!(
            ctx.accounts.gateway.key() == ctx.accounts.config.gateway_address,
            ErrorCode::InvalidGateway
        );
        
        // Verify the chain is supported
        let is_supported = ctx.accounts.config.supported_chains.iter()
            .any(|chain| chain == &destination_chain);
        require!(is_supported, ErrorCode::UnsupportedChain);
        
        // Verify the owner is the signer
        require!(
            ctx.accounts.owner.key() == ctx.accounts.metadata.owner,
            ErrorCode::InvalidSigner
        );
        
        // Burn the NFT
        let cpi_accounts = anchor_spl::token_2022::Burn {
            mint: ctx.accounts.mint.to_account_info(),
            from: ctx.accounts.token_account.to_account_info(),
            authority: ctx.accounts.owner.to_account_info(),
        };
        
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_context = CpiContext::new(cpi_program, cpi_accounts);
        
        // Burn exactly 1 token (NFT standard)
        burn(cpi_context, 1)?;
        
        // Create cross-chain state to track the transfer
        let cross_chain_state = &mut ctx.accounts.cross_chain_state;
        cross_chain_state.nft_mint = ctx.accounts.mint.key();
        cross_chain_state.source_chain = "solana".to_string();
        cross_chain_state.destination_chain = destination_chain;
        cross_chain_state.destination_address = destination_address;
        cross_chain_state.nonce = nonce;
        cross_chain_state.status = 0; // Pending
        cross_chain_state.timestamp = Clock::get()?.unix_timestamp;
        
        // Here we would call the ZetaChain gateway to initiate the cross-chain transfer
        // This is a placeholder for the actual ZetaChain gateway integration
        // In a real implementation, we would serialize the NFT data and send it to the gateway
        
        msg!("NFT sent to another chain");
        Ok(())
    }

    /// Handle incoming NFT from another chain
    pub fn receive_nft(
        ctx: Context<ReceiveNft>,
        source_chain: String,
        source_address: String,
        nonce: u64,
    ) -> Result<()> {
        // Check if program is paused
        require!(!ctx.accounts.config.paused, ErrorCode::ProgramPaused);
        
        // Verify the gateway account
        require!(
            ctx.accounts.gateway.key() == ctx.accounts.config.gateway_address,
            ErrorCode::InvalidGateway
        );
        
        // Verify the chain is supported
        let is_supported = ctx.accounts.config.supported_chains.iter()
            .any(|chain| chain == &source_chain);
        require!(is_supported, ErrorCode::UnsupportedChain);
        
        // Update cross-chain state
        let cross_chain_state = &mut ctx.accounts.cross_chain_state;
        cross_chain_state.status = 1; // Completed
        
        // In a real implementation, we would verify the cross-chain message from the gateway
        // and extract the NFT data from it
        
        msg!("NFT received from another chain");
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = admin,
        space = 8 + ProgramConfig::INIT_SPACE,
        seeds = [b"config"],
        bump
    )]
    pub config: Account<'info, ProgramConfig>,
    
    /// CHECK: This is the gateway address that will be stored
    pub gateway_address: UncheckedAccount<'info>,
    
    #[account(mut)]
    pub admin: Signer<'info>,
    
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct UpdateConfig<'info> {
    #[account(mut)]
    pub config: Account<'info, ProgramConfig>,
    
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct MintNft<'info> {
    pub config: Account<'info, ProgramConfig>,
    
    /// CHECK: This is the ZetaChain gateway account
    pub gateway: UncheckedAccount<'info>,
    
    #[account(mut)]
    pub mint: Account<'info, Mint>,
    
    #[account(
        init,
        payer = payer,
        space = 8 + NFTMetadata::INIT_SPACE,
        seeds = [b"nft", mint.key().as_ref()],
        bump
    )]
    pub metadata: Account<'info, NFTMetadata>,
    
    #[account(mut)]
    pub token_account: Account<'info, TokenAccount>,
    
    /// CHECK: This is the recipient of the NFT
    pub recipient: UncheckedAccount<'info>,
    
    #[account(mut)]
    pub payer: Signer<'info>,
    
    pub token_program: Program<'info, Token2022>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct SendNft<'info> {
    pub config: Account<'info, ProgramConfig>,
    
    /// CHECK: This is the ZetaChain gateway account
    #[account(mut)]
    pub gateway: UncheckedAccount<'info>,
    
    #[account(mut)]
    pub mint: Account<'info, Mint>,
    
    #[account(
        mut,
        seeds = [b"nft", mint.key().as_ref()],
        bump,
        constraint = metadata.mint == mint.key() @ ErrorCode::InvalidNFT,
        constraint = metadata.owner == owner.key() @ ErrorCode::InvalidSigner
    )]
    pub metadata: Account<'info, NFTMetadata>,
    
    #[account(
        mut,
        constraint = token_account.mint == mint.key() @ ErrorCode::InvalidNFT,
        constraint = token_account.owner == owner.key() @ ErrorCode::InvalidSigner
    )]
    pub token_account: Account<'info, TokenAccount>,
    
    pub owner: Signer<'info>,
    
    #[account(
        init,
        payer = owner,
        space = 8 + CrossChainState::INIT_SPACE,
        seeds = [
            b"cross_chain",
            destination_chain.as_bytes(),
            destination_address.as_bytes(),
            &nonce.to_le_bytes()
        ],
        bump
    )]
    pub cross_chain_state: Account<'info, CrossChainState>,
    
    pub token_program: Program<'info, Token2022>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
#[instruction(source_chain: String, source_address: String, nonce: u64)]
pub struct ReceiveNft<'info> {
    pub config: Account<'info, ProgramConfig>,
    
    /// CHECK: This is the ZetaChain gateway account
    pub gateway: UncheckedAccount<'info>,
    
    #[account(
        mut,
        seeds = [
            b"cross_chain",
            source_chain.as_bytes(),
            source_address.as_bytes(),
            &nonce.to_le_bytes()
        ],
        bump
    )]
    pub cross_chain_state: Account<'info, CrossChainState>,
    
    #[account(mut)]
    pub mint: Account<'info, Mint>,
    
    #[account(
        mut,
        seeds = [b"nft", mint.key().as_ref()],
        bump
    )]
    pub metadata: Account<'info, NFTMetadata>,
    
    #[account(mut)]
    pub token_account: Account<'info, TokenAccount>,
    
    /// CHECK: This is the recipient of the NFT
    pub recipient: UncheckedAccount<'info>,
    
    #[account(mut)]
    pub payer: Signer<'info>,
    
    pub token_program: Program<'info, Token2022>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[account]
#[derive(InitSpace)]
pub struct ProgramConfig {
    pub gateway_address: Pubkey,
    pub admin: Pubkey,
    pub paused: bool,
    #[max_len(10)]
    pub supported_chains: Vec<String>,
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
    pub status: u8,
    pub timestamp: i64,
}

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
}