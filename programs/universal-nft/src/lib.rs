// programs/universal-nft/src/lib.rs

use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    program::{invoke, invoke_signed},
    system_instruction,
    instruction::Instruction,
};
use anchor_spl::{
    associated_token::AssociatedToken,
    token::{Mint, Token, TokenAccount},
    token_2022::{Token2022, mint_to, burn, initialize_mint2, set_authority},
};
use std::str::FromStr;

mod state;
mod tss;
mod gateway;

use state::{
    ProgramConfig, NFTMetadata, CrossChainState, 
    constants::{CONFIG_SEED, NFT_SEED, CROSS_CHAIN_SEED, NONCE_SEED, SOLANA_CHAIN_ID},
    ErrorCode,
};
use tss::{verify_tss_signature, prepare_eth_message, build_cross_chain_message, parse_cross_chain_message, create_compute_budget_ix};
use gateway::{ZetaChainGateway, GatewayMessageType};

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod universal_nft {
    use super::*;

    /// Initialize the Universal NFT program with the ZetaChain gateway
    pub fn initialize(
        ctx: Context<Initialize>,
        tss_address: [u8; 20],
        supported_chains: Vec<String>,
    ) -> Result<()> {
        let config = &mut ctx.accounts.config;
        
        // Initialize program config
        config.tss_address = tss_address;
        config.authority = ctx.accounts.authority.key();
        config.nonce = 0;
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
        new_tss_address: Option<[u8; 20]>,
        new_authority: Option<Pubkey>,
        paused: Option<bool>,
        supported_chains: Option<Vec<String>>,
    ) -> Result<()> {
        let config = &mut ctx.accounts.config;
        
        // Verify the authority is the signer
        require!(
            ctx.accounts.authority.key() == config.authority,
            ErrorCode::InvalidSigner
        );
        
        // Update TSS address if provided
        if let Some(tss_address) = new_tss_address {
            config.tss_address = tss_address;
        }
        
        // Update authority if provided
        if let Some(authority) = new_authority {
            config.authority = authority;
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
        signature: Vec<u8>,
        recovery_id: u8,
        nonce: u64,
    ) -> Result<()> {
        // Add compute budget instruction to optimize for compute units
        let compute_budget_ix = create_compute_budget_ix();
        invoke(
            &compute_budget_ix,
            &[]
        )?;
        
        // Check if program is paused
        require!(!ctx.accounts.config.paused, ErrorCode::ProgramPaused);
        
        // Verify the chain is supported
        let is_supported = ctx.accounts.config.supported_chains.iter()
            .any(|chain| chain == &original_chain);
        require!(is_supported, ErrorCode::UnsupportedChain);
        
        // Verify the nonce is valid and hasn't been used
        require!(nonce > ctx.accounts.config.nonce, ErrorCode::InvalidNonce);
        
        // Build the message that should have been signed
        let message = build_cross_chain_message(
            &ctx.accounts.mint.key(),
            &original_chain,
            "solana",
            &ctx.accounts.recipient.key().to_string(),
            nonce,
        );
        
        // Prepare the message for Ethereum-style signing
        let eth_message = prepare_eth_message(&message);
        
        // Verify the TSS signature
        let is_valid = verify_tss_signature(
            &eth_message,
            &signature,
            recovery_id,
            &ctx.accounts.config.tss_address,
        )?;
        
        require!(is_valid, ErrorCode::InvalidTssSignature);
        
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
        
        // Update program nonce
        let config = &mut ctx.accounts.config;
        config.nonce = nonce;
        
        // Create cross-chain state to track the transfer
        let cross_chain_state = &mut ctx.accounts.cross_chain_state;
        cross_chain_state.nft_mint = ctx.accounts.mint.key();
        cross_chain_state.source_chain = original_chain;
        cross_chain_state.destination_chain = "solana".to_string();
        cross_chain_state.destination_address = ctx.accounts.recipient.key().to_string();
        cross_chain_state.nonce = nonce;
        cross_chain_state.status = 1; // Completed
        cross_chain_state.timestamp = Clock::get()?.unix_timestamp;
        cross_chain_state.processed = true;
        
        msg!("NFT minted successfully");
        Ok(())
    }

    /// Send an NFT to another chain via ZetaChain
    pub fn send_nft(
        ctx: Context<SendNft>,
        destination_chain: String,
        destination_address: String,
    ) -> Result<()> {
        // Add compute budget instruction to optimize for compute units
        let compute_budget_ix = create_compute_budget_ix();
        invoke(
            &compute_budget_ix,
            &[]
        )?;
        
        // Check if program is paused
        require!(!ctx.accounts.config.paused, ErrorCode::ProgramPaused);
        
        // Verify the chain is supported
        let is_supported = ctx.accounts.config.supported_chains.iter()
            .any(|chain| chain == &destination_chain);
        require!(is_supported, ErrorCode::UnsupportedChain);
        
        // Verify the owner is the signer
        require!(
            ctx.accounts.owner.key() == ctx.accounts.metadata.owner,
            ErrorCode::InvalidSigner
        );
        
        // Increment nonce for this transaction
        let config = &mut ctx.accounts.config;
        config.nonce = config.nonce.checked_add(1).unwrap_or(config.nonce);
        let nonce = config.nonce;
        
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
        cross_chain_state.destination_chain = destination_chain.clone();
        cross_chain_state.destination_address = destination_address.clone();
        cross_chain_state.nonce = nonce;
        cross_chain_state.status = 0; // Pending
        cross_chain_state.timestamp = Clock::get()?.unix_timestamp;
        cross_chain_state.processed = false;
        
        // Serialize NFT data for cross-chain transfer
        let payload = ZetaChainGateway::serialize_nft_data(
            &ctx.accounts.mint.key(),
            &ctx.accounts.metadata.name,
            &ctx.accounts.metadata.symbol,
            &ctx.accounts.metadata.uri,
            &ctx.accounts.metadata.original_chain,
            &ctx.accounts.metadata.original_token_id,
            nonce,
        );
        
        // Send message to ZetaChain gateway
        ZetaChainGateway::send_message(
            &ctx.accounts.gateway_program.to_account_info(),
            &ctx.accounts.gateway_meta.to_account_info(),
            &ctx.accounts.owner.to_account_info(),
            &ctx.accounts.owner.to_account_info(), // Owner pays for the message
            &ctx.accounts.system_program.to_account_info(),
            GatewayMessageType::SendNFT,
            &destination_chain,
            &destination_address,
            &payload,
        )?;
        
        msg!("NFT sent to another chain");
        Ok(())
    }

    /// Handle incoming NFT from another chain
    pub fn receive_nft(
        ctx: Context<ReceiveNft>,
        signature: Vec<u8>,
        recovery_id: u8,
        message: Vec<u8>,
    ) -> Result<()> {
        // Add compute budget instruction to optimize for compute units
        let compute_budget_ix = create_compute_budget_ix();
        invoke(
            &compute_budget_ix,
            &[]
        )?;
        
        // Check if program is paused
        require!(!ctx.accounts.config.paused, ErrorCode::ProgramPaused);
        
        // Verify the gateway caller
        ZetaChainGateway::verify_gateway_caller(&ctx.accounts.gateway.key())?;
        
        // Prepare the message for Ethereum-style signing
        let eth_message = prepare_eth_message(&message);
        
        // Verify the TSS signature
        let is_valid = verify_tss_signature(
            &eth_message,
            &signature,
            recovery_id,
            &ctx.accounts.config.tss_address,
        )?;
        
        require!(is_valid, ErrorCode::InvalidTssSignature);
        
        // Parse the cross-chain message
        let (mint, source_chain, destination_address, nonce) = parse_cross_chain_message(&message)?;
        
        // Verify the mint matches
        require!(mint == ctx.accounts.mint.key(), ErrorCode::InvalidNFT);
        
        // Verify the chain is supported
        let is_supported = ctx.accounts.config.supported_chains.iter()
            .any(|chain| chain == &source_chain);
        require!(is_supported, ErrorCode::UnsupportedChain);
        
        // Verify the nonce is valid and hasn't been used
        require!(nonce > ctx.accounts.config.nonce, ErrorCode::InvalidNonce);
        
        // Verify the cross-chain state hasn't been processed
        require!(!ctx.accounts.cross_chain_state.processed, ErrorCode::ReplayAttempt);
        
        // Update program nonce
        let config = &mut ctx.accounts.config;
        config.nonce = nonce;
        
        // Update cross-chain state
        let cross_chain_state = &mut ctx.accounts.cross_chain_state;
        cross_chain_state.status = 1; // Completed
        cross_chain_state.processed = true;
        
        // Deserialize NFT data
        let (name, symbol, uri, original_chain, original_token_id, _) = 
            ZetaChainGateway::deserialize_nft_data(&message)?;
        
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
        
        msg!("NFT received from another chain");
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + ProgramConfig::INIT_SPACE,
        seeds = [CONFIG_SEED],
        bump
    )]
    pub config: Account<'info, ProgramConfig>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct UpdateConfig<'info> {
    #[account(mut)]
    pub config: Account<'info, ProgramConfig>,
    
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(
    name: String,
    symbol: String,
    uri: String,
    original_chain: String,
    original_token_id: String,
    signature: Vec<u8>,
    recovery_id: u8,
    nonce: u64
)]
pub struct MintNft<'info> {
    #[account(mut)]
    pub config: Account<'info, ProgramConfig>,
    
    /// CHECK: This is the ZetaChain gateway account
    pub gateway: UncheckedAccount<'info>,
    
    #[account(mut)]
    pub mint: Account<'info, Mint>,
    
    #[account(
        init,
        payer = payer,
        space = 8 + NFTMetadata::INIT_SPACE,
        seeds = [NFT_SEED, mint.key().as_ref()],
        bump
    )]
    pub metadata: Account<'info, NFTMetadata>,
    
    #[account(
        init_if_needed,
        payer = payer,
        associated_token::mint = mint,
        associated_token::authority = recipient,
    )]
    pub token_account: Account<'info, TokenAccount>,
    
    /// CHECK: This is the recipient of the NFT
    pub recipient: UncheckedAccount<'info>,
    
    #[account(
        init,
        payer = payer,
        space = 8 + CrossChainState::INIT_SPACE,
        seeds = [
            CROSS_CHAIN_SEED,
            original_chain.as_bytes(),
            original_token_id.as_bytes(),
            &nonce.to_le_bytes()
        ],
        bump
    )]
    pub cross_chain_state: Account<'info, CrossChainState>,
    
    #[account(mut)]
    pub payer: Signer<'info>,
    
    pub token_program: Program<'info, Token2022>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
#[instruction(destination_chain: String, destination_address: String)]
pub struct SendNft<'info> {
    #[account(mut)]
    pub config: Account<'info, ProgramConfig>,
    
    /// CHECK: This is the ZetaChain gateway program
    pub gateway_program: UncheckedAccount<'info>,
    
    /// CHECK: This is the ZetaChain gateway meta account
    pub gateway_meta: UncheckedAccount<'info>,
    
    #[account(mut)]
    pub mint: Account<'info, Mint>,
    
    #[account(
        mut,
        seeds = [NFT_SEED, mint.key().as_ref()],
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
    
    #[account(mut)]
    pub owner: Signer<'info>,
    
    #[account(
        init,
        payer = owner,
        space = 8 + CrossChainState::INIT_SPACE,
        seeds = [
            CROSS_CHAIN_SEED,
            destination_chain.as_bytes(),
            destination_address.as_bytes(),
            &config.nonce.checked_add(1).unwrap_or(config.nonce).to_le_bytes()
        ],
        bump
    )]
    pub cross_chain_state: Account<'info, CrossChainState>,
    
    pub token_program: Program<'info, Token2022>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
#[instruction(signature: Vec<u8>, recovery_id: u8, message: Vec<u8>)]
pub struct ReceiveNft<'info> {
    #[account(mut)]
    pub config: Account<'info, ProgramConfig>,
    
    /// CHECK: This is the ZetaChain gateway account, verified in the instruction
    pub gateway: UncheckedAccount<'info>,
    
    #[account(mut)]
    pub mint: Account<'info, Mint>,
    
    #[account(
        init,
        payer = payer,
        space = 8 + NFTMetadata::INIT_SPACE,
        seeds = [NFT_SEED, mint.key().as_ref()],
        bump
    )]
    pub metadata: Account<'info, NFTMetadata>,
    
    #[account(
        init_if_needed,
        payer = payer,
        associated_token::mint = mint,
        associated_token::authority = recipient,
    )]
    pub token_account: Account<'info, TokenAccount>,
    
    /// CHECK: This is the recipient of the NFT
    pub recipient: UncheckedAccount<'info>,
    
    #[account(
        init_if_needed,
        payer = payer,
        space = 8 + CrossChainState::INIT_SPACE,
        seeds = [
            CROSS_CHAIN_SEED,
            "incoming".as_bytes(),
            mint.key().as_ref(),
            &[0, 0, 0, 0, 0, 0, 0, 0]
        ],
        bump
    )]
    pub cross_chain_state: Account<'info, CrossChainState>,
    
    #[account(mut)]
    pub payer: Signer<'info>,
    
    pub token_program: Program<'info, Token2022>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}
