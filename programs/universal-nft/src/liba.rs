use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount, MintTo, Burn, Transfer};
use anchor_spl::metadata::{self, Metadata, CreateMetadataAccountsV2};
use borsh::{BorshDeserialize, BorshSerialize};
use common_utils::{CrossChainPayload, VerificationProof};
use std::convert::TryInto;

declare_id!("UNiVErsaL1111111111111111111111111111111111");

pub const CONFIG_SEED: &[u8] = b"config";
pub const MINT_AUTHORITY_SEED: &[u8] = b"mint_authority";
pub const ESCROW_SEED: &[u8] = b"escrow";
pub const NONCE_SEED: &[u8] = b"nonce";

#[program]
pub mod universal_nft {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, admin: Pubkey, chain_id: u16) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.admin = admin;
        config.chain_id = chain_id;
        config.nonce = 0;
        Ok(())
    }

    pub fn mint_nft(ctx: Context<MintNFT>, uri: String, name: String, symbol: String) -> Result<()> {
        // Mint the NFT token to the user
        let mint_authority = ctx.accounts.mint_authority.key();
        let cpi_accounts = MintTo {
            mint: ctx.accounts.mint.to_account_info(),
            to: ctx.accounts.token_account.to_account_info(),
            authority: ctx.accounts.mint_authority.to_account_info(),
        };
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let signer_seeds = &[MINT_AUTHORITY_SEED, &[*ctx.bumps.get("mint_authority").unwrap()]];
        let cpi_ctx = CpiContext::new_with_signer(cpi_program, cpi_accounts, &[&signer_seeds[..]]);
        token::mint_to(cpi_ctx, 1)?;

        // Create Metadata for NFT using Metaplex Metadata program
        let metadata_accounts = CreateMetadataAccountsV2 {
            metadata: ctx.accounts.metadata.to_account_info(),
            mint: ctx.accounts.mint.to_account_info(),
            mint_authority: ctx.accounts.mint_authority.to_account_info(),
            payer: ctx.accounts.payer.to_account_info(),
            update_authority: ctx.accounts.mint_authority.to_account_info(),
            system_program: ctx.accounts.system_program.to_account_info(),
            rent: ctx.accounts.rent.to_account_info(),
        };
        let metadata_ctx = CpiContext::new(ctx.accounts.metadata_program.to_account_info(), metadata_accounts);
        metadata::create_metadata_accounts_v2(
            metadata_ctx,
            name,
            symbol,
            uri,
            Some(ctx.accounts.mint_authority.key()),
            1,
            true,
            false,
            None,
            None,
        )?;

        emit!(MintEvent {
            mint: ctx.accounts.mint.key(),
            owner: ctx.accounts.payer.key(),
        });
        Ok(())
    }

    pub fn send_nft(ctx: Context<SendNFT>, destination_chain: u16, recipient: [u8; 32]) -> Result<()> {
        // Transfer NFT token from user to escrow PDA (lock it)
        let cpi_accounts = Transfer {
            from: ctx.accounts.user_token_account.to_account_info(),
            to: ctx.accounts.escrow_token_account.to_account_info(),
            authority: ctx.accounts.owner.to_account_info(),
        };
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
        token::transfer(cpi_ctx, 1)?;

        // Increment nonce to prevent replay attacks
        let nonce_data = &mut ctx.accounts.nonce;
        nonce_data.nonce = nonce_data.nonce.checked_add(1).ok_or(ErrorCode::NonceOverflow)?;

        // Build cross-chain payload
        let payload = CrossChainPayload {
            mint: ctx.accounts.mint.key(),
            sender: ctx.accounts.owner.key(),
            recipient,
            destination_chain,
            nonce: nonce_data.nonce,
        };
        let payload_bytes = payload.try_to_vec().map_err(|_| ErrorCode::SerializationError)?;

        // Here you would call the ZetaChain gateway to send cross-chain message
        // This is a placeholder: actual integration depends on ZetaChain SDK
        // emit event for off-chain relayer
        emit!(SendEvent {
            mint: ctx.accounts.mint.key(),
            destination_chain,
            recipient,
        });

        Ok(())
    }

    pub fn receive_nft(ctx: Context<ReceiveNFT>, payload: Vec<u8>, proof: VerificationProof) -> Result<()> {
        // Verify the cross-chain message using ZetaChain proof
        // Placeholder for proof verification logic
        require!(proof.verify(), ErrorCode::InvalidProof);

        let payload_data = CrossChainPayload::try_from_slice(&payload).map_err(|_| ErrorCode::DeserializationError)?;

        // Check nonce for replay protection
        let nonce_data = &mut ctx.accounts.nonce;
        require!(payload_data.nonce > nonce_data.nonce, ErrorCode::NonceReplay);
        nonce_data.nonce = payload_data.nonce;

        // Mint or release NFT to recipient
        // If mint does not exist, mint it
        if ctx.accounts.mint.supply == 0 {
            let mint_authority_seeds = &[MINT_AUTHORITY_SEED, &[*ctx.bumps.get("mint_authority").unwrap()]];
            let cpi_accounts = MintTo {
                mint: ctx.accounts.mint.to_account_info(),
                to: ctx.accounts.recipient_token_account.to_account_info(),
                authority: ctx.accounts.mint_authority.to_account_info(),
            };
            let cpi_program = ctx.accounts.token_program.to_account_info();
            let cpi_ctx = CpiContext::new_with_signer(cpi_program, cpi_accounts, &[&mint_authority_seeds[..]]);
            token::mint_to(cpi_ctx, 1)?;
        } else {
            // Release NFT from escrow to recipient
            let cpi_accounts = Transfer {
                from: ctx.accounts.escrow_token_account.to_account_info(),
                to: ctx.accounts.recipient_token_account.to_account_info(),
                authority: ctx.accounts.escrow_authority.to_account_info(),
            };
            let cpi_program = ctx.accounts.token_program.to_account_info();
            let signer_seeds = &[ESCROW_SEED, &[*ctx.bumps.get("escrow_authority").unwrap()]];
            let cpi_ctx = CpiContext::new_with_signer(cpi_program, cpi_accounts, &[&signer_seeds[..]]);
            token::transfer(cpi_ctx, 1)?;
        }

        emit!(ReceiveEvent {
            mint: ctx.accounts.mint.key(),
            recipient: ctx.accounts.recipient.key(),
        });

        Ok(())
    }
}

// Accounts and Context Definitions

#[derive(Accounts)]
#[instruction(admin: Pubkey, chain_id: u16)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = payer,
        seeds = [CONFIG_SEED],
        bump,
        space = 8 + 32 + 2 + 8 // discriminator + admin pubkey + u16 + nonce u64
    )]
    pub config: Account<'info, Config>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct MintNFT<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut)]
    pub mint: Account<'info, Mint>,
    #[account(
        init_if_needed,
        payer = payer,
        associated_token::mint = mint,
        associated_token::authority = payer,
    )]
    pub token_account: Account<'info, TokenAccount>,
    /// CHECK: Metaplex metadata account
    #[account(mut)]
    pub metadata: UncheckedAccount<'info>,
    #[account(
        seeds = [MINT_AUTHORITY_SEED],
        bump,
    )]
    /// CHECK: mint authority PDA
    pub mint_authority: UncheckedAccount<'info>,
    pub token_program: Program<'info, Token>,
    pub metadata_program: Program<'info, metadata::Metadata>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct SendNFT<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,
    #[account(mut, has_one = owner)]
    pub user_token_account: Account<'info, TokenAccount>,
    #[account(mut)]
    pub mint: Account<'info, Mint>,
    #[account(
        seeds = [ESCROW_SEED, mint.key().as_ref()],
        bump,
    )]
    pub escrow_authority: UncheckedAccount<'info>,
    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = escrow_authority,
    )]
    pub escrow_token_account: Account<'info, TokenAccount>,
    #[account(mut, seeds = [NONCE_SEED], bump)]
    pub nonce: Account<'info, NonceAccount>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct ReceiveNFT<'info> {
    #[account(mut)]
    pub recipient: Signer<'info>,
    #[account(mut)]
    pub mint: Account<'info, Mint>,
    #[account(
        seeds = [MINT_AUTHORITY_SEED],
        bump,
    )]
    pub mint_authority: UncheckedAccount<'info>,
    #[account(mut)]
    pub recipient_token_account: Account<'info, TokenAccount>,
    #[account(
        seeds = [ESCROW_SEED, mint.key().as_ref()],
        bump,
    )]
    pub escrow_authority: UncheckedAccount<'info>,
    #[account(mut)]
    pub escrow_token_account: Account<'info, TokenAccount>,
    #[account(mut, seeds = [NONCE_SEED], bump)]
    pub nonce: Account<'info, NonceAccount>,
    pub token_program: Program<'info, Token>,
}

// State accounts

#[account]
pub struct Config {
    pub admin: Pubkey,
    pub chain_id: u16,
    pub nonce: u64,
}

#[account]
pub struct NonceAccount {
    pub nonce: u64,
}

// Events

#[event]
pub struct MintEvent {
    pub mint: Pubkey,
    pub owner: Pubkey,
}

#[event]
pub struct SendEvent {
    pub mint: Pubkey,
    pub destination_chain: u16,
    pub recipient: [u8; 32],
}

#[event]
pub struct ReceiveEvent {
    pub mint: Pubkey,
    pub recipient: Pubkey,
}

// Errors

#[error_code]
pub enum ErrorCode {
    #[msg("Invalid proof for cross-chain message")]
    InvalidProof,
    #[msg("Serialization error")]
    SerializationError,
    #[msg("Deserialization error")]
    DeserializationError,
    #[msg("Nonce overflow")]
    NonceOverflow,
    #[msg("Nonce replay detected")]
    NonceReplay,
}