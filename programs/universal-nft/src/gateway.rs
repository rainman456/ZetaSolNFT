// programs/universal-nft/src/gateway.rs

use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    program::invoke,
    system_instruction,
};
use std::str::FromStr;

use crate::state::constants::{GATEWAY_META_ADDRESS, GATEWAY_RENT_PAYER_ADDRESS};

/// ZetaChain Gateway Message Types
pub enum GatewayMessageType {
    SendNFT = 1,
    ReceiveNFT = 2,
}

/// Structure for ZetaChain Gateway
pub struct ZetaChainGateway;

impl ZetaChainGateway {
    /// Get the gateway meta address
    pub fn meta_address() -> Pubkey {
        Pubkey::from_str(GATEWAY_META_ADDRESS).unwrap_or_else(|_| panic!("Invalid gateway meta address"))
    }
    
    /// Get the gateway rent payer address
    pub fn rent_payer_address() -> Pubkey {
        Pubkey::from_str(GATEWAY_RENT_PAYER_ADDRESS).unwrap_or_else(|_| panic!("Invalid gateway rent payer address"))
    }
    
    /// Send a message to ZetaChain
    pub fn send_message<'info>(
        gateway_program: &AccountInfo<'info>,
        gateway_meta: &AccountInfo<'info>,
        message_sender: &AccountInfo<'info>,
        rent_payer: &AccountInfo<'info>,
        system_program: &AccountInfo<'info>,
        message_type: GatewayMessageType,
        destination_chain: &str,
        destination_address: &str,
        payload: &[u8],
    ) -> Result<()> {
        // Prepare the instruction data
        let mut instruction_data = Vec::new();
        
        // Add message type
        instruction_data.push(message_type as u8);
        
        // Add destination chain
        instruction_data.extend_from_slice(destination_chain.as_bytes());
        instruction_data.push(0); // Null terminator
        
        // Add destination address
        instruction_data.extend_from_slice(destination_address.as_bytes());
        instruction_data.push(0); // Null terminator
        
        // Add payload
        instruction_data.extend_from_slice(payload);
        
        // Create the instruction
        let instruction = anchor_lang::solana_program::instruction::Instruction {
            program_id: gateway_program.key(),
            accounts: vec![
                anchor_lang::solana_program::instruction::AccountMeta::new(*gateway_meta.key, false),
                anchor_lang::solana_program::instruction::AccountMeta::new(*message_sender.key, true),
                anchor_lang::solana_program::instruction::AccountMeta::new(*rent_payer.key, true),
                anchor_lang::solana_program::instruction::AccountMeta::new_readonly(*system_program.key, false),
            ],
            data: instruction_data,
        };
        
        // Invoke the instruction
        invoke(
            &instruction,
            &[
                gateway_meta.clone(),
                message_sender.clone(),
                rent_payer.clone(),
                system_program.clone(),
            ],
        ).map_err(|err| {
            msg!("Error sending message to ZetaChain: {:?}", err);
            error!(ErrorCode::CrossChainError)
        })?;
        
        Ok(())
    }
    
    /// Verify that the caller is the ZetaChain gateway
    pub fn verify_gateway_caller(caller: &Pubkey) -> Result<()> {
        require!(
            *caller == Self::meta_address() || *caller == Self::rent_payer_address(),
            ErrorCode::InvalidGateway
        );
        
        Ok(())
    }
}