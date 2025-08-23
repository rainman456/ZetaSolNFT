// programs/universal-nft/src/gateway.rs

use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    program::invoke,
    system_instruction,
};
use std::str::FromStr;

use crate::state::constants::{GATEWAY_META_ADDRESS, GATEWAY_RENT_PAYER_ADDRESS};
use crate::state::ErrorCode;

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
    
    /// Serialize NFT data for cross-chain transfer
    pub fn serialize_nft_data(
        mint: &Pubkey,
        name: &str,
        symbol: &str,
        uri: &str,
        original_chain: &str,
        original_token_id: &str,
        nonce: u64,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        
        // Add mint
        data.extend_from_slice(&mint.to_bytes());
        
        // Add name
        data.extend_from_slice(name.as_bytes());
        data.push(0); // Null terminator
        
        // Add symbol
        data.extend_from_slice(symbol.as_bytes());
        data.push(0); // Null terminator
        
        // Add URI
        data.extend_from_slice(uri.as_bytes());
        data.push(0); // Null terminator
        
        // Add original chain
        data.extend_from_slice(original_chain.as_bytes());
        data.push(0); // Null terminator
        
        // Add original token ID
        data.extend_from_slice(original_token_id.as_bytes());
        data.push(0); // Null terminator
        
        // Add nonce
        data.extend_from_slice(&nonce.to_le_bytes());
        
        // Add Solana chain ID
        data.extend_from_slice(&crate::state::constants::SOLANA_CHAIN_ID.to_le_bytes());
        
        data
    }
    
    /// Deserialize NFT data from cross-chain transfer
    pub fn deserialize_nft_data(data: &[u8]) -> Result<(String, String, String, String, String, u64)> {
        let mut pos = 32; // Skip mint (first 32 bytes)
        let mut next_pos;
        
        // Helper function to extract a string
        let extract_string = |start: usize, data: &[u8]| -> Result<(String, usize)> {
            let mut end = start;
            while end < data.len() && data[end] != 0 {
                end += 1;
            }
            
            if end >= data.len() {
                return Err(error!(ErrorCode::InvalidMessageFormat));
            }
            
            let str_data = std::str::from_utf8(&data[start..end])
                .map_err(|_| error!(ErrorCode::InvalidMessageFormat))?;
                
            Ok((str_data.to_string(), end + 1)) // +1 to skip null terminator
        };
        
        // Extract name
        let (name, next_position) = extract_string(pos, data)?;
        pos = next_position;
        
        // Extract symbol
        let (symbol, next_position) = extract_string(pos, data)?;
        pos = next_position;
        
        // Extract URI
        let (uri, next_position) = extract_string(pos, data)?;
        pos = next_position;
        
        // Extract original chain
        let (original_chain, next_position) = extract_string(pos, data)?;
        pos = next_position;
        
        // Extract original token ID
        let (original_token_id, next_position) = extract_string(pos, data)?;
        pos = next_position;
        
        // Extract nonce
        if pos + 8 > data.len() {
            return Err(error!(ErrorCode::InvalidMessageFormat));
        }
        
        let mut nonce_bytes = [0u8; 8];
        nonce_bytes.copy_from_slice(&data[pos..pos+8]);
        let nonce = u64::from_le_bytes(nonce_bytes);
        
        // Verify chain ID
        pos += 8;
        if pos + 8 <= data.len() {
            let mut chain_id_bytes = [0u8; 8];
            chain_id_bytes.copy_from_slice(&data[pos..pos+8]);
            let chain_id = u64::from_le_bytes(chain_id_bytes);
            
            if chain_id != crate::state::constants::SOLANA_CHAIN_ID {
                return Err(error!(ErrorCode::InvalidChainId));
            }
        }
        
        Ok((name, symbol, uri, original_chain, original_token_id, nonce))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_nft_data_serialization() {
        let mint = Pubkey::new_unique();
        let name = "Test NFT";
        let symbol = "TNFT";
        let uri = "https://example.com/nft.json";
        let original_chain = "ethereum";
        let original_token_id = "0x1234567890";
        let nonce = 123456789;
        
        let data = ZetaChainGateway::serialize_nft_data(
            &mint,
            name,
            symbol,
            uri,
            original_chain,
            original_token_id,
            nonce,
        );
        
        assert!(data.len() > 0);
        
        // First 32 bytes should be the mint
        let mut mint_bytes = [0u8; 32];
        mint_bytes.copy_from_slice(&data[0..32]);
        let parsed_mint = Pubkey::new_from_array(mint_bytes);
        assert_eq!(parsed_mint, mint);
    }
    
    #[test]
    fn test_nft_data_deserialization() {
        let mint = Pubkey::new_unique();
        let name = "Test NFT";
        let symbol = "TNFT";
        let uri = "https://example.com/nft.json";
        let original_chain = "ethereum";
        let original_token_id = "0x1234567890";
        let nonce = 123456789;
        
        let data = ZetaChainGateway::serialize_nft_data(
            &mint,
            name,
            symbol,
            uri,
            original_chain,
            original_token_id,
            nonce,
        );
        
        let result = ZetaChainGateway::deserialize_nft_data(&data);
        assert!(result.is_ok());
        
        let (parsed_name, parsed_symbol, parsed_uri, parsed_chain, parsed_token_id, parsed_nonce) = result.unwrap();
        assert_eq!(parsed_name, name);
        assert_eq!(parsed_symbol, symbol);
        assert_eq!(parsed_uri, uri);
        assert_eq!(parsed_chain, original_chain);
        assert_eq!(parsed_token_id, original_token_id);
        assert_eq!(parsed_nonce, nonce);
    }
}
