// programs/universal-nft/src/tss.rs

use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    keccak::hash,
    secp256k1::{
        Secp256k1Pubkey, 
        recover_pubkey,
    },
    compute_budget::ComputeBudgetInstruction,
};

use crate::state::constants::MAX_COMPUTE_UNITS;
use crate::state::ErrorCode;

/// Ethereum address length (20 bytes)
pub const ETH_ADDRESS_LENGTH: usize = 20;

/// Verifies a TSS ECDSA signature using secp256k1_recover
pub fn verify_tss_signature(
    message: &[u8],
    signature: &[u8],
    recovery_id: u8,
    expected_address: &[u8; ETH_ADDRESS_LENGTH],
) -> Result<bool> {
    // Hash the message using keccak256 (Ethereum standard)
    let message_hash = hash(message).to_bytes();
    
    // Recover the public key from the signature
    let recovered_pubkey = recover_pubkey(
        &message_hash,
        signature,
        recovery_id,
    ).map_err(|_| error!(ErrorCode::InvalidTssSignature))?;
    
    // Convert the recovered public key to an Ethereum address
    let recovered_address = pubkey_to_eth_address(&recovered_pubkey);
    
    // Check if the recovered address matches the expected address
    Ok(recovered_address == expected_address)
}

/// Converts a Secp256k1 public key to an Ethereum address
fn pubkey_to_eth_address(pubkey: &Secp256k1Pubkey) -> [u8; ETH_ADDRESS_LENGTH] {
    // Get the serialized public key
    let serialized_pubkey = pubkey.to_bytes();
    
    // Hash the serialized public key (excluding the first byte which is the format)
    let hashed = hash(&serialized_pubkey[1..]).to_bytes();
    
    // Take the last 20 bytes as the Ethereum address
    let mut eth_address = [0u8; ETH_ADDRESS_LENGTH];
    eth_address.copy_from_slice(&hashed[12..32]);
    
    eth_address
}

/// Prepares a message for TSS signature verification by prefixing with Ethereum standard
pub fn prepare_eth_message(message: &[u8]) -> Vec<u8> {
    // Ethereum signed message prefix
    let prefix = b"\x19Ethereum Signed Message:\n";
    
    // Message length as string
    let message_length = message.len().to_string();
    
    // Concatenate prefix + message length + message
    let mut prefixed_message = Vec::with_capacity(
        prefix.len() + message_length.len() + message.len()
    );
    
    prefixed_message.extend_from_slice(prefix);
    prefixed_message.extend_from_slice(message_length.as_bytes());
    prefixed_message.extend_from_slice(message);
    
    prefixed_message
}

/// Builds a cross-chain message with replay protection
pub fn build_cross_chain_message(
    nft_mint: &Pubkey,
    source_chain: &str,
    destination_chain: &str,
    destination_address: &str,
    nonce: u64,
) -> Vec<u8> {
    // Format: mint + source_chain + destination_chain + destination_address + nonce + SOLANA_CHAIN_ID
    let mut message = Vec::new();
    
    // Add NFT mint
    message.extend_from_slice(&nft_mint.to_bytes());
    
    // Add source chain
    message.extend_from_slice(source_chain.as_bytes());
    
    // Add destination chain
    message.extend_from_slice(destination_chain.as_bytes());
    
    // Add destination address
    message.extend_from_slice(destination_address.as_bytes());
    
    // Add nonce (as little-endian bytes)
    message.extend_from_slice(&nonce.to_le_bytes());
    
    // Add Solana chain ID for replay protection
    message.extend_from_slice(&crate::state::constants::SOLANA_CHAIN_ID.to_le_bytes());
    
    message
}

/// Parse a cross-chain message from ZetaChain
pub fn parse_cross_chain_message(
    message: &[u8],
) -> Result<(Pubkey, String, String, u64)> {
    // Ensure the message is long enough
    if message.len() < 32 + 8 + 8 {
        return Err(error!(ErrorCode::InvalidMessageFormat));
    }
    
    // Extract mint (first 32 bytes)
    let mut mint_bytes = [0u8; 32];
    mint_bytes.copy_from_slice(&message[0..32]);
    let mint = Pubkey::new_from_array(mint_bytes);
    
    // Find delimiters for strings
    let mut pos = 32;
    let mut next_pos = pos;
    
    // Find end of source chain
    while next_pos < message.len() && message[next_pos] != 0 {
        next_pos += 1;
    }
    if next_pos >= message.len() {
        return Err(error!(ErrorCode::InvalidMessageFormat));
    }
    
    // Extract source chain
    let source_chain = std::str::from_utf8(&message[pos..next_pos])
        .map_err(|_| error!(ErrorCode::InvalidMessageFormat))?
        .to_string();
    
    // Move past null terminator
    pos = next_pos + 1;
    next_pos = pos;
    
    // Find end of destination address
    while next_pos < message.len() && message[next_pos] != 0 {
        next_pos += 1;
    }
    if next_pos >= message.len() {
        return Err(error!(ErrorCode::InvalidMessageFormat));
    }
    
    // Extract destination address
    let destination_address = std::str::from_utf8(&message[pos..next_pos])
        .map_err(|_| error!(ErrorCode::InvalidMessageFormat))?
        .to_string();
    
    // Move past null terminator
    pos = next_pos + 1;
    
    // Ensure there's enough space for nonce
    if pos + 8 > message.len() {
        return Err(error!(ErrorCode::InvalidMessageFormat));
    }
    
    // Extract nonce
    let mut nonce_bytes = [0u8; 8];
    nonce_bytes.copy_from_slice(&message[pos..pos+8]);
    let nonce = u64::from_le_bytes(nonce_bytes);
    
    Ok((mint, source_chain, destination_address, nonce))
}

/// Create a compute budget instruction to optimize for the maximum allowed compute units
pub fn create_compute_budget_ix() -> anchor_lang::solana_program::instruction::Instruction {
    ComputeBudgetInstruction::set_compute_unit_limit(MAX_COMPUTE_UNITS)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_message_building() {
        let mint = Pubkey::new_unique();
        let source = "solana";
        let destination = "ethereum";
        let address = "0x1234567890123456789012345678901234567890";
        let nonce = 123456789;
        
        let message = build_cross_chain_message(
            &mint,
            source,
            destination,
            address,
            nonce,
        );
        
        // Verify the message contains all components
        assert!(message.len() > 0);
        
        // Verify the message ends with Solana chain ID
        let chain_id_bytes = crate::state::constants::SOLANA_CHAIN_ID.to_le_bytes();
        assert_eq!(
            message[message.len() - chain_id_bytes.len()..],
            chain_id_bytes
        );
    }
    
    #[test]
    fn test_message_parsing() {
        let mint = Pubkey::new_unique();
        let source = "ethereum";
        let destination = "0x1234567890123456789012345678901234567890";
        let nonce = 123456789;
        
        // Build a test message
        let mut message = Vec::new();
        message.extend_from_slice(&mint.to_bytes());
        message.extend_from_slice(source.as_bytes());
        message.push(0); // Null terminator
        message.extend_from_slice(destination.as_bytes());
        message.push(0); // Null terminator
        message.extend_from_slice(&nonce.to_le_bytes());
        
        // Parse the message
        let result = parse_cross_chain_message(&message);
        assert!(result.is_ok());
        
        let (parsed_mint, parsed_source, parsed_destination, parsed_nonce) = result.unwrap();
        assert_eq!(parsed_mint, mint);
        assert_eq!(parsed_source, source);
        assert_eq!(parsed_destination, destination);
        assert_eq!(parsed_nonce, nonce);
    }
}
