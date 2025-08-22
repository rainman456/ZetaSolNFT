use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::pubkey::Pubkey;

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct CrossChainPayload {
    pub mint: Pubkey,
    pub sender: Pubkey,
    pub recipient: [u8; 32], // recipient address bytes for destination chain
    pub destination_chain: u16,
    pub nonce: u64,
}

#[derive(Debug)]
pub struct VerificationProof {
    // Placeholder fields for ZetaChain TSS verification proof
    pub signature: Vec<u8>,
    pub message: Vec<u8>,
}

impl VerificationProof {
    pub fn verify(&self) -> bool {
        // Placeholder verification - integrate ZetaChain SDK here
        // For now, always return true for testing
        true
    }
}

// Serialization helper functions

pub fn encode_payload(payload: &CrossChainPayload) -> Result<Vec<u8>, std::io::Error> {
    Ok(payload.try_to_vec()?)
}

pub fn decode_payload(data: &[u8]) -> Result<CrossChainPayload, std::io::Error> {
    let payload = CrossChainPayload::try_from_slice(data)?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_payload() {
        let payload = CrossChainPayload {
            mint: Pubkey::new_unique(),
            sender: Pubkey::new_unique(),
            recipient: [0u8; 32],
            destination_chain: 2,
            nonce: 42,
        };
        let encoded = encode_payload(&payload).unwrap();
        let decoded = decode_payload(&encoded).unwrap();
        assert_eq!(payload.mint, decoded.mint);
        assert_eq!(payload.sender, decoded.sender);
        assert_eq!(payload.recipient, decoded.recipient);
        assert_eq!(payload.destination_chain, decoded.destination_chain);
        assert_eq!(payload.nonce, decoded.nonce);
    }

    #[test]
    fn test_proof_verify() {
        let proof = VerificationProof {
            signature: vec![1, 2, 3],
            message: vec![4, 5, 6],
        };
        assert!(proof.verify());
    }
}