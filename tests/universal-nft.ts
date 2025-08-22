import * as anchor from "@project-serum/anchor";
import { Program } from "@project-serum/anchor";
import { PublicKey, Keypair, SystemProgram, Transaction } from "@solana/web3.js";
import { assert } from "chai";
import { UniversalNft } from "../target/types/universal_nft";

describe("universal-nft", () => {
  // Configure the client to use the local cluster.
  const provider = anchor.AnchorProvider.local();
  anchor.setProvider(provider);

  const program = anchor.workspace.UniversalNft as Program<UniversalNft>;
  const payer = provider.wallet;

  let configPda: PublicKey;
  let configBump: number;

  let mint: Keypair;
  let tokenAccount: PublicKey;

  // Helper to find PDA for config
  async function findConfigPda() {
    return await PublicKey.findProgramAddress(
      [Buffer.from("config")],
      program.programId
    );
  }

  before(async () => {
    [configPda, configBump] = await findConfigPda();
  });

  it("Initialize config", async () => {
    const admin = payer.publicKey;
    const chainId = 1; // Solana chain id

    await program.methods
      .initialize(admin, chainId)
      .accounts({
        config: configPda,
        payer: payer.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const configAccount = await program.account.config.fetch(configPda);
    assert.equal(configAccount.admin.toBase58(), admin.toBase58());
    assert.equal(configAccount.chainId, chainId);
    assert.equal(configAccount.nonce.toNumber(), 0);
  });

  it("Mint NFT", async () => {
    mint = Keypair.generate();

    // Create mint account
    const lamports = await program.provider.connection.getMinimumBalanceForRentExemption(
      82
    );
    const tx = new Transaction();
    tx.add(
      SystemProgram.createAccount({
        fromPubkey: payer.publicKey,
        newAccountPubkey: mint.publicKey,
        space: 82,
        lamports,
        programId: anchor.web3.TokenInstructions.TOKEN_PROGRAM_ID,
      })
    );

    // Send transaction to create mint
    await provider.sendAndConfirm(tx, [mint]);

    // Call mint_nft instruction
    await program.methods
      .mintNft(
        "https://example.com/nft.json",
        "ExampleNFT",
        "EXNFT"
      )
      .accounts({
        payer: payer.publicKey,
        mint: mint.publicKey,
        tokenAccount: await anchor.utils.token.associatedAddress({
          mint: mint.publicKey,
          owner: payer.publicKey,
        }),
        metadata: await anchor.utils.publicKey.findProgramAddress(
          [
            Buffer.from("metadata"),
            anchor.utils.programIds().metadata.toBuffer(),
            mint.publicKey.toBuffer(),
          ],
          anchor.utils.programIds().metadata
        )[0],
        mintAuthority: await PublicKey.findProgramAddress(
          [Buffer.from("mint_authority")],
          program.programId
        )[0],
        tokenProgram: anchor.web3.TokenInstructions.TOKEN_PROGRAM_ID,
        metadataProgram: anchor.utils.programIds().metadata,
        systemProgram: SystemProgram.programId,
        rent: anchor.web3.SYSVAR_RENT_PUBKEY,
      })
      .rpc();

    // Verify token account balance = 1
    const tokenAccountInfo = await program.provider.connection.getTokenAccountBalance(
      await anchor.utils.token.associatedAddress({
        mint: mint.publicKey,
        owner: payer.publicKey,
      })
    );
    assert.equal(tokenAccountInfo.value.uiAmount, 1);
  });

  it("Send NFT cross-chain", async () => {
    // Prepare token account and escrow accounts here for testing
    // For brevity, this test simulates calling send_nft without actual cross-chain message
    const destinationChain = 2; // Example chain id (e.g., Ethereum)
    const recipient = new Uint8Array(32).fill(1); // Dummy recipient address

    const userTokenAccount = await anchor.utils.token.associatedAddress({
      mint: mint.publicKey,
      owner: payer.publicKey,
    });

    const escrowTokenAccount = await anchor.utils.token.associatedAddress({
      mint: mint.publicKey,
      owner: (
        await PublicKey.findProgramAddress(
          [Buffer.from("escrow"), mint.publicKey.toBuffer()],
          program.programId
        )
      )[0],
    });

    const noncePda = await PublicKey.findProgramAddress(
      [Buffer.from("nonce")],
      program.programId
    );

    await program.methods
      .sendNft(destinationChain, recipient)
      .accounts({
        owner: payer.publicKey,
        userTokenAccount,
        mint: mint.publicKey,
        escrowAuthority: (
          await PublicKey.findProgramAddress(
            [Buffer.from("escrow"), mint.publicKey.toBuffer()],
            program.programId
          )
        )[0],
        escrowTokenAccount,
        nonce: noncePda[0],
        tokenProgram: anchor.web3.TokenInstructions.TOKEN_PROGRAM_ID,
      })
      .rpc();
  });

  it("Receive NFT cross-chain", async () => {
    // Simulate receiving cross-chain message and minting NFT on destination chain
    // Build payload
    const payload = {
      mint: mint.publicKey.toBuffer(),
      sender: payer.publicKey.toBuffer(),
      recipient: payer.publicKey.toBuffer(),
      destination_chain: 1,
      nonce: 1,
    };

    // Serialize payload (mock)
    const payloadSerialized = Buffer.from(JSON.stringify(payload));

    // Mock verification proof always passes
    const proof = {
      verify: () => true,
    };

    const recipientTokenAccount = await anchor.utils.token.associatedAddress({
      mint: mint.publicKey,
      owner: payer.publicKey,
    });

    const mintAuthority = await PublicKey.findProgramAddress(
      [Buffer.from("mint_authority")],
      program.programId
    );

    const escrowAuthority = await PublicKey.findProgramAddress(
      [Buffer.from("escrow"), mint.publicKey.toBuffer()],
      program.programId
    );

    const escrowTokenAccount = await anchor.utils.token.associatedAddress({
      mint: mint.publicKey,
      owner: escrowAuthority[0],
    });

    const noncePda = await PublicKey.findProgramAddress(
      [Buffer.from("nonce")],
      program.programId
    );

    await program.methods
      .receiveNft(payloadSerialized, proof)
      .accounts({
        recipient: payer.publicKey,
        mint: mint.publicKey,
        mintAuthority: mintAuthority[0],
        recipientTokenAccount,
        escrowAuthority: escrowAuthority[0],
        escrowTokenAccount,
        nonce: noncePda[0],
        tokenProgram: anchor.web3.TokenInstructions.TOKEN_PROGRAM_ID,
      })
      .rpc();
  });
});