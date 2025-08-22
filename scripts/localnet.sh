#!/bin/bash

set -e

echo "Building Solana program..."
anchor build

echo "Starting Solana local validator..."
solana-test-validator --reset --quiet &
SOLANA_PID=$!

sleep 10

echo "Deploying universal-nft program..."
anchor deploy

echo "Running tests..."
anchor test

echo "Killing solana-test-validator..."
kill $SOLANA_PID

echo "Localnet deployment and test complete."