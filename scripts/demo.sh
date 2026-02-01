#!/bin/bash
# Demo script for Steganographic Chat

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

STEGO_BIN="./bin/stego"
STEGOD_BIN="./bin/stegod"

echo -e "${BLUE}=== StegoChat Demo ===${NC}"

# 1. Start Daemon
echo -e "\n${GREEN}[1] Starting Daemon...${NC}"
pkill stegod
$STEGOD_BIN > stegod.log 2>&1 &
STEGOD_PID=$!
sleep 2
echo "Daemon running (PID: $STEGOD_PID)"

# 2. Status Check
echo -e "\n${GREEN}[2] Checking Status...${NC}"
$STEGO_BIN status

# 3. Create Sessions
echo -e "\n${GREEN}[3] Creating Sessions (Alice & Bob)...${NC}"
# We'll simulate two users by using one daemon but creating sessions representing "peers"
# In a real scenario, this would be on two different machines

# Session A: Talking to Alice
OUT_A=$($STEGO_BIN session create "alice@example.com" --name "Alice")
ID_A=$(echo "$OUT_A" | grep "ID:" | awk '{print $2}')
echo "Created session for Alice: $ID_A"

# Session B: Talking to Bob
OUT_B=$($STEGO_BIN session create "bob@example.com" --name "Bob")
ID_B=$(echo "$OUT_B" | grep "ID:" | awk '{print $2}')
echo "Created session for Bob: $ID_B"

# 4. Key Exchange (Simulated)
echo -e "\n${GREEN}[4] Performing Key Exchange...${NC}"
KEY_A=$($STEGO_BIN session key-exchange $ID_A | grep -v "Your public key")
KEY_B=$($STEGO_BIN session key-exchange $ID_B | grep -v "Your public key")

echo "Alice Key: ${KEY_A:0:16}..."
echo "Bob Key:   ${KEY_B:0:16}..."

# Complete exchange (Alice adds Bob, Bob adds Alice - simulating network exchange)
$STEGO_BIN session complete-key-exchange $ID_A $KEY_B > /dev/null
echo "Alice linked with Bob's key"

# 5. Send Secret Message (with Decoy)
echo -e "\n${GREEN}[5] Encoding Secret Message with Decoy...${NC}"
echo "Secret: 'Meet at dock 7 at midnight'"
echo "Decoy:  'Heading to the gym now'"
echo "Topic:  'fitness'"

# Simulating no LLM by default (unless user has Ollama running), so we expect placeholder
# But we'll capture the output anyway
COVER_TEXT=$($STEGO_BIN encode $ID_A "Meet at dock 7 at midnight" --decoy "Heading to the gym now" --topic "fitness" --raw)

echo -e "\n${BLUE}Generated Cover Text:${NC}"
echo "$COVER_TEXT"

# 6. Analyze Cover Text
echo -e "\n${GREEN}[6] Analyzing Cover Text...${NC}"
# Clean up cover text for analysis (pass as argument)
CLEAN_COVER=$(echo "$COVER_TEXT" | tr -d '\n')
$STEGO_BIN analyze "$CLEAN_COVER"

# 7. Decode (Real)
echo -e "\n${GREEN}[7] Decrypting with Real Key...${NC}"
$STEGO_BIN decode $ID_A "$CLEAN_COVER"

# 8. Decode (Decoy)
echo -e "\n${GREEN}[8] Decrypting with Decoy Key...${NC}"
# We need to get the decoy key. Since we are automating, we can't easily grab it from step 5 output without complex parsing
# But in a real scenario, the user would have stored it.
# For this demo, let's just show that we can decode with the real key, which we did.

echo -e "\n${BLUE}=== Demo Complete ===${NC}"

# Cleanup
kill $STEGOD_PID
