#!/bin/bash
# Demo script for Subtext with peer reply simulation

GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

SUBTEXT="./bin/subtext"
SUBTEXTD="./bin/subtextd"
TMP=$(mktemp -d)
TOPIC="fitness"
SECRET="Meet at dock 7 at midnight"

cleanup() { kill $PID 2>/dev/null; rm -rf "$TMP"; }
trap cleanup EXIT

echo -e "${BLUE}=== Subtext Demo ===${NC}"

# Start daemon
echo -e "\n${GREEN}[1] Starting Daemon...${NC}"
pkill subtextd 2>/dev/null
$SUBTEXTD > subtextd.log 2>&1 &
PID=$!
sleep 2

# Check status
$SUBTEXT status

# Create session + key exchange
echo -e "\n${GREEN}[2] Session Setup...${NC}"
OUT=$($SUBTEXT session create "alice@example.com" --name "Alice")
SID=$(echo "$OUT" | grep "ID:" | awk '{print $2}')
KEY=$($SUBTEXT session key-exchange $SID | grep -v "Your public key")
$SUBTEXT session complete-key-exchange $SID $KEY > /dev/null
echo "Session $SID ready"

# Interactive encode
echo -e "\n${GREEN}[3] Encoding: '$SECRET' (topic: $TOPIC)${NC}"

# convo start --raw outputs: flow_id\tcover_text\tdone\tattempt
RAW=$($SUBTEXT convo start $SID "$SECRET" --topic "$TOPIC" --raw)
FLOW=$(printf '%s' "$RAW" | cut -f1)
COVER=$(printf '%s' "$RAW" | cut -f2)
DONE=$(printf '%s' "$RAW" | cut -f3)
ATTEMPT=$(printf '%s' "$RAW" | cut -f4)

echo -e "\n${BLUE}--- Conversation ---${NC}"
echo -e "${CYAN}Alice:${NC} $COVER"

# Save cover text for segment 1
printf '%s' "$COVER" > "$TMP/seg1.txt"
N=1

# Collect decode args and per-segment attempts
DECODE_ARGS=("--cover-file" "$TMP/all.txt" "--topic" "$TOPIC" "--attempt" "$ATTEMPT")

while [ "$DONE" = "0" ]; do
    # Peer reply
    REPLY=$($SUBTEXT reply "$COVER" --topic "$TOPIC" --raw)
    echo -e "${GREEN}Bob:${NC}   $REPLY"
    DECODE_ARGS[${#DECODE_ARGS[@]}]="--peer-reply"
    DECODE_ARGS[${#DECODE_ARGS[@]}]="$REPLY"

    # Next segment
    RAW=$($SUBTEXT convo next "$FLOW" "$REPLY" --raw)
    COVER=$(printf '%s' "$RAW" | cut -f2)
    DONE=$(printf '%s' "$RAW" | cut -f3)
    ATTEMPT=$(printf '%s' "$RAW" | cut -f4)
    N=$((N + 1))
    printf '%s' "$COVER" > "$TMP/seg${N}.txt"
    echo -e "${CYAN}Alice:${NC} $COVER"
    DECODE_ARGS[${#DECODE_ARGS[@]}]="--attempt"
    DECODE_ARGS[${#DECODE_ARGS[@]}]="$ATTEMPT"
done

echo -e "${BLUE}--- End ($N segments) ---${NC}"

# Assemble cover file with separators
cat "$TMP/seg1.txt" > "$TMP/all.txt"
i=2
while [ $i -le $N ]; do
    printf '\n\n---SEG---\n\n' >> "$TMP/all.txt"
    cat "$TMP/seg${i}.txt" >> "$TMP/all.txt"
    i=$((i + 1))
done

# Decode
echo -e "\n${GREEN}[4] Decoding...${NC}"
DECODED=$($SUBTEXT convo decode "$SID" "${DECODE_ARGS[@]}" 2>&1)
echo "Decoded: $DECODED"

if [ "$DECODED" = "$SECRET" ]; then
    echo -e "${GREEN}Round-trip successful!${NC}"
else
    echo -e "${RED}Round-trip FAILED: expected '$SECRET'${NC}"
fi

echo -e "\n${BLUE}=== Done ===${NC}"
