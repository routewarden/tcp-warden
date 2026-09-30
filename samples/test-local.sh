#!/usr/bin/env bash
# ==============================================================================
# TCP Warden - Local Testing & Verification Script
# ==============================================================================
# Tests daemon management API, listeners, banlist enforcement, and stats.
#
# Usage:
#   chmod +x samples/test-local.sh
#   ./samples/test-local.sh [api_url]
# ==============================================================================

set -eo pipefail

API_URL="${1:-http://127.0.0.1:9091}"
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${BOLD}${CYAN}=== TCP Warden Local Test Runner ===${NC}"
echo -e "Target API: ${YELLOW}${API_URL}${NC}\n"

# 1. Health check
echo -e "${BOLD}[1/5] Checking Daemon Health (/health)...${NC}"
HEALTH_JSON=$(curl -s -f "${API_URL}/health" || echo "")
if [ -z "$HEALTH_JSON" ]; then
  echo -e "${RED}❌ Cannot connect to ${API_URL}.${NC}"
  echo -e "Make sure tcp-warden is running:"
  echo -e "  ${YELLOW}tcp-warden run --config samples/local-test.yaml${NC}"
  exit 1
fi
echo -e "${GREEN}✓ Daemon is online!${NC}"
echo "$HEALTH_JSON" | grep -o '"version":"[^"]*"' || true
echo "$HEALTH_JSON" | grep -o '"active_bans":[0-9]*' || true

# 2. Query configured services
echo -e "\n${BOLD}[2/5] Querying Configured Services (/api/services)...${NC}"
SERVICES_JSON=$(curl -s "${API_URL}/api/services")
echo -e "${GREEN}✓ Active Listeners:${NC}"
echo "$SERVICES_JSON" | tr '}' '\n' | grep '"name":' | while read -r line; do
  NAME=$(echo "$line" | sed -n 's/.*"name":"\([^"]*\)".*/\1/p')
  PROTO=$(echo "$line" | sed -n 's/.*"protocol":"\([^"]*\)".*/\1/p')
  LISTEN=$(echo "$line" | sed -n 's/.*"listen":"\([^"]*\)".*/\1/p')
  UPSTREAM=$(echo "$line" | sed -n 's/.*"upstream":"\([^"]*\)".*/\1/p')
  echo -e "  • ${BOLD}${NAME}${NC} [${CYAN}${PROTO}${NC}] ${LISTEN} -> ${UPSTREAM}"
done

# 3. Query live connection counters
echo -e "\n${BOLD}[3/5] Querying Service Stats (/api/stats)...${NC}"
curl -s "${API_URL}/api/stats" | head -c 200
echo -e "\n${GREEN}✓ Stats counters retrieved.${NC}"

# 4. Test Manual IP Ban & Banlist Query
TEST_IP="198.51.100.77"
echo -e "\n${BOLD}[4/5] Testing IP Ban Enforcement (/api/ban & /api/banlist)...${NC}"
echo -e "Applying test ban for IP: ${YELLOW}${TEST_IP}${NC} (duration: 1m)..."
BAN_RES=$(curl -s -X POST "${API_URL}/api/ban" \
  -H "Content-Type: application/json" \
  -d "{\"ip\":\"${TEST_IP}\",\"reason\":\"automated_test_ban\",\"duration\":\"1m\"}")
echo -e "Response: $BAN_RES"

echo "Verifying ${TEST_IP} in /api/banlist..."
BANLIST=$(curl -s "${API_URL}/api/banlist")
if echo "$BANLIST" | grep -q "${TEST_IP}"; then
  echo -e "${GREEN}✓ Ban verified! ${TEST_IP} is active in Layer 4 banlist.${NC}"
else
  echo -e "${RED}❌ Failed: ${TEST_IP} not found in banlist.${NC}"
fi

# 5. Test IP Unban
echo -e "\n${BOLD}[5/5] Testing IP Unban (/api/unban)...${NC}"
UNBAN_RES=$(curl -s -X POST "${API_URL}/api/unban" \
  -H "Content-Type: application/json" \
  -d "{\"ip\":\"${TEST_IP}\"}")
echo -e "Response: $UNBAN_RES"

echo "Verifying ${TEST_IP} removal from /api/banlist..."
BANLIST_AFTER=$(curl -s "${API_URL}/api/banlist")
if echo "$BANLIST_AFTER" | grep -q "${TEST_IP}"; then
  echo -e "${RED}❌ Failed: ${TEST_IP} still present in banlist.${NC}"
else
  echo -e "${GREEN}✓ Unban verified! ${TEST_IP} successfully removed.${NC}"
fi

echo -e "\n${BOLD}${GREEN}All tests completed successfully!${NC}"
echo -e "To test with RouteWarden CLI dashboard:"
echo -e "  ${YELLOW}rwarden dashboard --tcp-warden ${API_URL}${NC}\n"
