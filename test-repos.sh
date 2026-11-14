#!/bin/bash
# OSTE Multi-Repo Test Script
# Tests various repos with different risk profiles

BASE_URL="http://localhost:3000"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Test repos - mix of healthy, moderate, and potentially risky
REPOS=(
  "facebook/react"           # Healthy, well-maintained
  "expressjs/express"        # Popular web framework
  "moment/moment"            # Deprecated / no longer maintained
  "jquery/jquery"            # Legacy, many historical CVEs
  "marcogreselin/jsteg"      # Small steganography tool
  "left-pad/left-pad"        # Tiny abandoned/archived package (famous incident)
  "nicehash/excavator"       # Crypto mining tool
  "wifiphisher/wifiphisher"  # Security/hacking tool
)

echo -e "${BOLD}${CYAN}"
echo "╔═══════════════════════════════════════════════════╗"
echo "║   OSTE Multi-Repository Test Suite                ║"
echo "║   Testing ${#REPOS[@]} repositories...                      ║"
echo "╚═══════════════════════════════════════════════════╝"
echo -e "${NC}"

declare -A JOB_IDS

# Step 1: Submit and poll each repository sequentially (respects free-tier rate limits & concurrency cap)
echo -e "${BOLD}📤 Running analyses sequentially (free-tier safe)...${NC}"
for repo in "${REPOS[@]}"; do
  for attempt in $(seq 1 10); do
    RESPONSE=$(curl -s -X POST "$BASE_URL/api/analyze" \
      -H 'Content-Type: application/json' \
      -d "{\"input\":\"$repo\"}")
    JOB_ID=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('jobId',''))" 2>/dev/null)
    SUCCESS=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('success',False))" 2>/dev/null)
    if [ "$SUCCESS" = "True" ]; then
      break
    fi
    sleep 3
  done

  if [ "$SUCCESS" = "True" ]; then
    JOB_IDS["$repo"]="$JOB_ID"
    echo -ne "  ${CYAN}⏳${NC} $repo → $JOB_ID ..."
    for i in $(seq 1 90); do
      STATUS=$(curl -s "$BASE_URL/api/jobs/$JOB_ID" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null)
      if [ "$STATUS" = "completed" ] || [ "$STATUS" = "failed" ]; then
        break
      fi
      sleep 2
    done
    echo -e "\r  ${GREEN}✔${NC} $repo → $JOB_ID ($STATUS)"
  else
    echo -e "  ${RED}✖${NC} $repo → Failed to submit"
  fi
done

echo ""

# Step 2: Collect results
echo ""
echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════════════════════════${NC}"
printf "${BOLD}%-30s %6s  %-10s  %-24s  %s${NC}\n" "REPOSITORY" "SCORE" "LEVEL" "DECISION" "VULNS"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════════${NC}"

for repo in "${REPOS[@]}"; do
  JOB_ID="${JOB_IDS[$repo]}"
  if [ -z "$JOB_ID" ]; then
    printf "%-30s %6s  %-10s  %-24s  %s\n" "$repo" "ERR" "—" "SUBMIT FAILED" "—"
    continue
  fi
  
  # Poll until done (max 30 seconds)
  for i in $(seq 1 15); do
    STATUS=$(curl -s "$BASE_URL/api/jobs/$JOB_ID" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null)
    if [ "$STATUS" = "completed" ] || [ "$STATUS" = "failed" ]; then
      break
    fi
    sleep 2
  done
  
  RESULT=$(curl -s "$BASE_URL/api/jobs/$JOB_ID")
  
  SCORE=$(echo "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('result',{}).get('riskScore',{}).get('overallRiskScore','?'))" 2>/dev/null)
  LEVEL=$(echo "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('result',{}).get('riskScore',{}).get('riskLevel','?'))" 2>/dev/null)
  DECISION=$(echo "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('result',{}).get('riskScore',{}).get('decision','?'))" 2>/dev/null)
  VULNS=$(echo "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('result',{}).get('data',{}).get('vulnerabilitySummary',{}).get('total',0))" 2>/dev/null)
  JOB_STATUS=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','?'))" 2>/dev/null)
  
  # Color based on level
  case "$LEVEL" in
    CRITICAL) COLOR=$RED ;;
    HIGH)     COLOR=$RED ;;
    MEDIUM)   COLOR=$YELLOW ;;
    LOW)      COLOR=$BLUE ;;
    MINIMAL)  COLOR=$GREEN ;;
    *)        COLOR=$NC ;;
  esac
  
  if [ "$JOB_STATUS" = "failed" ]; then
    printf "%-30s %6s  %-10s  %-24s  %s\n" "$repo" "ERR" "—" "ANALYSIS FAILED" "—"
  else
    printf "%-30s ${COLOR}%6s  %-10s${NC}  %-24s  %s\n" "$repo" "$SCORE" "$LEVEL" "$DECISION" "$VULNS"
  fi
done

echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════════${NC}"
echo ""

# Step 3: Print detailed breakdown for each
echo -e "${BOLD}📊 Detailed Component Breakdowns${NC}"
echo ""

for repo in "${REPOS[@]}"; do
  JOB_ID="${JOB_IDS[$repo]}"
  [ -z "$JOB_ID" ] && continue
  
  echo -e "${BOLD}── $repo ──${NC}"
  
  curl -s "$BASE_URL/api/jobs/$JOB_ID" | python3 -c "
import sys, json
d = json.load(sys.stdin)
r = d.get('result', {})
rs = r.get('riskScore', {})
comps = rs.get('components', {})

if d.get('status') != 'completed':
    print('  Status:', d.get('status', '?'))
    if d.get('error'):
        print('  Error:', d.get('error'))
    print()
    sys.exit()

# Repo info
repo = r.get('data', {}).get('repository', {})
if repo:
    print(f'  Stars: {repo.get(\"stars\",\"?\"):,}  Forks: {repo.get(\"forks\",\"?\"):,}  Issues: {repo.get(\"openIssues\",\"?\")}')
    lic = repo.get('license')
    print(f'  License: {lic.get(\"name\") if lic else \"None\"}  Archived: {repo.get(\"archived\", False)}')
    print(f'  Last push: {repo.get(\"pushedAt\",\"?\")[:10] if repo.get(\"pushedAt\") else \"?\"}')

# Components
for k, v in comps.items():
    if v.get('available') is False:
        print(f'  {v[\"label\"]:30s}   n/a   {\"░\"*20}  (excluded)')
    else:
        bar = '█' * (v['score'] // 5) + '░' * (20 - v['score'] // 5)
        w = v.get('effectiveWeight', v['weight']) * 100
        print(f'  {v[\"label\"]:30s} {v[\"score\"]:3d}/100  {bar}  ({w:.0f}%)')

# Vulns
vs = r.get('data', {}).get('vulnerabilitySummary', {})
if vs.get('total', 0) > 0:
    print(f'  Vulnerabilities: {vs[\"total\"]} total (C:{vs.get(\"CRITICAL\",0)} H:{vs.get(\"HIGH\",0)} M:{vs.get(\"MEDIUM\",0)} L:{vs.get(\"LOW\",0)})')

print()
" 2>/dev/null
done

echo -e "${BOLD}${GREEN}✅ Test complete!${NC}"

