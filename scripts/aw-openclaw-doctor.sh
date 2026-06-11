#!/usr/bin/env bash
# aw-openclaw-doctor.sh — diagnose whether Agent Warden is actually governing
# OpenClaw RIGHT NOW. Read-only: it changes nothing, it just answers "is AW in
# the loop, and if not, why?" Run it any time the integration feels off.
#
# Checks, in order:
#   1. bridge binary on PATH + self-test passes
#   2. plugin is enabled
#   3. before_tool_call hook is registered in the running Gateway
#   4. ledger exists and how fresh it is (did a recent session route through us?)
#   5. reminders for the two classic traps (tui vs chat; trusting agent self-report)
#
# Target: Linux OpenClaw VPS. jq used if present.
# Licensed under the Apache License 2.0.
set -uo pipefail   # NOT -e: the doctor reports failures, it doesn't abort on them

AW_DATA_DIR="${AW_DATA_DIR:-/root/aw-data}"
LEDGER="$AW_DATA_DIR/.aw-openclaw/ledger.log"

pass() { printf '  \033[32m[PASS]\033[0m %s\n' "$*"; }
fail() { printf '  \033[31m[FAIL]\033[0m %s\n' "$*"; PROBLEMS=$((PROBLEMS+1)); }
info() { printf '  \033[36m[i]\033[0m %s\n' "$*"; }
PROBLEMS=0

printf '\n\033[1mAgent Warden — Tier-1 doctor\033[0m  (data dir: %s)\n' "$AW_DATA_DIR"

# 1. bridge on PATH + self-test
printf '\n1. Bridge binary\n'
if command -v aw-openclaw-bridge >/dev/null; then
  pass "aw-openclaw-bridge on PATH ($(command -v aw-openclaw-bridge))"
  VER="$(aw-openclaw-bridge -version 2>/dev/null || echo '?')"; info "version: $VER"
  if aw-openclaw-bridge -selftest >/tmp/aw-selftest.out 2>&1; then
    pass "self-test PASS (four-verdict mapping healthy)"
  else
    fail "self-test FAILED — see /tmp/aw-selftest.out"
  fi
else
  fail "aw-openclaw-bridge NOT on PATH. Run scripts/aw-openclaw-setup.sh."
fi

# 2. plugin enabled
printf '\n2. Plugin enabled\n'
if openclaw plugins list 2>/dev/null | grep -qi 'agent-warden'; then
  pass "agent-warden appears in 'plugins list'"
else
  fail "agent-warden NOT in 'plugins list'. Run setup (install --link + enable)."
fi

# 3. hook registered in the running gateway
printf '\n3. before_tool_call hook (running Gateway)\n'
INSPECT="$(openclaw plugins inspect agent-warden --runtime --json 2>/dev/null || true)"
if [ -z "$INSPECT" ]; then
  fail "plugins inspect returned nothing — plugin not loaded in the running Gateway."
elif printf '%s' "$INSPECT" | grep -q 'before_tool_call'; then
  pass "before_tool_call present in runtime inspect — AW is in the loop"
  if command -v jq >/dev/null; then
    ACT="$(printf '%s' "$INSPECT" | jq -r '.activated // .runtime.activated // "?"' 2>/dev/null)"
    info "activated: $ACT"
  fi
else
  fail "before_tool_call NOT registered. Tool calls are UNGOVERNED. Re-run setup + restart gateway."
fi

# 4. ledger freshness
printf '\n4. Ledger (proof of real governance)\n'
if [ -f "$LEDGER" ]; then
  LINES="$(wc -l < "$LEDGER" 2>/dev/null || echo 0)"
  AGE=$(( $(date +%s) - $(stat -c %Y "$LEDGER" 2>/dev/null || echo 0) ))
  pass "ledger exists: $LEDGER ($LINES records)"
  if [ "$AGE" -lt 3600 ]; then
    info "last written ${AGE}s ago — a recent session routed through the broker"
  else
    info "last written ${AGE}s ago — no governance in the last hour (drive a tool call to refresh)"
  fi
else
  info "no ledger yet at $LEDGER — none written until a governed tool call runs (this is normal pre-first-run)"
fi

# 5. the two classic traps
printf '\n5. Reminders (the two traps that wasted real time before)\n'
info "Use 'openclaw tui' (gateway-backed). 'chat'/'terminal'/'tui --local' run EMBEDDED and BYPASS the plugin."
info "Do NOT trust the agent's self-description of its sandbox — it confabulates. The LEDGER is the truth (verify-over-trust)."
info "Gateway logs (user systemd service) live in files, e.g. /tmp/openclaw-*/openclaw-*.log — grep for '[agent-warden]'."

# verdict
printf '\n'
if [ "$PROBLEMS" -eq 0 ]; then
  printf '\033[32m[DOCTOR] All checks passed — Agent Warden is governing OpenClaw.\033[0m\n'
  exit 0
else
  printf '\033[31m[DOCTOR] %s problem(s) found — see [FAIL] lines above. Re-run scripts/aw-openclaw-setup.sh.\033[0m\n' "$PROBLEMS"
  exit 1
fi
