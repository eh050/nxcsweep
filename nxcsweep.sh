#!/usr/bin/env bash
#
# nxcsweep — port-aware NetExec enumeration wrapper.
#
# Usage:
#   nxcsweep <IP> -u <username> (-p <password> | -H <hash>) [global flags...]
#
# Examples:
#   nxcsweep 10.10.10.50 -u alice -p 'Password1' --local-auth
#   nxcsweep 10.10.10.50 -u alice -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

set -u

# =============================================================================
# Colors
# =============================================================================
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  BLUE='\033[0;34m'
  YELLOW='\033[38;5;226m'
  GREEN='\033[0;32m'
  GREY='\033[38;5;244m'
  RED='\033[0;31m'
  BOLD_RED='\033[1;31m'
  NC='\033[0m'
else
  BLUE='' YELLOW='' GREEN='' GREY='' RED='' BOLD_RED='' NC=''
fi

log()      { printf '%b[*] %s%b\n' "$BLUE" "$*" "$NC" | tee -a "$LOGFILE"; }
ok()       { printf '%b[+] %s%b\n' "$GREEN" "$*" "$NC" | tee -a "$LOGFILE"; }
skip()     { printf '%b[-] %s%b\n' "$GREY" "$*" "$NC" | tee -a "$LOGFILE"; }
warn()     { printf '%b[!] %s%b\n' "$RED" "$*" "$NC" >&2; }
pwned()    { printf '%b[!!!] %s%b\n' "$BOLD_RED" "$*" "$NC" | tee -a "$LOGFILE"; }
die()      { warn "$*"; exit 1; }

# =============================================================================
# Usage / dependencies
# =============================================================================
usage() {
  printf '%bUsage: %s <IP> -u <username> (-p <password> | -H <hash>) [global flags...]%b\n' \
    "$YELLOW" "$(basename "$0")" "$NC" >&2
  exit 1
}

command -v nxc &>/dev/null || die "Required binary 'nxc' not found in PATH."

HAVE_NC=0
command -v nc &>/dev/null && HAVE_NC=1

# =============================================================================
# Argument parsing (nxc-style: target first)
# =============================================================================
[[ -n "${1:-}" && "$1" != -* ]] || usage

TARGET=$1
shift

USER=""
PASS=""
HASH=""
GLOBAL_FLAGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -u)
      [[ $# -ge 2 ]] || die "-u requires a username"
      USER=$2
      shift 2
      ;;
    -p)
      [[ $# -ge 2 ]] || die "-p requires a password"
      PASS=$2
      shift 2
      ;;
    -H)
      [[ $# -ge 2 ]] || die "-H requires a hash"
      HASH=$2
      shift 2
      ;;
    *)
      GLOBAL_FLAGS+=("$1")
      shift
      ;;
  esac
done

[[ -n "$TARGET" && -n "$USER" ]] || usage

if [[ -z "$PASS" && -z "$HASH" ]]; then
  warn "Provide either -p <password> or -H <hash>."
  usage
fi
if [[ -n "$PASS" && -n "$HASH" ]]; then
  warn "Provide only one of -p or -H, not both."
  usage
fi

if [[ -n "$PASS" ]]; then
  AUTH_FLAGS=(-u "$USER" -p "$PASS")
else
  AUTH_FLAGS=(-u "$USER" -H "$HASH")
fi

# =============================================================================
# Output
# =============================================================================
STAMP=$(date +%Y%m%d-%H%M%S)
OUTDIR="nxcsweep_${TARGET}_${STAMP}"
mkdir -p "$OUTDIR"
LOGFILE="$OUTDIR/full.log"

# Protocols that returned "(Pwn3d!)" this run
PWNED_PROTOS=()

log "Starting NXC sweep for $TARGET as $USER ..."
skip "Output directory: $OUTDIR"
printf '\n' | tee -a "$LOGFILE"

# =============================================================================
# Port check
# =============================================================================
port_open() {
  local port=$1
  if [[ "$HAVE_NC" -eq 1 ]]; then
    nc -z -w 1 "$TARGET" "$port" 2>/dev/null
    return $?
  fi

  (exec 3<>"/dev/tcp/$TARGET/$port") 2>/dev/null
  local rc=$?
  exec 3>&- 2>/dev/null || true
  return "$rc"
}

# Per-protocol flags to strip from GLOBAL_FLAGS (extend as needed)
declare -A EXCLUDE_FLAGS=(
  [ftp]="--local-auth"
)

filtered_global_flags() {
  local proto=$1
  local -n _out=$2
  _out=()
  local skip_flag="${EXCLUDE_FLAGS[$proto]:-}"
  local flag
  for flag in "${GLOBAL_FLAGS[@]+"${GLOBAL_FLAGS[@]}"}"; do
    [[ -n "$skip_flag" && "$flag" == "$skip_flag" ]] && continue
    _out+=("$flag")
  done
}

# run_check <port> <proto> <variant_array_name> [<variant_array_name> ...]
run_check() {
  local port=$1 proto=$2
  shift 2
  local variant_names=("$@")

  if ! port_open "$port"; then
    skip "Port $port closed/filtered. Skipping ${proto}"
    printf '\n'
    return
  fi

  ok "Port $port open. Checking ${proto} ..."

  local safe_flags=()
  filtered_global_flags "$proto" safe_flags

  local vname tmp_out
  for vname in "${variant_names[@]}"; do
    local -n variant="$vname"
    log "nxc $proto ${variant[*]}"

    tmp_out=$(mktemp)
    nxc "$proto" "$TARGET" "${AUTH_FLAGS[@]}" \
      ${safe_flags[@]+"${safe_flags[@]}"} \
      ${variant[@]+"${variant[@]}"} \
      2>&1 | tee -a "$LOGFILE" "$tmp_out"

    if grep -q '(Pwn3d!)' "$tmp_out"; then
      pwned "ADMIN ACCESS — ${proto^^} on ${TARGET} returned (Pwn3d!). This account has high-privileged access to the target."
      PWNED_PROTOS+=("$proto")
    fi
    rm -f "$tmp_out"
    printf '\n'
  done

  printf '\n' | tee -a "$LOGFILE"
}

# =============================================================================
# Protocol command variants
# =============================================================================
SMB_1=(--shares)
SMB_2=(--users-export "$OUTDIR/users.list")
SMB_3=(--loggedon-users)
SMB_4=(--pass-pol)
SMB_5=(-M gpp_autologin)
SMB_6=(-M gpp_password)

WINRM_1=()
RDP_1=()
MSSQL_1=(-q "SELECT name FROM master.sys.databases;")
FTP_1=(--ls)

LDAP_1=()
LDAP_2=(--kerberoasting "$OUTDIR/kerberoast.out")
LDAP_3=(--asreproast "$OUTDIR/asreproast.out")

# =============================================================================
# Sweep
# =============================================================================
run_check 445  smb   SMB_1 SMB_2 SMB_3 SMB_4 SMB_5 SMB_6
run_check 5985 winrm WINRM_1
run_check 3389 rdp   RDP_1
run_check 1433 mssql MSSQL_1
run_check 21   ftp   FTP_1
run_check 389  ldap  LDAP_1 LDAP_2 LDAP_3

log "All active services checked. Results in ${OUTDIR}/"

if [[ "${#PWNED_PROTOS[@]}" -gt 0 ]]; then
  unique_protos=$(printf '%s\n' "${PWNED_PROTOS[@]}" | sort -u | tr '\n' ' ')
  pwned "$USER has admin/high-privileged access via: ${unique_protos^^}"
else
  skip "No (Pwn3d!) admin markers seen this sweep."
fi
