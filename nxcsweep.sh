#!/bin/bash
# nxc-sweep - port-aware NetExec enumeration wrapper
set -u

# --- Colors ---
BLUE='\033[0;34m'
YELLOW='\033[38;5;226m'
GREEN='\033[0;32m'
GREY='\033[38;5;244m'
RED='\033[0;31m'
BOLD_RED='\033[1;31m'
NC_COLOR='\033[0m'

# --- Help Menu ---
usage() {
    echo -e "${YELLOW}Usage: nxc-sweep <IP> -u <username> (-p <password> | -H <hash>) [global flags]${NC_COLOR}"
    exit 1
}

# --- Dependency checks ---
for bin in nxc; do
    if ! command -v "$bin" &>/dev/null; then
        echo -e "${RED}[!] Required binary '$bin' not found in PATH.${NC_COLOR}"
        exit 1
    fi
done
HAVE_NC=1
command -v nc &>/dev/null || HAVE_NC=0

# --- Argument parsing ---
# pulls IP first like in native nxc syntax
if [[ -z "${1:-}" || "$1" == -* ]]; then
    usage
fi
TARGET=$1
shift

USER=""
PASS=""
HASH=""
GLOBAL_FLAGS=()
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -u) USER=$2; shift 2 ;;
        -p) PASS=$2; shift 2 ;;
        -H) HASH=$2; shift 2 ;;
        *) GLOBAL_FLAGS+=("$1"); shift 1 ;;
    esac
done

if [[ -z "$TARGET" || -z "$USER" ]]; then
    usage
fi
if [[ -z "$PASS" && -z "$HASH" ]]; then
    echo -e "${RED}[!] Provide either -p <password> or -H <hash>.${NC_COLOR}"
    usage
fi
if [[ -n "$PASS" && -n "$HASH" ]]; then
    echo -e "${RED}[!] Provide only one of -p or -H, not both.${NC_COLOR}"
    usage
fi

# builds the auth flags once, used by every nxc call below
if [[ -n "$PASS" ]]; then
    AUTH_FLAGS=(-u "$USER" -p "$PASS")
else
    AUTH_FLAGS=(-u "$USER" -H "$HASH")
fi

# --- Output directory (per target, timestamped) ---
STAMP=$(date +%Y%m%d-%H%M%S)
OUTDIR="nxc-sweep_${TARGET}_${STAMP}"
mkdir -p "$OUTDIR"
LOGFILE="$OUTDIR/full.log"

# tracks which protocols returned a "(Pwn3d!)" admin hit, for the end-of-run summary
PWNED_PROTOS=()

echo -e "${BLUE}[*] Starting NXC sweep for $TARGET as $USER ...${NC_COLOR}\n" | tee -a "$LOGFILE"
echo -e "${GREY}[*] Output directory: $OUTDIR${NC_COLOR}\n" | tee -a "$LOGFILE"

# --- Port check (nc if available, else /dev/tcp fallback) ---
port_open() {
    local port=$1
    if [[ "$HAVE_NC" -eq 1 ]]; then
        nc -z -w 1 "$TARGET" "$port" 2>/dev/null
        return $?
    else
        (exec 3<>"/dev/tcp/$TARGET/$port") 2>/dev/null
        local rc=$?
        exec 3>&- 2>/dev/null
        return $rc
    fi
}

# per-protocol flags to strip from GLOBAL_FLAGS (extend as needed)
declare -A EXCLUDE_FLAGS=(
    [ftp]="--local-auth"
)

filtered_global_flags() {
    local proto=$1
    local -n _out=$2   # nameref to caller's array
    _out=()
    local skip="${EXCLUDE_FLAGS[$proto]:-}"
    for flag in "${GLOBAL_FLAGS[@]}"; do
        if [[ -n "$skip" && "$flag" == "$skip" ]]; then
            continue
        fi
        _out+=("$flag")
    done
}

# Runs one or more nxc command variants against a protocol, after confirming
# the port is open. Each variant is passed as the *name* of a bash array
# variable (nameref), so no eval / string-splitting is involved.
#
# Usage: run_check <port> <proto> <variant_array_name> [<variant_array_name> ...]
run_check() {
    local port=$1 proto=$2
    shift 2
    local variant_names=("$@")

    if ! port_open "$port"; then
        echo -e "${GREY}[-] Port $port closed/filtered. Skipping ${proto}${NC_COLOR}" | tee -a "$LOGFILE"
        echo ""
        return
    fi
    echo -e "${GREEN}[+] Port $port open. Checking ${proto} ...${NC_COLOR}" | tee -a "$LOGFILE"

    local safe_flags
    filtered_global_flags "$proto" safe_flags

    for vname in "${variant_names[@]}"; do
        local -n variant="$vname"
        echo -e "${BLUE}[*] nxc $proto ${variant[*]}${NC_COLOR}" | tee -a "$LOGFILE"

        # capture this run's output to a temp file (in addition to the live
        # log) so we can scan it for the "(Pwn3d!)" admin marker afterward
        local tmp_out
        tmp_out=$(mktemp)
        nxc "$proto" "$TARGET" "${AUTH_FLAGS[@]}" "${safe_flags[@]}" "${variant[@]}" 2>&1 | tee -a "$LOGFILE" "$tmp_out"

        if grep -q '(Pwn3d!)' "$tmp_out"; then
            echo -e "${BOLD_RED}[!!!] ADMIN ACCESS — ${proto^^} on ${TARGET} returned (Pwn3d!). This account has high-privileged access to the target.${NC_COLOR}" | tee -a "$LOGFILE"
            PWNED_PROTOS+=("$proto")
        fi
        rm -f "$tmp_out"
        echo ""
    done
    echo "" | tee -a "$LOGFILE"
}

# --- Protocol command variants ---
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

# --- Run sweep ---
run_check 445  smb   SMB_1 SMB_2 SMB_3 SMB_4 SMB_5 SMB_6
run_check 5985 winrm WINRM_1
run_check 3389 rdp   RDP_1
run_check 1433 mssql MSSQL_1
run_check 21   ftp   FTP_1
run_check 389  ldap  LDAP_1 LDAP_2 LDAP_3

echo -e "${BLUE}[*] All active services checked. Results in ${OUTDIR}/${NC_COLOR}" | tee -a "$LOGFILE"

# --- Admin-access summary ---
if [[ "${#PWNED_PROTOS[@]}" -gt 0 ]]; then
    # de-duplicate in case a protocol had multiple variants that each hit Pwn3d!
    unique_protos=$(printf '%s\n' "${PWNED_PROTOS[@]}" | sort -u | tr '\n' ' ')
    echo -e "${BOLD_RED}[!!!] $USER has admin/high-privileged access via: ${unique_protos^^}${NC_COLOR}" | tee -a "$LOGFILE"
else
    echo -e "${GREY}[*] No (Pwn3d!) admin markers seen this sweep.${NC_COLOR}" | tee -a "$LOGFILE"
fi
