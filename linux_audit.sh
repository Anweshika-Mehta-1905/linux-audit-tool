#!/usr/bin/env bash
#
# linux_audit.sh - Automated, READ-ONLY Linux security configuration & permission audit
#
# Usage:  ./linux_audit.sh [--no-color] [-h|--help]
#
# Notes:
#   * Strictly read-only: nothing is modified, no discovered binary is executed.
#   * Access checks reflect the EFFECTIVE privileges of the invoking user. When run
#     as root, "can write/read" is evaluated from world-accessible mode bits instead
#     (root bypasses permission checks, so a literal test would flag everything).
#   * Exit status: 0 = no critical findings, 1 = at least one critical finding.
#

LC_ALL=C
export LC_ALL

TOTAL=0
CRIT=0
INFO=0
PASS=0
MAX_LIST=40

# Common GTFOBins / living-off-the-land utilities (matched on basename;
# versioned names such as python3, python3.11, perl5.34.0 also match).
GTFO_BINS=(
  bash sh dash zsh ksh csh tcsh
  find vim vi nano ed cp mv awk gawk mawk sed
  python perl ruby php lua node tclsh
  tar zip unzip nmap less more man env pkexec
  gdb strace tcpdump rsync git ssh ftp wget curl
  dd tee base64 xargs nice timeout taskset watch
  docker systemctl
)

usage() {
  cat <<'EOF'
linux_audit.sh - read-only Linux security configuration & permission audit

Options:
  --no-color    Disable ANSI colors (also honored via NO_COLOR=1)
  -h, --help    Show this help

Tip: ./linux_audit.sh 2>&1 | less -R    (paginate while keeping colors)
EOF
}

NO_COLOR_FLAG=0
for arg in "$@"; do
  case "$arg" in
    --no-color) NO_COLOR_FLAG=1 ;;
    -h|--help)  usage; exit 0 ;;
    *)          printf 'Unknown option: %s\n' "$arg" >&2; usage >&2; exit 2 ;;
  esac
done

# ----------------------------------------------------------------------------
# Colors
# ----------------------------------------------------------------------------
if [ "$NO_COLOR_FLAG" -eq 1 ] || [ -n "${NO_COLOR:-}" ]; then
  RED=""; BOLD_RED=""; YELLOW=""; GREEN=""; BLUE=""; BOLD=""; RESET=""
else
  RED=$'\033[0;31m'
  BOLD_RED=$'\033[1;31m'
  YELLOW=$'\033[0;33m'
  GREEN=$'\033[0;32m'
  BLUE=$'\033[0;34m'
  BOLD=$'\033[1m'
  RESET=$'\033[0m'
fi

UID_NOW=$(id -u 2>/dev/null)
UID_NOW=${UID_NOW:-65534}
USER_NOW=$(id -un 2>/dev/null)
USER_NOW=${USER_NOW:-unknown}

# ----------------------------------------------------------------------------
# Output helpers
# ----------------------------------------------------------------------------
section() { printf '\n%s%s=== %s ===%s\n' "$BOLD" "$BLUE" "$1" "$RESET"; }
kv()      { printf '  %s%-20s%s %s\n' "$BOLD" "$1" "$RESET" "$2"; }
plain()   { printf '             %s\n' "$*"; }
chk()     { TOTAL=$((TOTAL + 1)); }

crit() {
  CRIT=$((CRIT + 1))
  printf '  %s[CRITICAL]%s %s%s%s\n' "$BOLD_RED" "$RESET" "$RED" "$*" "$RESET"
}
crit_hl() {
  CRIT=$((CRIT + 1))
  printf '  %s[CRITICAL] %s%s\n' "$BOLD_RED" "$*" "$RESET"
}
warn() {
  INFO=$((INFO + 1))
  printf '  %s[REVIEW]%s   %s%s%s\n' "$YELLOW" "$RESET" "$YELLOW" "$*" "$RESET"
}
note() {
  INFO=$((INFO + 1))
  printf '  %s[INFO]%s     %s\n' "$BLUE" "$RESET" "$*"
}
ok() {
  PASS=$((PASS + 1))
  printf '  %s[ OK ]%s     %s\n' "$GREEN" "$RESET" "$*"
}

stat_brief() { stat -c '%A %U:%G' "$1" 2>/dev/null || printf '?'; }

can_write() {
  if [ "$UID_NOW" -eq 0 ]; then
    [ -n "$(find -H "$1" -maxdepth 0 -perm -0002 2>/dev/null)" ]
  else
    [ -w "$1" ]
  fi
}
can_read() {
  if [ "$UID_NOW" -eq 0 ]; then
    [ -n "$(find -H "$1" -maxdepth 0 -perm -0004 2>/dev/null)" ]
  else
    [ -r "$1" ]
  fi
}

find_writable() {
  local p="$1"
  shift
  if [ "$UID_NOW" -eq 0 ]; then
    find "$p" "$@" -perm -0002 2>/dev/null
  else
    find "$p" "$@" -writable 2>/dev/null
  fi
}

report_paths() {
  local level="$1" label="$2" list="$3" n=0 p
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    n=$((n + 1))
    if [ "$n" -le "$MAX_LIST" ]; then
      "$level" "$label: $p"
    elif [ "$level" = "crit" ]; then
      CRIT=$((CRIT + 1))
    else
      INFO=$((INFO + 1))
    fi
  done <<< "$list"
  if [ "$n" -gt "$MAX_LIST" ]; then
    plain "... $((n - MAX_LIST)) additional entries not shown (counted in summary)"
  fi
  return 0
}

is_gtfo() {
  local name="$1" g
  for g in "${GTFO_BINS[@]}"; do
    if [[ "$name" == "$g" || "$name" == "$g"[0-9]* ]]; then
      return 0
    fi
  done
  return 1
}

banner() {
  printf '%s' "$BLUE"
  cat <<'EOF'
 +------------------------------------------------------------+
 |   _     ___ _   _ _   ___  __     _   _   _ ____ ___ _____ |
 |  | |   |_ _| \ | | | | \ \/ /    / \ | | | |  _ \_ _|_   _||
 |  | |    | ||  \| | | | |\  /    / _ \| | | | | | | |  | |  |
 |  | |___ | || |\  | |_| |/  \   / ___ \ |_| | |_| | |  | |  |
 |  |_____|___|_| \_|\___//_/\_\ /_/   \_\___/|____/___| |_|  |
 |                                                            |
 |        READ-ONLY SECURITY CONFIGURATION & PERMISSION AUDIT |
 +------------------------------------------------------------+
EOF
  printf '%s' "$RESET"
  printf '  Started : %s\n' "$(date '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null)"
  printf '  Mode    : read-only (no changes are made to this system)\n'
}

# ============================================================================
# MODULE 1: System & Environment Profile
# ============================================================================
audit_path() {
  local entry issues=0
  local -a entries
  chk
  if [[ ":$PATH:" == *"::"* ]]; then
    crit "\$PATH contains an empty entry (resolves to the current directory)"
    issues=$((issues + 1))
  fi
  IFS=':' read -r -a entries <<< "$PATH"
  for entry in "${entries[@]}"; do
    [ -n "$entry" ] || continue
    case "$entry" in
      /*) ;;
      *)
        crit "\$PATH contains a relative/dot entry: '$entry'"
        issues=$((issues + 1))
        continue
        ;;
    esac
    case "$entry" in
      */.|*/./*|*/..|*/../*)
        crit "\$PATH entry contains a '.'/'..' component: '$entry'"
        issues=$((issues + 1))
        ;;
    esac
    if [ -d "$entry" ] && [ -n "$(find -H "$entry" -maxdepth 0 -perm -0002 2>/dev/null)" ]; then
      crit "\$PATH directory is world-writable: $entry ($(stat_brief "$entry"))"
      issues=$((issues + 1))
    fi
  done
  if [ "$issues" -eq 0 ]; then
    ok "\$PATH has no relative, dot, or world-writable entries"
  fi
}

audit_profile() {
  section "1. SYSTEM & ENVIRONMENT PROFILE"
  local os="" g gflag=0

  if [ -r /etc/os-release ]; then
    os=$(grep -m1 '^PRETTY_NAME=' /etc/os-release 2>/dev/null | sed 's/^PRETTY_NAME=//; s/^"//; s/"$//')
  fi
  if [ -z "$os" ] && [ -r /etc/redhat-release ]; then
    os=$(head -n 1 /etc/redhat-release 2>/dev/null)
  fi
  [ -n "$os" ] || os=$(uname -s 2>/dev/null)

  kv "OS release:"   "$os"
  kv "Kernel:"       "$(uname -r 2>/dev/null)"
  kv "Hostname:"     "$(uname -n 2>/dev/null)"
  kv "Architecture:" "$(uname -m 2>/dev/null)"
  kv "User:"         "$USER_NOW"
  kv "UID:"          "$UID_NOW"
  kv "GID:"          "$(id -g 2>/dev/null)"
  kv "Groups:"       "$(id -Gn 2>/dev/null) [$(id -G 2>/dev/null)]"

  chk
  if [ "$UID_NOW" -eq 0 ]; then
    note "Running as root: write/read checks are evaluated using world-accessible mode bits"
  else
    for g in $(id -Gn 2>/dev/null); do
      case "$g" in
        docker|lxd|lxc|disk|shadow|root)
          crit "User is in group '$g' (root-equivalent or direct access to sensitive data)"
          gflag=1
          ;;
        sudo|wheel|admin|adm)
          warn "User is in privileged group '$g' (review its privileges)"
          gflag=1
          ;;
      esac
    done
    [ "$gflag" -eq 0 ] && ok "User belongs to no known privileged groups"
  fi

  audit_path
}

# ============================================================================
# MODULE 2: Privileged Access & Sudoers
# ============================================================================
audit_sudo() {
  section "2. PRIVILEGED ACCESS & SUDOERS"
  local out rc f found=0

  chk
  if command -v sudo >/dev/null 2>&1; then
    out=$(sudo -n -l 2>/dev/null </dev/null)
    rc=$?
    if [ "$rc" -eq 0 ]; then
      if printf '%s\n' "$out" | grep -Eq 'NOPASSWD:.*(ALL|/bin/(ba)?sh|/usr/bin/(ba)?sh)'; then
        crit "sudo -n -l: passwordless sudo with broad/ALL command access"
      else
        warn "sudo -n -l succeeded without a password prompt (sudo rights exist)"
      fi
      printf '%s\n' "$out" | while IFS= read -r f; do plain "$f"; done
    else
      ok "sudo -n -l: no passwordless sudo rights (password required or no rights)"
    fi
  else
    note "sudo is not installed"
  fi

  chk
  if [ -e /etc/sudoers ]; then
    if can_write /etc/sudoers; then
      crit "/etc/sudoers is WRITABLE by $USER_NOW ($(stat_brief /etc/sudoers))"
    elif can_read /etc/sudoers; then
      crit "/etc/sudoers is READABLE by $USER_NOW ($(stat_brief /etc/sudoers))"
    else
      ok "/etc/sudoers is not readable/writable by $USER_NOW ($(stat_brief /etc/sudoers))"
    fi
  else
    note "/etc/sudoers does not exist"
  fi

  chk
  if [ -d /etc/sudoers.d ]; then
    if can_write /etc/sudoers.d; then
      crit "/etc/sudoers.d directory is WRITABLE by $USER_NOW"
      found=1
    fi
    for f in /etc/sudoers.d/*; do
      [ -e "$f" ] || continue
      if can_write "$f"; then
        crit "$f is WRITABLE by $USER_NOW ($(stat_brief "$f"))"
        found=1
      elif can_read "$f"; then
        crit "$f is READABLE by $USER_NOW ($(stat_brief "$f"))"
        found=1
      fi
    done
    [ "$found" -eq 0 ] && ok "/etc/sudoers.d and its files are not accessible to $USER_NOW"
  else
    note "/etc/sudoers.d does not exist"
  fi
}

# ============================================================================
# MODULE 3: SUID & SGID Binaries
# ============================================================================
report_bits() {
  local kind="$1" list="$2" f base meta n=0 hits=0
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    n=$((n + 1))
    base=${f##*/}
    meta=$(stat_brief "$f")
    if is_gtfo "$base"; then
      hits=$((hits + 1))
      crit_hl "$kind $meta $f  <-- GTFOBins/LOLBin match: $base"
    else
      warn "$kind $meta $f"
    fi
  done <<< "$list"
  if [ "$n" -eq 0 ]; then
    ok "No $kind files found"
  else
    plain "$kind total: $n | GTFOBins matches: $hits"
  fi
}

audit_suid_sgid() {
  section "3. SUID & SGID BINARIES"
  local suid sgid

  chk
  printf '  Enumerating SUID files (-perm -4000)...\n'
  suid=$(find / \( -path /proc -o -path /sys \) -prune -o -type f -perm -4000 -print 2>/dev/null | sort)
  report_bits "SUID" "$suid"

  chk
  printf '  Enumerating SGID files (-perm -2000)...\n'
  sgid=$(find / \( -path /proc -o -path /sys \) -prune -o -type f -perm -2000 -print 2>/dev/null | sort)
  report_bits "SGID" "$sgid"
}

# ============================================================================
# MODULE 4: Sensitive File & Directory Permissions
# ============================================================================
check_write_path() {
  local p="$1" recurse="$2" w
  [ -e "$p" ] || return 0
  chk
  if can_write "$p"; then
    crit "$p is WRITABLE by $USER_NOW ($(stat_brief "$p"))"
  else
    ok "$p is not writable ($(stat_brief "$p"))"
  fi
  if [ -d "$p" ]; then
    if [ "$recurse" -eq 1 ]; then
      w=$(find_writable "$p" -mindepth 1 \( -type f -o -type d \))
    else
      w=$(find_writable "$p" -mindepth 1 -maxdepth 1 \( -type f -o -type d \))
    fi
    if [ -n "$w" ]; then
      report_paths crit "Writable item inside $p" "$w"
    fi
  fi
}

audit_sensitive_perms() {
  section "4. SENSITIVE FILE & DIRECTORY PERMISSIONS"
  local f d ww sticky ns

  for f in /etc/passwd /etc/shadow /etc/group; do
    chk
    if [ ! -e "$f" ]; then
      note "$f does not exist"
    elif can_write "$f"; then
      crit "$f is WRITABLE by $USER_NOW ($(stat_brief "$f"))"
    else
      ok "$f is not writable ($(stat_brief "$f"))"
    fi
  done

  chk
  if [ -e /etc/shadow ]; then
    if can_read /etc/shadow; then
      crit "/etc/shadow is READABLE by $USER_NOW ($(stat_brief /etc/shadow))"
    else
      ok "/etc/shadow is not readable by $USER_NOW"
    fi
  else
    note "/etc/shadow does not exist"
  fi

  check_write_path /etc/crontab 0
  for d in /etc/cron.*; do
    [ -e "$d" ] || continue
    check_write_path "$d" 0
  done
  check_write_path /etc/systemd/system 1

  chk
  printf '  Scanning for world-writable directories (excluding /tmp, /var/tmp, /dev/shm)...\n'
  ww=$(find / \( -path /proc -o -path /sys -o -path /tmp -o -path /var/tmp -o -path /dev/shm \) -prune \
        -o -type d -perm -0002 ! -perm -1000 -print 2>/dev/null | sort)
  if [ -n "$ww" ]; then
    report_paths crit "World-writable directory WITHOUT sticky bit" "$ww"
  else
    ok "No world-writable directories without the sticky bit found outside temp locations"
  fi

  chk
  sticky=$(find / \( -path /proc -o -path /sys -o -path /tmp -o -path /var/tmp -o -path /dev/shm \) -prune \
        -o -type d -perm -1002 -print 2>/dev/null | sort)
  ns=$(printf '%s\n' "$sticky" | grep -c .)
  if [ "$ns" -gt 0 ]; then
    warn "$ns world-writable directories WITH sticky bit outside temp locations (usually benign; review)"
    printf '%s\n' "$sticky" | head -n 10 | while IFS= read -r f; do plain "$f"; done
  else
    ok "No sticky world-writable directories found outside temp locations"
  fi
}

# ============================================================================
# MODULE 5: Cron Jobs & Scheduled Tasks
# ============================================================================
extract_cron_targets() {
  sed -E 's/[0-9&]*>>?[[:space:]]*[^[:space:]]+//g' \
    | tr '\047"();|&<>`$' ' ' \
    | awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^\//) print $i }' \
    | sort -u
}

check_cron_target() {
  local p="$1" src="$2" parent
  case "$p" in
    /dev/*|/proc/*|/sys/*|*'*'*|*'?'*|*'['*) return 0 ;;
  esac
  parent=$(dirname "$p")
  if [ -f "$p" ]; then
    chk
    if can_write "$p"; then
      crit "Cron target $p (from $src) is WRITABLE by $USER_NOW ($(stat_brief "$p"))"
    elif can_write "$parent" && [ -z "$(find -H "$parent" -maxdepth 0 -perm -1000 2>/dev/null)" ]; then
      crit "Cron target $p (from $src): parent directory $parent is writable, file can be replaced"
    else
      ok "Cron target $p (from $src) is not writable"
    fi
  elif [ ! -e "$p" ] && [ -d "$parent" ]; then
    chk
    if can_write "$parent"; then
      crit "Cron target $p (from $src) is MISSING and its directory $parent is writable"
    fi
  fi
}

process_cron_file() {
  local f="$1" entries n line targets p
  [ -f "$f" ] && [ -r "$f" ] || return 0
  entries=$(grep -v -E '^[[:space:]]*(#|$)' "$f" 2>/dev/null \
            | grep -v -E '^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=')
  n=$(printf '%s\n' "$entries" | grep -c .)
  chk
  printf '  %sReading %s%s (%s active entries)\n' "$BOLD" "$f" "$RESET" "$n"
  [ "$n" -gt 0 ] || return 0
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    warn "$(printf '%s' "$line" | cut -c1-150)"
  done <<< "$entries"
  targets=$(printf '%s\n' "$entries" | extract_cron_targets)
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    check_cron_target "$p" "$f"
  done <<< "$targets"
}

audit_cron() {
  section "5. CRON JOBS & SCHEDULED TASKS"
  local f d s names count

  process_cron_file /etc/crontab
  process_cron_file /etc/anacrontab
  if [ -d /etc/cron.d ]; then
    for f in /etc/cron.d/*; do process_cron_file "$f"; done
  fi

  for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    [ -d "$d" ] || continue
    chk
    names=""
    count=0
    for s in "$d"/*; do
      [ -f "$s" ] || continue
      count=$((count + 1))
      names="$names ${s##*/}"
    done
    if [ "$count" -gt 0 ]; then
      warn "$d: $count script(s):$names"
    else
      ok "$d: no scripts found (or directory not listable)"
    fi
  done

  chk
  if [ -d /var/spool/cron/crontabs ]; then
    if [ -r /var/spool/cron/crontabs ] && [ -x /var/spool/cron/crontabs ]; then
      for f in /var/spool/cron/crontabs/*; do process_cron_file "$f"; done
    else
      ok "/var/spool/cron/crontabs exists but is not readable by $USER_NOW"
    fi
  fi
  if [ -d /var/spool/cron ] && [ -r /var/spool/cron ] && [ -x /var/spool/cron ]; then
    for f in /var/spool/cron/*; do
      [ -f "$f" ] && process_cron_file "$f"
    done
  fi
}

# ============================================================================
# MODULE 6: Running Services & Processes
# ============================================================================
audit_processes() {
  section "6. RUNNING SERVICES & PROCESSES"
  local procs roots total_root line uid pid args exe first deleted susp=0

  if ! command -v ps >/dev/null 2>&1; then
    chk
    warn "ps is not available; process checks skipped"
    return 0
  fi

  procs=$(ps -eo uid=,pid=,args= 2>/dev/null)

  chk
  roots=$(printf '%s\n' "$procs" | awk '$1 == 0 && $3 !~ /^\[/ { $1 = ""; sub(/^ +/, ""); print }' | cut -c1-150)
  total_root=$(printf '%s\n' "$roots" | grep -c .)
  note "$total_root user-space process(es) running as UID 0 (kernel threads excluded)"
  printf '%s\n' "$roots" | head -n 60 | while IFS= read -r line; do
    [ -n "$line" ] && plain "root: $line"
  done
  [ "$total_root" -gt 60 ] && plain "... $((total_root - 60)) more root processes not listed"

  chk
  while read -r uid pid args; do
    case "$uid" in ''|*[!0-9]*) continue ;; esac
    case "$pid" in ''|*[!0-9]*) continue ;; esac
    exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
    if [ -z "$exe" ]; then
      first=${args%% *}
      case "$first" in
        /*) exe="$first" ;;
        *)  continue ;;
      esac
    fi
    deleted=0
    case "$exe" in
      *" (deleted)") deleted=1; exe=${exe% (deleted)} ;;
    esac

    case "$exe" in
      /tmp/*|/var/tmp/*|/dev/shm/*|/run/shm/*)
        crit "PID $pid (uid $uid) runs from a temp/shared-memory path: $exe"
        susp=$((susp + 1))
        ;;
      /home/*)
        warn "PID $pid (uid $uid) runs from a home directory path: $exe"
        susp=$((susp + 1))
        ;;
    esac
    if [ "$deleted" -eq 1 ]; then
      warn "PID $pid (uid $uid) executable has been deleted from disk: $exe"
      susp=$((susp + 1))
    fi
    if [ "$uid" -eq 0 ] && [ -f "$exe" ] && can_write "$exe"; then
      crit "Root process PID $pid executable is WRITABLE by $USER_NOW: $exe ($(stat_brief "$exe"))"
      susp=$((susp + 1))
    fi
  done <<< "$procs"

  if [ "$susp" -eq 0 ]; then
    ok "No processes found running from /tmp, /var/tmp, /dev/shm, /home, or writable root binaries"
  fi
}

# ============================================================================
# Summary
# ============================================================================
box_border() { printf '%s+%s+%s\n' "$BLUE" "$(printf '%48s' '' | tr ' ' '-')" "$RESET"; }
box_line()   { printf '%s|%s %-46s %s|%s\n' "$BLUE" "$RESET" "$1" "$BLUE" "$RESET"; }
box_stat()   { printf '%s|%s  %-31s %s%-13s%s %s|%s\n' "$BLUE" "$RESET" "$1" "$3" "$2" "$RESET" "$BLUE" "$RESET"; }

print_summary() {
  printf '\n'
  box_border
  box_line "${BOLD}AUDIT SUMMARY${RESET}"
  box_border
  box_stat "Total checks executed:"         "$TOTAL" "$BOLD"
  box_stat "Critical / high-risk alerts:"   "$CRIT"  "$BOLD_RED"
  box_stat "Informational / review items:"  "$INFO"  "$YELLOW"
  box_stat "Passed checks:"                 "$PASS"  "$GREEN"
  box_border
  if [ "$CRIT" -gt 0 ]; then
    box_stat "Verdict:" "ATTENTION" "$BOLD_RED"
  else
    box_stat "Verdict:" "NO CRITICAL" "$GREEN"
  fi
  box_border
  printf '  Finished: %s\n' "$(date '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null)"
}

# ============================================================================
# Main
# ============================================================================
main() {
  banner
  audit_profile
  audit_sudo
  audit_suid_sgid
  audit_sensitive_perms
  audit_cron
  audit_processes
  print_summary
  [ "$CRIT" -gt 0 ] && exit 1
  exit 0
}

main
