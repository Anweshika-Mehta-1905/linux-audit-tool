# Linux Audit Tool 🛡️

> Automated, read-only Linux security configuration and permission audit — pure Bash, zero dependencies.

---

## What Is This?

A single Bash script that scans your Linux system for security misconfigurations,
dangerous permissions, and suspicious activity — without modifying anything.

Built for: SOC analysts, penetration testers, security students, and Linux administrators.

---

## Quick Start

```bash
# Step 1 — Make executable
chmod +x linux_audit.sh

# Step 2 — Run (as normal user)
./linux_audit.sh 2>&1 | less -R

# Step 3 — Run (as root, sees more)
sudo ./linux_audit.sh 2>&1 | less -R

# Step 4 — Save a report
./linux_audit.sh --no-color > audit_report.txt 2>&1
```

---

## What It Checks (6 Modules)

| # | Module | What It Looks For |
|---|--------|-------------------|
| 1 | System Profile | OS info, user context, $PATH safety |
| 2 | Privileged Access | sudo rights, sudoers file permissions |
| 3 | SUID / SGID Binaries | GTFOBins cross-reference (50+ binaries) |
| 4 | File Permissions | /etc/shadow, /etc/passwd, crontab, systemd |
| 5 | Cron Jobs | Writable cron targets, missing scripts |
| 6 | Processes | Executables in /tmp, deleted binaries |

---

## Output Color Codes

| Color | Meaning |
|-------|---------|
| 🔴 RED — [CRITICAL] | Fix immediately — active security risk |
| 🟡 YELLOW — [REVIEW] | Investigate — may be intentional |
| 🟢 GREEN — [ OK ] | Check passed, no issue found |
| 🔵 BLUE — [INFO] | Informational note |

---

## Flags

```
--no-color    Disable ANSI colors (for saving to file)
-h, --help    Show usage help
```

---

## Test It With Dummy Files

```bash
# Test SUID GTFOBins detection (look for bold red alert on vim)
mkdir -p /tmp/audit_test
touch /tmp/audit_test/vim /tmp/audit_test/harmless_tool
chmod 4755 /tmp/audit_test/vim
chmod 2755 /tmp/audit_test/harmless_tool
./linux_audit.sh 2>&1 | less -R

# Test dangerous $PATH detection
mkdir -m 0777 /tmp/audit_path
PATH="/tmp/audit_path:.:$PATH" ./linux_audit.sh 2>&1 | less -R

# Test process-in-/tmp detection
cp "$(command -v sleep)" /tmp/audit_sleep
/tmp/audit_sleep 300 &
./linux_audit.sh 2>&1 | less -R

# Cleanup
pkill -f /tmp/audit_sleep
rm -rf /tmp/audit_test /tmp/audit_path /tmp/audit_sleep
```

---

## Compatibility

- Ubuntu 20.04, 22.04, 24.04, 26.04
- Debian 11, 12
- RHEL / CentOS 7, 8, 9
- Kali Linux (rolling)
- Any POSIX-compliant Linux system

---

## Key Concepts

**SUID bit** — A permission flag that makes a program run as its owner (usually root)
instead of the person running it. If a dangerous tool like `vim` or `find` has this
flag, any user can abuse it to become root.

**GTFOBins** — A database of Unix binaries that can be abused for privilege escalation.
See: https://gtfobins.github.io

**Shadow file** — /etc/shadow stores hashed passwords. If readable by a normal user,
an attacker can extract and crack the hashes offline.

---

## Project Website

https://claude.ai/artifact/XbTtC8bVxKiMKatq3ju5UM

---

## Disclaimer

This tool is strictly read-only. It does not modify any files, permissions, or system
state. Always obtain proper authorisation before auditing any system you do not own.

---

*Built as a portfolio project demonstrating Linux security auditing, Bash scripting,
and SOC analyst thinking.*
