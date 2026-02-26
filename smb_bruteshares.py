#!/usr/bin/env python3
"""
smb_bruteshares.py — SMB Share Enumerator / Brute-Forcer
Author : red-team-toolkit
Version: 2.0.0
"""

import argparse
import subprocess
import sys
import os
import datetime
from pathlib import Path

# ── Colour helpers ────────────────────────────────────────────────────────────
try:
    from colorama import Fore, Back, Style, init as colorama_init
    colorama_init(autoreset=True)
    GREEN   = Fore.GREEN + Style.BRIGHT
    RED     = Fore.RED   + Style.BRIGHT
    YELLOW  = Fore.YELLOW + Style.BRIGHT
    CYAN    = Fore.CYAN  + Style.BRIGHT
    MAGENTA = Fore.MAGENTA + Style.BRIGHT
    WHITE   = Fore.WHITE + Style.BRIGHT
    DIM     = Style.DIM
    RESET   = Style.RESET_ALL
except ImportError:
    print("[!] colorama not found – pip install colorama")
    GREEN = RED = YELLOW = CYAN = MAGENTA = WHITE = DIM = RESET = ""

# ── ASCII Banner ───────────────────────────────────────────────────────────────
BANNER = rf"""
{CYAN}   ____  __  __ ____      ____  ____  _   _ _____ _____
{CYAN}  / ___||  \/  | __ )    | __ )|  _ \| | | |_   _| ____|
{CYAN}  \___ \| |\/| |  _ \    |  _ \| |_) | | | | | | |  _|
{CYAN}   ___) | |  | | |_) |   | |_) |  _ <| |_| | | | | |___
{CYAN}  |____/|_|  |_|____/    |____/|_| \_\\____/  |_| |_____|
{MAGENTA}
{MAGENTA}         ──  S M B   S H A R E   B R U T E F O R C E R  ──
{WHITE}               v2.0  |  Aldayr Ruiz (xSmaky) |  2026
{RESET}
"""

# ── Helpers ────────────────────────────────────────────────────────────────────

def print_ok(msg: str, verbose: bool = True):
    if verbose:
        print(f"{GREEN}[+]{RESET} {msg}")

def print_fail(msg: str, verbose: bool = True):
    if verbose:
        print(f"{RED}[-]{RESET} {msg}")

def print_info(msg: str):
    print(f"{CYAN}[*]{RESET} {msg}")

def print_warn(msg: str):
    print(f"{YELLOW}[!]{RESET} {msg}")

def log_result(fh, msg: str):
    if fh:
        fh.write(msg + "\n")
        fh.flush()

# ── Core logic ─────────────────────────────────────────────────────────────────

def build_smbclient_cmd(target: str, share: str, args) -> str:
    """Construct the smbclient command string based on CLI arguments."""
    # Build the UNC path
    if args.domain:
        # Domain prefix is passed via -W for workgroup/domain
        domain_flag = f"-W {args.domain}"
    else:
        domain_flag = ""

    if args.anonymous:
        auth = "-N"                        # null session
    elif args.password is not None:
        user_part = f"{args.domain}\\{args.username}" if args.domain else args.username
        auth = f"-U '{user_part}%{args.password}'"
    else:
        print_warn("No password or --anonymous flag supplied; defaulting to null session.")
        auth = "-N"

    unc = f"//{target}/{share}"
    return f"smbclient {unc} {auth} {domain_flag} -c exit 2>/dev/null"

def run_check(target: str, share: str, args, out_fh) -> bool:
    """Run a single share check; return True if accessible."""
    cmd = build_smbclient_cmd(target, share, args)

    if args.verbose:
        print_info(f"Running: {DIM}{cmd}{RESET}")

    result = subprocess.run(cmd, capture_output=True, text=True, shell=True)

    if result.returncode == 0:
        msg = f"[+] ACCESSIBLE   //{target}/{share}"
        print_ok(f"ACCESSIBLE   {CYAN}//{target}/{share}{RESET}", verbose=True)
        log_result(out_fh, msg)
        return True
    else:
        msg = f"[-] DENIED       //{target}/{share}"
        print_fail(f"DENIED       //{target}/{share}{RESET}", verbose=args.verbose)
        log_result(out_fh, msg)
        return False

def brute_shares(args):
    # ── Validate wordlist ──
    wl_path = Path(args.wordlist)
    if not wl_path.is_file():
        print_warn(f"Wordlist not found: {wl_path}")
        sys.exit(1)

    # ── Open output file if requested ──
    out_fh = None
    if args.output:
        try:
            out_fh = open(args.output, "w")
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            out_fh.write(f"# SMB Share Bruteforce – {timestamp}\n")
            out_fh.write(f"# Target  : {args.target}\n")
            if args.domain:
                out_fh.write(f"# Domain  : {args.domain}\n")
            out_fh.write(f"# Wordlist: {args.wordlist}\n\n")
            print_info(f"Output will be saved to: {args.output}")
        except OSError as exc:
            print_warn(f"Cannot open output file: {exc}")

    # ── Print run summary ──
    print_info(f"Target   : {WHITE}{args.target}{RESET}")
    if args.domain:
        print_info(f"Domain   : {WHITE}{args.domain}{RESET}")
    if args.username:
        print_info(f"User     : {WHITE}{args.username}{RESET}")
    print_info(f"Wordlist : {WHITE}{args.wordlist}{RESET}")
    print_info(f"Anonymous: {WHITE}{args.anonymous}{RESET}")
    print("")

    ok_count   = 0
    fail_count = 0

    with open(wl_path, "r", errors="ignore") as f:
        for raw_line in f:
            share = raw_line.strip()
            if not share or share.startswith("#"):
                continue

            if run_check(args.target, share, args, out_fh):
                ok_count += 1
            else:
                fail_count += 1

    # ── Summary ──
    print("")
    print_info("─" * 50)
    print_info(f"Scan complete.  "
               f"{GREEN}Accessible: {ok_count}{RESET}  |  "
               f"{RED}Denied: {fail_count}{RESET}")
    if out_fh:
        out_fh.write(f"\n# Accessible: {ok_count}  |  Denied: {fail_count}\n")
        out_fh.close()
        print_info(f"Results saved → {args.output}")

# ── Argument Parser ────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        prog="smb_bruteshares.py",
        description="SMB Share Brute-Forcer with Active Directory support",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    # Target
    parser.add_argument(
        "-t", "--target",
        required=True,
        metavar="HOST",
        help="Target IP address or hostname  (e.g. 192.168.1.10)",
    )
    # Active Directory domain
    parser.add_argument(
        "-d", "--domain",
        default=None,
        metavar="DOMAIN",
        help="Active Directory domain / workgroup  (e.g. corp.local)",
    )
    # Authentication
    parser.add_argument(
        "-u", "--username",
        default=None,
        metavar="USER",
        help="SMB username",
    )
    parser.add_argument(
        "-p", "--password",
        default=None,
        metavar="PASS",
        help="SMB password",
    )
    parser.add_argument(
        "-a", "--anonymous",
        action="store_true",
        help="Use null / anonymous session  (overrides -u / -p)",
    )
    # Wordlist
    parser.add_argument(
        "-w", "--wordlist",
        required=True,
        metavar="FILE",
        help="Path to share-name wordlist  (one share per line)",
    )
    # Output
    parser.add_argument(
        "-o", "--output",
        default=None,
        metavar="FILE",
        help="Save results to this file",
    )
    # Verbosity / banner
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show denied shares and raw smbclient commands",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Suppress the ASCII art banner",
    )
    return parser.parse_args()


# ── Entry Point ────────────────────────────────────────────────────────────────

def main():
    args = parse_args()

    if not args.no_banner:
        print(BANNER)

    brute_shares(args)


if __name__ == "__main__":
    main()