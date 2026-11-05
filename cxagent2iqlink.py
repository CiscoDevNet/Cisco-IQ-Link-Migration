#!/usr/bin/env python3
# Copyright (c) 2026 Cisco and/or its affiliates.

# This software is licensed to you under the terms of the Cisco Sample
# Code License, Version 1.1 (the "License"). You may obtain a copy of the
# License at

#              https://developer.cisco.com/docs/licenses

# All use of the material herein must be in accordance with the terms of
# the License. All rights not expressly granted by the License are
# reserved. Unless required by applicable law or agreed to separately in
# writing, software distributed under the License is distributed on an "AS
# IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied.

import os
import re
import sys
import csv
import json
import shutil
import subprocess
import datetime
import platform
from pathlib import Path
import ipaddress
from collections import defaultdict

# ---- Color codes for console output --------------------------------------
CYAN     = "\033[96m"
GREEN    = "\033[92m"
YELLOW   = "\033[93m"
RED      = "\033[91m"
WHITE    = "\033[97m"
DARKCYAN = "\033[36m"
GRAY     = "\033[37m"
RESET    = "\033[0m"


def enable_windows_ansi():
    """Turn on VT100/ANSI escape-code processing on Windows consoles."""
    if platform.system() == "Windows":
        os.system("")  # harmless no-op that triggers ANSI support in cmd.exe


# ---- Output helpers: consistent, color-coded status messages -------------
def write_step(msg):
    print(f"{CYAN}[*] {msg}{RESET}", flush=True)


def write_ok(msg):
    print(f"{GREEN}[OK] {msg}{RESET}", flush=True)


def write_warn(msg):
    print(f"{YELLOW}[!] {msg}{RESET}", flush=True)


def write_fail(msg):
    print(f"{RED}[X] {msg}{RESET}", flush=True)


def write_section(title):
    line = "-" * (len(title) + 4)
    print(flush=True)
    print(f"{DARKCYAN}{line}{RESET}", flush=True)
    print(f"{WHITE}  {title}{RESET}", flush=True)
    print(f"{DARKCYAN}{line}{RESET}", flush=True)


# ---- Helper: run a native command, capture stderr, return exit code ------
def invoke_native(exe, arguments):
    proc = subprocess.run([exe] + arguments, capture_output=True, text=True, encoding="utf-8", errors="replace")
    output = (proc.stdout or "") + (proc.stderr or "")
    return {"Output": output, "ExitCode": proc.returncode}


# ---- Helper: run a native command, feeding a script to it on STDIN -------
# Used to pipe a bash script into `ssh ... bash -s`, mirroring the quoted
# heredoc (<<'REMOTE_SCRIPT') technique from the bash version. The remote
# text is passed verbatim, so no shell-side quote escaping is needed.
#
# CRLF -> LF: We normalize line endings AND send the data as raw bytes
# (not text) to subprocess. On Windows, text=True input causes Python to
# translate '\n' back into '\r\n' when writing to the pipe, which silently
# reintroduces the very carriage returns we just stripped out. Sending
# bytes avoids any newline translation entirely.
def invoke_native_stdin(exe, arguments, stdin_text):
    normalized = stdin_text.replace("\r\n", "\n").replace("\r", "\n")
    proc = subprocess.run(
        [exe] + arguments,
        input=normalized.encode("utf-8"),   # bytes, not text
        capture_output=True,
    )
    output = (
        (proc.stdout or b"").decode("utf-8", errors="replace")
        + (proc.stderr or b"").decode("utf-8", errors="replace")
    )
    return {"Output": output, "ExitCode": proc.returncode}


def normalize_cron_weekday(cron):
    """
    Converts named day-of-week tokens in a cron string to numeric values.
    Mapping: SUN=0, MON=1, TUE=2, WED=3, THU=4, FRI=5, SAT=6

    Only the day-of-week field (5th field) is normalized. Names are matched
    case-insensitively. Handles lists (MON,WED), ranges (MON-FRI), and
    step values (MON-FRI/2). Fields that are already numeric or contain
    '*' are left untouched.
    """
    if not cron or not cron.strip():
        return cron

    day_map = {
        "SUN": "0", "MON": "1", "TUE": "2", "WED": "3",
        "THU": "4", "FRI": "5", "SAT": "6"
    }

    fields = cron.split()
    if len(fields) != 5:
        return cron

    def repl(match):
        token = match.group(0).upper()
        return day_map.get(token, match.group(0))

    fields[4] = re.sub(r"[A-Za-z]{3}", repl, fields[4])
    return " ".join(fields)

def normalize_auth_algorithm(value):
    """
    Normalizes an SNMPv3 authentication algorithm value into one of the accepted
    tokens in the IQ Link import template:
        MD5 / SHA / SHA_256 / SHA_384 / SHA_512
        (where SHA represents SHA-1, and SHA_256..SHA_512 represent SHA-2)
    """
    if not value or not str(value).strip():
        return ""

    token = str(value).strip().upper().replace('-', '_').replace(' ', '_')
    while '__' in token:
        token = token.replace('__', '_')

    auth_map = {
        'MD5': 'MD5',
        'MD_5': 'MD5',
        'SHA': 'SHA',
        'SHA1': 'SHA',
        'SHA_1': 'SHA',
        'SHA256': 'SHA_256',
        'SHA_2_256': 'SHA_256',
        'SHA2_256': 'SHA_256',
        'SHA_256': 'SHA_256',
        'SHA384': 'SHA_384',
        'SHA_2_384': 'SHA_384',
        'SHA2_384': 'SHA_384',
        'SHA_384': 'SHA_384',
        'SHA512': 'SHA_512',
        'SHA_2_512': 'SHA_512',
        'SHA2_512': 'SHA_512',
        'SHA_512': 'SHA_512',
    }
    return auth_map.get(token, token)


def normalize_priv_algorithm(value):
    """
    Normalizes an SNMPv3 privacy algorithm value into one of the accepted
    tokens in the IQ Link import template:
        DES / TDES / AES_128 / AES_192 / AES_256
    """
    if not value or not str(value).strip():
        return ""

    token = str(value).strip().upper().replace('-', '_').replace(' ', '_')
    while '__' in token:
        token = token.replace('__', '_')

    priv_map = {
        'DES': 'DES',
        '3DES': 'TDES',
        '3_DES': 'TDES',
        'TDES': 'TDES',
        'T_DES': 'TDES',
        'AES': 'AES_128',
        'AES128': 'AES_128',
        'AES_128': 'AES_128',
        'AES192': 'AES_192',
        'AES_192': 'AES_192',
        'AES256': 'AES_256',
        'AES_256': 'AES_256',
    }
    return priv_map.get(token, token)



def load_schedule_map(schedule_csv):
    """
    Reads the discovery schedule file and returns a dict mapping
    range string -> normalized cron expression.

    Expected columns: Range, ControllerId, Cron

    Robust to:
      - comma- OR pipe-delimited files (auto-detected)
      - leading/trailing whitespace around headers and values
      - comment lines (starting with ';') and blank lines
    """
    schedule_map = {}
    if not schedule_csv:
        return schedule_map

    with open(schedule_csv, 'r', newline='', encoding='utf-8') as f:
        # Keep only meaningful lines
        lines = [ln for ln in f if ln.strip() and not ln.lstrip().startswith(';')]

    if not lines:
        print(f"[WARNING]: Schedule file '{schedule_csv}' contained no usable rows.")
        return schedule_map

    # Auto-detect delimiter: prefer pipe if present, else comma.
    delimiter = '|' if '|' in lines[0] else ','

    reader = csv.reader(lines, delimiter=delimiter)
    rows = list(reader)

    # Strip whitespace from every cell. Only drop cells at the very
    # START or END of a row that are empty -- these are artifacts of
    # leading/trailing delimiters in markdown-style tables (| a | b |).
    # Empty cells that occur BETWEEN real columns (e.g. a blank
    # ControllerId value) must be preserved, otherwise later columns
    # shift left and get matched against the wrong header index.
    cleaned = []
    for row in rows:
        cells = [c.strip() for c in row]
        if cells and cells[0] == "":
            cells = cells[1:]
        if cells and cells[-1] == "":
            cells = cells[:-1]
        cleaned.append(cells)

    if not cleaned:
        print(f"[WARNING]: Schedule file '{schedule_csv}' produced no parseable columns.")
        return schedule_map

    header = [h.strip() for h in cleaned[0]]

    # Skip a markdown separator row like ---, --- if present.
    data_rows = cleaned[1:]
    if data_rows and all(set(c) <= set("-: ") for c in data_rows[0]):
        data_rows = data_rows[1:]

    header_lower = [h.strip().lower() for h in header]
    try:
        range_idx = header_lower.index("range")
        cron_idx = header_lower.index("cron")
    except ValueError:
        print(f"[WARNING]: Could not find 'Range'/'Cron' columns in header {header}. "
              f"No cron values will be applied.")
        return schedule_map

    for row in data_rows:
        if len(row) <= max(range_idx, cron_idx):
            continue
        rng = row[range_idx].strip()
        cron = row[cron_idx].strip()
        if rng:
            schedule_map[rng] = normalize_cron_weekday(cron)

    return schedule_map


def is_ip_range(val):
    """Check if a string represents a valid IPv4 address range (e.g. 10.0.0.1-10.0.0.50)."""
    if not val or "-" not in val:
        return False
    parts = val.split("-", 1)
    try:
        ipaddress.ip_address(parts[0].strip())
        ipaddress.ip_address(parts[1].strip())
        return True
    except ValueError:
        return False


def get_best_pattern(ip_list):
    """
    Groups valid IPv4 addresses by their /16 subnet (first two octets) when
    multiple IPs exist in that subnet. Preserves explicit IP ranges, single
    IPs, IPv6 addresses, and FQDNs.
    """
    if not ip_list:
        return ""

    singles = []
    ranges = []
    subnets = defaultdict(list)

    for item in ip_list:
        item = item.strip()
        if not item:
            continue
        if '-' in item:
            ranges.append(item)
            continue
        try:
            ip_obj = ipaddress.ip_address(item)
            if ip_obj.version == 4:
                prefix = ".".join(item.split('.')[:2])
                subnets[prefix].append(item)
            else:
                singles.append(item)
        except ValueError:
            singles.append(item)

    patterns = list(ranges) + list(singles)
    for prefix, group_ips in subnets.items():
        if len(group_ips) == 1:
            patterns.append(group_ips[0])
        else:
            patterns.append(f"{prefix}.*.*")

    return "|".join(sorted(list(set(patterns))))



def prompt_unencrypted_credentials_acknowledgment(device_count=None, auto_approve=False):
    """
    Prompts the user for explicit acknowledgment and approval that the generated
    IQ Link credential import file will contain unencrypted/plaintext device credentials,
    in compliance with Cisco S&TO and CSDL policies.

    Returns:
        bool: True if approved, False if disapproved.
    """
    if auto_approve:
        write_ok("Unencrypted credentials file generation pre-approved via CLI flag.")
        return True

    print()
    print("=" * 80)
    print(f"{YELLOW}[SECURITY ACKNOWLEDGMENT - CISCO S&TO / CSDL COMPLIANCE]{RESET}")
    print("The upcoming conversion will generate an IQ Link Credentials Import file")
    print("containing UNENCRYPTED plaintext device credentials (including passwords,")
    print("enable secrets, SNMPv3 authentication/privacy keys, and community strings)")
    if device_count:
        print(f"for {device_count:,} managed device(s).")
    else:
        print("extracted from the collector configuration.")
    print()
    print(f"{WHITE}  - Generated files will be created with restricted permissions (0600 / rw-------).{RESET}")
    print(f"{WHITE}  - You are responsible for safeguarding and securely deleting these files post-import.{RESET}")
    print("=" * 80)

    try:
        if not sys.stdin.isatty():
            response = sys.stdin.readline().strip()
            if response.lower() in ('y', 'yes'):
                return True
            write_warn("Non-interactive execution without explicit approval flag.")
            return False

        prompt_msg = f"{CYAN}Do you acknowledge and approve creating the unencrypted credentials file? [y/N]: {RESET}"
        resp = input(prompt_msg).strip().lower()
        if resp in ('y', 'yes'):
            return True
        return False
    except (EOFError, KeyboardInterrupt):
        print()
        return False

def convert_json_to_csv(input_json, schedule_csv=None, output_dir=None, timestamp=None, auto_approve=False):
    old_umask = None
    if hasattr(os, 'umask'):
        old_umask = os.umask(0o077)
    try:
        """
        Converts the CX Agent device-credentials JSON (and optional discovery-
        schedule CSV) into IQ Link import files.

        output_dir : directory the IQ_Link_*.csv files are written to.
                     Defaults to the current working directory if not given.
        timestamp  : filename timestamp to reuse (e.g. from the caller's own
                     download run). Defaults to "now" if not given, so this
                     function still works fine when called standalone.

        Returns a dict of the output file paths actually created:
            {"credentials": <path>, "hosts": <path or None>, "discoveries": <path or None>}
        """
        if timestamp is None:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

        out_dir = Path(output_dir) if output_dir else Path(".")
        out_dir.mkdir(parents=True, exist_ok=True)

        output_creds = out_dir / f"IQ_Link_Credentials_Import_{timestamp}.csv"

        results = {"credentials": None, "hosts": None, "discoveries": None}

        # Load the schedule map up front (empty dict if no CSV provided).
        schedule_map = load_schedule_map(schedule_csv)

        target_header = [
            "Name", "Include Patterns", "SSHv2 User", "SSHv2 Password",
            "SSHv2 Enable User", "SSHv2 Enable Password", "SSHv2 Port",
            "Telnet User", "Telnet Password", "Telnet Enable User",
            "Telnet Enable Password", "Telnet Port", "SNMPv2c Read Community",
            "SNMPv3 User", "SNMPv3 Engine ID", "SNMPv3 Auth Algorithm",
            "SNMPv3 Auth Password", "SNMPv3 Privacy Algorithm",
            "SNMPv3 Privacy Password", "HTTP Auth Type", "HTTP User", "HTTP Password"
        ]

        # Added telnet / snmpv3 / http groups so every credential type the
        # template documents is actually extracted from the source JSON.
        groups = {"ssh": {}, "telnet": {}, "snmp": {}, "snmpv3": {}, "https": {}, "http": {}}
        counters = {"ssh": 1, "telnet": 1, "snmp": 1, "snmpv3": 1, "https": 1, "http": 1}
        unique_hosts = set()
        discovery_ranges = set()
        topology_configs = []
        dnac_ips = set()
        found_range = False

        def add_to_group(proto, creds, ips):
            if creds not in groups[proto]:
                groups[proto][creds] = {"name": f"cxagent_{proto.upper()}_cred_{counters[proto]}", "hosts": set()}
                counters[proto] += 1
            groups[proto][creds]["hosts"].update(ips)

        # AutoDiscovery with complete topology keys -> builds Discovery file (Scenario 3)
        autodiscovery_detected = False
        # AutoDiscovery credName but MISSING topology keys -> terminal note only (Scenario 4)
        autodiscovery_missing_keys = False

        with open(input_json, 'r') as f:
            data = json.load(f)

        device_list = data if isinstance(data, list) else []

        for device in data:
            cred_name = device.get("credName", "")

            # Only evaluate topology logic when the credName signals AutoDiscovery.
            if "AUTODISCOVERY" in cred_name.upper():
                # Scenario 3: all topology keys present -> build the Discovery file.
                if all(k in device for k in ("hopCount", "seedIp", "protocols")):
                    autodiscovery_detected = True
                    topology_configs.append({
                        "credName": cred_name,
                        "protocols": device["protocols"],
                        "hopCount": device["hopCount"],
                        "seedIp": device["seedIp"]
                    })
                else:
                    # Scenario 4: AutoDiscovery but topology keys missing -> terminal note.
                    autodiscovery_missing_keys = True

            ips = device.get("includeIpList", [])
            if not ips:
                continue

            # Collect DNAC IPs
            if device.get("category") == "DNAC":
                for ip in ips:
                    dnac_ips.add(ip)

            for ip in ips:
                if is_ip_range(ip):
                    found_range = True
                    discovery_ranges.add(ip.strip())
                elif device.get("category") != "DNAC":
                    unique_hosts.add(ip)

            cmap = device.get("credentialMap", {})

            if "sshv2" in cmap:
                ssh = cmap["sshv2"]
                add_to_group('ssh', (ssh.get("user"), ssh.get("password"), ssh.get("enableUser", ""), ssh.get("enablePassword", ""), ssh.get("port", "22")), ips)
            if "telnet" in cmap:
                telnet = cmap["telnet"]
                add_to_group('telnet', (telnet.get("user"), telnet.get("password"), telnet.get("enableUser", ""), telnet.get("enablePassword", ""), telnet.get("port", "23")), ips)
            if "snmpv2c" in cmap:
                add_to_group('snmp', ('v2c', cmap["snmpv2c"].get("read")), ips)
            if "snmpv3" in cmap:
                snmpv3 = cmap["snmpv3"]
                add_to_group('snmpv3', (
                    snmpv3.get("user", ""),
                    snmpv3.get("engineId", ""),
                    normalize_auth_algorithm(snmpv3.get("authAlgorithm", "")),
                    snmpv3.get("authPassword", ""),
                    normalize_priv_algorithm(snmpv3.get("privacyAlgorithm", "")),
                    snmpv3.get("privacyPassword", "")
                ), ips)
            if "https" in cmap:
                https = cmap["https"]
                add_to_group('https', (https.get("user"), https.get("password")), ips)
            if "http" in cmap:
                http = cmap["http"]
                add_to_group('http', (http.get("user"), http.get("password")), ips)

        # S&TO / CSDL Acknowledgment Gate
        dev_count = len(device_list) if device_list else len(unique_hosts) if unique_hosts else None
        if not prompt_unencrypted_credentials_acknowledgment(device_count=dev_count, auto_approve=auto_approve):
            print()
            write_warn("Customer disapproved unencrypted credentials file generation.")
            write_fail("Conversion canceled: IQ Link import files were NOT created.")
            print(f"\n{YELLOW}[NOTICE] To comply with Cisco S&TO/CSDL policies, unencrypted credential files are only created upon explicit customer approval.{RESET}\n")
            return results

        write_ok("Security acknowledgment approved. Proceeding with IQ Link import file creation...")
        with open(output_creds, 'w', newline='', encoding='utf-8') as outfile:
            credential_template = [
                "; ============================================================",
                "; Credentials Import Template",
                "; ------------------------------------------------------------",
                "; How to use this file:",
                "; - Add one row per credential set below the header row.",
                "; - The header row is required and columns can be in any order.",
                "; - Lines that start with ';' are notes and are skipped on import.",
                "; - In list columns (Include Patterns) separate values with '|'.",
                "; - Leave columns blank for protocols you do not use.",
                "; - Fill in at least one protocol (SSHv2 / Telnet / SNMPv2c / SNMPv3 / HTTP).",
                ";",
                "; Columns:",
                ";   Name                       Required. Unique name for this credential set.",
                ";   Include Patterns           Required. One or more values separated by '|'.",
                ";                                Supported formats:",
                ";                                  single host  10.1.1.1",
                ";                                  wildcard     10.1.*.*",
                ";                                  range        10.0.0.1-10.0.0.50",
                ";",
                ";   SSHv2",
                ";     SSHv2 User               Required.",
                ";     SSHv2 Password           Required.",
                ";     SSHv2 Enable User        Optional.",
                ";     SSHv2 Enable Password    Optional.",
                ";     SSHv2 Port               Optional. Defaults to 22 when left blank.",
                ";",
                ";   Telnet",
                ";     Telnet User              Required.",
                ";     Telnet Password          Required.",
                ";     Telnet Enable User       Optional.",
                ";     Telnet Enable Password   Optional.",
                ";     Telnet Port              Optional. Defaults to 23 when left blank.",
                ";",
                ";   SNMPv2c",
                ";     SNMPv2c Read Community    Required.",
                ";",
                ";   SNMPv3",
                ";     SNMPv3 User              Required.",
                ";     SNMPv3 Auth Algorithm    Required. One of: MD5 / SHA / SHA_256 / SHA_384 / SHA_512.",
                ";                              SHA is SHA-1. SHA_256 to SHA_512 are the SHA-2 protocols.",
                ";     SNMPv3 Auth Password     Required.",
                ";     SNMPv3 Engine ID         Optional.",
                ";     SNMPv3 Privacy Algorithm Optional. One of: DES / TDES / AES_128 / AES_192 / AES_256.",
                ";     SNMPv3 Privacy Password  Required when a Privacy Algorithm is set.",
                ";",
                ";   HTTP",
                ";     HTTP Auth Type           Required. Only BASIC is supported.",
                ";     HTTP User                Required.",
                ";     HTTP Password            Required.",
                "; ============================================================"

            ]
            for line in credential_template:
                outfile.write(line + "\n")

            writer = csv.writer(outfile)
            writer.writerow(target_header)

            for proto, cred_map in groups.items():
                for creds, host_data in cred_map.items():
                    row = [""] * 22
                    row[0] = host_data["name"]
                    row[1] = get_best_pattern(list(host_data["hosts"]))

                    if proto == 'ssh':
                        row[2], row[3], row[4], row[5], row[6] = creds
                    elif proto == 'telnet':
                        row[7], row[8], row[9], row[10], row[11] = creds
                    elif proto == 'snmp':
                        row[12] = creds[1]
                    elif proto == 'snmpv3':
                        row[13], row[14], row[15], row[16], row[17], row[18] = creds
                    elif proto == 'https':
                        row[19], row[20], row[21] = "BASIC", creds[0], creds[1]
                    elif proto == 'http':
                        row[19], row[20], row[21] = "BASIC", creds[0], creds[1]
                    writer.writerow(row)

        results["credentials"] = str(output_creds)

        # Host Import file guard (Scenario 1): Create the Host file only when
        # unique single hosts exist AND neither AutoDiscovery scenario applies
        # (both use a wildcard include list, so there are no specific hosts to import).
        if unique_hosts and not autodiscovery_detected and not autodiscovery_missing_keys:
            output_hosts = out_dir / f"IQ_Link_Hosts_Import_{timestamp}.csv"

            host_template = [
                "; ============================================================",
                "; Assets (Host) Import Template",
                "; ------------------------------------------------------------",
                "; How to use this file:",
                "; - Add one host per row below the header row.",
                "; - The header row is required. Keep the single 'Host' column exactly as shown below.",
                "; - Lines that start with ';' are notes and are skipped on import.",
                ";",
                "; Columns:",
                ";   Host   Required. One IPv4 address or hostname per row.",
                ";            Examples: 192.0.2.10 or host.example.com",
                "; ============================================================"
            ]

            with open(output_hosts, 'w', newline='', encoding='utf-8') as hostfile:
                for line in host_template:
                    hostfile.write(line + "\n")

                writer = csv.writer(hostfile)
                writer.writerow(["Host"])
                for host in sorted(unique_hosts):
                    writer.writerow([host])

            results["hosts"] = str(output_hosts)

        # Write the Discovery Profiles file for any IP ranges OR topology configs
        # (Scenario 2: IP ranges | Scenario 3: AutoDiscovery + topology keys)
        if discovery_ranges or topology_configs:
            output_discoveries = out_dir / f"IQ_Link_Network_Scan_Import_{timestamp}.csv"

            discovery_template = [
                "; ============================================================",
                "; Discovery Profiles Import Template",
                "; ------------------------------------------------------------",
                "; How to use this file:",
                "; - Add one row per discovery profile below the header row.",
                "; - The header row is required and columns can be in any order.",
                "; - Lines that start with ';' are notes and are skipped on import.",
                "; - In list columns separate values with '|'.",
                "; - Fill in the columns for the chosen Type and leave the rest blank.",
                ";",
                "; Columns:",
                ";   Common",
                ";     Type                 Required. One of: IP_RANGE / TOPOLOGY_DISCOVERY.",
                ";     Name                 Required. Unique profile name (up to 255 characters).",
                ";     Recurring Schedule   Required. UNIX cron with 5 fields (for example 0 2 * * *).",
                ";",
                ";   IP_RANGE",
                ";     IP Range From        Required. A single IPv4 address.",
                ";     IP Range To          Required. A single IPv4 address.",
                ";",
                ";   TOPOLOGY_DISCOVERY",
                ";     Topology Protocols   Required. One or more of: CDP / LLDP.",
                ";     Topology Hop Count   Required. A whole number from 1 to 10.",
                ";     Topology Seed IPs    Required. One or more IPv4 addresses separated by '|'.",
                "; ============================================================"
            ]

            discovery_header = [
                "Type", "Name", "Recurring Schedule", "IP Range From",
                "IP Range To", "Topology Protocols", "Topology Hop Count",
                "Topology Seed IPs"
            ]

            matched = 0
            skipped_ranges = []
            discovery_rows = []

            # --- IP_RANGE profiles (Scenario 2) ---
            for rng in sorted(discovery_ranges):
                cron = schedule_map.get(rng, "")

                # Empty-result guard: skip ranges with no matching cron,
                # consistent with the empty-handling pattern.
                if not cron:
                    skipped_ranges.append(rng)
                    continue

                range_from, range_to = rng.split('-', 1)
                row = [
                    "IP_RANGE",          # Type
                    rng,                 # Name
                    cron,                # Recurring Schedule (from schedule CSV, normalized)
                    range_from.strip(),  # IP Range From
                    range_to.strip(),    # IP Range To
                    "",                  # Topology Protocols
                    "",                  # Topology Hop Count
                    ""                   # Topology Seed IPs
                ]
                discovery_rows.append(row)
                matched += 1

            # --- TOPOLOGY_DISCOVERY profiles (Scenario 3) ---
            # For AutoDiscovery, the schedule CSV lists the range as
            # "AutoDiscovery", so we look that up for the cron value.
            for topo in topology_configs:
                cron = schedule_map.get("AutoDiscovery", "")
                name = topo["protocols"] if topo["protocols"] else "Topology_Discovery"

                row = [
                    "TOPOLOGY_DISCOVERY",              # Type
                    name,                              # Name (from "protocols")
                    cron,                              # Recurring Schedule (from CSV "Cron")
                    "",                                # IP Range From
                    "",                                # IP Range To
                    topo["protocols"],                 # Topology Protocols (from "protocols")
                    topo["hopCount"],                  # Topology Hop Count (from "hopCount")
                    topo["seedIp"].replace(",", "|")   # Topology Seed IPs (from "seedIp")
                ]
                discovery_rows.append(row)
                matched += 1

            if discovery_rows:
                with open(output_discoveries, 'w', newline='', encoding='utf-8') as discfile:
                    for line in discovery_template:
                        discfile.write(line + "\n")

                    writer = csv.writer(discfile)
                    writer.writerow(discovery_header)
                    for r in discovery_rows:
                        writer.writerow(r)

                results["discoveries"] = str(output_discoveries)

            if skipped_ranges:
                print("\n[WARNING]: The following IP range(s) had no matching cron in the schedule file and were skipped:")
                for rng in skipped_ranges:
                    print(f"        - {rng}")

        # Terminal Notifications

        # Scenario 4: AutoDiscovery credName was present but the topology keys
        # (hopCount, seedIp, protocols) were missing, so no Discovery file was
        # built. Direct the user to enter this manually in IQ Link.
        if autodiscovery_missing_keys:
            print("\n[NOTE]: CDP/LLDP discovery job found, please configure this in IQ Link using the following path:")
            print("        System Settings -> Connection Management -> Network Scan")

        # Independent check: Catalyst Center (DNAC) IPs must be added manually.
        if dnac_ips:
            print("\n[NOTE]: The following Catalyst Center IP address(es) were found in the seed file:")
            for ip in sorted(dnac_ips):
                print(f"        - {ip}")
            print("        Please configure this in IQ Link using the following path:")
            print("        System Settings -> Connection Management -> Catalyst Center")

        for p_out in (output_creds, results.get('hosts'), results.get('discoveries')):
            if p_out and os.path.exists(p_out) and os.name == 'posix':
                try:
                    os.chmod(p_out, 0o600)
                except OSError:
                    pass

        print('\n' + '=' * 80)
        print(f"{YELLOW}[SECURITY WARNING - CISCO S&TO / CSDL COMPLIANCE]{RESET}")
        print('The generated file(s) contain unencrypted device credentials (passwords, enable')
        print('secrets, SNMPv3 keys, and community strings).')
        print('  - Output files were created with restrictive permissions (0600 / rw-------).')
        print('  - Ensure these files are stored securely and NOT committed to version control.')
        print('  - Securely delete (shred / rm) all credential CSV files immediately after')
        print('    importing them into IQ Link!')
        print('=' * 80 + '\n')
        return results

    finally:
        if old_umask is not None:
            os.umask(old_umask)
def main():
    enable_windows_ansi()

    # ---- Step 1: Verify native OpenSSH is available -----------------------
    write_section("Preflight")
    for tool in ("ssh", "ssh-keygen", "scp"):
        if shutil.which(tool) is None:
            write_fail(
                f"Required tool '{tool}' not found. Enable it with: "
                "Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0"
            )
            sys.exit(1)
    write_ok("OpenSSH client tools found (ssh, ssh-keygen, scp).")

    # ---- Step 2: Prompts ---------------------------------------------------
    while True:
        server_ip = input(
            "Enter the IP address of the CX Agent server: "
        ).strip()
        if server_ip:
            break
        write_warn("Server IP cannot be empty. Please enter a valid IP address.")

    while True:
        port_raw = input("Enter the port (default is 22): ").strip()
        if not port_raw:
            ssh_port = 22
            break
        try:
            ssh_port = int(port_raw)
            if 1 <= ssh_port <= 65535:
                break
            write_warn("Port must be between 1 and 65535.")
        except ValueError:
            write_warn("Invalid port number. Please enter a valid integer.")
    # ---- Step 3: User, target, key location --------------------------------
    ssh_user = "cxcadmin"
    ssh_target = f"{ssh_user}@{server_ip}"

    userprofile = os.environ.get("USERPROFILE") or str(Path.home())
    ssh_dir = Path(userprofile) / ".ssh"
    key_path = ssh_dir / "cxagent_id_ed25519"
    pub_key_path = Path(str(key_path) + ".pub")

    ssh_dir.mkdir(parents=True, exist_ok=True)

    # Shared options for NON-interactive (key-based) calls.
    # IdentitiesOnly=yes => use ONLY our key file, don't offer other agent keys.
    ssh_opts = [
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=15",
        "-o", "ServerAliveInterval=5",
        "-o", "ServerAliveCountMax=3",
        "-o", "LogLevel=ERROR",
        "-o", "IdentitiesOnly=yes",
        "-p", str(ssh_port),
        "-i", str(key_path),
    ]

    # ---- Step 4: Generate the key pair if missing --------------------------
    write_section("SSH Key Setup")
    if not key_path.exists():
        write_step(f"No SSH key found for this task. Generating a new one at {key_path}...")

        keygen_proc = subprocess.run(
            [
                "ssh-keygen", "-t", "ed25519",
                "-f", str(key_path),
                "-N", "",
                "-C", "cxagent-cred-fetcher",
            ],
            capture_output=True,
            text=True,
        )

        if keygen_proc.returncode != 0:
            write_fail("Failed to generate SSH key.")
            sys.exit(1)
        write_ok("Key pair created.")
    else:
        write_ok(f"Existing SSH key found at {key_path}.")

    # ---- Step 5: Install the key if passwordless login not yet working -----
    write_step(f"Checking for passwordless access to {ssh_target}...")

    probe_args = ssh_opts + [
        "-o", "BatchMode=yes",
        "-o", "PasswordAuthentication=no",
        ssh_target, "true",
    ]
    probe = invoke_native("ssh", probe_args)
    key_works = probe["ExitCode"] == 0

    if key_works:
        write_ok("Passwordless SSH is already working.")
    else:
        write_warn("Key not yet installed on the server (this is normal on first run).")
        write_step("You'll be asked for the SSH password ONCE so the key can be copied over.")

        pub_key_content = pub_key_path.read_text().strip()

        install_cmd = (
            "mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
            "touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && "
            f"grep -qxF '{pub_key_content}' ~/.ssh/authorized_keys || "
            f"echo '{pub_key_content}' >> ~/.ssh/authorized_keys; "
            "echo INSTALL_OK"
        )

        write_step("Enter the SSH password when prompted:")
        install_args = [
            "-n",
            "-T",
            "-p", str(ssh_port),
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "LogLevel=ERROR",
            "-o", "ConnectTimeout=15",
            "-o", "PubkeyAuthentication=no",
            "-o", "PreferredAuthentications=password",
            "-o", "ServerAliveInterval=5",
            "-o", "ServerAliveCountMax=3",
            ssh_target, install_cmd,
        ]
        install_proc = subprocess.run(
            ["ssh"] + install_args,
            stdin=subprocess.DEVNULL
        )
        install_exit = install_proc.returncode

        if install_exit != 0:
            write_fail(
                f"Failed to copy the key to the server (ssh exit code {install_exit}). "
                "Check the password and try again."
            )
            sys.exit(1)

        write_step("Key copied. Verifying key-based login...")

        probe2 = invoke_native("ssh", probe_args)
        if probe2["ExitCode"] != 0:
            write_fail(
                f"Key-based login still not working after copying the key. "
                f"Details: {probe2['Output']}"
            )
            sys.exit(1)
        write_ok("Key installed successfully.")

    # ---- Step 6: Local & remote destination paths --------------------------
    downloads_path = Path(userprofile) / "Downloads"
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    remote_migration_dir = "/home/cxcadmin/migration"

    local_path = downloads_path / f"cxagent_device_credentials_{timestamp}.json"
    remote_path = f"{remote_migration_dir}/cxagent_device_credentials.json"

    local_csv_path = None

    # ---- Step 7: Generate and enrich cxagent_device_credentials.json remotely ----
    write_section("Device Credentials")

    # NOTE: raw string (r"""...""") -- no Python escape processing at all.
    # NOTE: the awk block builds quote characters via the `q` variable
    #       instead of embedding escaped quotes directly in the printf
    #       format string. This avoids a BusyBox-awk parsing bug that
    #       throws a bogus "division by zero attempted in `%'" fatal error
    #       when a format string mixes \" escapes with %s conversions.
    remote_step7 = r"""set -eo pipefail
export KUBECONFIG=/home/cxcadmin/.kube/config
mkdir -p /home/cxcadmin/migration

svc_ip=$(kubectl get svc | grep device-credentials | awk '{print $3}')

# 1. Fetch the JSON into a variable
raw_json=$(curl -s "http://${svc_ip}:8080/credentialmgmt/credentials/getAll" -H "accept: application/json")

# 2. Check if any credName contains AUTODISCOVERY
if echo "$raw_json" | jq -e '.[] | select(.credName | contains("AUTODISCOVERY"))' > /dev/null 2>&1; then

    # 3. Get discovery data, map labels, and trim whitespace
    discovery_json=$(kubectl logs deploy/device-data-collector | grep -A3 "Seed Discovery Data" | sed 1d | \
        awk -F ' : ' '{
            q = "\""
            key = $1; val = $2
            gsub(/^[ \t]+|[ \t]+$/, "", val)
            if (key == "Hop Count") k = "hopCount"
            else if (key == "Seed List") k = "seedIp"
            else if (key == "Neighbor Discovery Modules") k = "protocols"
            else k = key
            printf "%s%s%s: %s%s%s,", q, k, q, q, val, q
        }' | sed 's/,$//' | sed 's/^/{/;s/$/}/')

    # 4. Merge the new data into the credentials array
    echo "$raw_json" | jq --argjson disc "$discovery_json" 'map(select(.credName | contains("AUTODISCOVERY")) += $disc)' > /home/cxcadmin/migration/cxagent_device_credentials.json
else
    # No AUTODISCOVERY found, save original JSON
    echo "$raw_json" | jq > /home/cxcadmin/migration/cxagent_device_credentials.json
fi

test -s /home/cxcadmin/migration/cxagent_device_credentials.json && echo "OK"
"""

    write_step("Extracting and verifying device credentials on the server...")
    gen_args = ssh_opts + ["-T", ssh_target, "bash", "-s"]
    gen_run = invoke_native_stdin("ssh", gen_args, remote_step7)

    if "OK" not in gen_run["Output"].strip():
        write_fail(
            f"The remote file was not created or is empty. Aborting transfer. "
            f"Details: {gen_run['Output']}"
        )
        sys.exit(1)
    write_ok("Remote file confirmed present and non-empty.")

    # ---- Step 8: Pull the credentials file down via SCP --------------------
    if local_path.exists():
        write_warn(f"An existing file was found at {local_path}. Removing it before transfer...")
        local_path.unlink()

    #write_step(f"Copying the file to {local_path}...")
    scp_args = [
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "LogLevel=ERROR",
        "-o", "ConnectTimeout=15",
        "-o", "IdentitiesOnly=yes",
        "-P", str(ssh_port),
        "-i", str(key_path),
        f"{ssh_target}:{remote_path}",
        str(local_path),
    ]
    scp_run = invoke_native("scp", scp_args)

    if scp_run["ExitCode"] == 0:
        write_ok("Device credentials data retrieved successfully.")
    else:
        write_fail(f"Failed to copy file via SCP. Details: {scp_run['Output']}")
        sys.exit(1)

    # ---- Step 9: Build cxagent_discovery_schedule.csv remotely -------------
    write_section("Discovery Schedule")

    remote_csv_path = f"{remote_migration_dir}/cxagent_discovery_schedule.csv"

    # NOTE: raw string -- the sed pattern 's/\?/*/g' below is passed through
    # to bash completely untouched, with no Python SyntaxWarning.
    remote_step9 = r"""set -eo pipefail

export KUBECONFIG=/home/cxcadmin/.kube/config

mkdir -p /home/cxcadmin/migration
pushd /home/cxcadmin/migration > /dev/null

declare -a results=()
while IFS= read -r line; do
    results+=("$line")
done < <(debug-cxcli agent getController \
            | awk '{print$3" "$4}' \
            | awk NF \
            | tail -n +2 \
            | sed 's/_/,/g; s/ /,/g' \
            | awk -F, '{print $(NF-1) "," $NF}' \
            | { grep -v "^DNAC" || true; })

# No controllers after filtering -> skip creating the CSV entirely.
if [ "${#results[@]}" -eq 0 ]; then
    popd > /dev/null
    echo "NO_CONTROLLERS"
    exit 0
fi

declare -a enriched=()
for entry in "${results[@]}"; do
    IFS=',' read -r field1 field2 <<< "$entry"
    svc_ip=$(kubectl get svc | { grep collection || true; } | awk '{print $3}')
    field3=$(curl -sX GET "http://${svc_ip}:8080/collection/profile/${field2}" \
                -H "accept: application/json" \
                | jq -r '.schedule' \
                | sed 's/^[^ ]* //' \
                | sed 's/\?/*/g')
    enriched+=("${field1},${field2},${field3}")
done

csv_file="cxagent_discovery_schedule.csv"
echo "Range,ControllerId,Cron" > "$csv_file"
for line in "${enriched[@]}"; do
    echo "$line" >> "$csv_file"
done

popd > /dev/null
test -s /home/cxcadmin/migration/cxagent_discovery_schedule.csv && echo "OK"
"""

    write_step("Extracting discovery schedule configuration on the server...")
    gen_args2 = ssh_opts + ["-T", ssh_target, "bash", "-s"]
    gen_run2 = invoke_native_stdin("ssh", gen_args2, remote_step9)

    gen2_clean = gen_run2["Output"].strip()

    if "NO_CONTROLLERS" in gen2_clean:
        write_warn("No non-DNAC controllers found. Skipping discovery schedule export.")
    elif "OK" in gen2_clean:
        write_ok("Remote discovery file confirmed present and non-empty.")

        # ---- Step 10: Pull cxagent_discovery_schedule.csv down via SCP -----
        local_csv_path = downloads_path / f"cxagent_discovery_schedule_{timestamp}.csv"

        if local_csv_path.exists():
            write_warn(f"An existing file was found at {local_csv_path}. Removing it before transfer...")
            local_csv_path.unlink()

        #write_step(f"Copying the file to {local_csv_path}...")
        scp_csv_args = [
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "LogLevel=ERROR",
            "-o", "ConnectTimeout=15",
            "-o", "IdentitiesOnly=yes",
            "-P", str(ssh_port),
            "-i", str(key_path),
            f"{ssh_target}:{remote_csv_path}",
            str(local_csv_path),
        ]
        scp_csv_run = invoke_native("scp", scp_csv_args)

        if scp_csv_run["ExitCode"] == 0:
            write_ok("Discovery schedule data retrieved successfully.")
        else:
            write_fail(f"Failed to retrieve discovery schedule via SCP. Details: {scp_csv_run['Output']}")
            local_csv_path = None
    else:
        write_fail(
            f"cxagent_discovery file was not created or is empty on the remote host. "
            f"Aborting transfer. Details: {gen_run2['Output']}"
        )
        sys.exit(1)

    # ---- Step 11: Convert downloaded files into IQ Link import files -------
    write_section("IQ Link Conversion")
    write_step("Converting downloaded files into IQ Link import files...")

    iqlink_results = {"credentials": None, "hosts": None, "discoveries": None}
    try:
        auto_approve_creds = any(arg in sys.argv for arg in ('--yes', '-y', '--accept-unencrypted-credentials', '--ack-unencrypted'))
        iqlink_results = convert_json_to_csv(
            input_json=str(local_path),
            schedule_csv=str(local_csv_path) if local_csv_path else None,
            output_dir=str(downloads_path),
            timestamp=timestamp,
            auto_approve=auto_approve_creds,
        )
        write_ok("IQ Link import file conversion complete.")
    except Exception as exc:
        write_fail(f"IQ Link conversion failed: {exc}")

    # ---- Step 12: Gather and display CX Agent Network Configuration -------
    remote_step11 = r"""set -eo pipefail

export KUBECONFIG=/home/cxcadmin/.kube/config

ip_address=$(ip add | grep inet | grep eth0 | awk '{print $2}')
default_gw=$(ip route | grep default | awk '{print $3}')

if command -v resolvectl &>/dev/null; then
    dns_server=$(resolvectl | grep -B5 InsightEngine | grep "Current DNS" | awk '{print $4}')
else
    dns_server=$(systemd-resolve --status | grep -B10 InsightEngine | grep "Current DNS" | awk '{print $4}')
fi

svc_ip=$(kubectl get svc | grep agent-router | awk '{print $3}')
proxyConfig=$(curl -s "http://${svc_ip}:8080/connector/api/getproxy")
proxyStatus=$(echo "$proxyConfig" | jq -r '.proxystatus')

proxyConfigured="no"
auth="no"
if [ "$proxyStatus" == "Not Configured" ]; then
    proxy="No proxy configuration found."
else
    proxyConfigured="yes"
    proxy="Proxy configuration found. Please verify the details."
    proxyIP=$(echo "$proxyConfig" | jq -r '.proxyIP')
    proxyPort=$(echo "$proxyConfig" | jq -r '.proxyPort')
    auth=$(echo "$proxyConfig" | jq -r '.auth')
    if [ "$auth" == "yes" ]; then
        proxyUser=$(echo "$proxyConfig" | jq -r '.proxyUser')
        proxyPass=$(echo "$proxyConfig" | jq -r '.proxyPass')
    fi
fi

echo "CX Agent IP/subnet: $ip_address"
echo "Default Gateway: $default_gw"
echo "DNS Server: $dns_server"
echo "Proxy: $proxy"
if [ "$proxyConfigured" == "yes" ]; then
    echo -e "\tIP/Hostname: $proxyIP"
    echo -e "\tPort: $proxyPort"
    if [ "$auth" == "yes" ]; then
        echo -e "\tUsername: $proxyUser"
        echo -e "\tPassword: $proxyPass"
    fi
fi

"""

    write_section("CX Agent Network Configuration")
    write_step("Gathering network configuration from the server...")
    gen_args3 = ssh_opts + ["-T", ssh_target, "bash", "-s"]
    gen_run3 = invoke_native_stdin("ssh", gen_args3, remote_step11)

    gen3_clean = gen_run3["Output"].strip()

    if gen_run3["ExitCode"] != 0 or not gen3_clean:
        write_fail(f"Failed to gather CX Agent network configuration. Details: {gen_run3['Output']}")
    else:
        print()
        for raw_line in gen3_clean.split("\n"):
            match = re.match(r'^\s*(.+?):\s*(.*)$', raw_line)
            if match:
                label = match.group(1).strip()
                value = match.group(2).strip()

                if "Password" in label:
                    print(f"  {label:<22}: ", end="")
                    print(f"{YELLOW}{value}{RESET}")
                else:
                    print(f"{GRAY}  {label:<22}: {value}{RESET}")
            else:
                print(f"{GRAY}  {raw_line}{RESET}")

    # ---- Step 13: Local & Remote temporary file cleanup & End-of-run summary -------
    # Securely delete raw intermediate extract files from localhost
    for temp_file in (local_path, local_csv_path):
        if temp_file and isinstance(temp_file, Path) and temp_file.exists():
            try:
                temp_file.unlink()
            except OSError:
                pass

    # Clean up temporary extract files on remote CX Agent server
    try:
        remote_cleanup_cmd = f"rm -f {remote_path} {remote_csv_path}"
        invoke_native("ssh", ssh_opts + [ssh_target, remote_cleanup_cmd])
    except Exception:
        pass

    # ---- Step 13: SSH Key Cleanup & Reset (Replicating reset-cxagent process) -----
    write_section("SSH Key Cleanup")

    # Part 1: Delete local key pair
    write_step("Deleting local temporary SSH key pair...")
    pub_content = ""
    if pub_key_path.exists():
        try:
            pub_content = pub_key_path.read_text().strip()
        except Exception:
            pass

    for f in (key_path, pub_key_path):
        if f and isinstance(f, Path) and f.exists():
            try:
                f.unlink()
                write_ok(f"Removed local key file: {f.name}")
            except OSError as e:
                write_warn(f"Could not remove {f.name}: {e}")
        else:
            write_warn(f"Not found: {f.name if f else 'None'}")

    # Part 2: Remove the fetcher key on the server (prompt for password)
    write_step(f"Removing the fetcher key from {ssh_target}'s authorized_keys...")
    write_warn(f"You'll be prompted for the '{ssh_user}' SSH password.")

    remote_key_cmd = (
        "if [ -f ~/.ssh/authorized_keys ]; then "
        "sed -i '/cxagent-cred-fetcher/d' ~/.ssh/authorized_keys 2>/dev/null; "
        "fi; "
        "echo REMOVED_OK"
    )
    if pub_content:
        remote_key_cmd = (
            f"if [ -f ~/.ssh/authorized_keys ]; then "
            f"grep -vF '{pub_content}' ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.tmp 2>/dev/null && "
            f"mv ~/.ssh/authorized_keys.tmp ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys; "
            f"sed -i '/cxagent-cred-fetcher/d' ~/.ssh/authorized_keys 2>/dev/null; "
            f"fi; "
            f"echo REMOVED_OK"
        )

    cleanup_args = [
        "-n",
        "-T",
        "-p", str(ssh_port),
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "LogLevel=ERROR",
        "-o", "ConnectTimeout=15",
        "-o", "PubkeyAuthentication=no",
        "-o", "PreferredAuthentications=password",
        "-o", "ServerAliveInterval=5",
        "-o", "ServerAliveCountMax=3",
        ssh_target, remote_key_cmd,
    ]
    cleanup_proc = subprocess.run(
        ["ssh"] + cleanup_args,
        stdin=subprocess.DEVNULL
    )
    if cleanup_proc.returncode == 0:
        write_ok("Server authorized_keys cleaned (fetcher entry removed).")
    else:
        write_fail("Could not confirm server cleanup.")
        write_warn("Check the password/connection and re-run reset if needed.")

    # Part 3: Verify passwordless login now FAILS
    write_step("Confirming passwordless (key-based) login no longer works...")
    probe_args = [
        "-p", str(ssh_port),
        "-o", "BatchMode=yes",
        "-o", "PasswordAuthentication=no",
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "LogLevel=ERROR",
        "-o", "ConnectTimeout=15",
        "-i", str(key_path),
        ssh_target, "true",
    ]
    probe_proc = subprocess.run(
        ["ssh"] + probe_args,
        capture_output=True,
        text=True,
    )
    if probe_proc.returncode != 0:
        write_ok("Passwordless login correctly FAILS. Reset is clean.")
    else:
        write_fail("Passwordless login still SUCCOEDS (exit 0). Reset incomplete.")
        write_warn("Re-check local key files and server authorized_keys.")

    # Part 4: Clear stale host key and control sockets
    write_step("Clearing host key cache and lingering SSH control sockets...")
    known_hosts_path = ssh_dir / "known_hosts"
    host_entry = f"[{server_ip}]:{ssh_port}" if ssh_port != 22 else server_ip

    if known_hosts_path.exists():
        try:
            subprocess.run(
                ["ssh-keygen", "-f", str(known_hosts_path), "-R", host_entry],
                capture_output=True,
                text=True,
            )
            if ssh_port != 22:
                subprocess.run(
                    ["ssh-keygen", "-f", str(known_hosts_path), "-R", server_ip],
                    capture_output=True,
                    text=True,
                )
            write_ok(f"Removed stale host key for {host_entry}.")
        except Exception:
            pass
    else:
        write_warn(f"No stored host key found for {host_entry} (nothing to remove).")

    try:
        for muk in ssh_dir.glob(f"cxagent_mux_{server_ip}_{ssh_port}_*"):
            try:
                muk.unlink()
            except OSError:
                pass
        write_ok("Control sockets cleaned.")
    except Exception:
        pass

    write_section("Summary")

    if iqlink_results.get("credentials"):
        write_ok(f"IQ Link Credentials  : {iqlink_results['credentials']}")
    else:
        write_warn("IQ Link Credentials  : NOT CREATED (Unencrypted credentials acknowledgment disapproved)")

    if iqlink_results.get("hosts"):
        write_ok(f"IQ Link Hosts        : {iqlink_results['hosts']}")
    elif iqlink_results.get("credentials") is None:
        write_warn("IQ Link Hosts        : NOT CREATED (Unencrypted credentials acknowledgment disapproved)")

    if iqlink_results.get("discoveries"):
        write_ok(f"IQ Link Network Scan : {iqlink_results['discoveries']}")
    elif iqlink_results.get("credentials") is None:
        write_warn("IQ Link Network Scan : NOT CREATED (Unencrypted credentials acknowledgment disapproved)")

    print()
    write_warn("SECURITY REMINDER (CSDL): Output files contain unencrypted device credentials.")
    write_warn("Files created with 0600 permissions. Securely delete after IQ Link import!")
    print()
    print(f"{GREEN}All tasks complete.{RESET}")


if __name__ == "__main__":
    main()
