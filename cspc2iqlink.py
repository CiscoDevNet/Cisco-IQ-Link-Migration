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

import csv
import sys
import os
import ipaddress
from collections import defaultdict
from datetime import datetime
from pathlib import Path
import platform

# ---- Color codes for conRatvarre output --------------------------------------
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
        os.system("")  # triggers ANSI support in cmd.exe / PowerShell


# ---- Output helpers: consistent, color-codestatus messages -------------
def write_step(msg):
    print(f"{CYAN}[*] {msg}{RESET}")


def write_ok(msg):
    print(f"{GREEN}[OK] {msg}{RESET}")


def write_warn(msg):
    print(f"{YELLOW}[!] {msg}{RESET}")


def write_fail(msg):
    print(f"{RED}[X] {msg}{RESET}")


def write_section(title):
    line = "-" * (len(title) + 4)
    print()
    print(f"{DARKCYAN}{line}{RESET}")
    print(f"{WHITE}  {title}{RESET}")
    print(f"{DARKCYAN}{line}{RESET}")


def is_ipv4(val):
    """Returns True if val is a valid IPv4 address."""
    if not val:
        return False
    try:
        ipaddress.IPv4Address(str(val).strip())
        return True
    except ValueError:
        return False


def is_ipv6(val):
    """Returns True if val is a valid IPv6 address."""
    if not val:
        return False
    try:
        ipaddress.IPv6Address(str(val).strip())
        return True
    except ValueError:
        return False


def is_ip_range(val):
    """Returns True if val is an explicit IP range (e.g. 10.0.0.1-10.0.0.50)."""
    if not val or '-' not in val:
        return False
    parts = val.split('-', 1)
    return is_ipv4(parts[0].strip()) and is_ipv4(parts[1].strip())


def parse_status(status_str):
    """
    Parses pipe-delimited protocol status string from CSPC into a lowercase dict.
    Example:
      'http-No Credentials Found|snmpv2c-Successful|sshv2-Successful:Status'
      -> {'http': 'no credentials found', 'snmpv2c': 'successful', 'sshv2': 'successful'}
    """
    if not status_str:
        return {}
    clean_str = str(status_str).split(':')[0]
    parts = clean_str.split('|')
    statuses = {}
    for part in parts:
        if '-' in part:
            proto, result = part.split('-', 1)
            statuses[proto.strip().lower()] = result.strip().lower()
    return statuses


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


def get_best_pattern(ip_list):
    """
    Groups IP addresses by /16 prefix when multiple Ips fall into that subnet.
    Preserves explicit IP ranges (e.g. 10.0.0.1-10.0.0.50) and QDDNs/hostnames.
    """
    if not ip_list:
        return ""

    patterns = set()
    ipv4_subnets = defaultdict(list)

    for item in ip_list:
        item_str = str(item).strip()
        if not item_str:
            continue

        if is_ip_range(item_str):
            patterns.add(item_str)
        elif is_ipv4(item_str):
            prefix = '.'.join(item_str.split('.')[:2])
            ipv4_subnets[prefix].append(item_str)
        else:
            patterns.add(item_str)

    for prefix, group_ips in ipv4_subnets.items():
        if len(group_ips) == 1:
            patterns.add(group_ips[0])
        else:
            patterns.add(f"{prefix}.*.*")

    return "|".join(sorted(patterns))


def stream_cspc_rows(file_path):
    """
    Streams non-comment, non-empty data rows from a CSPC CSV file without
    loading the entire file into memory.
    """
    with open(file_path, 'r', encoding='utf-8', errors='replace') as infile:
        line_generator = (
            ln for ln in infile
            if ln.strip() and not ln.lstrip().startswith(';')
        )
        reader = csv.reader(line_generator)
        for row in reader:
            if not row:
                continue
            clean_row = [item.strip() for item in row]
            if not clean_row[0] or clean_row[0].startswith(';') or 'Here are' in clean_row[0]:
                continue
            yield clean_row



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

def convert_csv(input_file, output_dir=None, auto_approve=False):
    old_umask = None
    if hasattr(os, 'umask'):
        old_umask = os.umask(0o077)
    try:
        """
        Converts a CSPC ManagedDevicesCredentials.csv file to IQ Link format.

        Args:
            input_file: Path to the CSPC CSV file.
            output_dir: Optional directory to save output files. Defaults to input file directory.

        Returns:
            dict: Paths of generated CSV files {'credentials': path, 'hosts': path}
        """
        if not os.path.isfile(input_file):
            raise FileNotFoundError(f"Input file not found: {input_file}")

        if output_dir is None:
            output_dir = os.path.dirname(os.path.abspath(input_file))
        os.makedirs(output_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        write_section("CSPC to IQ Link Migration")
        write_step(f"Analyzing CSPC Managed Devices export: {input_file}")
        output_creds = os.path.join(output_dir, f"IQ_Link_Credentials_Import_{timestamp}.csv")
        output_hosts = os.path.join(output_dir, f"IQ_Link_Hosts_Import_{timestamp}.csv")

        groups = {
            'sshv2': {},
            'telnet': {},
            'snmpv2c': {},
            'snmpv3': {},
            'http': {},
            'https': {}
        }
        counters = {
            'sshv2': 1,
            'telnet': 1,
            'snmpv2c': 1,
            'snmpv3': 1,
            'http': 1,
            'https': 1
        }
        unique_hosts = set()

        def add_to_group(proto, creds_tuple, host):
            if not host:
                return
            if creds_tuple not in groups[proto]:
                prefix_map = {
                    'sshv2': 'cspc_SSH_cred',
                    'telnet': 'cspc_Telnet_cred',
                    'snmpv2c': 'cspc_SNMPv2c_cred',
                    'snmpv3': 'cspc_SNMPv3_cred',
                    'http': 'cspc_HTTP_cred',
                    'https': 'cspc_HTTPS_cred'
                }
                prefix = prefix_map.get(proto, f"cspc_{proto}_cred")
                groups[proto][creds_tuple] = {
                    "name": f"{prefix}_{counters[proto]}",
                    'hosts': set()
                }
                counters[proto] += 1
            groups[proto][creds_tuple]['hosts'].add(host)

        device_count = 0
        for row in stream_cspc_rows(input_file):
            device_count += 1
            host = row[0]
            unique_hosts.add(host)

            status_col = row[36] if len(row) > 36 else ''
            status_map = parse_status(status_col)

            # 1. SSHv2
            # Col 17 = Primary User (row[16]), Col 18 = Primary Pass (row[17]), Col 19 = Enable Pass (row[18])
            ssh_st = status_map.get('sshv2', '')
            if ssh_st and ssh_st not in ['no credentials found', 'skipped']:
                u = row[16] if len(row) > 16 else ""
                p = row[17] if len(row) > 17 else ""
                ep = row[18] if len(row) > 18 else ""
                if u or p or ep:
                    creds = (u, p, "", ep, "22")
                    add_to_group('sshv2', creds, host)

            # 2. Telnet
            tel_st = status_map.get('telnet', '')
            if tel_st and tel_st not in ['no credentials found', 'skipped']:
                u = row[16] if len(row) > 16 else ""
                p = row[17] if len(row) > 17 else ""
                ep = row[18] if len(row) > 18 else ""
                if u or p or ep:
                    creds = (u, p, "", ep, "23")
                    add_to_group('telnet', creds, host)

            # 3. SNMPv2c
            # Col 9 = Snmp RO (row[8])
            snmpv2_st = status_map.get('snmpv2c', '')
            if snmpv2_st and snmpv2_st not in ['no credentials found', 'skipped']:
                ro_comm = row[8] if len(row) > 8 else ""
                if ro_comm:
                    creds = ('v2c', ro_comm)
                    add_to_group('snmpv2c', creds, host)

            # 4. SNMPv3
            # Col 11 = User (row[10]), Col 12 = Auth Pass (row[11]), Col 13 = Engine ID (row[12]),
            # Col 14 = Auth Alg (row[13]), Col 31 = Priv Alg (row[30]), Col 32 = Priv Pass (row[31])
            snmpv3_st = status_map.get('snmpv3', '')
            if snmpv3_st and snmpv3_st not in ['no credentials found', 'skipped']:
                v3_user = row[10] if len(row) > 10 else ""
                if v3_user:
                    v3_auth_pass = row[11] if len(row) > 11 else ""
                    v3_engine_id = row[12] if len(row) > 12 else ""
                    v3_auth_alg = normalize_auth_algorithm(row[13]) if len(row) > 13 else ""
                    v3_priv_alg = normalize_priv_algorithm(row[30]) if len(row) > 30 else ""
                    v3_priv_pass = row[31] if len(row) > 31 else ""
                    creds = (
                        'v3',
                        v3_user,
                        v3_engine_id,
                        v3_auth_alg,
                        v3_auth_pass,
                        v3_priv_alg,
                        v3_priv_pass
                    )
                    add_to_group('snmpv3', creds, host)

            # 5. HTTP / HTTPS
            # Col 20 = Http User (row[19]), Col 21 = Http Pass (row[20])
            http_st = status_map.get('http', '')
            if http_st and http_st not in ['no credentials found', 'skipped']:
                hu = row[19] if len(row) > 19 else ""
                hp = row[20] if len(row) > 20 else ""
                if hu or hp:
                    add_to_group('http', (hu, hp), host)

            https_st = status_map.get('https', '')
            if https_st and https_st not in ['no credentials found', 'skipped']:
                hu = row[19] if len(row) > 19 else ""
                hp = row[20] if len(row) > 20 else ""
                if hu or hp:
                    add_to_group('https', (hu, hp), host)

        write_ok(f"Parsed {device_count:,} managed device(s) across {len(unique_hosts):,} unique IP(s).")
        write_step("Identified credential groups:")
        for proto, cred_dict in groups.items():
            if cred_dict:
                print(f"{GRAY}    - {proto.upper():<8}: {len(cred_dict)} distinct credential set(s){RESET}")

        # S&TO / CSDL Acknowledgment Gate
        if not prompt_unencrypted_credentials_acknowledgment(device_count=device_count, auto_approve=auto_approve):
            print()
            write_warn("Customer disapproved unencrypted credentials file generation.")
            write_fail("Conversion canceled: IQ Link import files were NOT created.")
            print(f"\n{YELLOW}[NOTICE] To comply with Cisco S&TO/CSDL policies, unencrypted credential files are only created upon explicit customer approval.{RESET}\n")
            return None

        write_ok("Security acknowledgment approved. Proceeding with IQ Link import file creation...")
        write_step("Writing IQ Link import files...")

        target_header = [
            'Name', 'Include Patterns', 'SSHv2 User', 'SSHv2 Password',
            'SSHv2 Enable User', 'SSHv2 Enable Password', 'SSHv2 Port',
            'Telnet User', 'Telnet Password', 'Telnet Enable User',
            'Telnet Enable Password', 'Telnet Port', 'SNMPv2c Read Community',
            'SNMPv3 User', 'SNMPv3 Engine ID', 'SNMPv3 Auth Algorithm',
            'SNMPv3 Auth Password', 'SNMPv3 Privacy Algorithm',
            'SNMPv3 Privacy Password', 'HTTP Auth Type', 'HTTP User', 'HTTP Password'
        ]

        credential_template = [
            '; ============================================================',
            '; Credentials Import Template',
            '; ------------------------------------------------------------',
            '; How to use this file:',
            '; - Add one row per credential set below the header row.',
            '; - The header row is required and columns can be in any order.',
            '; - Lines that start with ";" are notes and are skipped on import.',
            '; - In list columns (Include Patterns) separate values with "|".',
            '; - Leave columns blank for protocols you do not use.',
            '; - Fill in at least one protocol (SSHv2 / Telnet / SNMPv2c / SNMPv3 / HTTP).',
            ';',
            '; Columns:',
            ';   Name                       Required. Unique name for this credential set.',
            ';   Include Patterns           Required. One or more values separated by "|".',
            ';                                Supported formats:',
            ';                                  single host  10.1.1.1',
            ';                                  wildcard     10.1.*.*',
            ';                                  range        10.0.0.1-10.0.0.50',
            ';',
            ';   SSHv2',
            ';     SSHv2 User               Required.',
            ';     SSHv2 Password           Required.',
            ';     SSHv2 Enable User        Optional.',
            ';     SSHv2 Enable Password    Optional.',
            ';     SSHv2 Port               Optional. Defaults to 22 when left blank.',
            ';',
            ';   Telnet',
            ';     Telnet User              Required.',
            ';     Telnet Password          Required.',
            ';     Telnet Enable User       Optional.',
            ';     Telnet Enable Password   Optional.',
            ';     Telnet Port              Optional. Defaults to 23 when left blank.',
            ';',
            ';   SNMPv2c',
            ';     SNMPv2c Read Community   Required.',
            ';',
            ';   SNMPv3',
            ';     SNMPv3 User              Required.',
            ';     SNMPv3 Auth Algorithm    Required. One of: MD5 / SHA / SHA_256 / SHA_384 / SHA_512.',
            ';                              SHA is SHA-1. SHA_256 to SHA_512 are the SHA-2 protocols.',
            ';     SNMPv3 Auth Password     Required.',
            ';     SNMPv3 Engine ID         Optional.',
            ';     SNMPv3 Privacy Algorithm Optional. One of: DES / TDES / AES_128 / AES_192 / AES_256.',
            ';     SNMPv3 Privacy Password  Required when a Privacy Algorithm is set.',
            ';',
            ';   HTTP',
            ';     HTTP Auth Type           Required. Only BASIC is supported.',
            ';     HTTP User                Required.',
            ';     HTTP Password            Required.',
            '; ============================================================'
        ]

        with open(output_creds, 'w', newline='', encoding='utf-8') as outfile:
            for line in credential_template:
                outfile.write(line + '\n')
            writer = csv.writer(outfile)
            writer.writerow(target_header)

            for proto, cred_dict in groups.items():
                for creds, group_data in cred_dict.items():
                    pattern = get_best_pattern(group_data['hosts'])
                    row = [''] * len(target_header)
                    row[0] = group_data['name']
                    row[1] = pattern

                    if proto == 'sshv2':
                        row[2] = creds[0]
                        row[3] = creds[1]
                        row[4] = creds[2]
                        row[5] = creds[3]
                        row[6] = creds[4]
                    elif proto == 'telnet':
                        row[7] = creds[0]
                        row[8] = creds[1]
                        row[9] = creds[2]
                        row[10] = creds[3]
                        row[11] = creds[4]
                    elif proto == 'snmpv2c':
                        row[12] = creds[1]
                    elif proto == 'snmpv3':
                        row[13] = creds[1]
                        row[14] = creds[2]
                        row[15] = creds[3]
                        row[16] = creds[4]
                        row[17] = creds[5]
                        row[18] = creds[6]
                    elif proto in ('http', 'https'):
                        row[19] = 'BASIC'
                        row[20] = creds[0]
                        row[21] = creds[1]

                    writer.writerow(row)

        host_template = [
            '; ============================================================',
            '; Host Import Template',
            '; ------------------------------------------------------------',
            '; How to use this file:',
            '; - Add one host per row below the header row.',
            '; - The header row is required. Keep the single "Host" column exactly as shown below.',
            '; - Lines that start with ";" are notes and are skipped on import.',
            ';',
            '; Columns:',
            ';   Host   Required. One IPv4 address or hostname per row.',
            ';            Examples: 192.0.2.10 or host.example.com',
            '; ============================================================'
        ]

        with open(output_hosts, 'w', newline='', encoding='utf-8') as hostfile:
            for line in host_template:
                hostfile.write(line + '\n')
            writer = csv.writer(hostfile)
            writer.writerow(['Host'])
            for host in sorted(unique_hosts):
                writer.writerow([host])


        for p_out in (output_creds, output_hosts):
            if p_out and os.path.exists(p_out) and os.name == 'posix':
                try:
                    os.chmod(p_out, 0o600)
                except OSError:
                    pass

        creds_created = bool(output_creds and os.path.exists(output_creds) and os.path.getsize(output_creds) > 0)
        hosts_created = bool(output_hosts and os.path.exists(output_hosts) and os.path.getsize(output_hosts) > 0)

        if creds_created and hosts_created:
            write_ok("IQ Link import files created successfully")
            write_section("Summary")
            write_ok(f"Credentials CSV : {output_creds} (Permissions: 0600)")
            write_ok(f"Host List CSV   : {output_hosts} (Permissions: 0600)")

            print("\n" + "=" * 80)
            print(f"{YELLOW}[SECURITY WARNING - CISCO S&TO / CSDL COMPLIANCE]{RESET}")
            print("The generated credential file contains unencrypted device credentials")
            print("(passwords, enable secrets, SNMPv3 keys, and community strings).")
            print(f"{WHITE}  - Output files were created with restrictive permissions (0600 / rw-------).{RESET}")
            print(f"{WHITE}  - Ensure files are stored in a secure location and NOT committed to git.{RESET}")
            print(f"{WHITE}  - Securely delete all credential CSV files immediately after importing into IQ Link!{RESET}")
            print("=" * 80)
            print(f"\n{CYAN}[NOTE]: Recreate IP Range or Protocol Discoveries in IQ Link using the following path:{RESET}")
            print(f"        {WHITE}System Settings -> Connection Management -> Network Scan{RESET}\n")
            return {
                'credentials': output_creds,
                'hosts': output_hosts
            }
        else:
            write_fail("Failed to create all required IQ Link import files.")
            if not creds_created:
                write_fail(f"Credentials file missing or empty: {output_creds}")
            if not hosts_created:
                write_fail(f"Host list file missing or empty: {output_hosts}")
            return None


    finally:
        if old_umask is not None:
            os.umask(old_umask)
def main():
    enable_windows_ansi()

    auto_approve = any(arg in sys.argv for arg in ('--yes', '-y', '--accept-unencrypted-credentials', '--ack-unencrypted'))
    cli_args = [arg for arg in sys.argv[1:] if not arg.startswith('-')]

    if not cli_args:
        write_section("Usage")
        print(f"{YELLOW}Syntax: {WHITE}python cspc2iqlink.py <ManagedDevicesCredentials.csv> [output_directory] [--yes]{RESET}")
        print(f"{GRAY}Options:{RESET}")
        print(f"{GRAY}  --yes, -y    Automatically acknowledge and approve unencrypted credentials export (for CI/CD){RESET}\n")
        sys.exit(1)

    input_file = cli_args[0]
    out_dir = cli_args[1] if len(cli_args) > 1 else None

    try:
        res = convert_csv(input_file, out_dir, auto_approve=auto_approve)
        if res is not None:
            print(f"{GREEN}All tasks complete.{RESET}")
        else:
            sys.exit(2)
    except Exception as e:
        write_fail(f"Error during conversion: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
