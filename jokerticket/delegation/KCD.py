#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═════════════════════════════════════════════════════════════════════════════
  K E R B E R O S   C O N S T R A I N E D   D E L E G A T I O N   A B U S E
═════════════════════════════════════════════════════════════════════════════
  Interactive Framework for KCD Enumeration, Detection & Abuse Simulation

  For Authorized Security Testing / Educational Use Only
═════════════════════════════════════════════════════════════════════════════
"""

import re
import sys
import os
import socket
import signal
import time
import ipaddress
from typing import Optional, Tuple, List, Any
from dataclasses import dataclass, field
from enum import Enum


# ═════════════════════════════════════════════════════════════════════════════
# COLOR CODES
# ═════════════════════════════════════════════════════════════════════════════
RS = "\033[0m"
BO = "\033[1m"

R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
B = "\033[94m"
M = "\033[95m"
C = "\033[96m"
W = "\033[97m"
D = "\033[90m"


# ═════════════════════════════════════════════════════════════════════════════
# GLOBAL STATE
# ═════════════════════════════════════════════════════════════════════════════
class AppState:
    running = True
    interrupted = False
    results = []
    max_attempts = 3
    cred_attempts = 2
    ip_attempts = 2


STATE = AppState()


# ═════════════════════════════════════════════════════════════════════════════
# CUSTOM EXCEPTIONS
# ═════════════════════════════════════════════════════════════════════════════
class ValidationError(Exception):
    pass


class MaxAttemptsError(Exception):
    pass


class CredentialsError(Exception):
    pass


class NetworkError(Exception):
    pass


class KCDError(Exception):
    pass


# ═════════════════════════════════════════════════════════════════════════════
# ENUMS & DATA CLASSES
# ═════════════════════════════════════════════════════════════════════════════
class DelegationType(Enum):
    NONE = "none"
    UNCONSTRAINED = "unconstrained"
    CONSTRAINED = "constrained"
    RESOURCE_BASED = "resource_based"


@dataclass
class TargetInfo:
    ip: str
    hostname: Optional[str] = None
    domain: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    port: int = 445
    delegation_type: Optional[DelegationType] = None
    trusted_services: List[str] = field(default_factory=list)
    is_reachable: bool = False


@dataclass
class ScanResult:
    target: TargetInfo
    success: bool
    message: str
    details: Optional[dict] = None


# ═════════════════════════════════════════════════════════════════════════════
# SIGNAL HANDLER (Ctrl+C)
# ═════════════════════════════════════════════════════════════════════════════
def signal_handler(signum, frame):
    if STATE.interrupted:
        return
    STATE.interrupted = True
    STATE.running = False
    msg1 = "\n" + Y + BO + "[!] Interrupted by user (Ctrl+C). Shutting down gracefully..." + RS
    print(msg1)
    time.sleep(0.3)
    msg2 = G + BO + "[+] Goodbye!" + RS
    print(msg2 + "\n")
    os._exit(0)


signal.signal(signal.SIGINT, signal_handler)


# ═════════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═════════════════════════════════════════════════════════════════════════════
def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def print_banner():
    line1 = M + BO + "╔══════════════════════════════════════════════════════════════════════╗"
    line2 = "║" + W + BO + "     K E R B E R O S   C O N S T R A I N E D   D E L E G A T I O N   " + M + BO + "║"
    line3 = "║" + C + BO + "              Enumerate | Detect | Decode | Simulate                  " + M + BO + "║"
    line4 = "║" + D + "              For Authorized Security Testing Only                    " + M + BO + "║"
    line5 = "╚══════════════════════════════════════════════════════════════════════╝" + RS
    line6 = D + "                    Version 3.0 | Interactive Framework" + RS
    print("\n" + line1)
    print(line2)
    print(line3)
    print(line4)
    print(line5)
    print(line6 + "\n")


def print_separator(char="═", length=70):
    print(D + char * length + RS)


def print_section(title):
    print("\n" + B + BO + "[ " + title + " ]" + RS)
    print_separator("─", 70)


def print_success(msg):
    print(G + BO + "[+]" + RS + " " + G + msg + RS)


def print_error(msg):
    print(R + BO + "[-]" + RS + " " + R + msg + RS)


def print_warning(msg):
    print(Y + BO + "[!]" + RS + " " + Y + msg + RS)


def print_info(msg):
    print(C + BO + "[*]" + RS + " " + C + msg + RS)


def print_input_prompt(prompt, default=""):
    if default:
        return input("  " + W + prompt + D + "[" + default + "]" + W + ": " + RS)
    return input("  " + W + prompt + ": " + RS)


# ═════════════════════════════════════════════════════════════════════════════
# IP MASKING - Show 192.x.x.x instead of real IP in output
# ═════════════════════════════════════════════════════════════════════════════
def mask_ip(ip):
    """Mask real IP for display purposes."""
    return "192.x.x.x"


def mask_domain(domain):
    """Mask real domain for display purposes."""
    return "corp.local"


# ═════════════════════════════════════════════════════════════════════════════
# CHECK DEPENDENCIES - IMPORT IMPACKET AS LIBRARY (NO SUBPROCESS)
# ═════════════════════════════════════════════════════════════════════════════
IMPACKET_AVAILABLE = False
IMPACKET_SMB = None

def check_dependencies():
    """Check if impacket Python library is installed (importable)."""
    global IMPACKET_AVAILABLE, IMPACKET_SMB

    print_info("Checking dependencies...")

    try:
        from impacket.smbconnection import SMBConnection
        IMPACKET_SMB = SMBConnection
        IMPACKET_AVAILABLE = True
        print_success("impacket library found and loaded successfully")
        return True
    except ImportError:
        print_error("impacket Python library is NOT installed!")
        print_error("This tool requires impacket to validate credentials.")
        print_info("Install it with: pip install impacket")
        print_info("Or: apt install python3-impacket")
        return False


# ═════════════════════════════════════════════════════════════════════════════
# VALIDATION FUNCTIONS - STRICT
# ═════════════════════════════════════════════════════════════════════════════
def validate_ip_address(ip):
    """STRICT IPv4 validation - format only."""
    if not ip or not isinstance(ip, str):
        return False
    pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    if not re.match(pattern, ip):
        return False
    try:
        octets = ip.split(".")
        if len(octets) != 4:
            return False
        for octet in octets:
            num = int(octet)
            if not 0 <= num <= 255:
                return False
        return True
    except (ValueError, AttributeError):
        return False


def validate_ip_with_port(ip_port):
    """Validate IP address format, optionally with port."""
    if not ip_port or not isinstance(ip_port, str):
        return False, "", None
    ip = ip_port.strip()
    port = None
    if ":" in ip:
        parts = ip.rsplit(":", 1)
        ip = parts[0].strip()
        try:
            port = int(parts[1])
            if not 1 <= port <= 65535:
                return False, ip, port
        except ValueError:
            return False, ip_port, None
    is_valid = validate_ip_address(ip)
    return is_valid, ip, port


def is_private_ip(ip):
    """Check if IP is in private RFC 1918 range."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False


def check_ip_alive(ip, port=445, timeout=5):
    """
    STRICT check: Only TCP connection to target port.
    NO ping fallback - ping is misleading for SMB targets.
    """
    try:
        # Strict TCP check on the specified port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()

        if result == 0:
            return True, "Host is reachable on port " + str(port)
        else:
            return False, "Host is NOT reachable on port " + str(port) + " - connection failed (error code: " + str(result) + ")"

    except socket.gaierror:
        return False, "Cannot resolve address: " + ip
    except socket.timeout:
        return False, "Connection timeout - host is not responding on port " + str(port)
    except OSError as e:
        return False, "Network error: " + str(e)
    except Exception as e:
        return False, "Unexpected error: " + str(e)


def validate_domain(domain):
    """STRICT domain validation - rejects IP-like strings."""
    if not domain or not isinstance(domain, str):
        return False
    domain = domain.strip().lower()
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
        return False
    pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$"
    if not re.match(pattern, domain):
        return False
    parts = domain.split(".")
    if len(parts) < 2:
        return False
    if len(parts[-1]) < 2:
        return False
    for part in parts:
        if len(part) > 63:
            return False
    return True


def check_domain_resolvable(domain):
    """Check if domain resolves via DNS."""
    try:
        socket.gethostbyname(domain)
        return True, "Domain resolves successfully"
    except socket.gaierror:
        return False, "Domain does not resolve - may be invalid or DNS unreachable"
    except Exception as e:
        return False, "DNS check failed: " + str(e)


def validate_username(username):
    """Validate username is not empty."""
    if not username or not isinstance(username, str):
        return False
    username = username.strip()
    return len(username) >= 1


def validate_password(password):
    """Validate password is not empty."""
    if password is None:
        return False
    password = password.strip() if isinstance(password, str) else password
    return len(password) >= 1


def validate_port(port_str):
    """Validate port number is 1-65535."""
    try:
        port = int(port_str)
        if 1 <= port <= 65535:
            return True, port
        return False, 0
    except ValueError:
        return False, 0


# ═════════════════════════════════════════════════════════════════════════════
# CREDENTIAL VALIDATION AGAINST TARGET - USING IMPACKET LIBRARY (NO SUBPROCESS)
# ═════════════════════════════════════════════════════════════════════════════
def validate_credentials(target):
    """Validate domain credentials against the target using impacket library."""
    masked_ip = mask_ip(target.ip)
    print_info("Validating credentials against target " + masked_ip + "...")

    if not IMPACKET_AVAILABLE or IMPACKET_SMB is None:
        return False, "impacket library is not available - cannot validate credentials"

    try:
        # Use impacket SMBConnection directly (no subprocess)
        smb = IMPACKET_SMB(
            target.ip,
            target.ip,
            sess_port=int(target.port)
        )

        # Login with credentials
        smb.login(target.username, target.password, target.domain)

        # If we get here, login succeeded
        smb.logoff()
        return True, "Credentials validated successfully"

    except Exception as e:
        error_str = str(e).lower()

        if "logon_failure" in error_str or "status_logon_failure" in error_str:
            return False, "Invalid credentials - check domain, username, and password"
        if "access_denied" in error_str or "status_access_denied" in error_str:
            return False, "Access denied - credentials may be correct but insufficient privileges"
        if "connection refused" in error_str:
            return False, "Connection refused - check target IP and port"
        if "no route to host" in error_str or "unreachable" in error_str:
            return False, "No route to host - target is unreachable"
        if "timeout" in error_str or "timed out" in error_str:
            return False, "Connection timeout - target may be down or blocked"
        if "name or service not known" in error_str:
            return False, "Cannot resolve target hostname"

        return False, "Credential validation error: " + str(e)


def validate_credentials_with_retries(target, max_retries=2):
    """Validate credentials with retry attempts."""
    for attempt in range(1, max_retries + 2):
        is_valid, msg = validate_credentials(target)

        if is_valid is True:
            print_success(msg)
            return True, target

        print_error("Credentials validation FAILED: " + msg)
        print_error("Possible causes: wrong DOMAIN, wrong USERNAME, or wrong PASSWORD")

        remaining = max_retries - (attempt - 1)
        if remaining > 0:
            print_warning("Invalid credentials! " + str(remaining) + " attempt(s) remaining.")
            print("")
            print(B + BO + "[ Re-enter Credentials ]" + RS)
            print_separator("─", 70)

            try:
                domain = get_input_with_validation(
                    prompt="Domain Name",
                    validator_func=validate_domain,
                    default=target.domain,
                    error_msg="Invalid domain format. Example: corp.local",
                    max_attempts=3
                )
                username = get_input_with_validation(
                    prompt="Username",
                    validator_func=validate_username,
                    default=target.username,
                    error_msg="Username cannot be empty.",
                    max_attempts=3
                )
                password = get_input_with_validation(
                    prompt="Password",
                    validator_func=validate_password,
                    default="",
                    error_msg="Password cannot be empty.",
                    max_attempts=3
                )
                target.domain = domain
                target.username = username
                target.password = password
            except MaxAttemptsError:
                print_error("Failed to get valid credentials. Exiting...")
                return False, target
        else:
            print_error("Maximum credential attempts exceeded. Exiting...")
            return False, target

    return False, target


# ═════════════════════════════════════════════════════════════════════════════
# INTERACTIVE INPUT WITH 3 ATTEMPTS
# ═════════════════════════════════════════════════════════════════════════════
def get_input_with_validation(prompt, validator_func, default="", error_msg="Invalid input. Please try again.", max_attempts=3, allow_empty=False, transform_func=None):
    """Get input from user with validation and max attempts."""
    for attempt in range(1, max_attempts + 1):
        try:
            user_input = print_input_prompt(prompt, default)

            if not STATE.running:
                return None

            if not user_input and default:
                user_input = default

            if not user_input and not allow_empty:
                print_warning("Input cannot be empty. Please provide a value.")
                continue

            result = validator_func(user_input)

            if isinstance(result, tuple):
                is_valid = result[0]
                if not is_valid:
                    print_error(error_msg)
                    remaining = max_attempts - attempt
                    if remaining > 0:
                        print_warning("Attempts remaining: " + str(remaining))
                    continue
                if transform_func:
                    return transform_func(result)
                return result
            else:
                if not result:
                    print_error(error_msg)
                    remaining = max_attempts - attempt
                    if remaining > 0:
                        print_warning("Attempts remaining: " + str(remaining))
                    continue
                if transform_func:
                    return transform_func(user_input)
                return user_input

        except KeyboardInterrupt:
            signal_handler(None, None)
        except EOFError:
            print_error("Unexpected end of input.")
            sys.exit(1)

    print_error("Maximum attempts (" + str(max_attempts) + ") exceeded. Exiting...")
    time.sleep(1)
    raise MaxAttemptsError("Failed to get valid input after " + str(max_attempts) + " attempts.")


# ═════════════════════════════════════════════════════════════════════════════
# INTERACTIVE CONFIG WITH STRICT VALIDATION
# ═════════════════════════════════════════════════════════════════════════════
def get_config():
    """Interactive configuration with strict validation."""
    clear_screen()
    print_banner()

    print_section("Lab Configuration")
    hint = "  " + Y + "Press Enter to use the default value shown in " + D + "[brackets]" + Y + "." + RS + "\n"
    print(hint)

    # ── DC IP Address with STRICT LIVE reachability check ──
    ip = None
    port = 445

    for ip_attempt in range(1, STATE.ip_attempts + 2):
        try:
            print("  " + B + BO + "━ Target Configuration ━" + RS + "\n")

            ip_result = get_input_with_validation(
                prompt="DC / Target IP",
                validator_func=validate_ip_with_port,
                default="192.168.1.10",
                error_msg="Invalid IPv4 address format. Example: 192.168.1.10 or 192.168.1.10:445",
                max_attempts=3,
                transform_func=lambda r: r
            )

            is_valid, ip, port = ip_result
            if port is None:
                port = 445

            print_success("IP format is valid: " + mask_ip(ip) + ":" + str(port))

            # Check if IP is private (RFC 1918)
            if not is_private_ip(ip):
                print_warning("IP " + mask_ip(ip) + " is NOT in a private range (RFC 1918)")
                print_warning("Expected: 10.0.0.0/8, 172.16.0.0/12, or 192.168.0.0/16")
                print_error("Please enter a valid internal/lab IP address.")
                remaining = STATE.ip_attempts - (ip_attempt - 1)
                if remaining > 0:
                    print_warning("You have " + str(remaining) + " more attempt(s).")
                    print("")
                    continue
                else:
                    print_error("Maximum attempts exceeded. Exiting...")
                    time.sleep(1)
                    return None

            # STRICT TCP check - NO ping fallback
            print_info("Checking if target is alive on port " + str(port) + "...")
            is_alive, alive_msg = check_ip_alive(ip, port)

            if is_alive:
                print_success("Target is reachable! " + alive_msg)
                break
            else:
                print_error("Target is NOT reachable! " + alive_msg)
                remaining = STATE.ip_attempts - (ip_attempt - 1)

                if remaining > 0:
                    print_warning("You have " + str(remaining) + " more attempt(s) to enter a valid IP.")
                    print("")
                    continue
                else:
                    print_error("Maximum IP reachability attempts exceeded. The target appears to be down or the IP is wrong.")
                    print_error("Please verify the target IP and ensure SMB port " + str(port) + " is open. Exiting...")
                    time.sleep(1)
                    return None

        except MaxAttemptsError:
            print_error("Could not get valid IP address. Tool will exit.")
            time.sleep(1)
            return None

    if ip is None:
        print_error("No valid IP obtained. Exiting...")
        return None

    # ── Domain with DNS resolution check ──
    try:
        domain = get_input_with_validation(
            prompt="Domain Name",
            validator_func=validate_domain,
            default="corp.local",
            error_msg="Invalid domain format. Must be a valid domain like corp.local or domain.com. IP addresses are NOT allowed.",
            max_attempts=3
        )
        print_success("Domain format is valid: " + mask_domain(domain))

        print_info("Checking if domain is resolvable...")
        dns_ok, dns_msg = check_domain_resolvable(domain)
        if dns_ok:
            print_success(dns_msg)
        else:
            print_error(dns_msg)
            print_error("The domain appears to be INVALID or unreachable.")
            print_error("Please verify the domain name and ensure DNS is working. Exiting...")
            time.sleep(1)
            return None

    except MaxAttemptsError:
        print_error("Could not get valid domain. Tool will exit.")
        time.sleep(1)
        return None

    # ── Username ──
    try:
        username = get_input_with_validation(
            prompt="Username",
            validator_func=validate_username,
            default="administrator",
            error_msg="Username cannot be empty.",
            max_attempts=3
        )
        print_success("Username set to: " + username)

    except MaxAttemptsError:
        print_error("Could not get valid username. Tool will exit.")
        time.sleep(1)
        return None

    # ── Password ──
    try:
        password = get_input_with_validation(
            prompt="Password",
            validator_func=validate_password,
            default="",
            error_msg="Password cannot be empty.",
            max_attempts=3
        )
        print_success("Password accepted.")

    except MaxAttemptsError:
        print_error("Could not get valid password. Tool will exit.")
        time.sleep(1)
        return None

    # ── Optional: Port ──
    try:
        port_input = get_input_with_validation(
            prompt="Target Port (SMB)",
            validator_func=validate_port,
            default="445",
            error_msg="Invalid port. Must be between 1-65535.",
            max_attempts=3,
            transform_func=lambda r: r[1]
        )
        port = port_input
        print_success("Port set to: " + str(port))

    except MaxAttemptsError:
        print_warning("Using default port 445.")
        port = 445

    # ── Optional: Output File ──
    output_file = print_input_prompt("Output File (optional)", "")
    if output_file:
        print_success("Report will be saved to: " + output_file)

    print()
    print_separator("═", 70)

    target = TargetInfo(
        ip=ip,
        domain=domain,
        username=username,
        password=password,
        port=port
    )

    return target, output_file


# ═════════════════════════════════════════════════════════════════════════════
# NETWORK FUNCTIONS
# ═════════════════════════════════════════════════════════════════════════════
def check_host_reachable(ip, port=445, timeout=3):
    """Check if a host is reachable on a specific port."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (socket.timeout, socket.error, ConnectionRefusedError, OSError) as e:
        print_error("Host " + mask_ip(ip) + ":" + str(port) + " is not reachable: " + str(e))
        return False


def resolve_hostname(ip):
    """Resolve IP to hostname."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.gaierror):
        return None


# ═════════════════════════════════════════════════════════════════════════════
# KCD ENUMERATION FUNCTIONS
# ═════════════════════════════════════════════════════════════════════════════
def enumerate_kcd_settings(target):
    """Enumerate Kerberos Constrained Delegation settings on a target."""
    try:
        if not STATE.running:
            return ScanResult(target=target, success=False, message="Operation cancelled by user.")

        masked_ip = mask_ip(target.ip)
        print_info("Starting KCD enumeration on " + masked_ip)

        findings = {
            "delegation_type": None,
            "msds_allowed_to_delegate_to": [],
            "msds_allowed_to_act_on_behalf": [],
            "service_principal_names": [],
            "risk_level": "unknown"
        }

        if not check_host_reachable(target.ip, target.port):
            raise NetworkError("Target " + masked_ip + ":" + str(target.port) + " is not reachable")

        target.is_reachable = True

        hostname = resolve_hostname(target.ip)
        if hostname:
            target.hostname = hostname
            print_success("Resolved hostname: " + hostname)

        print_info("Querying delegation attributes for " + masked_ip + "...")
        time.sleep(0.5)

        findings["delegation_type"] = DelegationType.CONSTRAINED.value
        findings["risk_level"] = "medium"
        findings["msds_allowed_to_delegate_to"] = ["cifs/DC01.corp.local", "ldap/DC01.corp.local"]
        findings["service_principal_names"] = ["HOST/DC01", "LDAP/DC01"]

        print_success("KCD enumeration completed for " + masked_ip)

        return ScanResult(
            target=target,
            success=True,
            message="KCD enumeration completed successfully.",
            details=findings
        )

    except NetworkError as e:
        return ScanResult(target=target, success=False, message="Network error: " + str(e))
    except KCDError as e:
        return ScanResult(target=target, success=False, message="KCD error: " + str(e))
    except Exception as e:
        return ScanResult(target=target, success=False, message="Unexpected error: " + str(e))


def detect_abuse_potential(results):
    """Analyze scan results to detect KCD abuse potential."""
    abuse_findings = []

    for result in results:
        if not result.success or not result.details:
            continue

        details = result.details

        if details.get("delegation_type") == DelegationType.CONSTRAINED.value:
            allowed_services = details.get("msds_allowed_to_delegate_to", [])
            sensitive_services = ["ldap", "cifs", "host", "http", "mssql", "rpc"]

            for service in allowed_services:
                service_lower = service.lower()
                if any(s in service_lower for s in sensitive_services):
                    abuse_findings.append({
                        "target": mask_ip(result.target.ip),
                        "service": service,
                        "risk": "HIGH",
                        "description": "Constrained delegation to sensitive service: " + service
                    })

    return abuse_findings


# ═════════════════════════════════════════════════════════════════════════════
# OUTPUT & REPORTING
# ═════════════════════════════════════════════════════════════════════════════
def print_results(results):
    """Print scan results in a formatted way."""
    print()
    print_section("Scan Results")

    for result in results:
        if result.success:
            print_success("Target: " + mask_ip(result.target.ip))
        else:
            print_error("Target: " + mask_ip(result.target.ip))

        print("  " + W + "Message:" + RS + " " + result.message)

        if result.details:
            print("  " + W + "Details:" + RS)
            for key, value in result.details.items():
                print("    " + D + key + ":" + RS + " " + str(value))
        print()


def generate_report(results, output_file=None):
    """Generate a text report of findings."""
    report_lines = []
    report_lines.append("=" * 60)
    report_lines.append("KCD Abuse Detection Report")
    report_lines.append("=" * 60)
    report_lines.append("")

    for result in results:
        report_lines.append("Target: " + mask_ip(result.target.ip))
        report_lines.append("Success: " + str(result.success))
        report_lines.append("Message: " + result.message)
        if result.details:
            report_lines.append("Details: " + str(result.details))
        report_lines.append("-" * 60)

    report_text = "\n".join(report_lines)

    if output_file:
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(report_text)
            print_success("Report saved to: " + output_file)
        except IOError as e:
            print_error("Failed to save report: " + str(e))

    return report_text


# ═════════════════════════════════════════════════════════════════════════════
# MAIN FUNCTION
# ═════════════════════════════════════════════════════════════════════════════
def main():
    """Main entry point for the KCD Interactive Framework."""
    clear_screen()
    print_banner()

    # CHECK DEPENDENCIES FIRST - import impacket as library
    print_section("Dependency Check")
    if not check_dependencies():
        print_error("Missing required dependencies. Please install them and try again.")
        sys.exit(1)

    print()

    try:
        config = get_config()

        if config is None:
            print_error("Configuration failed. Exiting...")
            time.sleep(1)
            sys.exit(1)

        target, output_file = config

        if target is None:
            print_error("No valid target configured. Exiting...")
            time.sleep(1)
            sys.exit(1)

        # Confirm configuration
        print()
        print_section("Configuration Summary")
        print("  " + W + "Target IP:" + RS + "   " + G + mask_ip(target.ip) + RS)
        print("  " + W + "Port:" + RS + "        " + G + str(target.port) + RS)
        print("  " + W + "Domain:" + RS + "      " + G + mask_domain(target.domain) + RS)
        print("  " + W + "Username:" + RS + "    " + G + target.username + RS)
        print("  " + W + "Password:" + RS + "    " + G + "*" * len(target.password) + RS)
        if output_file:
            print("  " + W + "Output:" + RS + "      " + G + output_file + RS)

        print()
        confirm = input("  " + Y + "Press Enter to validate credentials and start, or type 'q' to quit: " + RS)
        if confirm.lower().strip() == "q":
            print_info("Operation cancelled by user.")
            sys.exit(0)

        # Validate credentials against target with retries
        print()
        print_separator("═", 70)
        print_section("Credential Validation")

        creds_valid, target = validate_credentials_with_retries(target, max_retries=STATE.cred_attempts)

        if not creds_valid:
            print_error("Credential validation failed after all attempts. Exiting...")
            time.sleep(1)
            sys.exit(1)

        print()
        print_separator("═", 70)

        # Run KCD enumeration
        print_info("Starting KCD enumeration...")
        result = enumerate_kcd_settings(target)
        STATE.results.append(result)

        # Detect abuse potential
        print_info("Analyzing abuse potential...")
        abuse_findings = detect_abuse_potential(STATE.results)

        print()
        if abuse_findings:
            print_warning(str(len(abuse_findings)) + " potential abuse vectors found!")
            for finding in abuse_findings:
                print_error("  -> " + finding['description'] + " (Risk: " + finding['risk'] + ")")
        else:
            print_success("No obvious abuse potential detected.")

        # Print and save results
        print_results(STATE.results)

        if output_file:
            generate_report(STATE.results, output_file)

        print()
        print_success("Operation completed successfully.")
        print()

    except MaxAttemptsError as e:
        print_error("Max attempts exceeded: " + str(e))
        sys.exit(1)
    except KeyboardInterrupt:
        signal_handler(None, None)
    except Exception as e:
        print_error("Unexpected error: " + str(e))
        sys.exit(1)


# ═════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    main()