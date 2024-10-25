#!/usr/bin/env python3

import sys
import subprocess
import socket
import logging
import json

logger = logging.getLogger(__name__)

def run_command(command: str) -> str:
    """
    Run a command in the shell and return the output as a string.

    Args:
        command (str): The command to be executed in the shell.

    Returns:
        str: The output of the command as a string.

    Raises:
        None.
    """
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
    return result.stdout.decode('utf-8').strip()

def get_local_fqdn_and_ip():
    """
    Retrieves the Fully Qualified Domain Name (FQDN) and IP address of the local machine.

    The function determines the FQDN using the socket module. It then attempts to retrieve
    the IP address of the 'eth0' interface using the 'ip' command. If the 'ip' command is
    not found, it prints an error message and exits.

    Returns:
        tuple: A tuple containing the FQDN and IP address of the local machine.
    """
    fqdn = socket.getfqdn()
    try:
        result = subprocess.run(['ip', 'addr', 'show', 'eth0'], capture_output=True, text=True)
        lines = result.stdout.splitlines()
        for line in lines:
            if 'inet ' in line:
                ip = line.strip().split()[1].split('/')[0]
                break
    except FileNotFoundError:
        print(f"[ERROR] 'ip' command not found.")
        sys.exit(1)

    return fqdn, ip

def list_nameservers():
    """
    Lists the nameservers configured in the /etc/resolv.conf file.

    The function reads the /etc/resolv.conf file and extracts nameserver entries,
    ignoring the localhost IP "127.0.0.1". If the /etc/resolv.conf file is not found,
    it prints an error message and exits.

    Returns:
        tuple: A tuple containing a dictionary with the title, result, and details
        of the nameservers and a list of the nameservers.
    """
    title = "Nameservers"
    result = "INFO"
    details = ""
    nameservers = []
    try:
        with open("/etc/resolv.conf", "r") as f:
            lines = f.readlines()
        nameservers = [line.strip().split()[1] for line in lines if
                       line.startswith("nameserver") and line.strip().split()[1] != "127.0.0.1"]
    except FileNotFoundError:
        print(f"[ERROR] /etc/resolv.conf not found. Cannot retrieve nameservers.")
        sys.exit(1)
    if nameservers:
        for ns in nameservers:
            details += f"\n{ns}"
    return {'title': title, 'result': result, 'details': details}, nameservers

def list_etc_hosts_entries():
    """
    Retrieves and lists the entries from the /etc/hosts file.

    Returns:
        List of tuples: A list of tuples where each tuple contains an IP address and its associated hostname.
    """
    title = "Entries in /etc/hosts"
    result = "INFO"
    # details = ""
    try:
        with open("/etc/hosts", "r") as f:
            lines = f.readlines()
        # Filter out lines starting with '#' and return the remaining lines
        title += "\n\t\t" + "\n\t\t".join([line.strip() for line in lines if not line.strip().startswith("#")])
    except FileNotFoundError:
        title += "\n\t\t" + f"\n\t\tERROR: /etc/hosts not found."
        result = "FAIL"
        sys.exit(1)
    return {'title': title, 'result': result}

def check_hosts_file():
    """
    Verifies the /etc/hosts file for any entries that were put there manually.

    This function scans the /etc/hosts file for any entries outside the `VAMI_EDIT` region.
    If any such entries are found, it categorizes them as non-standard and attempts to ping
    the associated IP addresses. The function then returns the result of the verification
    and ping tests.
    """
    title = "Checking for non-standard /etc/hosts entries"
    result = ""
    details = ""
    # Extract lines from /etc/hosts
    with open("/etc/hosts", "r") as f:
        lines = f.readlines()

    # Variables to hold full lines and individual components
    filtered_full_lines = []
    filtered_components = []

    inside_vami_edit = False
    for line in lines:
        if "VAMI_EDIT_BEGIN" in line:
            inside_vami_edit = True
            continue
        elif "VAMI_EDIT_END" in line:
            inside_vami_edit = False
            continue

        # If not inside VAMI_EDIT and line isn't a comment and isn't empty
        if not inside_vami_edit and not line.strip().startswith("#") and line.strip():
            filtered_full_lines.append(line.strip())
            filtered_components.extend(line.strip().split())

    # Display the full lines
    if not filtered_full_lines:
        result = "PASS"
    else:
        sus_entries = True
        result = "WARN"
        details = "Detected non-standard entries!\n\t" + "\n\t".join(
            filtered_full_lines) + "\nTrying to ping suspicious entries"

        # Ping test for the individual components
        sus_ip_list = [item.split()[0] for item in filtered_full_lines]
        for sus_ip in sus_ip_list:
            ping_result = subprocess.run(["ping", "-c", "1", "-W", "2", sus_ip], stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)
            if ping_result.returncode != 0:
                result = "FAIL"
                details += f"\n\t{sus_ip} is not pingable!"
            else:
                details += f"\n\t{sus_ip} - OK"
    return {'title': title, 'result': result, 'details': details}

class queryNameServer(object):
    """
    A class to facilitate DNS queries for forward and reverse lookups using both UDP and TCP.

    Attributes:
        fqdn (str): Fully qualified domain name of the local system.
        ip (str): IP address of the local system.
        nameservers (list): List of nameservers to be queried.
    """

    def __init__(self):
        """
        Initialize the object with local fqdn and ip.

        Attributes:
            fqdn (str): Fully Qualified Domain Name of the local machine.
            ip (str): IP address of the local machine.
            nameservers (list): A list of nameservers for the local machine.
        """
        self.fqdn, self.ip = get_local_fqdn_and_ip()
        self.nameservers = list_nameservers()[1]

    def query_forward_udp(self, ns):
        """
        Performs a forward DNS lookup using UDP for the local FQDN against the provided nameserver.

        Parameters:
            ns (str): The nameserver to be queried.

        Returns:
            dict: A dictionary containing the title of the test, the result (PASS/FAIL), and details of the test.
        """
        result = "PASS"
        details = ""
        title = f"DNS with UDP - testing if {self.fqdn} resolves to {self.ip}"
        forward_udp_command = ['dig', '+short', self.fqdn, f'@{ns}']
        forward_udp = subprocess.run(forward_udp_command, capture_output=True, text=True).stdout.strip()
        if forward_udp != self.ip:
            result = "FAIL"
            details = f"VC uses UDP 53 for DNS queries by default, but will switch to TCP if UDP fails, causing a delayed response"
        return {'title': title, 'result': result, 'details': details}

    def query_forward_tcp(self, ns):
        """
        Performs a forward DNS lookup using TCP for the local FQDN against the provided nameserver.

        Parameters:
            ns (str): The nameserver to be queried.

        Returns:
            dict: A dictionary containing the title of the test, the result (PASS/FAIL), and details of the test.
        """
        result = "PASS"
        details = ""
        title = f"DNS with TCP - testing if {self.fqdn} resolves to {self.ip}"
        forward_tcp_command = ['dig', '+short', '+tcp', self.fqdn, f'@{ns}']
        forward_tcp = subprocess.run(forward_tcp_command, capture_output=True, text=True).stdout.strip()
        if forward_tcp != self.ip:
            result = "FAIL"
            details = f"VC uses TCP 53 for DNS queries when UDP fails, or if the size is too large for a single UDP packet"
        return {'title': title, 'result': result, 'details': details}

    def query_reverse_udp(self, ns):
        """
        Performs a reverse DNS lookup using UDP for the local IP address against the provided nameserver.

        Args:
            ns (str): The nameserver to be queried.

        Returns:
            dict: A dictionary containing the title of the test, the result (PASS/WARN), and details of the test.
        """
        result = "PASS"
        details = ""
        documentation = ""
        title = f"Reverse DNS - testing if {self.ip} resolves to {self.fqdn}"
        reverse_udp_command = ['dig', '+noall', '+answer', '-x', self.ip, f'@{ns}']
        reverse_udp_fqdn = ""
        command_str = ' '.join(reverse_udp_command)
        cmd_result = run_command(command_str)
        if cmd_result:
            reverse_udp_fqdn = cmd_result.split()[-1].strip('.').lower()

        if reverse_udp_fqdn != self.fqdn.lower():
            result = "FAIL"
            details = (f"""{self.ip} resolves to {reverse_udp_fqdn}.
    Non-functional reverse DNS is known to cause issues with domain joined VCs (IWA).  
    Reverse DNS is a requirement of vCenter Server FQDNs.""")
            documentation = (f"\nhttps://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-vcenter-installation/GUID-752FCA83-1A9B-499E-9C65-D5625351C0B5.html\nhttps://kb.vmware.com/s/article/52930")

        return {'title': title, 'result': result, 'details': details, 'documentation': documentation}

    def notes(self):
        """
        Return a dictionary containing command notes.

        Returns:
            dict: Dictionary containing two keys: 'title' (str) and 'result' (str).
        """
        title = f"""Commands used:
      dig +short <fqdn> <nameserver>
      dig +noall +answer -x <ip> <namserver>
      dig +short +tcp <fqdn> <nameserver>
      """
        result = "INFO"
        return {'title': title, 'result': result}

    def run_query(self):
        """
        Executes all the DNS query tests (forward and reverse, UDP and TCP) for each nameserver in the nameservers list.

        Returns:
            list[dict]: A list of dictionaries where each dictionary contains a subheading (nameserver) and
                        a list of checks (results of the DNS queries).
        """
        output = []
        for ns in self.nameservers:
            ns_checks = []
            ns_checks.append(self.query_forward_udp(ns))
            ns_checks.append(self.query_forward_tcp(ns))
            ns_checks.append(self.query_reverse_udp(ns))
            ns_checks.append(self.notes())
            output.append({'subheading': ns, 'checks': ns_checks})
        return output

def new_query_nameserver():
    """
    Create a new query to a nameserver.

    Returns:
        str: The result of the query to the nameserver.

    Raises:
        <specific_exception>: If an error occurs while running the query.
    """
    nscheck = queryNameServer()
    return nscheck.run_query()

def execute_nsq():
    """
    Execute NSQ service and return the query nameserver.

    Returns:
        object: The query nameserver object.
    """
    return new_query_nameserver()

def main():
    """
    Main function that returns a list of outputs.

    Returns:
        list: A list containing the outputs of the functions `list_etc_hosts_entries()` and `check_hosts_file()`.

    Raises:
        None
    """
    fqdn, ip = get_local_fqdn_and_ip()
    output = []
    output.append(list_etc_hosts_entries())
    output.append(check_hosts_file())
    return output
