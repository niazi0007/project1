#!/usr/bin/env python
__title__ = "VC AD CHECK"
import os
import sys
import subprocess
import re
import socket
import threading
from vcenter.vc_lib.common import Command, CheckConnect
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import logging
logger = logging.getLogger(__name__)
command_timeout = 5

_DefaultCommmandEncoding = sys.getfilesystemencoding()
def getHostname():
    """
    Get the fully qualified hostname of the current system.

    Returns:
        str: The fully qualified hostname.

    Raises:
        None.
    """    
    cmd = ['/usr/bin/hostname', '-f']
    output, errors, timeout = Command(cmd).run().strip()
    return output

def getAdDomain():
    """
    Get the Active Directory domain name.

    Returns:
        str: The Active Directory domain name.
    """    
    cmd = ['/opt/likewise/bin/domainjoin-cli', 'query']
    query, errors, timeout = Command(cmd).run()
    query_result = query.split('\n')[1].split(' = ')
    if len(query_result) > 1:
        result = (query_result[1])
    else:
        result = ""
    return result

def getDomains():
    """
    Retrieve a list of DNS domains.

    Returns:
        list: A list of DNS domain names.

    Raises:
        None.
    """    
    results = []
    cmd = ['/opt/likewise/bin/lw-get-status']
    query, errors, timeout = Command(cmd).run()
    query_result = query.strip()
    for line in query_result.splitlines():
        line = line.strip()
        if line.startswith('DNS Domain'):
            results.append(line.split(':')[1].strip())
    return results

def validateIPorHost(address):
    """
    Validate whether a string is an IP address or a hostname.

    Args:
        address (str): The input string to be validated.

    Returns:
        str: 'IP' if the input string is a valid IP address.
             'HOSTNAME' if the input string is a valid hostname.

    Raises:
        None.
    """    
    is_ip = re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", address)
    is_hostname = re.match("^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$", address)
    if is_ip:
        return 'IP'
    if is_hostname:
        return 'HOSTNAME'

def dns_lookup(addr):
    """
    Perform DNS lookup for a given address.

    Args:
        addr (str): The address to perform the DNS lookup on. Can be either an IP address or a hostname.

    Returns:
        tuple: A tuple containing the resolved address (if successful) and the result of the lookup.

    Raises:
        ValueError: If the input address is neither a valid IP address nor a valid hostname.
        socket.error: If an error occurred during the DNS lookup.
    """    
    addr_type = validateIPorHost(addr)
    result = ""
    address = ""
    if addr_type == 'IP':
        try:
            address = socket.gethostbyaddr(addr)[0]
            result = "PASS"

        except:
            result = "FAIL"
        # print("Reverse lookup for IP %s resolved to hostname %s" % (addr, hostname[0]))
    if addr_type == 'HOSTNAME':
        try:
            address = socket.gethostbyname(addr)
            result = "PASS"
        except:
            result = "FAIL"
    return address, result

def getDcList(domain):

    """
    Get a list of Domain Controllers (DCs) for a specific domain.

    Args:
        domain (str): The name of the domain.

    Returns:
        list: A list of dictionaries containing information about each DC.

    Raises:
        None.
    """    
    domain = "\"" + domain + "\""
    results = []

    cmd = "\"/opt/likewise/bin/lw-get-dc-list " + domain + "\""
    query, errors, timeout = Command(cmd, shell=True).run()

    for line in query.splitlines():
        if line.startswith('DC '):
            line = line.split(': ', 1)[1].strip()
            line = line.split(',')
            entry = dict(x.split('=',1) for x in line)
            result = {k.strip():v.replace('\'','').strip() for k, v in entry.items()}
            results.append(result)
    return results

def dnsCheck(hostname):
    """
    Perform forward and reverse DNS lookups for a given hostname.

    Args:
        hostname (str): The hostname to perform DNS lookups on.

    Returns:
        dict: A dictionary containing the following keys:
            - title (str): The title of the DNS lookup.
            - result (str): The result of the DNS lookup, either "PASS" or "FAIL".
            - details (str): Additional details about the DNS lookup, if any.
            - documentation (str): A link to relevant documentation, if applicable.

    Raises:
        None.
    """    
    documentation = ""
    details = ""
    failflag = False
    result = "PASS"
    title = f"Forward and reverse DNS lookup for {hostname}"
    alarm = []

    ip, hnresult = dns_lookup(hostname)


    if 'FAIL' in hnresult:
        failflag = True
        msg = "%s: Forward DNS lookup failed!" % hostname
        alarm.append("Forward Lookup: %s failed to resolve." % hostname)
    else:
        rhostname, ipresult = dns_lookup(ip)
        if 'FAIL' in ipresult:
            failflag = True
            if rhostname == "":
                alarm.append("Reverse Lookup: %s failed to resolve." % ip)

        if rhostname.lower() != hostname.lower() and rhostname != "":
            failflag = True
            alarm.append(f"DNS lookup mismatch:  {hostname} resolved to IP: {ip}, {ip} resolved to {rhostname}")
    if failflag:
        result = "FAIL"
        details = "\n\t".join(alarm)
        documentation = "https://kb.vmware.com/s/article/52930"


    return {'title': title, 'result': result, 'details': details, 'documentation': documentation}

def portCheck(dc, ports):
    """
    Performs a port check on a list of ports for a given data center.

    Args:
        dc (str): The name or identifier of the data center.
        ports (list): A list of port numbers to be checked.

    Returns:
        dict: A dictionary containing the following keys:
            - 'title' (str): The title of the port check, including the checked ports.
            - 'result' (str): The result of the port check, either 'PASS' or 'FAIL'.
            - 'details' (str): Additional details or error message, if applicable.

    Raises:
        None.
    """    
    title = f"Port check ({', '.join([str(x) for x in ports])})"
    details = ""
    success, output = CheckConnect(dc, ports).check()
    if success:
        result = "PASS"
    else:
        result = "FAIL"
        details = output
    return {'title': title, 'result': result, 'details': details}


def getRegValue(regtree, regkey):
    """
    Get the values of a specific registry key in a registry tree.

    Args:
        regtree (str): The name of the registry tree to search in.
        regkey (str): The name of the registry key to retrieve values for.

    Returns:
        list: A list of values associated with the input registry key.
    """    
    result = []
    cmd = ["/opt/likewise/bin/lwregshell", "list_values", regtree]
    query, errors, timeout = Command(cmd).run()
    entries = '%s.+?(?=^...")' % regkey
    sortme = re.compile(entries, re.DOTALL | re.MULTILINE)
    out = sortme.findall(query)
    if len(out) > 0:
        temp_result = out[0].split()
        regkey_remove = [x.replace('"', '') for x in temp_result if 'REG' not in x]
        result = [entry for entry in regkey_remove if regkey not in entry]
        result = [entry for entry in result if entry != '']

    return result

def getExcludeTrust():
    """
    Get the list of excluded domains for trust.

    Returns:
        dict: A dictionary with the following keys:
              - title (str): The title of the result. If there are excluded domains, it is 'Domain Exclusions'. If there are no excluded domains, it is 'Domain Exclusions (None)'.
              - result (str): The result, which is always 'INFO'.
              - details (str): The details of the excluded domains, formatted as a string with each domain on a new line. If there are no excluded domains, it is an empty string.
    """    
    title = "Domain Exclusions"
    result = "INFO"
    details = ""
    domain_list = getRegValue("[HKEY_THIS_MACHINE\Services\lsass\Parameters\Providers\ActiveDirectory]","DomainManagerExcludeTrustsList")
    if len(domain_list) >= 1:
        for item in domain_list:
            details += f"\n{item}"
    else:
        title = f"{title} (None)"
    return {'title': title, 'result': result, 'details': details}
    # print(trustExcludeList)

def getExcludedDcs():
    """
    Get the list of excluded domain controllers.

    Returns:
        dict: A dictionary with the following keys:
            - 'title' (str): The title of the result.
            - 'result' (str): The result of the operation.
            - 'details' (str): The details of the excluded domain controllers, separated by new lines.
    """    
    title = "DC Exclusions"
    result = "INFO"
    details = ""
    dc_list = getRegValue("[HKEY_THIS_MACHINE\Services\\netlogon\Parameters]","BlacklistedDCs")
    if len(dc_list) >= 1:
        for item in dc_list:
            details += f"\n{item}"
    else:
        title = f"{title} (None)"
    return {'title': title, 'result': result, 'details': details}



def domainReport(override=False):
    """
    Generate a report on joined domains.

    Args:
        override (bool, optional): Determines if the test should be run for more than 5 domains. Defaults to False.

    Returns:
        list: A list of dictionaries containing the results of various checks for each domain.
            Each dictionary contains the following keys:
            - 'subheading' (str): The name of the domain being checked.
            - 'checks' (list): A list of dictionaries containing the results of checks for each domain controller (DC) in the domain.
                Each dictionary contains the following keys:
                - 'subheading' (str): The name and address of the DC being checked.
                - 'checks' (list): A list of dictionaries containing the results of specific checks for each DC.
                    Each dictionary contains the following keys:
                    - 'portCheck' (dict): The result of a port check for each port in the provided `ports` list.
                    - 'dnsCheck' (dict): The result of a DNS check for the DC.

    Raises:
        None
    """    
    title = "Joined Domain Report"
    ports = [88, 135, 389, 445, 464, 636, 3268, 3269]
    results = {}

    domainlist = getDomains()
    if len(domainlist) > 0:
        checks = []
        if len(domainlist) >= 5 and override == False:
            msg = """
There are more than 5 domains.  Results could take a long time to complete.
If you would still like to run this test and wait for the output, select 'Y' when prompted.'
            """
            print(msg)
        for domain in domainlist:
            results[domain] = getDcList(domain)

        for domain in results:
            dom_result = {'subheading': f'Domain: {domain}', 'checks': []}
            for dc in results[domain]:
                subheading = f"{dc['Name']}({dc['Address']})"
                dc_result = {'subheading': subheading, 'checks': []}
                dc_result['checks'].append(portCheck(dc['Name'], ports))
                dc_result['checks'].append(dnsCheck(dc['Name']))
                dom_result['checks'].append(dc_result)
            checks.append(dom_result)
        return checks

    else:
        return {'title': f"{title} (No domain(s) detected)", 'result': 'INFO'}

def run_domain_checks():
    """
    Run domain checks and return the domain report.

    Returns:
        domainReport (object): The report generated after running various checks on the domain.
    """    
    return domainReport()

def run_registry_checks():
    """
    Run registry checks and return a list of excluded trust and excluded DCs.

    Returns:
        list: A list of excluded trust and excluded DCs.
    """    
    return [getExcludeTrust(), getExcludedDcs()]


