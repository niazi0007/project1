#!/usr/bin/env python

__title__ = "Syslog Check"
import os
import sys
import subprocess
import stat
import time
import re
import socket
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
libdir = os.path.join(parentdir, 'lib')
sys.path.append(os.path.abspath(libdir))
import logging

def run_command(command: str) -> str:
    """
    Run a command and return the output as a string.

    Args:
        command (str): The command to be executed.

    Returns:
        str: The output of the command as a string.

    Raises:
        None.

    Note:
        This function uses the `subprocess.run()` function to execute the command.
        The command is executed in a subshell with `shell=True` parameter.
        The result is captured from the stdout and decoded using 'utf-8' encoding.
        Any trailing whitespace is stripped from the output.
    """    
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
    return result.stdout.decode('utf-8').strip()

def getSyslog():
    """
    Get the remote syslog configuration and server information.

    Returns a tuple containing a dictionary with the following keys:
        - 'title' (str): The title indicating the remote syslog configuration.
        - 'result' (str): The result of the function execution.
        - 'details' (str): Additional details regarding the remote syslog configuration.

    The tuple also contains the server information (str) obtained from the configuration.

    The function retrieves the remote syslog configuration details from the file "/etc/vmware-syslog/syslog.conf". It searches for lines containing either '@' or 'omrelp', and extracts the server information using the regex pattern "(?:@+|\\bomrelp:)(?:\\(\\w+\\))?(\\S+):\\d+".

    Returns:
        tuple: A tuple containing a dictionary with the remote syslog configuration information and the server information.
    """    
    title = "Remote Syslog config: None Configured"
    result = "INFO"
    details = ""
    file = "/etc/vmware-syslog/syslog.conf"
    pattern = r"(?:@+|\bomrelp:)(?:\(\w+\))?(\S+):\d+"
    server = "None Configured"
    with open(file) as f:
        data = f.read()
    for line in data.splitlines():
        if '@' in line or 'omrelp' in line:
            #line = line.replace("(o)", '')
            server = re.search(pattern,line).group(1)
            title = f"Remote Syslog config: {server}"
            details = """
We've detected you have a remote syslog server configured.
Please search your remote syslog server for the following string 
to validate syslog is working correctly: VDT SYSLOG TEST MESSAGE
"""
    return {'title': title, 'result': result, 'details': details}, server

def writeSyslog():
    """
    Write a syslog message with a specific tag.

    Returns:
        str: The generated tag for the syslog message.
    """    
    message = "VDT SYSLOG TEST MESSAGE"
    tag = str(time.strftime("vdt" + "-%Y-%m-%d-%H%M%S"))
    cmd = ['/usr/bin/logger', message, '-t', tag]
    command_str = ' '.join(cmd)
    run_command(command_str)
    return tag

def checkSyslogTest(file, tag, lines=100):
    """
    Check if the syslog daemon is writing to the logs it manages.

    Args:
        file (str): The path to the syslog file to check.
        tag (str): The tag to look for in the syslog file.
        lines (int, optional): The number of lines to read from the end of the syslog file. Default is 100.

    Returns:
        dict: A dictionary containing the title, result, and details of the check.
            - title (str): The title of the check.
            - result (str): The result of the check, can be 'PASS' or 'FAIL'.
            - details (str): Additional details about the check result.

    Raises:
        UnicodeDecodeError: If the syslog file cannot be decoded with the default encoding.
    """    
    title = "Local Syslog Functional Check"
    result = "FAIL"
    details = """
The syslog daemon is not writing to the logs it manages:
/var/log/vmware/messages, /var/log/vmdird/vmdird-syslog.log, etc.
Please see https://kb.vmware.com/s/article/81829
    """
    try:
        with open(file) as syslogfile:
            for line in (syslogfile.readlines()[-lines:]):
                if tag in line:
                    result = "PASS"
                    details = ""
    except UnicodeDecodeError:
        with open(file, encoding="ISO-8859-1") as syslogfile:
            for line in (syslogfile.readlines()[-lines:]):
                if tag in line:
                    result = "PASS"
                    details = ""
    return {'title': title, 'result': result, 'details': details}


def validateIPorHost(address):
    """
    Validate if an address is either an IP or a hostname.

    Args:
        address (str): The address to be validated.

    Returns:
        str: 'IP' if the address is a valid IP address, 'HOSTNAME' if the address is a valid hostname.

    Raises:
        None

    Note:
        The function uses regular expressions to match the address pattern. The IP address pattern follows the standard dotted-decimal notation, while the hostname pattern follows the standard rules for valid hostnames.
    """    
    is_ip = re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", address)
    is_hostname = re.match("^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$", address)
    if is_ip:
        return 'IP'
    if is_hostname:
        return 'HOSTNAME'

def dns_lookup(addr):
    """
    Perform a DNS lookup on an IP address or hostname.

    Args:
        addr (str): The IP address or hostname to perform the DNS lookup on.

    Returns:
        tuple: A tuple containing the resolved address (if successful) and the outcome (either 'PASS' or 'FAIL').

    Raises:
        None.
    """    
    addr_type = validateIPorHost(addr)
    address = ""
    outcome = "FAIL"
    if addr_type == 'IP':
        address = "IP"
        outcome = "PASS"
    if addr_type == 'HOSTNAME':
        try:
            address = socket.gethostbyname(addr)
            outcome = "PASS"
        except:
            pass
    return address, outcome

def resolveSyslogServer(server):
    """
    Resolve the syslog server address and return the result.

    Args:
        server (str): The name or IP address of the syslog server.

    Returns:
        dict: A dictionary containing the title and result of the resolution.
            - title (str): The title describing the outcome of the resolution.
            - result (str): The result of the resolution, either "PASS" or "FAIL".
    """    
    title = ""
    address, outcome = dns_lookup(server)
    if address == "":
        title = "DNS lookup for %s could not be resolved." % server
        result = "FAIL"
    elif address == "IP":
        title = "DNS lookup unnecessary - rsyslog is configured with an IP"
        result = "PASS"
    else:
        title = "DNS lookup for %s resolved to %s" % (server, address)
        result = "PASS"
    return {'title': title, 'result': result}

def main():
    """
    Main function that performs various tasks using syslog data.

    Returns:
        list: A list containing the output of different tasks performed.
    """    
    syslogfile = '/var/log/vmware/messages'
    server = getSyslog()[1]
    tagsearch = writeSyslog()
    if "None Configured" not in server:
        writeSyslog()
    output = []
    output.append(getSyslog()[0])
    if "None Configured" not in server:
        output.append(resolveSyslogServer(server))
    output.append(checkSyslogTest(syslogfile, tagsearch))
    return output

if __name__ == '__main__':
    main()
