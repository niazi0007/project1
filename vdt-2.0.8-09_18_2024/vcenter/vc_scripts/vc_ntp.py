#!/usr/bin/env python3
import subprocess
import logging

logger = logging.getLogger(__name__)
title = "vCenter NTP Check"


def run_command(command: str) -> str:
    """
    Run a command and return the output.

    Args:
        command (str): The command to be executed.

    Returns:
        str: The output of the command as a string.

    Raises:
        None.

    Note:
        This function uses the subprocess module to execute the command and captures the stdout output. The stdout output is decoded to a string using 'utf-8' encoding.
    """    
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
    return result.stdout.decode('utf-8').strip()


ntplist = run_command("cat /etc/ntp.conf | grep server | awk '{print $2}'").splitlines()
ntprunning = run_command("systemctl status ntpd | grep 'Active: ' | awk '{print $2}'")
vmtoolstime = run_command("/usr/bin/vmware-toolbox-cmd timesync status")
teststatus = 0
testkb = "https://kb.vmware.com/s/article/57146"
timeout = 9


def ntp_service_check():
    """
    Check the NTP service status and time source.

    Returns a tuple with two elements:
        - A dictionary containing the following keys:
            - 'title': The title of the NTP service check.
            - 'result': The result of the service check ('PASS', 'WARN', or 'FAIL').
            - 'details': Additional details about the service check.
        - A string representing the time source used.

    Raises:
        None
    """    
    title = "NTP Service Check"
    result = ""
    details = ""
    if vmtoolstime == "Enabled":
        result = "WARN"
        details = "Time sync provided by ESXi host"
        timesource = "vmtools"
    else:
        if ntprunning != "active":
            result = "FAIL"
            details = "NTP and Host time are both disabled!"
            timesource = "disabled"
        else:
            result = "PASS"
            details = "NTP service is running"
            timesource = "ntp"

    return {'title': title, 'result': result, 'details': details}, timesource

def ntp_server_check(timesource):
    """
    Check the status of an NTP server.

    Args:
        timesource (str): The type of timesource being checked.

    Returns:
        dict: A dictionary containing the title, result, details, and documentation of the NTP server check.

    Raises:
        None
    """    
    title = "NTP Server Check"
    result = "PASS"
    details = ""
    documentation = ""
    if timesource != "ntp":
        result = "FAIL"
        details = """
NTP is not configured.  Use the VAMI to configure NTP. NTP might need to be re-enabled on fresh installs.
Once configured, synchronization may take several minutes.

"""
        documentation = "https://kb.vmware.com/s/article/57146"

    else:
        for ntp in ntplist:
            ntpquery = run_command(f"timeout {timeout} ntpdate -q {ntp}")
            if "no server suitable for synchronization found" in ntpquery:
                result = "FAIL"
                details += f"\n\t{ntp} - no server suitable for synchronization found"
            else:
                details += f"\n\t{ntp} - OK"
    return {'title': title, 'result': result, 'details': details, 'documentation': documentation}

def ntp_status_check():
    """
    Check the NTP status and display the details.

    Returns a dictionary with the following keys:
    - title (str): The title of the check.
    - result (str): The result of the check (INFO in this case).
    - details (str): A formatted string containing the NTP status details.

    The details string includes a legend explaining the different columns and prefixes used in the output of the 'ntpq -pn' command.

    """    
    title = "NTP Status Check"
    result = "INFO"
    details = f'''
+-----------------------------------LEGEND-----------------------------------+
| remote: NTP peer server                                                    |
| refid: server that this peer gets its time from                            |
| when: number of seconds passed since last response                         |
| poll: poll interval in seconds                                             |
| delay: round-trip delay to the peer in milliseconds                        |
| offset: time difference between the server and client in milliseconds      |
+-----------------------------------PREFIX-----------------------------------+
| * Synchronized to this peer                                                |
| # Almost synchronized to this peer                                         |
| + Peer selected for possible synchronization                               |
| – Peer is a candidate for selection                                        |
| ~ Peer is statically configured                                            |
+----------------------------------------------------------------------------+
    {run_command("ntpq -pn")}    
        '''
    return {'title': title, 'result': result, 'details': details}

def main():
    """
    Run the main function.

    Returns:
        list: A list of output results.

    The main function performs the following steps:
    1. Calls the `ntp_service_check()` function to check the NTP service.
    2. Appends the result of the service check to the `output` list.
    3. If the `timesource` is set to 'ntp', it calls the `ntp_server_check()` function and appends the result to the `output` list.
    4. Calls the `ntp_status_check()` function and appends the result to the `output` list.
    5. Returns the `output` list containing all the results.
    """    
    output = []

    servicecheck, timesource = ntp_service_check()
    output.append(servicecheck)
    if timesource == 'ntp':
        output.append(ntp_server_check(timesource))
        output.append(ntp_status_check())
    return output