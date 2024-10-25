#!/usr/bin/env python
__title__ = "VMdir Check"

import os
import logging
import re
import shlex
from vcenter.vc_lib.common import Command, RunCommand, CheckConnect

logger = logging.getLogger(__name__)


def getRegValue(regtree, regkey):
    '''
    Get the value of a specific registry key.

    Args:
        regtree (str): The registry tree to search in.
        regkey (str): The key to search for.

    Returns:
        str: The value associated with the input registry key.

    Raises:
        None.
    '''

    result = ""
    cmd = "/opt/likewise/bin/lwregshell list_values '%s'" % regtree
    query, errors, timeout = Command(cmd).run()
    for line in query.splitlines():
        line = line.replace('+', ' ')
        if regkey in line:
            return line


def getVmdirDatabaseSize():
    """
    Get the size of the VMware vmdir database file.

    Returns:
        str: The size of the database file in megabytes (MB).
    """
    logger.debug("Getting size of data.mdb")
    datamdb = "/storage/db/vmware-vmdir/data.mdb"
    filesize = os.path.getsize(datamdb)
    filesize = filesize / (1024 * 1024)
    filesize = str(round(filesize, 2)) + "MB"
    return filesize


def get_partners(username, password):
    """
    Get the partner details for a given username and password.

    Args:
        username (str): The username for authentication.
        password (str): The password for authentication.

    Returns:
        list: A list of dictionaries, each containing the details of a partner. Each dictionary has the following keys:
            - Name: The name of the partner.
            - UTD Vector: The UTD vector of the partner.
            - Connection State: The connection state of the partner.
            - Up-to-date: Whether the partner is up-to-date or not.
            - Last Change USN: The last change USN of the partner.
            - Last Sync time: The last synchronization time of the partner.
            - Last Schema Change time: The last schema change time of the partner.
            - Total Changes: The total number of changes.
            - Changes Behind: The number of changes behind the partner.

    Raises:
        None
    """
    partnerdetails = []
    logger.debug("Getting partner status with vdcrepadmin")
    cmd = ["/usr/lib/vmware-vmdir/bin/vdcrepadmin", "-f", "showpartnerstatus", "-h", "localhost", "-u", username.split('@')[0], "-w", rf"{password}"]
    partnerstatus, errors= RunCommand(cmd).run()
    logger.debug(f"partnerstatus: {partnerstatus}, errors: {errors}, {username}")
    if partnerstatus.strip() != "":
        partnerdata = [x for x in partnerstatus.split('\n\n')]

        for partner_item in partnerdata:
            new_partner = {}
            for line in partner_item.splitlines():
                line_map = line.split(':')
                if len(line_map) > 1:
                    new_partner[line_map[0].strip()] = line_map[1].strip()
                else:
                    new_partner['Changes Behind'] = line_map[0]
            partnerdetails.append(new_partner)
    return partnerdetails


def get_host_available(partner_detail: dict):
    """
    Get the host availability status of a partner.

    Args:
        partner_detail (dict): A dictionary containing partner details, including whether the host is available 
            and the status availability.

    Returns:
        dict: A dictionary containing the host availability status, result, and additional details.

    Notes:
        - The function will check the values of 'Host available' and 'Status available' in the partner_detail dict
          to determine the host availability status.
        - The result can be either 'PASS' or 'FAIL'.
        - If the host is not available on the network, the result will be 'FAIL' and the details will indicate that 
          the partner is not reachable.
        - If the vmdir service on the partner is unreachable, the result will be 'FAIL' and the details will indicate that
          the service is unreachable.
    """
    title = "Service Availability"
    result = "PASS"
    details = ""

    if partner_detail['Host available'] == "No" or partner_detail['Status available'] == "No":
        result = "FAIL"
        details = "This partner is not reachable on the network!"
    else:
        if partner_detail['Status available'] == "No":
            result = "FAIL"
            details = "The vmdir service on this partner is unreachable!"
    return {'title': title, 'result': result, 'details': details}


def get_host_changes(partner_detail: dict):
    """
    Get host changes from a partner detail dictionary.

    Args:
        partner_detail (dict): A dictionary containing partner details.

    Returns:
        dict: A dictionary with the title, result, and details of host changes.
              If no host changes are found, returns None.

    """
    title = "Host Changes"
    result = "INFO"
    details = ""
    for k, v in partner_detail.items():
        if 'change' in k.lower():
            details += f"{k}: {v}\n"
    if details != "":
        return {'title': title, 'result': result, 'details': details}
    else:
        return None


def get_port_check(partner_detail: dict):
    """
    Get the results of port checks for a partner.

    Args:
        partner_detail (dict): A dictionary containing partner information, including 'Partner' key.

    Returns:
        dict: A dictionary containing the subheading 'Port Check' and a list of checks.
              Each check is a dictionary with 'title' (port number as string) and 'result' (either 'PASS' or 'FAIL') keys.
    """
    checks = []
    partner_name = partner_detail['Partner']
    ports = [443, 389, 2012, 2020]
    for port in ports:
        rc, output = CheckConnect(partner_name, ports).check()
        if not rc:
            checks.append({'title': str(port), 'result': "FAIL"})
        else:
            checks.append({'title': str(port), 'result': "PASS"})
    return {'subheading': 'Port Check', 'checks': checks}


def run_partner_check(username, password):
    """
    Run a partner check using the provided username and password.

    Args:
        username (str): The username used to authenticate.
        password (str): The password used to authenticate.

    Returns:
        list: A list of dictionaries containing the results of the partner checks. Each dictionary has the following keys:
            - 'subheading' (str): The partner's name.
            - 'checks' (list): A list of the partner's available hosts, host changes, and port checks that pass.

        dict: A dictionary with the following keys if no partners are found:
            - 'title' (str): The title indicating that no partners were found.
            - 'result' (str): An informational message.

    """
    results = []
    partners = get_partners(username, password)
    if len(partners) > 0:
        for partner in partners:
            checks = [x for x in [get_host_available(partner), get_host_changes(partner), get_port_check(partner)] if x]
            results.append({'subheading': partner['Partner'], 'checks': checks})
        return results
    else:
        return {'title': "No partners", "result": "INFO"}


def run_dfl_check(username, password):
    """
    Run a VMdir DFL (Domain Functional Level) check.

    Args:
        username (str): The username to log in.
        password (str): The password for the username.

    Returns:
        dict: A dictionary with the following keys:
            - title (str): The title of the check.
            - result (str): The result of the check, either 'PASS' or 'FAIL'.
            - details (str): Additional details about the check.
            - documentation (str): A link to the documentation for the check.

    Raises:
        None.
    """
    title = "VMdir DFL Check"
    documentation = ""
    details = ""

    dfl, errors, timeout = Command(
        "/usr/lib/vmware-vmafd/bin/dir-cli domain-functional-level get --login %s" % username, response=password).run()

    try:
        dfl = dfl.splitlines()[1]
    except:
        pass

    if "Domain Functional Level: 4" in dfl:
        result = "PASS"
    else:
        result = "FAIL"
        details = "VMDIR Domain Functional Level is incorrect!"
        documentation = "https://kb.vmware.com/s/article/92962"

    return {'title': title, 'result': result, 'details': details, 'documentation': documentation}


def run_vmdir_state_check(username, password):
    """
    Run a state check on the VMdir service.

    Args:
        username (str): The username for authentication.
        password (str): The password for authentication.

    Returns:
        dict: A dictionary containing the title, result, and details of the state check.

    Raises:
        None
    """
    title = "VMdir Local State Check"
    result = "PASS"
    details = ""
    username = username.split('@')[0]

    state, errors, timeout = Command(
        "/usr/lib/vmware-vmafd/bin/dir-cli state get --server-name localhost --login %s" % username,
        response=password).run()
    logger.debug("State = %s" % state)
    state = state.rsplit(":", 1)[1]
    title = f"{title} ({state.strip().split()[0]})"
    if 'Normal' not in state:
        result = "FAIL"
        details = """
    Please use /usr/lib/vmware-vmdir/bin/vdcadmintool option 6 to 
    confirm the state.  Check /var/log/vmware/vmdird/vmdird-syslog.log 
    to investigate.
    """

    return {'title': title, 'result': result, 'details': details}


def run_argument_check():
    """
    Check if the VMdir arguments are set correctly.

    Returns:
        dict: A dictionary with the following keys:
            - 'title': (str) The title of the check.
            - 'result': (str) The result of the check ('PASS' if arguments are set correctly, 'FAIL' otherwise).
            - 'details': (str) Additional details about the check.
            - 'documentation': (str) Instructions for fixing the issue if the result is 'FAIL'.
    """
    title = "VMdir Arguments Check"
    result = "PASS"
    details = ""
    documentation = ""

    arg_reg = getRegValue("[HKEY_THIS_MACHINE\Services\\vmdir]", "Arguments")
    if '-m standalone' in arg_reg:
        result = "FAIL"
        details = "Vmdir is flagged to start in standalone mode."
        documentation = """Please run the following command, then restart all services:

/opt/likewise/bin/lwregshell set_value '[HKEY_THIS_MACHINE\Services\\vmdir]' "Arguments" "/usr/lib/vmware-vmdir/sbin/vmdird -s -l 0 -f /usr/lib/vmware-vmdir/share/config/vmdirschema.ldif\""""

    return {'title': title, 'result': result, 'details': details, 'documentation': documentation}


def run_nativeha_check():
    """
    Run a native HA check for stale PSC HA configuration.

    Returns a dictionary with the following keys:
        - title (str): The title of the check.
        - result (str): The result of the check, either 'PASS' or 'FAIL'.
        - details (str): Additional details about the check.
        - documentation (str): A link to further documentation if the check fails.

    Returns:
        dict: A dictionary containing information about the check.

    Raises:
        None
    """
    title = "Stale PSC HA Check"
    result = "PASS"
    details = ""
    documentation = ""

    arg_reg = getRegValue("[HKEY_THIS_MACHINE\Services\\vmafd\Parameters]", "DCNameHA")
    cmd = ['/usr/lib/vmware-vmafd/bin/cdc-cli', 'client-affinity', 'state']
    query, errors, timeout = Command(cmd).run()
    query_result = query.split(':')[1].replace(" ", "").strip()

    if query_result != "LegacyMode" or arg_reg != None:
        result = "FAIL"
        details = "Stale PSC HA configuration detected!"
        documentation = "https://kb.vmware.com/s/article/57229"

    return {'title': title, 'result': result, 'details': details, 'documentation': documentation}


def run_vmdir_info():
    """
    Run the VMdir info command and return the result.

    Returns:
        dict: A dictionary containing the title and result of the command.

    Example output:
        {'title': 'VMdir database size: <database_size>', 'result': 'INFO'}
    """
    title = f"VMdir database size: {getVmdirDatabaseSize()}"
    result = "INFO"
    return {'title': title, 'result': result}
