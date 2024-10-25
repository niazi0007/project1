# -*- coding: utf-8 -*-
#!/usr/bin/env python
__title__ = "vCenter Basic Info"
import os
import sys
import subprocess
import xml.etree.ElementTree as xml
from datetime import datetime, timedelta
from multiprocessing import cpu_count
from vcenter.vc_cfg.current_defaults import *
from vcenter.vc_lib.common import psqlQuery
import traceback
# from lib.pformatting import color_wrap, formResult
# from lib.vdt_formatter import CheckFormatter, Display
import logging
try:
    from urllib.parse import urlparse as urlparse
except ImportError:
    from urlparse import urlparse as urlparse
logger = logging.getLogger(__name__)
_DefaultCommmandEncoding = sys.getfilesystemencoding()


def run_command(cmd, stdin=None, quiet=False, close_fds=False,
                encoding=_DefaultCommmandEncoding, log_command=True):

    """
    Run a command and return the output.

    Args:
        cmd (list or str): The command to run. If it is a string, the command will be executed through the shell.
        stdin (str, optional): Input to be passed to the command. The input will be sent via stdin.
        quiet (bool, optional): If True, suppresses any output to stdout and stderr. Defaults to False.
        close_fds (bool, optional): If True, close all file descriptors, except stdin, stdout, and stderr before executing the command. Defaults to False.
        encoding (str, optional): The encoding to be used for stdin, stdout, and stderr. Defaults to _DefaultCommmandEncoding.
        log_command (bool, optional): If True, logs the executed command. Defaults to True.

    Returns:
        bytes: The output of the command.

    Note:
        This function uses subprocess.Popen to run the command.
    """    
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    if sys.version_info[0] >= 3 and isinstance(stdin, str):
        stdin = stdin.encode(encoding)
    stdout, stderr = process.communicate(stdin)
    return stdout


def getDisabledPlugins():
    """
    Get a list of disabled plugins.

    Returns:
        str: A string representation of the disabled plugins. If there are no disabled plugins, returns 'None'.

    Raises:
        FileNotFoundError: If the compatibility matrix XML file cannot be found.
        ParseError: If there is an error parsing the compatibility matrix XML file.
    """    
    results = []
    matrix = xml.parse("/etc/vmware/vsphere-ui/compatibility-matrix.xml")
    plugins = matrix.findall('.//PluginPackage')
    for plugin in plugins:
        results.append(plugin.get('id'))
    if len(results) > 0:
        output = "\n\t" + '\n\t'.join(results)
    else:
        output = "None"
    return output


def SDDCManaged():
    """
    Returns values as indications that the vCenter is managed by SDDC manager as part of VCF deployment.

    Returns:
        str: The machine ID extracted from the vpxd.cfg file. If an error occurs during parsing, it returns 'FAILED TO PARSE VPXD.CFG'.
    """
    try:
        vpxd = xml.parse("/etc/vmware-vpx/vpxd.cfg")
        sddc_tag = vpxd.find('SDDC')
        if sddc_tag:
            if sddc_tag[0].tag == 'Deployed':
                return f"""
SDDC Type: {sddc_tag[0].find('Type').text}
Workload Domain: {sddc_tag[0].find('WorkloadDomain').text}"""

    except Exception as e:

        return f"WARNING!  FAILED TO PARSE VPXD.CFG. Trace: {traceback.format_exc()}"

    return None

def psqlQuery(query):
    """
    Runs a SQL query against vPostgres database.

    Args:
        query (str): The SQL query to be executed.

    Returns:
        str: The output of the query.

    Raises:
        None.
    """    
    logger.debug("running SQL query: %s" % query)
    psqlpath = "/opt/vmware/vpostgres/current/bin/psql"
    cmd = [psqlpath, '-d','VCDB', 'postgres', '-c', query]
    try:
        output = run_command(cmd)
        output = output.decode()
        output = output.split('\n')[2]
        return output.strip()
    except:
        msg = "ERROR: Requires vPostgres service!"
        return msg


def getIp():
    """
    Get the IP address of a network interface.

    Returns:
        str: The IP address of the network interface.

    Raises:
        None
    """    
    logger.debug("Getting IP from ifconfig")
    ip = ""
    ifconfig = run_command(["ifconfig", "eth0"])
    ifconfig = ifconfig.decode()
    for line in ifconfig.split('\n'):
        mylist = list(line.split())
        for param in mylist:
            if "addr:" in param:
                ip = param.split(':')[1]
    return ip


def getNtpServers():
    """
    Get NTP servers from the ntp.conf file.

    Returns:
        str: A string containing a comma-separated list of NTP servers.

    Raises:
        FileNotFoundError: If the ntp.conf file is not found or cannot be opened.
    """    
    logger.debug("Getting NTP servers from ntp.conf")
    ntpservers = []
    with open('/etc/ntp.conf') as ntpconf:
        data = ntpconf.read()
    for line in data.split('\n'):
        if 'server' in line:
            ntpservers.append(line.split()[1])
    result = ', '.join(ntpservers)
    return result


def getAdDomain():
    """
    Get the Active Directory (AD) domain by running a domainjoin-cli query.

    Returns:
        str: The AD domain name.

    Raises:
        None.
    """    
    logger.debug("Getting AD domain from domainjoin-cli query")
    cmd = ['/opt/likewise/bin/domainjoin-cli', 'query']
    query = run_command(cmd).decode()
    query_result = query.split('\n')[1].split(' = ')
    if len(query_result) > 1:
        result = (query_result[1])
    else:
        result = "No DOMAIN"
    return result


def getMem():
    """
    Get the available system memory in gigabytes.

    Returns:
        float: The available system memory in gigabytes.
    """    
    logger.debug("Getting memory")
    mem_bytes = os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES')  # e.g. 4015976448
    mem_gb = round(mem_bytes/(1024.**3), 2)
    return mem_gb


def getUptime():
    """
    Get the system uptime and load average.

    Returns:
        tuple: A tuple containing the system uptime and load average. The system uptime is a string indicating the time duration the system has been running, and the load average is a string indicating the average load on the system.
    """    
    logger.debug("Getting uptime")
    cmd = ['/usr/bin/uptime']
    output = run_command(cmd).decode().split('\n')
    output = [x for x in output if x]
    output = output[0].split(',  ')
    uptime = output[0].split(', ')[0]
    uptime = uptime.split()
    del uptime[0]
    uptime = ' '.join(uptime)
    for item in output:
        if 'load average' in item:
            loadavg = item.replace('load average: ','')
        else:
            continue
    return uptime,loadavg


def getVchaConfig():
    # place holder
    """
    Retrieve the VCHA (vCenter High Availability) configuration.

    Returns:
        dict: The VCHA configuration parameters.

    Raises:
        None.
    """    
    pass


def getProxy():
    """
    Get the proxy configuration.

    Returns:
        tuple: A tuple containing the proxy settings. The first element of the tuple is the proxy enabled status, and the second element is the list of excluded URLs.

    Raises:
        None
    """    
    logger.debug("Getting proxy config")
    result = ""
    with open('/etc/sysconfig/proxy') as f:
        contents = f.read()
    for line in contents.splitlines():
        if 'PROXY_ENABLED' in line:
            result = line.split('=')[1]
        if 'NO_PROXY' in line:
            exclude_list = line.split('=')[1]
    return result, exclude_list


def VcInfo():

    """
    Get information about the VC (virtual control) system.

    Returns:
        dict: A dictionary containing the following information:
            - pnid (str): The PNID (Private Network ID) of the VC system.
            - ssodomain (str): The SSO domain of the VC system.
            - version (str): The version of the VC system.
            - currenttime (datetime): The current system time.
            - hostname (str): The hostname of the VC system.
            - ip (str): The IP address of the VC system.
            - addomain (str): The AD (Active Directory) domain of the VC system.
            - numcpus (int): The number of CPUs in the VC system.
            - nummem (str): The amount of memory in the VC system.
            - disabledplugins (list): A list of disabled plugins in the VC system.
            - ntpservers (list): A list of NTP (Network Time Protocol) servers used by the VC system.
            - uptime (str): The uptime of the VC system.
            - loadavg (str): The system load average of the VC system.
    """    
    info = {}


    info["pnid"] = pnid
    info["ssodomain"] = sso_domain
    info["version"] = version + " - " + build
    uptime, loadavg = getUptime()
    info['currenttime'] = datetime.now()
    info["hostname"] = hostname
    info["ip"] = getIp()
    info["addomain"] = getAdDomain()
    info["numcpus"] = cpu_count()
    info["nummem"] = getMem()
    info["disabledplugins"] = getDisabledPlugins()
    info["ntpservers"] = getNtpServers()
    info["uptime"] = uptime
    info["loadavg"] = loadavg

    return info


def get_inventory_summary():
    """
    Return the summary of the inventory.

    Returns:
        dict: A dictionary that contains the following keys:
            - 'title' (str): The title of the inventory summary.
            - 'result' (str): The result of the inventory summary.
            - 'details' (str): The details of the inventory summary, including the number of ESXi hosts, the number of virtual machines, and the number of clusters.
    """    
    title = "Inventory Summary"
    result = "INFO"
    info = {}
    info["numhosts"] = psqlQuery("SELECT COUNT(*) FROM vpx_host;")
    info["numvms"] = psqlQuery("SELECT COUNT(*) FROM vpx_vm;")
    info["numclusters"] = psqlQuery("SELECT COUNT(*) FROM vpx_compute_resource WHERE resource_type=2;")
    details = """
Number of ESXi Hosts: {numhosts}
Number of Virtual Machines: {numvms}
Number of Clusters: {numclusters}
    """.format(**info)
    return {'title': title, 'result': result, 'details': details}


def main():
    """
    The main function that retrieves vCenter information and returns formatted details.

    Returns:
        dict: A dictionary containing following keys:
            - title (str): The title of the vCenter information.
            - result (str): The result of the function, which is 'INFO'.
            - details (str): The formatted details of the vCenter information.

    Raises:
        None
    """    
    info = VcInfo()
    pnidkb = ""

    details = """
Current Time: {currenttime}
vCenter Uptime: {uptime}
vCenter Load Average: {loadavg}
Number of CPUs: {numcpus}
Total Memory: {nummem}
vCenter Hostname: {hostname}
vCenter PNID: {pnid}
vCenter IP Address: {ip}
NTP Servers: {ntpservers}
vCenter Version: {version}
vCenter SSO Domain: {ssodomain}
vCenter AD Domain: {addomain}
Disabled Plugins: {disabledplugins}""".format(**info)

    sddc_data = SDDCManaged()
    if sddc_data:
        details = details + sddc_data

    title = __title__
    result = "INFO"

    return {"title": title, "result": result, "details": details}

def is_noproxy_domain_present(custom_exclude_list):
    """
    Check if a no-proxy domain is present in the custom exclude list.

    Args:
        custom_exclude_list (list): A list of string values representing the custom exclude list.

    Returns:
        bool: True if a no-proxy domain is present in the custom exclude list, False otherwise.
    """    
    for item in custom_exclude_list:
        if item.lower() in pnid.lower():
            return True
    return False

def proxy_check():
    """
    Check if a proxy is enabled for vCenter and validate the NO_PROXY list.

    Returns a dictionary with the following keys:
        - title (str): The title of the check.
        - result (str): The result of the check (PASS or FAIL).
        - details (str): Additional details about the check.
        - documentation (str): Documentation related to the check.
    """    
    proxy_article = "https://kb.vmware.com/s/article/87793"
    title = "vCenter Proxy Check"
    details = ""
    documentation = ""
    result = "PASS"
    custom_exclude = []
    proxy_enabled, exclude_str = getProxy()
    exclude_list = [x.strip() for x in exclude_str.replace('\"', '').strip().split(",")]
    for item in exclude_list:
        if '.*.' in item:
            custom_exclude.append(item.split('.*.')[1].lower())

    if 'yes' in proxy_enabled:
        title = f"{title} (Enabled)"
        if pnid.lower() not in exclude_list and not is_noproxy_domain_present(custom_exclude):
            result = "FAIL"
            details = f"""There is a proxy enabled for this vCenter, but the PNID or domain has not been included in the NO_PROXY list.
In order to avoid issues with upgrades, skyline health, etc., please see the provided article.
NO_PROXY list: {exclude_list}
"""
            documentation = proxy_article
        else:
            details = f"NO_PROXY list: {exclude_list}"
    else:
        title = f"{title} (Not Enabled)"

    return {"title": title, "result": result, "details": details, "documentation": documentation}




if __name__ == '__main__':
    main()
