#!/usr/bin/env python
"""
__author__ =  ["Laraib Kazi", "Tyler FitzGerald"]
__credits__ = ["Keenan Matheny", "Christopher Morrow", "Fouad Sethna", "Kevin Hagopian"]

"""
__title__ = "SDDC MANAGER BASIC INFO"
from sddc_manager.sddc_cfg.current_defaults import sddcHostname, sddcIp, sddcVersion, mgmtVcHostname, mgmtVcIp, mgmtVcVersion, isVxRail
from sddc_manager.sddc_lib.commandUtils import run_command

import logging
from datetime import datetime
 
logger = logging.getLogger(__name__)

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

def getDnsServers():
	"""
	Gets the DNS Servers configured in the SDDC Manager

	Args:
		None

	Returns:
		str: DNS Servers comma seperated
	"""
	logger.debug("Getting DNS servers from resolv.conf")
	dnsservers = []
	with open('/etc/resolv.conf') as resolvconf:
		data = resolvconf.read()
	for line in data.split('\n'):
		if 'nameserver' in line:
			dnsservers.append(line.split()[1])
	result = ', '.join(dnsservers)
	return result

def getFIPSStatus():
	"""
	Gets the FIPS Status in the SDDC Manager

	Args:
		None

	Returns:
		str: String reporting whether FIPS is enabled or not.
	"""
	logger.debug("Getting if system is FIPS enabled. 1 is yes, 0 is no")
	with open('/proc/sys/crypto/fips_enabled') as fips:
		data = fips.readline()
	if '0' in data:
		return 'FIPS is NOT enabled.'
	else:
		return 'FIPS is enabled.'

def generalInfo():
    """
    Get general information about the VCF Environment.

    Returns:
        dict: A dictionary containing the following information:
            - mgmtVCHostname (str): The hostname of the Management WLD vCenter Server.
            - mgmtVCIP (str): The IP address of the Management WLD vCenter Server.
            - mgmtVCversion (str): The version of the Management WLD vCenter Server.
            - isVxRail (str): If this is a VCF on VxRail environment or not.
    """
    info={}
    
    info["mgmtVCHostname"] = mgmtVcHostname
    info["mgmtVCIP"] = mgmtVcIp
    info["mgmtVCversion"] = mgmtVcVersion
    info["isVxRail"] = isVxRail
    ## TODO: Add a check for stretched vSAN Clusters
    ## TODO: Add a check for shared NSX Clusters
    return info

def sddcMInfo():
    """
    Get information about the SDDC Manager.

    Returns:
        dict: A dictionary containing the following information:
            - currenttime (datetime): The current system time.
            - hostname (str): The hostname of the SDDC Manager.
            - ip (str): The IP address of the SDDC Manager.
            - version (str): The version of the SDDC Manager.
            - uptime (str): The uptime of the SDDC Manager.
            - loadavg (str): The system load average of the SDDC Manager.
            - dnsservers (list): A list of DNS (Domain Name Resolution) servers used by the SDDC Manager.
            - ntpservers (list): A list of NTP (Network Time Protocol) servers used by the SDDC Manager.
            - fipsEnabled (str): The status of FIPs in the VCF Environment (enabled|disabled).

    """ 
    info = {}
    uptime,loadavg = getUptime()

    info["currenttime"] = datetime.now()
    info["hostname"] = sddcHostname
    info["ip"] = sddcIp 
    info["version"] = sddcVersion
    info["uptime"] = uptime    
    info["loadavg"] = loadavg    
    info["dnsservers"] = getDnsServers()    
    info["ntpservers"] = getNtpServers()
    info["fipsEnabled"] = getFIPSStatus()
    
    return info

def main():
    """
    The main function that retrieves SDDC Manager information and returns formatted details.

    Returns:
        dict: A dictionary containing following keys:
            - title (str): The title of the SDDC Manager information.
            - result (str): The result of the function, which is 'INFO'.
            - details (str): The formatted details of the SDDC Manager information.

    Raises:
        None
    """    
    result = "INFO"
    
    sddcInfo = sddcMInfo()
    sddcDetails = '''
Current Time: {currenttime}
Hostname: {hostname}
IP Address: {ip}
Version: {version}
Uptime: {uptime}
Load Average: {loadavg}
NTP Servers: {ntpservers}
DNS Servers: {dnsservers}
'''.format(**sddcInfo)
    sddcInfoTitle = 'SDDC MANAGER INFO'
    
    vcfInfo = generalInfo()
    vcfDetails = '''
Management VC Hostname: {mgmtVCHostname}
Management VC IP Address: {mgmtVCIP}
Management VC Version: {mgmtVCversion}
VCF on VxRail Deployment: {isVxRail}
'''.format(**vcfInfo)
    vcfInfoTitle = 'GENERAL INFO'
    
    return [{"title": sddcInfoTitle, "result": result, "details": sddcDetails},
            {"title": vcfInfoTitle, "result": result, "details": vcfDetails}
            ]
    
if __name__ == '__main__':
	main()
    
