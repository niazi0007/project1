import sys
import os
sys.path.append("../")
import json
import logging
import requests
import urllib3

import subprocess
import configparser

from sddc_manager.sddc_lib.authUtils import sso_username
from sddc_manager.sddc_lib.inventoryUtils import getMgmtVC, listVCenters, nsxManagerVIPList
from sddc_manager.sddc_lib.certUtils import getSDDCTrustedCerts

logger = logging.getLogger(__name__)
_DefaultCommmandEncoding = sys.getfilesystemencoding()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 20
RETRIES = 3
defaults_file = os.path.join(os.path.dirname(__file__), "current_defaults.py")
SDDC_CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'sddc_vdt.ini')
defaults_conf_file = os.path.join(os.path.dirname(__file__), 'defaults.ini')

def setConfig():
    """
    Set the configuration options for the application.

    This function reads the configuration file specified by SDDC_CONFIG_FILE, sets the 'root_path' value to the parent directory of the current file, and writes the updated configuration back to the file.
    """
    config = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
    config.read(SDDC_CONFIG_FILE)
    config.set('paths', 'root_path', os.path.dirname(os.path.dirname(__file__)))
    with open(SDDC_CONFIG_FILE, 'w') as configfile:
        config.write(configfile)

def run_command(cmd, stdin=None, quiet=False, close_fds=False, encoding=_DefaultCommmandEncoding, log_command=True):
    """
    Run a command and capture its output.

    Args:
        cmd (str): The command to be run.
        stdin (str, optional): The input to be passed to the command. Defaults to None.
        quiet (bool, optional): If True, suppresses the output of the command. Defaults to False.
        close_fds (bool, optional): If True, closes all file descriptors before executing the command. Defaults to False.
        encoding (str, optional): The encoding used for stdin and stdout. Defaults to _DefaultCommmandEncoding.
        log_command (bool, optional): If True, logs the command being executed. Defaults to True.

    Returns:
        bytes: The output of the command.
    """
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    if sys.version_info[0] >= 3 and isinstance(stdin, str):
        stdin = stdin.encode(encoding)
    stdout, stderr = process.communicate(stdin)
    return stdout

def getHostname():
    """
    Get the hostname of the current system.

    Returns:
        str: The hostname of the current system.

    Raises:
        None
    """
    logger.debug("Getting hostname")
    cmd = ['/usr/bin/hostname', '-f']
    return run_command(cmd).decode().strip()

def getIp():
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

def getVersion():
    """
    Get the version information from a Local API call.

    Returns:
        str: A containing the version information.
    """
    logger.debug("Getting SDDC Manager version")
    api_url = 'http://localhost/inventory/sddcmanagercontrollers'
    api_type = "GET"
    response = requests.request(api_type, api_url, verify=False)

    sddc = json.loads(response.text)[0]
    return sddc["version"]

def vxrailChecker():
    """
    Checks if we have any VxRail Managers in the System i.e if this is a VxRail Environment
    
    Returns:
        bool: True is this is a VxRail Environment, False otherwise.
    """
    api_url = f'http://localhost/inventory/vxmanagers'
    headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
    response = requests.request("GET", api_url, headers=headers, verify=False)

    if response.text == '[]' or response.text == []:
        return False
    else:
        return True

# def get_Proxy_config():
#     '''
#     Helper method to proxy configuration from SDDC Manager
#     '''
#     ## TODO

class VcfConfig(object):

    def __init__(self):
        """
        Initialize the object with necessary information.

        Attributes:
            sso_domain (str): The domain name associated with the single sign-on service.
            sddchostname (str): The hostname of the machine.
            sddcIp (str): The ip of the machine.
            mgmtVcHostname (str): The hostname of the Management WLD VC.
            mgmtVcIp (str): The ip of the Management WLD VC.
            mgmtVcVersion (str): The version of the Management WLD VC.
            timeout (int): The timeout value.
            retries (int): The number of retries.
            sddcVersion (str): The version of the machine.
            isVxRail (str): If this is a VCF on VxRail environment
            commonsvcsCerts (list): List of certificates in the commonsvcs keystore
            alternativeJreCerts (list): List of certificates in the alternative keystore
            vcList (list): List of vCenters in the VCF environment.
            nsxVipList (list): List of NSX Managers in the VCF environment.

        """
        self.ssoAdmin = sso_username()
        self.sddcHostname = getHostname()
        self.sddcIp = getIp()
        self.mgmtVcHostname, self.mgmtVcIp, self.mgmtVcVersion = getMgmtVC()
        self.timeout = TIMEOUT
        self.retries = RETRIES
        self.sddcVersion = getVersion()
        self.isVxRail = vxrailChecker()
        self.commonsvcsCerts, self.alternativeJreCerts = getSDDCTrustedCerts()
        self.vcList = listVCenters()
        self.nsxVipList = nsxManagerVIPList()
        
        # self.service_status = VcServices().status()
        
    def __repr__(self):
        """
        Return a string representation of the object's attributes.

        Returns:
            str: A string representation of the object's attributes.
        """

        return str(self.__dict__)

    def __str__(self):
        """
        Return a string representation of the object.

        Returns:
            str: The string representation of the object.
        """
        return self.__repr__()

def setDefaults():
    """
    Set the default configuration settings.

    This function sets the default configuration settings by reading values from a configuration file and updating the `defaults` section.

    Returns:
        dict: A dictionary containing the updated default configuration settings.

    Raises:
        Exception: If there is an error retrieving the configuration settings.
    """
    setConfig()
    try:
        afd = VcfConfig().__dict__
    except Exception as e:
        raise
    
    config = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
    config.read(defaults_conf_file)

    for x, y in afd.items():
        config.set('defaults', x, str(y))
    with open(defaults_conf_file, 'w') as configfile:
        config.write(configfile)

    return afd


if __name__ == '__main__':
    setDefaults()
