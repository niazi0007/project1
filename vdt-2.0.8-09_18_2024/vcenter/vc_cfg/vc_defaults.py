import sys
import os

sys.path.append(os.environ['VMWARE_PYTHON_PATH'])
sys.path.append("../")
import json
import xml.etree.ElementTree as ET
import logging
import vmafd
import subprocess
import configparser
import contextlib
from cis.tools import get_install_parameter
from cis.utils import is_svc_vmon_integrated, CISVmonServiceControl
from cis.svcsController import get_services_status, SvcsInfoMgr
from cis.exceptions import ServiceNotFoundException

logger = logging.getLogger(__name__)
try:
    from vcenter.vc_lib.common import getSslCert
except ModuleNotFoundError:
    sys.path.append("../../../")
    # from cfg.vdt_defaults import VDT_CONFIG
    # from vcenter.vc_lib.common import getSslCert

_DefaultCommmandEncoding = sys.getfilesystemencoding()
TIMEOUT = 20
RETRIES = 3
defaults_file = os.path.join(os.path.dirname(__file__), "current_defaults.py")
VC_CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'vc_vdt.ini')
defaults_conf_file = os.path.join(os.path.dirname(__file__), 'defaults.ini')


def setConfig():
    """
    Set the configuration options for the application.

    This function reads the configuration file specified by VC_CONFIG_FILE, sets the 'root_path' value to the parent directory of the current file, and writes the updated configuration back to the file.
    """
    config = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
    config.read(VC_CONFIG_FILE)
    config.set('paths', 'root_path', os.path.dirname(os.path.dirname(__file__)))
    with open(VC_CONFIG_FILE, 'w') as configfile:
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


def is_svc_vmon_integrated(svc_name):
    """
    Check if a service is integrated with SVC vmon.

    Args:
        svc_name (str): The name of the service to check.

    Returns:
        bool: True if the service is integrated with SVC vmon, False otherwise.

    Raises:
        ServiceNotFoundException: If the service is not found.
    """
    svcInfoMgr = SvcsInfoMgr()
    try:
        svc_node_name = svcInfoMgr.get_svc_nodename(svc_name)
        if svcInfoMgr.is_vmon_svc(svc_node_name):
            return True
        else:
            return False
    except ServiceNotFoundException:
        # log_warning("Unable to find service %s" % svc_name)
        return False


def getSrvStartType(service, quiet=False):
    """
    On cloudvm: service start mode is determined using 'chkconfig srv_name' on
    SLES11 and via 'systemctl is-enabled srv_name' on systemd services.
    On ciswin: service configuration is checked from SCM. The call QuerySeriveConfig
    return a tuple. The second element of that tuple contains the startMode type.
    """
    startType = 'UNKNOWN'
    _systemctl_path = '/usr/bin/systemctl'

    # if vmon is enabled the start type from vmon manager
    if is_svc_vmon_integrated(service):
        cis_vmon = CISVmonServiceControl(service)
        rc, startType, stdout, stderr = cis_vmon.get_service_start_type()
        return startType.capitalize()
    else:

        # On systemd systems following us the start type contract
        # AUTOMATIC = enabled
        # MANUAL = disabled
        # DISABLED = masked
        cmd = [_systemctl_path, 'is-enabled', service]
        rc, stdout, stderr = run_command(cmd)
        if rc == 0:
            startType = 'Automatic'
        else:
            # rc is 1 for non enabled services.
            stdout = stdout.strip()
            if stdout == 'masked':
                startType = 'Disabled'
            elif stdout == 'disabled':
                startType = 'Manual'

    if startType == 'UNKNOWN':
        if rc != 0:
            logger.error("ERROR executing %s, %s, %s" % (cmd, stdout, stderr),
                         quiet)
            raise Exception("Unable to get %s startType. Error %s" %
                            (service, stderr))
        raise Exception("Unknown start type %s for service %s" % (stdout, service))

    return startType


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


def getDeployType():
    """
    Get the deployment type.

    Returns:
        str: The deployment type.

    Raises:
        FileNotFoundError: If the deployment.node.type file does not exist.
    """
    try:
        deploytype = get_install_parameter('deployment.node.type', quiet=True)
    except:
        file = os.path.join(os.environ['VMWARE_CFG_DIR'], 'deployment.node.type')
        with open(file) as fp:
            deploytype = fp.read().strip()

    return deploytype


def getVersion():
    """
    Get the version information from a configuration file.

    Returns:
        tuple: A tuple containing the version and build information.
    
    Raises:
        FileNotFoundError: If the configuration file is not found.
        KeyError: If the 'build' or 'version' key is not found in the configuration file.
    """
    logger.debug("getting version")
    with open("/etc/applmgmt/appliance/update.conf") as f:
        data = json.load(f)
    build = data['build']
    version = data['version']
    logger.debug(version + build)
    return version, build


def get_rhttpProxy_config():
    '''
    Helper method to read config.xml to get rhttpProxy ports and its endpoints directory
    '''
    rhttpProxyConfigDir = "/etc/vmware-rhttpproxy"

    if not os.path.isdir(rhttpProxyConfigDir):
        sys.exit('\nERROR: "%s" is not a valid directory' % rhttpProxyConfigDir)
        sys.exit(-1)

    tree = ET.parse(os.path.join(rhttpProxyConfigDir, 'config.xml'))
    proxy = tree.getroot().find('proxy')
    httpPort = httpsPort = None
    if proxy is not None:
        httpsPort = proxy.find('httpsPort').text
        httpPort = proxy.find('httpPort').text

    httpsPort = int(httpsPort) if httpsPort and httpsPort.strip() else 443
    httpPort = int(httpPort) if httpPort and httpPort.strip() else 80

    return httpPort, httpsPort


class VcServices(object):
    """
    A class representing a VC (Virtual Center) service.

    Attributes:
        services (dict): A dictionary containing the status of all services.
        service_status (dict): A dictionary containing the categorized status of the services.

    Methods:
        getStartup(service): Returns the startup type of the given service.
        status(): Returns the categorized status of all services.
    """

    def __init__(self):
        """
        Initialize the object.

        Sets the services status by calling the 'get_services_status' function with a 'None' parameter and ignoring any errors. Initializes the 'service_status' dictionary.

        Args:
            None

        Returns:
            None
        """
        self.services = get_services_status(None, ignore_err=True)
        self.service_status = {}

    # sys.exit()

    @staticmethod
    def getStartup(service):
        """
        Get the startup status of a service.

        Args:
            service (str): The name of the service.

        Returns:
            str: The startup status of the service. Possible values are 'Automatic', 'Manual', or 'Disabled'.

        Raises:
            None.
        """
        if 'vmware-' in service and 'postgres' not in service and 'sts' not in service:
            service = service.replace('vmware-', '')
            if 'watchdog' in service:
                service = service.replace('-watchdog', '')
        try:
            result = str(getSrvStartType(service, quiet=True))
        except:
            result = "Automatic"

        if not result:
            result = "Automatic"

        return result

    def status(self):
        """
        Get the status of different services.

        Returns:
            dict: A dictionary containing the status of different services. The keys in the dictionary are 'STOPPED', 'RUNNING', and 'DISABLED', and the corresponding values are lists of service names.
    
        Raises:
            Exception: If there is an error while retrieving the startup status of a service.
        """
        stopped_services = []
        running_services = []
        disabled_services = []
        for x, y in self.services.items():
            if len(y) == 2:
                status = y[0]
            else:
                status = y
            if status != 'RUNNING':
                # print("PRINTING" + x)
                try:
                    # print(x)
                    startup = self.getStartup(x)
                except Exception as e:
                    print("FAILED!")
                    raise e

                if startup == "Automatic" or startup == "Unknown":
                    stopped_services.append(x)
                else:
                    disabled_services.append(x)

            else:
                running_services.append(x)
        self.service_status['STOPPED'] = stopped_services
        self.service_status['RUNNING'] = running_services
        self.service_status['DISABLED'] = disabled_services

        return self.service_status


def test_vmafd():
    """
    Test the status of the VMAFD service.

    Returns:
        bool: True if the VMAFD service is running, False otherwise.

    Raises:
        Exception: If there is an error checking the status of the VMAFD service.
    """
    try:
        services = VcServices().status()
        if 'vmafdd' in services['RUNNING']:
            logger.debug("VMAFD is running")
            return True
        else:
            logger.debug("VMAFD is NOT running")
            return False
    except Exception as e:
        logger.error(f"Error checking status of VMAFD.  Error was: {e}")
        return False


class VcConfig(object):

    def __init__(self):

        """
        Initialize the object with necessary information.

        This function initializes the object with information obtained from the vmafd client and other sources.

        Attributes:
            ls_location (str): The location of the local site service.
            sso_domain (str): The domain name associated with the single sign-on service.
            pnid (str): The primary network identity of the machine.
            machine_id (str): The ID of the machine.
            sso_site (str): The site name associated with the single sign-on service.
            node_id (str): The local domain unit identifier.
            httpPort (int): The HTTP port number.
            httpsPort (int): The HTTPS port number.
            ssl_trust (str): The SSL trust information.
            deploy_type (str): The deployment type.
            timeout (int): The timeout value.
            retries (int): The number of retries.
            version (str): The version of the service.
            build (str): The build of the service.
            service_status (str): The status of the Vc services.
            hostname (str): The hostname of the machine.

        Raises:
            Exception: If the vmafd client fails to initialize.
        """
        if test_vmafd():
            client = vmafd.client()
            self.ls_location = client.GetLSLocation()
            self.sso_domain = client.GetDomainName()
            self.pnid = client.GetPNID()
            self.machine_id = client.GetMachineID()
            self.sso_site = client.GetSiteName()
            self.node_id = client.GetLDU()
        else:
            logger.error('Failed to create vmafd client!  Is vmafdd running?')
            self.ls_location = "vmafdd service required!"
            self.sso_domain = "vmafdd service required!"
            self.pnid = "vmafdd service required!"
            self.machine_id = "vmafdd service required!"
            self.sso_site = "vmafdd service required!"
            self.node_id = "vmafdd service required!"
            # raise e

        self.httpPort, self.httpsPort = get_rhttpProxy_config()

        try:
            self.ssl_trust = getSslCert('localhost', self.httpsPort)
        except:
            self.ssl_trust = f"Server not responding on port {self.httpsPort} "

        self.deploy_type = getDeployType()
        self.timeout = TIMEOUT
        self.retries = RETRIES
        self.version, self.build = getVersion()
        self.service_status = VcServices().status()
        self.hostname = getHostname()

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
        afd = VcConfig().__dict__
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
