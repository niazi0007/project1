#!/usr/bin/env python
__title__ = "VC CERTIFICATE CHECK"

import socket
import os
import sys
import json
import traceback
from collections import OrderedDict
from datetime import datetime, timedelta

try:
    # Python 3 hack.
    import urllib.request as urllib2
    import urllib.parse as urlparse
except ImportError:
    import urllib2
    import urlparse

sys.path.append(os.environ['VMWARE_PYTHON_PATH'])

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
libdir = os.path.join(parentdir, 'lib')
sys.path.append(os.path.abspath(libdir))


sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.vdt_formatter import ColorWrap
from vcenter.vc_lib.cert_utils import GetVecs, exManager, Cert, run_command
from vcenter.vc_cfg.current_defaults import sso_domain, hostname, pnid
import logging


logger = logging.getLogger(__name__)

vcsa_kblink = "https://kb.vmware.com/s/article/76719"
win_kblink = "https://kb.vmware.com/s/article/79263"

today = datetime.now()
today = today.strftime("%d-%m-%Y")
delay = 1
timeout = 2

########### CONFIGURABLE PARAMETERS ###########
NUM_DAYS_CRITICAL = 30
NUM_DAYS_WARNING = 60
NUM_DAYS_INFO = 90
CHECKS = {"CRITICAL": NUM_DAYS_CRITICAL,
          "WARNING": NUM_DAYS_WARNING,
          "INFO": NUM_DAYS_INFO}

##### END IMPORTS #####

_DefaultCommmandEncoding = sys.getfilesystemencoding()

### utilitiy functions ###
def getAddr():
    """
    Retrieve IP address and hostname.

    Returns:
        (str, str): A tuple containing the IP address and hostname.

    Raises:
        None.

    Logs:
        Debug log messages indicating the process of retrieving and resolving the IP address and hostname.
    """    
    logger.debug("getting IP and resolving to hostname")
    ip = ""
    ifconfig = run_command(["ifconfig", "eth0"])
    ifconfig = ifconfig.decode()
    for line in ifconfig.split('\n'):
        mylist = list(line.split())
        for param in mylist:
            if "addr:" in param:
                ip = param.split(':')[1]
    hostname = socket.gethostname()
    logger.debug("IP: %s, Hostname: %s" % (ip, hostname))
    return ip, hostname

class checkCert(object):

    """
    A class for checking certificates.

    Attributes:
        certdata (str): The certificate data.
        hostname (str): The hostname associated with the certificate.
        ip (str): The IP address associated with the certificate.
        alias (str): An alias for the certificate.
        note (str): Additional notes for the certificate.
    """    
    def __init__(self, certdata, hostname="", ip="", alias="", note=""):
        """
        Initialize a Cert object with the given certificate data.

        Args:
            certdata (str): The certificate data.
            hostname (str): The hostname associated with the certificate. Default is an empty string.
            ip (str): The IP address associated with the certificate. Default is an empty string.
            alias (str): An alias for the certificate. Default is an empty string.
            note (str): Additional notes for the certificate. Default is an empty string.

        Returns:
            None

        Raises:
            None
        """        
        self.load_cert = Cert(certdata)
        logger.debug(self.load_cert.combined)
        self.sigalg = self.load_cert.sigalg
        self.alias = alias
        self.note = note
        self.subject = self.load_cert.subject
        logger.debug("Checking certificate: %s for problems" % self.subject)
        if self.load_cert.authkey:
            if self.load_cert.authkey != "FAILED_TO_DECODE":
                self.authkey = self.load_cert.authkey.replace('keyid:', '')
                self.authkey = self.authkey.strip()
            else:
                self.authkey = "ERROR!"
        else:
            self.authkey = None
        if self.load_cert.subjectkey:
            if self.load_cert.subjectkey != "FAILED_TO_DECODE":
                self.subjectkey = self.load_cert.subjectkey.replace('keyid:', '')
                self.subjectkey = self.subjectkey.strip()
            else:
                self.subjectkey = "ERROR!"
        else:
            self.subjectkey = None
        self.san = self.load_cert.subjectAltName
        self.exp = self.load_cert.validuntil.split()[0]
        self.cert_name = self.load_cert.thumbprint
        self.subjectkey = self.load_cert.subjectkey
        self.exp_certs = {}
        self.hostname = hostname
        self.ip = ip
        self.certlist = trusted_list
        self.trustchain = {}
        sol_users = ['vpxd-extension', 'vpxd', 'machine', 'wcp', 'vsphere-webclient', 'hvc']

    def expCheck(self):
        """
        Check the expiration status of a certificate.

        Returns a dictionary containing information about the expiration status of the certificate.

        Returns:
            dict: A dictionary containing the following keys:
                - 'title' (str): The title of the certificate expiration check.
                - 'result' (str): The result of the expiration check ('FAIL', 'WARNING', or 'PASS').
                - 'details' (str): Additional details about the expiration status.
                - 'documentation' (str): Link to additional documentation.

        Raises:
            None

        Note:
            - The expiration check uses predefined thresholds for critical and warning levels.
            - The expiration date of the certificate is compared to the current date and time.
        """        
        title = "Certificate Expiration Check"
        result = ""
        details = ""
        documentation = ""

        CHECKS = {"CRITICAL": 30,
                  "WARNING": 60}

        today = datetime.now().strftime("%d-%m-%Y")
        conv_exp = datetime.strptime(self.exp, '%Y-%m-%d')
        exp = datetime.strftime(conv_exp, '%d-%m-%Y')
        exp_date = datetime.strptime(exp, '%d-%m-%Y')
        now = datetime.strptime(today, '%d-%m-%Y')

        if exp_date <= now + timedelta(days=CHECKS.get("CRITICAL")):
            result = "FAIL"
            diff = exp_date - now
            exp_in_days = diff.days
            if exp_in_days < 0:
                negative_days = str(exp_in_days).replace('-', '')
                details = f"{self.cert_name}: expired {negative_days} days ago!"
            else:
                details = f"{self.cert_name}: expires in {exp_in_days} days."
            documentation = "https://kb.vmware.com/s/article/68171 and https://kb.vmware.com/s/article/90561"

        elif exp_date <= now + timedelta(days=CHECKS.get("WARNING")):
            diff = exp_date - now
            exp_in_days = diff.days

            result = "WARNING"
            details = f"{self.cert_name}: expires in {exp_in_days} days!"
            documentation = "https://kb.vmware.com/s/article/68171 and https://kb.vmware.com/s/article/90561"

        else:
            result = "PASS"

        title = f"{title} - (Expires {str(datetime.strftime(exp_date, '%m-%d-%Y'))})"

        return {'title': title, 'result': result, 'details': details, 'documentation': documentation}

    def sanCheck(self):
        """
        Check the Subject Alternative Names (SAN) of a certificate.

        Returns a dictionary with the following keys:
            - "title" (str): The title of the check.
            - "result" (str): The result of the check.
            - "details" (str): Additional details about the check.
            - "documentation" (str): Documentation related to the check.

        Raises:
            None

        Returns:
            dict: A dictionary with the check results.
        """        
        title = "Certificate SAN Check"
        result = ""
        details = ""
        documentation = ""

        hostflag = True
        ipflag = True

        if self.san:
            if self.hostname.lower() not in self.san.lower():
                hostflag = False
                result = "FAIL"
                details = "Hostname is not in the SAN!"
                if self.ip not in self.san:
                    ipflag = False
                    details = "Neither hostname nor IP in the SAN!"
            if self.ip != "":
                if self.ip not in self.san:
                    ipflag = False
                    result = "PASS"

            if hostflag == True and ipflag == True:
                result = result = "PASS"
            if hostflag == True and ipflag == False:
                result = "INFO"
                details = "SAN contains hostname but not IP."
            if hostflag == False and ipflag == True:
                result = "WARNING"
                details = "SAN contains IP but not hostname.  This configuration is not recommended."

            if not hostflag and not ipflag:
                result = "FAIL"
                details = "SAN contains neither hostname nor IP!" % self.cert_name
        else:
            result = "WARNING"
            details = "No SAN detected"

        return {'title': title, 'result': result, 'details': details, 'documentation': documentation}

    def algCheck(self):
        """
        Check the certificate Subject Alternative Name (SAN) for compliance.

        Returns a dictionary with the following keys:

        - title (str): The title of the check.
        - result (str): The result of the check, either "PASS" or "FAIL".
        - details (str): Additional details about the check result.
        - documentation (str): Reference to the documentation for further information.

        Returns:
            dict: A dictionary containing the check results.
        """        
        title = "Certificate SAN Check"
        result = "PASS"
        details = ""
        documentation = ""

        if "sha1" in self.sigalg:
            result = "FAIL"
            details = f"{self.sigalg} is not a supported algorithm."
            documentation = "Please see the document 'Certificate Requirements for Different Solution Paths' on https://docs.vmware.com corresponding to your version."


        return {'title': title, 'result': result, 'details': details, 'documentation': documentation}


    def getTrustChain(self, authkey, canum=0):
        """
        Get the trust chain for a given authentication key.

        Args:
            authkey (str): The authentication key.
            canum (int, optional): The index number of the certificate authority. Defaults to 0.

        Returns:
            None

        Raises:
            None
        """        
        rc = 1
        cacount = 'ca' + str(canum)
        if authkey != None:
            for cert in self.certlist:
                if authkey == self.certlist[cert]['subjectkey']:
                    canum += 1
                    rc = 0
                    self.trustchain[cacount] = cert
                    if not 'children' in trusted_list[cert].keys():
                        trusted_list[cert]['children'] = []

                    if self.alias == "":
                        self.alias = self.cert_name

                    if self.note != "":
                        self.alias = self.alias + " (" + self.note + ")"

                    trusted_list[cert]['children'].append(self.alias)
                    if self.certlist[cert]['authkey'] != self.certlist[cert]['subjectkey']:
                        self.getTrustChain(self.certlist[cert]['authkey'], canum)
                else:
                    continue
        else:
            rc = 0

        if rc == 1:
            self.trustchain[authkey] = "Signing authority does not exist in TRUSTED_ROOTS!"

    def printChain(self):
        """
        Prints the trustchain in a formatted manner.

        Args:
            self (object): The instance of the class.

        Returns:
            None
        """        
        trustchain = OrderedDict(sorted(self.trustchain.items()))
        for ca, alias in trustchain.items():
            print("\t  See TRUSTED_ROOTS alias: %s" % alias)

    def authkeyTrusted(self, authkey):
        """
        Check if the given authentication key is trusted.

        Args:
            authkey (str): The authentication key to be checked.

        Returns:
            bool: True if the authentication key is trusted, False otherwise.
        """        
        subjectkeys = [x['subjectkey'] for x in self.certlist if 'subjectkey' in x]
        if authkey in subjectkeys:
            return True
        else:
            return False

    def issuerTrusted(self, issuer):

        """
        Check if an issuer is trusted.

        Args:
            self (obj): The object instance.
            issuer (str): The issuer to be checked.

        Returns:
            bool: True if the issuer is trusted, False otherwise.
        """        
        subjects = [self.certlist[x]['subject'] for x in self.certlist if 'subject' in self.certlist[x]]
        if issuer in subjects:
            return True
        else:
            return False
    def trustCheck(self):
        """
        Perform a certificate trust check.

        Returns a dictionary containing the result of the trust check.

        Returns:
            dict: A dictionary with the following keys:
                - 'title': (str) The title of the trust check.
                - 'result': (str) The result of the trust check.
                - 'details': (str) Additional details about the trust check.
                - 'documentation': (str) Documentation related to the trust check.

        Raises:
            None
        """        
        output = {'title': "Certificate Trust Check", 'result': '', 'details': '', 'documentation': ''}
        title = "Certificate Trust Check"
        result = "PASS"
        details = ""
        documentation = ""
        authkeypresent = True
        issuerpresent = True
        selfsigned = False

        if self.subjectkey:
            if self.authkey:
                if self.subjectkey in self.authkey:
                    selfsigned = True
                else:
                    if not self.authkeyTrusted(self.authkey):
                        authkeypresent = False
                        details += f"authkey: {self.authkey} not present in subject key of other certificates."
            if self.subject in self.load_cert.issuer:
                selfsigned = True
            else:
                if not self.issuerTrusted(self.load_cert.issuer):
                    issuerpresent = False
                    details += f"Issuer: {self.load_cert.issuer} not present in subject of other certificates."
            if selfsigned:
                output.update({'title': f'{title} (SELF-SIGNED)', 'result': "PASS"})
                return output
            if issuerpresent and authkeypresent:
                output.update({'title': f'{title} (TRUSTED)', 'result': "PASS"})
                return output
            elif issuerpresent and not authkeypresent:
                output.update({'title': f'{title} (TRUSTED BY ISSUER NAME)', 'result': "PASS"})
                return output
            elif authkeypresent and not issuerpresent:
                output.update({'title': f'{title} (TRUSTED BY AUTHKEY)', 'result': "PASS"})
                return output
            else:
                details = "This certificate is not trusted by either authkey nor issuer/subject."
                output.update({'title': f'{title} (NOT TRUSTED)', 'result': "FAIL", 'details': details})
                return output

        else:
            result = "FAIL"
            details = "This certificate does not have a subject key identifier (not compliant with RFC 5280)!"
            return {'title': title, 'result': result, 'details': details, 'documentation': documentation}

    def caCheck(self):
        """
        Check if a certificate is a Certificate Authority (CA).

        Returns a dictionary with the following keys:
        - 'title': A string describing the check being performed.
        - 'result': A string indicating if the check passed or failed.
        - 'details': Additional details about the check result.
        - 'documentation': A URL providing documentation related to the check.

        Raises:
            None
        """        
        title = "Certificate Authority Parameter Check"
        result = ""
        details = ""
        documentation = ""
        logger.info("Checking if certificate is a CA")
        keyusage = self.load_cert.keyusage
        if keyusage and 'Certificate Sign' in keyusage:
            logger.debug("found certificate sign")
            result = "PASS"
        else:
            logger.debug("did not find certificate sign")
            result = "FAIL"
            details = "Certificate is NOT a certificate authority!  It must be removed."
            documentation = "https://kb.vmware.com/s/article/2146011"

        return {'title': title, 'result': result, 'details': details, 'documentation': documentation}

    def extKeyUsageCheck(self):
        """
        Check the extended key usage of a certificate.

        Returns:
            dict: A dictionary containing the following keys:
                - title (str): The title of the check.
                - result (str): The result of the check ('PASS' or 'FAIL').
                - details (str): Additional details about the check, if applicable.
                - documentation (str): Documentation related to the check.
        """        
        title = "Certificate Key Usage Check"
        result = "PASS"
        details = ""
        documentation = ""

        if self.load_cert.extkeyusage:
            if 'TLS Web Client Authentication' not in self.load_cert.extkeyusage:
                result = "FAIL"
                details = "\tvpxd-extension solution user must have 'TLS Web Client Authentication'!"
        return {'title': title, 'result': result, 'details': details, 'documentation': documentation}

    def execute(self, alg=True, exp=True, san=True, ca=False, trust=True, extusage=False):
        """
        Execute various checks and return the results.

        Args:
            alg (bool): If True, perform algorithm check. Default is True.
            exp (bool): If True, perform expiration check. Default is True.
            san (bool): If True, perform subject alternative name check. Default is True.
            ca (bool): If True, perform certificate authority check. Default is False.
            trust (bool): If True, perform trust check. Default is True.
            extusage (bool): If True, perform extended key usage check. Default is False.

        Returns:
            list: A list of check results.
        """        
        output = []
        # self.printChain()
        if alg:
            output.append(self.algCheck())
        if trust:
            output.append(self.trustCheck())
        if exp:
            output.append(self.expCheck())
        if extusage:
            output.append(self.extKeyUsageCheck())
        if san:
            output.append(self.sanCheck())
        if ca:
            output.append(self.caCheck())
        return output

class parseSts(object):

    """
    A class for parsing STS certificates.

    Attributes:
        processed (list): A list of certificate thumbprints that have been processed.
        results (dict): A dictionary containing the results of the certificate parsing.
            'expired' (dict): A sub-dictionary containing expired certificate information.
                'root' (list): A list of expired root certificates.
                'leaf' (list): A list of expired leaf certificates.
            'valid' (dict): A sub-dictionary containing valid certificate information.
                'root' (list): A list of valid root certificates.
                'leaf' (list): A list of valid leaf certificates.
    """    
    def __init__(self):
        """
        Initialize an instance of the class.

        Stores empty lists and dictionaries within the instance to be used for storing processed and resulting data. 

        Attributes:
            processed (list): An empty list to store processed data.
            results (dict): A dictionary to store resulting data.
                expired (dict): A nested dictionary to store expired data.
                    root (list): An empty list to store expired root data.
                    leaf (list): An empty list to store expired leaf data.
                valid (dict): A nested dictionary to store valid data.
                    root (list): An empty list to store valid root data.
                    leaf (list): An empty list to store valid leaf data.
        """        
        self.processed = []
        self.results = {}
        self.results['expired'] = {}
        self.results['expired']['root'] = []
        self.results['expired']['leaf'] = []
        self.results['valid'] = {}
        self.results['valid']['root'] = []
        self.results['valid']['leaf'] = []

    def get_certs(self, force_refresh):
        """
        Get the certificates from the STS.

        Args:
            force_refresh (bool): A flag indicating whether to force a refresh of the certificates.

        Returns:
            dict: A dictionary containing the certificates.

        Raises:
            Exception: If there is an error while retrieving the certificates.
        """        
        logger.info("getting STS certs")
        urllib2.getproxies = lambda: {}
        # vmafd_client = VmafdClient()
        # domain_name = vmafd_client.get_domain_name()
        domain_name = sso_domain
        dc_name = hostname
        vmafd_pnid = pnid

        if vmafd_pnid.lower() == dc_name.lower():
            url = (
                    'http://localhost:7080/idm/tenant/%s/certificates?scope=TENANT'
                    % domain_name)
        else:
            url = (
                    'https://%s/idm/tenant/%s/certificates?scope=TENANT'
                    % (dc_name, domain_name))
        try:
            result = json.loads(urllib2.urlopen(url).read().decode('utf-8'))
        except Exception as e:
            e = str(e.reason).split(']')[1]
            logger.error(e)
            raise Exception(e)
        return result

    def check_cert(self, certificate):
        """
        Check the validity of a certificate and update the results.

        Args:
            self: The reference to the current object.
            certificate (str): The certificate to check.

        Returns:
            None

        Raises:
            None
        """        
        logger.info("Checking certificate: %s" % certificate)
        cert = Cert(certificate)
        certdetail = cert.combined

        #  Attempt to identify what type of certificate it is
        if cert.authkey:
            cert_type = "leaf"
        else:
            cert_type = "root"

        #  Try to only process a cert once
        if cert.thumbprint not in self.processed:
            # Date conversion
            self.processed.append(cert.thumbprint)
            exp = cert.validuntil.split()[0]
            conv_exp = datetime.strptime(exp, '%Y-%m-%d')
            exp = datetime.strftime(conv_exp, '%d-%m-%Y')
            now = datetime.strptime(today, '%d-%m-%Y')
            exp_date = datetime.strptime(exp, '%d-%m-%Y')

            # Get number of days until it expires
            diff = exp_date - now
            certdetail['daysUntil'] = diff.days

            # Sort expired certs into leafs and roots, put the rest in goodcerts.
            if exp_date <= now:
                self.results['expired'][cert_type].append(certdetail)
            else:
                self.results['valid'][cert_type].append(certdetail)

    def execute(self):

        """
        Execute the necessary operations on certificates.

        This function retrieves certificates in JSON format and iterates through each item in the JSON. For each item, it further iterates through each certificate and performs a check on the encoded value. The results of the checks are stored and returned.

        Returns:
            list: The results of the certificate checks.

        Raises:
            None
        """        
        json = self.get_certs(force_refresh=False)
        for item in json:
            for certificate in item['certificates']:
                self.check_cert(certificate['encoded'])
        return self.results

def checkExtCerts(username, password):
    """
    Check if the vCenter Server Extension Certificates have the correct thumbprint.

    Args:
        username (str): The username to authenticate with.
        password (str): The password to authenticate with.

    Returns:
        dict: A dictionary containing the results of the extension certificate check.
            - title (str): The title of the check.
            - result (str): The overall result of the check ('PASS' or 'FAIL').
            - details (str): Additional details about the check.
            - documentation (str): A link to relevant documentation.

    Raises:
        None
    """    
    title = "VPXD Extension Thumbprint Check"
    result = "PASS"
    details = ""
    documentation = ""

    extensions = ['com.vmware.vim.eam', 'com.vmware.rbd', 'com.vmware.imagebuilder']
    VecsClient = GetVecs()
    cert = Cert(VecsClient.GetVecsCert('vpxd-extension', 'vpxd-extension'))
    vpxd_ext_thumb = cert.thumbprint
    # logger.debug("Got vpxd-extension solution user thumbprint: %s" % vpxd_ext_thumb)

    client = exManager(username, password)
    extension_list = client.list()
    for extension in extensions:

        if extension in extension_list.keys():
            ext_thumb = extension_list[extension]['thumbprint']
            # logger.debug("Got vpxd-extension solution user thumbprint: %s" % vpxd_ext_thumb)
            if ext_thumb == vpxd_ext_thumb:
                details += f"\n{ColorWrap.ok('[PASS]')}\t{extension}: thumbprint match"
            else:
                result = "FAIL"
                details += f"\n{ColorWrap.fail('[FAIL]')}\t{extension}: Thumbprint mismatch detected!"
                documentation = "https://kb.vmware.com/s/article/57379 | https://kb.vmware.com/s/article/2112577 | https://kb.vmware.com/s/article/80588"
        else:
            details += f"\n{ColorWrap.info('[INFO]')}\t{extension} is not in use."
            continue
    return {'title': title, 'result': result, 'details': details, 'documentation': documentation}

def getCaTrustList():
    """
    Get the CA trust list.

    This function retrieves the list of trusted root certificates from a specific store.

    Returns:
        None

    Raises:
        None
    """    
    logger.info("Getting CA trust list")
    certlist = run_command(["/usr/lib/vmware-vmafd/bin/vecs-cli", "entry", "list", "--store", "TRUSTED_ROOTS"]).decode()
    templist = certlist.splitlines()
    templist[0] = '\n\n\n'
    certlist = '\n'.join(templist)

    global trusted_list
    trusted_list = {}

    for line in certlist.split('\n\n\n'):
        for field in line.split('\n'):
            if 'Alias' in field:
                error = ""

                alias = field.split()[2]
                VecsClient = GetVecs()
                cert = VecsClient.GetVecsCert('TRUSTED_ROOTS', alias)
                parsed_cert = Cert(cert)

                rootentry = {'subject': parsed_cert.subject, 'subjectkey': parsed_cert.subjectkey,
                             'thumbprint': parsed_cert.thumbprint, 'authkey': parsed_cert.authkey}
                trusted_list[alias] = rootentry

def checkCerts():
    """
    Check certificates in various stores.

    This function retrieves certificates from different stores and performs various checks on each certificate.

    Returns:
        generator: A generator that yields a dictionary containing the results of the certificate checks.

    Yields:
        dict: A dictionary containing information about each store and the certificate checks performed.

    Raises:
        Exception: If an error occurs while checking a certificate.
    """    
    output = []
    getCaTrustList()
    myip, myhostname = getAddr()

    storeignore = ['TRUSTED_ROOTS', 'TRUSTED_ROOT_CRLS', 'APPLMGMT_PASSWORD', 'KMS_ENCRYPTION']

    VecsClient = GetVecs(ignore_list=storeignore)
    certs = VecsClient.all()
    for store in certs:
        if store not in storeignore:
            store_check = {'subheading': store.upper(), "checks": []}
            logger.info("Checking certs in store: %s" % store)
            if len(certs[store].keys()) > 0:
                # newcheck = {'heading': store}
                if 'BACKUP_STORE' in store:
                    continue
                # aliases = []
                for alias in certs[store]:
                    aliases = {}

                    logger.info("Checking cert alias %s in store %s" % (alias, store))
                    try:
                        cert = certs[store].get(alias)
                        if 'wcp' in store or 'wcp' in alias:
                            store_check['checks'].append({'subheading': f"{alias}",
                                            'checks': checkCert(cert, myhostname, myip, alias=alias).execute(
                                                san=False)})
                        elif 'KMS_ENCRYPTION' in store and 'password' not in alias:
                            try:
                                store_check['checks'].append({'subheading': f"{alias}",
                                                'checks': checkCert(cert, myhostname, myip, alias=alias).execute(
                                                    alg=True, exp=True, san=False,
                                                    ca=False, trust=False,
                                                    extusage=False)})
                            except:
                                logger.error("There was a problem checking KMS certs.  Skipping...")
                                pass
                        else:
                            if 'SMS' in store:
                                store_check['checks'].append({'subheading': f"{alias}",
                                                'checks': checkCert(cert, myhostname, myip, alias=alias).execute(
                                                    trust=False, san=False)})
                            else:
                                store_check['checks'].append({'subheading': f"{alias}",
                                           'checks': checkCert(cert, myhostname, myip, alias=alias).execute()})

                    except Exception as e:
                        logger.error("skipping %s, error was: %s" % (alias, e))
                        logger.error(traceback.format_exc())
                        continue
                # newcheck['checks'] = aliases
                yield store_check

def checkRoots():

    """
    Check the roots in the trusted roots store.

    Yields a dictionary for each root certificate in the store, containing subheading and checks information.

    Yields:
        dict: Dictionary containing subheading and checks information for each root certificate.

    Raises:
        None
    """    
    certlist = run_command(["/usr/lib/vmware-vmafd/bin/vecs-cli", "entry", "list", "--store", "TRUSTED_ROOTS"]).decode()
    for line in certlist.split('\n\n\n'):
        for field in line.split('\n'):
            if 'Alias' in field:
                error = ""
                alias = field.split()[2]
                VecsClient = GetVecs()
                cert = VecsClient.GetVecsCert('TRUSTED_ROOTS', alias)
                yield {'subheading': f"{alias}",
                           'checks': checkCert(cert, alias=alias).execute(
                               san=False, ca=True)}


### entry functions ###

def root_check():
    """
    Check for root certificates on the system.

    This function checks for the presence of root certificates on the system by calling two other functions: getCaTrustList() and checkRoots(). It returns a list of results.

    Returns:
        list: A list of results from checking for root certificates.
    """    
    getCaTrustList()
    results = []
    for x in checkRoots():
        results.append(x)
    return results

def vecs_check():
    """
    Check the certificates and return the results.

    This function calls the `getCaTrustList` function to retrieve a list of certificates and then checks each certificate using the `checkCerts` function. The results of the checks are collected in a list and returned.

    Returns:
        list: A list of the results of the certificate checks.
    """    
    getCaTrustList()
    results = []
    for x in checkCerts():
        results.append(x)
    return results

def crls_check():
    """
    Check the number of CRLs in the TRUSTED_ROOT_CRLS store.

    Returns a dictionary with the following keys:
        - 'title': A string representing the title of the check.
        - 'result': A string representing the result of the check ('PASS' or 'FAIL').
        - 'details': A string providing additional details on the check.
        - 'documentation': A string with the link to the related documentation.

    Raises:
        None.
    """    
    title = "TRUSTED_ROOT_CRLS Check"
    documentation = ""
    logger.info("Checking CRLs...")

    details = ""
    kbarticle = "https://kb.vmware.com/s/article/80020"
    
    VecsClient = GetVecs()
    crlcount = VecsClient.getCertCountFromStore("TRUSTED_ROOT_CRLS")
    # title = "CRLS Count Check: %s CRLs" % crlcount?
    if int(crlcount) >= 500:
        result = "FAIL"
        details = f"Large number of CRLs found!  [Count: {crlcount}]"
        documentation = kbarticle
    else:
        result = "PASS"
        title = title + f" [Count: {crlcount}]"

    return {'title': title, 'result': result, 'details': details, 'documentation': documentation}


def esxi_cert_mode_check(username, password):
    """
    Check the ESXi Certificate Mode.

    Args:
        username (str): The username for accessing the ESXi server.
        password (str): The password for accessing the ESXi server.

    Returns:
        dict: A dictionary containing the title, result, and details of the certificate mode check.
            - title (str): The title of the certificate mode check, with the current certificate mode appended.
            - result (str): The result of the certificate mode check, either 'PASS' or 'FAIL'.
            - details (str): Additional details about the certificate mode check, including recommendations and instructions.

    Notes:
        - If the certificate mode is 'thumbprint', the function sets the result to 'FAIL' and provides recommendations for changing the mode.
    """    
    title = "ESXi Certificate Mode Check"
    details = ""
    result = "PASS"
    if username and password:
        client = exManager(username, password)
        certmode = client.getSetting('vpxd.certmgmt.mode')
        title = title + f" [{certmode}]"
        if certmode == "thumbprint":
            result = "FAIL"
            details = """\tVMware does not recommend using the value of 'thumbprint' for 
the vpxd.certmgmt.mode advanced Setting for extended periods.  
It is recommended to change the value to the default 'vmca', 
or 'custom',depending on your security requirements.  
Changing to one of these values will require that certificates 
be re-issued to the hosts.  See 'Renew or Refresh ESXi Certificates' 
section of the vSphere Security documentation.
            """

    return {'title': title, 'result': result, 'details': details}

def extension_check(username, password):
    """
    Check if a user's credentials have valid extensions.

    Args:
        username (str): The username of the user.
        password (str): The password of the user.

    Returns:
        bool: True if the user's credentials have valid extensions, False otherwise.
    """    
    return checkExtCerts(username, password)

def sts_check():
    """
    Check the status of STS certificates and return the result.

    Returns:
        dict: A dictionary containing the following keys:
            - title (str): The title of the check.
            - result (str): The result of the check, either "PASS" or "FAIL".
            - details (str): Additional details about the check result.
            - documentation (str): Documentation URL for further information.

    Raises:
        Exception: If there is an error contacting the STS service.
    """    
    title = "STS Certificate Check"
    result = "PASS"
    details = ""
    documentation = ""
    try:
        parse_sts = parseSts()
        results = parse_sts.execute()
        expired_count = len(results['expired']['leaf']) + len(results['expired']['root'])

        if expired_count > 0:
            result = "FAIL"
            details = f"{expired_count}x expired STS certificates."
            documentation = "https://kb.vmware.com/s/article/76719"
    except:
        result = "FAIL"
        details = "Failed to contacting STS service.  Are the STS services running?", 'fail'

    return {'title': title, 'result': result, 'details': details, 'documentation': documentation}


