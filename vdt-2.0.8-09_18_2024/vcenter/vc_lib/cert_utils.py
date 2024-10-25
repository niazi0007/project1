import sys
import os
import re
import json
import logging
import ssl
import subprocess
from vcenter.vc_lib.common import Command, psqlQuery
from vcenter.vc_cfg.current_defaults import httpsPort
from datetime import datetime
sys.path.append(os.environ['VMWARE_PYTHON_PATH'])
from OpenSSL.crypto import (load_certificate, dump_privatekey, dump_certificate, X509, X509Name, PKey)
from OpenSSL.crypto import (TYPE_DSA, TYPE_RSA, FILETYPE_PEM, FILETYPE_ASN1 )
from pyVmomi.VmomiSupport import newestVersions
from pyVmomi import Vim, SoapStubAdapter
from cis.vecs import *
try:
    # Python 3 hack.
    import urllib.request as urllib2
    import urllib.parse as urlparse
except ImportError:
    import urllib2
    import urlparse
_DefaultCommmandEncoding = sys.getfilesystemencoding()

logger = logging.getLogger(__name__)

def run_command(cmd, stdin=None, encoding=_DefaultCommmandEncoding):
    """
    Run a command in a subprocess and return the output.

    Args:
        cmd (list): A list of command and arguments to run.
        stdin (str, optional): Standard input for the command. Defaults to None.
        encoding (str, optional): The encoding to use for the input. Defaults to the default command encoding.

    Returns:
        bytes: The output of the command as bytes.

    Raises:
        subprocess.CalledProcessError: If the command returns a non-zero exit status.
        subprocess.TimeoutExpired: If the command times out.
    """    
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    if sys.version_info[0] >= 3 and isinstance(stdin, str):
        stdin = stdin.encode(encoding)
    stdout, stderr = process.communicate(stdin)
    if not stdout:
        logger.error(stderr.decode())
        sys.exit(1)
    return stdout

def getCaTrustList():
    """
    Get the list of CA trust certificates.

    Returns:
        None

    Raises:
        None
    """    
    logger.debug("Getting CA trust list")
    certlist = run_command(["/usr/lib/vmware-vmafd/bin/vecs-cli", "entry", "list", "--store", "TRUSTED_ROOTS"]).decode()
    templist = certlist.splitlines()
    templist[0] = '\n\n\n'
    certlist = '\n'.join(templist)
    # print(certlist)
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
                # print(parsed_cert)
                rootentry = {'subject': parsed_cert.subject, 'subjectkey': parsed_cert.subjectkey,
                             'thumbprint': parsed_cert.thumbprint, 'authkey': parsed_cert.authkey}
                trusted_list[alias] = rootentry

class parseCert(object):
    """
    This is a class that will parse a certificate into a dictionary of certificate information.

    Attributes:
        rawcert (TYPE): Description
        x509 (TYPE): Description
    """

    def __init__(self, certdata, file=True):
        """
        Args:
            certdata (TYPE): certificate data either string or file.
            file (bool, optional): flag telling us whether or not certdata is a file.
        """
        if file == True:
            built_cert = certdata
            logger.debug(built_cert)
            self.x509 = load_certificate(FILETYPE_PEM, built_cert)
        else:
            stringed_cert = re.sub("(.{64})", "\\1\n", certdata, 0, re.DOTALL)
            built_cert = "-----BEGIN CERTIFICATE-----\n" + stringed_cert + "\n" + "-----END CERTIFICATE-----"
            lines = '\n'.join([x for x in built_cert.split("\n") if x.strip() != ''])
            built_cert = lines
            self.x509 = load_certificate(FILETYPE_PEM, built_cert)
            self.rawcert = built_cert

    def decode(self, item, encoding):

        """
        Decode a string or bytes-like object using the specified encoding.

        Args:
            item (str or bytes): The string or bytes-like object to be decoded.
            encoding (str): The encoding to be used for decoding.

        Returns:
            str: The decoded string.

        Raises:
            UnicodeDecodeError: If the decoding process fails.
        """        
        try:
            return decode(item, encoding, errors='surrogateescape')
        except:
            return item.decode(encoding, errors='surrogateescape')

    def format_subject_issuer(self, x509name):

        """
        Create a formatted string representation of the subject/issuer of an X509Name object.

        Args:
            x509name (X509Name): An X509Name object representing the subject/issuer.

        Returns:
            str: A string representation of the subject/issuer, with each component formatted as "key=value".

        Note:
            The input X509Name object is expected to have components returned by the get_components() method.
        """        
        items = []
        for item in x509name.get_components():
            items.append('%s=%s' % (self.decode(item[0], 'utf-8'), self.decode(item[1], 'utf-8')))
        return ", ".join(items)

    def format_asn1_date(self, d):

        """
        Format an ASN.1 date string.

        Args:
            d (bytes): The ASN.1 date string encoded as bytes.

        Returns:
            str: The formatted date string in the format 'YYYY-MM-DD HH:MM:SS GMT'.
        """        
        return datetime.strptime(self.decode(d, 'utf-8'), '%Y%m%d%H%M%SZ').strftime("%Y-%m-%d %H:%M:%S GMT")

    def merge_cert(self, extensions, certificate):

        """
        Merge a dictionary of extensions into a certificate.

        Args:
            extensions (dict): A dictionary of extensions to be merged into the certificate.
            certificate (dict): A dictionary representing a certificate.

        Returns:
            dict: A new dictionary that is a merge of the extensions and the certificate.
        """        
        z = certificate.copy()
        z.update(extensions)
        return z

    def cert(self):

        """
        Get the details of a certificate.

        Returns:
            str: A JSON string containing the details of the certificate.
        """        
        keytype = self.x509.get_pubkey().type()
        keytype_list = {TYPE_RSA: 'rsaEncryption', TYPE_DSA: 'dsaEncryption', 408: 'id-ecPublicKey'}
        extension_list = ["extendedKeyUsage",
                          "keyUsage",
                          "subjectAltName",
                          "subjectKeyIdentifier",
                          "authorityKeyIdentifier"]

        key_type_str = keytype_list[keytype] if keytype in keytype_list else 'other'

        certificate = {}
        extension = {}
        for i in range(self.x509.get_extension_count()):
            critical = 'critical' if self.x509.get_extension(i).get_critical() else ''

            if self.decode(self.x509.get_extension(i).get_short_name(), 'utf-8') in extension_list:
                try:
                    extension[
                        self.decode(self.x509.get_extension(i).get_short_name(), 'utf-8')] = self.x509.get_extension(
                        i).__str__()
                except Exception as e:
                    name = self.x509.get_extension(i).get_short_name()
                    extension[self.decode(name, 'utf-8')] = "FAILED_TO_DECODE"
                    logger.debug("Failed to parse certificate extension %s" % name)

        certificate = {'Thumbprint': self.decode(self.x509.digest('sha1'), 'utf-8'),
                       'Version': self.x509.get_version(),
                       'SignatureAlg': self.decode(self.x509.get_signature_algorithm(), 'utf-8'),
                       'Issuer': self.format_subject_issuer(self.x509.get_issuer()),
                       'Valid From': self.format_asn1_date(self.x509.get_notBefore()),
                       'Valid Until': self.format_asn1_date(self.x509.get_notAfter()),
                       'Subject': self.format_subject_issuer(self.x509.get_subject())}
        combined = self.merge_cert(extension, certificate)

        cert_output = json.dumps(combined)
        return cert_output

    def __str__(self):
        """
        Returns the certificate in string form if desired.
        """
        return self.cert()

class Cert(object):
    """
    A class representing a certificate.

    Attributes:
        subjectAltName (str): The subject alternative name of the certificate.
        subject (str): The subject of the certificate.
        validfrom (str): The start date of the validity period of the certificate.
        validuntil (str): The end date of the validity period of the certificate.
        thumbprint (str): The thumbprint of the certificate.
        subjectkey (str): The subject key identifier of the certificate.
        authkey (str): The authority key identifier of the certificate.
        sigalg (str): The signature algorithm used in the certificate.
        keyusage (str): The key usage of the certificate.
        extkeyusage (str): The extended key usage of the certificate.
        issuer (str): The issuer of the certificate.
        combined (dict): The combined information of the certificate.
    """    
    def __init__(self, cert):
        """
        Initialize a Certificate object.

        Args:
            cert (str): The certificate in string format.

        Attributes:
            subjectAltName (str): The subject alternative name of the certificate.
            subject (str): The subject of the certificate.
            validfrom (str): The validity start date of the certificate.
            validuntil (str): The validity end date of the certificate.
            thumbprint (str): The thumbprint of the certificate.
            subjectkey (str): The subject key identifier of the certificate.
            authkey (str): The authority key identifier of the certificate.
            sigalg (str): The signature algorithm used in the certificate.
            keyusage (str): The key usage information of the certificate.
            extkeyusage (str): The extended key usage information of the certificate.
            issuer (str): The issuer of the certificate.
            combined (dict): The combined dictionary containing the parsed certificate information.
        """        
        combined = json.loads(str(parseCert(cert)))
        self.subjectAltName = combined.get('subjectAltName')
        self.subject = combined.get('Subject')
        self.validfrom = combined.get('Valid From')
        self.validuntil = combined.get('Valid Until')
        self.thumbprint = combined.get('Thumbprint')
        self.subjectkey = combined.get('subjectKeyIdentifier')
        self.authkey = combined.get('authorityKeyIdentifier')
        self.sigalg = combined.get('SignatureAlg')
        self.keyusage = combined.get('keyUsage')
        self.extkeyusage = combined.get('extendedKeyUsage')
        self.issuer = combined.get('Issuer')
        self.combined = combined

class GetVecs(object):
    """
    A class for interacting with VMware vSphere Certificate Store (VECS).

    Attributes:
        vecscli (str): The path to the vecs-cli binary.
        ignore_list (list): A list of stores to ignore when listing stores.

    Methods:
        GetVecsStores: Retrieves a list of VECS stores.
        ListStoreCerts: Retrieves a list of certificates in a specific store.
        getCertCountFromStore: Retrieves the number of certificates in a specific store.
        GetVecsCert: Retrieves a specific certificate from a store.
        all: Retrieves all certificates from all stores.
    """    
    def __init__(self, ignore_list=None):
        """
        Initializes an instance of the class.

        Args:
            ignore_list (list): A list of items to ignore.

        Attributes:
            vecscli (str): The path to the vecs-cli binary.
            ignore_list (list): A list of items to ignore.
        """        
        self.vecscli = "/usr/lib/vmware-vmafd/bin/vecs-cli"
        self.ignore_list = ignore_list

    def GetVecsStores(self):
        """
        Get the list of vector stores.

        Returns:
            list: A list of vector stores.
        """        
        output = []
        # logger.debug("Getting certificate with Alias: %s from Store: %s" % (alias,store))

        raw, errors, timeout = Command([self.vecscli, "store", "list"]).run()
        for store in raw.splitlines():
            if store not in self.ignore_list:
                output.append(store)
        return output

    def ListStoreCerts(self, store):
        """
        Store the certificates in a list.

        Args:
            self (class): The class instance.
            store (str): The name of the certificate store.

        Returns:
            list: A list of certificate aliases stored in the given certificate store.
        """        
        output = []
        raw, errors, timeout = Command([self.vecscli, "entry", "list", "--store", store]).run()
        for line in raw.splitlines():
            if 'Alias' in line:
                output.append(line.split(":", 1)[1].strip())
        return output

    def getCertCountFromStore(self, store):
        """
        Get the count of certificates from a specified store.

        Args:
            store (str): The name of the store.

        Returns:
            str: The count of certificates in the store.
        """        
        raw, errors, timeout = Command([self.vecscli, "entry", "list", "--store", store]).run()
        for line in raw.splitlines():
            if "Number of entries in store" in line:
                return line.split(":")[1].strip()

    def GetVecsCert(self, store, alias):
        """
        Get the certificate with a specified alias from a store.

        Args:
            store (str): The store name.
            alias (str): The alias of the certificate.

        Returns:
            str: The certificate.

        Raises:
            None.
        """        
        logger.debug("Getting certificate with Alias: %s from Store: %s" % (alias, store))
        cert, errors, timeout = Command([self.vecscli, "entry", "getcert", "--store", store, "--alias", alias]).run()
        return cert

    def all(self):
        """
        Return a dictionary containing all store-certificate pairs.

        Returns:
            dict: A dictionary with store names as keys and another dictionary as values. The inner dictionary contains aliases as keys and corresponding certificates as values.
        """        
        output = {}
        for store in self.GetVecsStores():
            output[store] = {}
            for alias in self.ListStoreCerts(store):
                output[store][alias] = self.GetVecsCert(store, alias)
        return output

class exManager(object):
    """
    A class representing an extension manager.

    Attributes:
        username (str): The username for authentication.
        password (str): The password for authentication.
    """    
    def __init__(self, username, password):
        # (httpPort, httpsPort, endpointsDir) = get_rhttpProxy_config()
        """
        Initialize an instance of the class.

        Args:
            username (str): The username for authentication.
            password (str): The password for authentication.

        Raises:
            Exception: If the user credentials are invalid.
        """        
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            stub = SoapStubAdapter(host='localhost', port=httpsPort, path='/sdk',
                                   version=newestVersions.GetName('vpx'), sslContext=context)
        except:
            stub = SoapStubAdapter(host='localhost', port=httpsPort, path='/sdk',
                                   version=newestVersions.Get('vpx'), sslContext=context)
        si = Vim.ServiceInstance('ServiceInstance', stub)

        self.sessionMgr = None
        try:
            self.sessionMgr = si.content.sessionManager
            self.sessionMgr.Login(username, password)
        except Vim.fault.InvalidLogin:
            # print('ERROR: Invalid user credentials. Please try again.')
            raise Exception("Invalid user credentials")
        self.em = si.content.extensionManager
        self.settings = si.content.setting.setting

    def getSetting(self, setting_key):
        """
        Get the value of a specific setting.

        Args:
            setting_key (str): The key of the setting to retrieve.

        Returns:
            object: The value of the specified setting.

        Raises:
            KeyError: If the specified setting key does not exist.
        """        
        for setting in self.settings:
            if setting.key == setting_key:
                return setting.value

    def getExtThumbprint(self, ext_name):
        """
        Get the thumbprint of a specific extension.

        Args:
            ext_name (str): The name of the extension.

        Returns:
            str: The thumbprint of the extension.
        """        
        output = psqlQuery('SELECT thumbprint from vpx_ext where ext_id=\'%s\'' % ext_name)
        return output

    def list(self):
        """
        List the details of extensions.

        Returns:
            dict: A dictionary of extension details. The keys are the extension keys and the values are dictionaries containing the label, description, company, version, hostname, and thumbprint of each extension.

        Raises:
            AssertionError: If the session manager is not initialized or if the logout fails.
        """        
        results = {}
        try:
            for extension in self.em.extensionList:
                ex_key = extension.GetKey()
                # print(extension)
                results[ex_key] = {}
                results[ex_key]['label'] = extension.description.label
                results[ex_key]['description'] = extension.description.summary
                results[ex_key]['company'] = extension.company
                results[ex_key]['version'] = extension.version
                dbtp = self.getExtThumbprint(ex_key)
                try:
                    results[ex_key]['hostname'] = urlparse.urlparse(extension.server[0].url).hostname
                    if dbtp == "":
                        results[ex_key]['thumbprint'] = extension.server[0].serverThumbprint
                    else:
                        results[ex_key]['thumbprint'] = dbtp
                except:
                    results[ex_key]['thumbprint'] = dbtp
            return results
        finally:
            assert self.sessionMgr is not None
            self.sessionMgr.Logout()
            self.sessionMgr = None

    def findByExtName(self, ex_name):
        """
        Find dictionary entries by extension name.

        Args:
            ex_name (str): The extension name to search for in the dictionary keys.

        Returns:
            dict: A dictionary containing the entries with the matching extension name.
        """        
        extensions = self.list()
        results = {}
        for extension in extensions:
            if ex_name in extension:
                results[extension] = extensions[extension]
        return results

