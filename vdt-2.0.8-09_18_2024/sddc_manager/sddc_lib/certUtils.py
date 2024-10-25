import logging.config
import datetime
import logging
import ssl
import socket
import json
import re
from OpenSSL.crypto import (load_certificate, FILETYPE_PEM, TYPE_DSA, TYPE_RSA)

from sddc_manager.sddc_lib.commandUtils import run_command

logger = logging.getLogger(__name__)

########### CONFIGURABLE PARAMETERS ###########
NUM_DAYS_CRITICAL = 30
NUM_DAYS_WARNING = 60
NUM_DAYS_INFO = 90
CHECKS = {"CRITICAL": NUM_DAYS_CRITICAL,
          "WARNING": NUM_DAYS_WARNING,
          "INFO": NUM_DAYS_INFO}

today = datetime.datetime.now()
today = today.strftime("%d-%m-%Y")
delay = 1
timeout = 2

def getSslCert(hostname,port):
    """
    Gets SSL cert from host on port specified. 
        
    Args:
        hostname (str): hostname
        port (int): port
    
    Returns:
        cert: certificate string formatted for lookup service endpoints
    """
    #  returns the cert trust value formatted for lstool
    logger.debug("Getting SSL certificate on %s:%s" % (hostname, port))
    socket.setdefaulttimeout(5)
    try:
        try:
            cert = ssl.get_server_certificate((hostname, port),ssl_version=ssl.PROTOCOL_TLS)
        
        except AttributeError:
            cert = ssl.get_server_certificate((hostname, port),ssl_version=ssl.PROTOCOL_SSLv23)

        except socket.timeout as e:
            raise Exception("Timed out getting certificate")

        except ConnectionRefusedError:
            # print("Connection refused while getting cert for host %s on port %s!" % (hostname, port))
            raise
        
        return cert

    except Exception as e:
        msg = ("[%s:%s]:%s" 
                        % (hostname, port, str(e)))
        raise Exception(msg)

def sddcTrustCheck(commonsvcsCerts, alternativeJreCerts, root256):
    """
    Checks if the passed root certificate is added to both the SDDC Manager
    trust keystores. 
        
    Args:
        commonsvcsCerts (list): List of certificates in the commonsvcs store
        alternativeJreCerts (list): List of certificates in the alternatives JRE store
    
    Returns:
        rootCheck (dict): Result of the Root certificate trust check
    """
    isInCommon = False
    isInAlternate = False
    
    for cert in commonsvcsCerts:
        if root256 == cert[1]:
            isInCommon = True
            break
    for cert in alternativeJreCerts:
        if root256 == cert[1]:
            isInAlternate = True
            break
    
    if (isInCommon == True) and (isInAlternate == True):
        result = 'PASS'
        details='Root Certificate is in both keystores of SDDC Manager.'
        documentation=''
        notes=''
    elif (isInCommon == True) and (isInAlternate == False):
        result = 'FAIL'
        details='Root Cert is missing from keystore "/etc/alternatives/jre/lib/security/cacerts".'
        documentation='https://kb.vmware.com/s/article/78607'
        notes='Refer to the KB above to add the Root Certificate to the keystore.'
    elif(isInCommon == False) and (isInAlternate == True):
        result = 'FAIL'
        details='Root Cert is missing from keystore "/etc/vmware/vcf/commonsvcs/trusted_certificates.store".'
        documentation='https://kb.vmware.com/s/article/78607'
        notes='Refer to the KB above to add the Root Certificate to the keystore.'
    else:
        result = 'FAIL'
        details='Root Cert is missing from keystore "/etc/vmware/vcf/commonsvcs/trusted_certificates.store" and \
            "/etc/alternatives/jre/lib/security/cacerts".'
        documentation='https://kb.vmware.com/s/article/86131'
        notes='Refer to the KB above to add the Root Certificate to the keystores.'
    
    rootCheck = {"title":'Certificate Trust Check',"result":result, "details":details,
                 "documentation":documentation, "notes":notes}
    
    return rootCheck

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
        self.sha256 = combined.get('ThumbprintSHA256')
        self.combined = combined

class checkCert(object):

    def __init__(self, certdata, hostname="", ip="", alias="", note=""):
        self.load_cert = Cert(certdata)
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
        self.exp = self.load_cert.validuntil.split()[0]
        self.cert_name = self.load_cert.thumbprint
        self.subjectkey = self.load_cert.subjectkey
        self.exp_certs = {}
        self.hostname = hostname
        self.ip = ip
        #self.certlist = trusted_list
        self.trustchain = {}
        
    def expCheck(self):
        logger.debug("Checking cert expiration")
        error = ""

        conv_exp = datetime.datetime.strptime(self.exp, '%Y-%m-%d')
        exp = datetime.datetime.strftime(conv_exp, '%d-%m-%Y')
        exp_date = datetime.datetime.strptime(exp, '%d-%m-%Y')
        now = datetime.datetime.strptime(today, '%d-%m-%Y')
        if exp_date <= now + datetime.timedelta(days=CHECKS.get("CRITICAL")):
            diff = exp_date - now
            exp_in_days = diff.days
            if exp_in_days < 0:
                negative_days = str(exp_in_days).replace('-', '')
                error = {"status":"FAIL","details":f'Server Certificate expired {negative_days["daysToExpire"]} ago!'}
            else:
                error = {"status":"FAIL","details":f'Server Certificate expires in {exp_in_days} days'}

        elif exp_date <= now + datetime.timedelta(days=CHECKS.get("WARNING")):
            diff = exp_date - now
            exp_in_days = diff.days
            error = {"status":"WARN","details":f'Server Certificate expires in {exp_in_days} days'}

        elif exp_date <= now + datetime.timedelta(days=CHECKS.get("INFO")):
            diff = exp_date - now
            exp_in_days = diff.days
            error = {"status":"INFO","details":f'Server Certificate expires in {exp_in_days} days'}
        else:
            diff = exp_date - now
            exp_in_days = diff.days
            error = {"status":"PASS","details":f'Server Certificate expires in {exp_in_days} days'}

        return error

    def sanCheck(self):
        logger.debug("Checking SAN for %s" % self.alias)
        self.san = self.load_cert.subjectAltName
        error = ""
        hostflag = True
        ipflag = True

        if self.san:
            if self.hostname.lower() not in self.san.lower():
                hostflag = False
                # #result = bcolors.FAIL + "\t[FAIL]" + bcolors.ENDC
                # # error = {"status":"FAIL","details":"%s: Hostname is not in the SAN!" % self.cert_name}
                # if self.ip not in self.san:
                #     ipflag = False
                #     # error = {"status":"FAIL","details":"Neither hostname nor IP in the SAN!"}
            if self.ip != "":
                if self.ip not in self.san:
                    ipflag = False
                    error = {"status":"PASS","details":""}

            if hostflag == True and ipflag == True:
                error = {"status":"PASS","details":"Hostname and IP in SAN"}
                #result = bcolors.OKGREEN + "\t[PASS]" + bcolors.ENDC
            if hostflag == True and ipflag == False:
                #result = bcolors.WARNING + "\t[INFO]" + bcolors.ENDC
                error = {"status":"WARN","details":"SAN contains hostname but not IP"}
            if hostflag == False and ipflag == True:
                #result = bcolors.WARNING + "\t[WARN]" + bcolors.ENDC
                error = {"status":"FAIL","details":"SAN contains IP but not hostname. This configuration is not recommended."}
            if hostflag == False and ipflag == False:
                #result = bcolors.FAIL + "\t[FAIL]" + bcolors.ENDC
                error = {"status":"FAIL","details":"%s - SAN contains neither hostname nor IP!" % self.cert_name}
        else:
            error = {"status":"FAIL","details":"No SAN detected!"}

        #msg = "Certificate SAN check"
        return (error)

    def execute(self, alg=True, exp=True, san=True, ca=False, trust=True, extusage=False):

        self.printChain()
        if exp:
            self.expCheck()
        if san:
            self.sanCheck()
            
class parseCert( object ):
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
            self.x509 = load_certificate(FILETYPE_PEM, built_cert)
        else:
            stringed_cert = re.sub("(.{64})", "\\1\n", certdata, 0, re.DOTALL)
            built_cert = "-----BEGIN CERTIFICATE-----\n" + stringed_cert +"\n" + "-----END CERTIFICATE-----"
            lines = '\n'.join([x for x in built_cert.split("\n") if x.strip()!=''])
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
            return decode(item,encoding, errors='surrogateescape')
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
            items.append('%s=%s' %  (self.decode(item[0],'ascii'), self.decode(item[1],'ascii')))
        return ", ".join(items)

    def format_asn1_date(self, d):
        """
        Format an ASN.1 date string.

        Args:
            d (bytes): The ASN.1 date string encoded as bytes.

        Returns:
            str: The formatted date string in the format 'YYYY-MM-DD HH:MM:SS GMT'.
        """

        return datetime.datetime.strptime(self.decode(d,'ascii'), '%Y%m%d%H%M%SZ').strftime("%Y-%m-%d %H:%M:%S GMT")
  
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
        keytype_list = {TYPE_RSA:'rsaEncryption', TYPE_DSA:'dsaEncryption', 408:'id-ecPublicKey'}
        extension_list = ["extendedKeyUsage",
                        "keyUsage",
                        "subjectAltName",
                        "subjectKeyIdentifier",
                        "authorityKeyIdentifier"]

        certificate = {}
        extension = {}
        for i in range(self.x509.get_extension_count()):
            critical = 'critical' if self.x509.get_extension(i).get_critical() else ''
          
            if self.decode(self.x509.get_extension(i).get_short_name(),'ascii') in extension_list:
                try:
                    extension[self.decode(self.x509.get_extension(i).get_short_name(),'ascii')] = self.x509.get_extension(i).__str__()
                except Exception as e:
                    name = self.x509.get_extension(i).get_short_name()
                    extension[self.decode(name,'ascii')] = "FAILED_TO_DECODE"
                    logger.debug("Failed to parse certificate extension %s" % name)
                    
        certificate = {'Thumbprint': self.decode(self.x509.digest('sha1'),'ascii'),
                    'ThumbprintSHA256': self.decode(self.x509.digest('sha256'),'ascii'),
                    'Version': self.x509.get_version(),
                    'SignatureAlg' : self.decode(self.x509.get_signature_algorithm(),'ascii'), 
                    'Issuer' :self.format_subject_issuer(self.x509.get_issuer()), 
                    'Valid From' : self.format_asn1_date(self.x509.get_notBefore()), 
                    'Valid Until' : self.format_asn1_date(self.x509.get_notAfter()),
                    'Subject' : self.format_subject_issuer(self.x509.get_subject())}
        combined = self.merge_cert(extension,certificate)

        cert_output = json.dumps(combined)

        return cert_output
  
    def __str__(self):
        """
        Returns the certificate in string form if desired.
        """
        return self.cert()

def getSDDCTrustedCerts():
    """
        Gets a list of the certificates in the SDDC Manager
        Trust Keystores

        Args:
            None

        Returns:
            commonsvcsCerts (list): List of certificates in the commonsvcs store
            alternativeJreCerts (list): List of certificates in the alternatives JRE store
    """
    commonsvcsCerts = []
    alternativeJreCerts = []
    
    commonsvcsStore = '/etc/vmware/vcf/commonsvcs/trusted_certificates.store'
    commonsvcsPassLocation = '/etc/vmware/vcf/commonsvcs/trusted_certificates.key'
    alternativeJreStore = '/etc/alternatives/jre/lib/security/cacerts'
    alternativeJrePass = 'changeit'
    
    cmd = ['/usr/bin/cat',commonsvcsPassLocation]
    commonsvcsPass = run_command(cmd)
    
    cmd = ['/usr/bin/keytool','-list','-keystore',commonsvcsStore,'--storepass',commonsvcsPass]
    commonsvcsDump = run_command(cmd)

    commonsvcsDump = str(commonsvcsDump, "utf-8")
    commonsvcsDump = commonsvcsDump.split('\n')

    for index,entry in enumerate(commonsvcsDump):
        if '(SHA-256)' in entry:
            alias = commonsvcsDump[index-1].split(",")[0]
            sha256 = entry.split(" ")[3]
            commonsvcsCerts.append([alias,sha256])
    
    cmd = ['/usr/bin/keytool','-list','-keystore',alternativeJreStore,'--storepass',alternativeJrePass]
    alternativeJreDump = run_command(cmd)

    alternativeJreDump = str(alternativeJreDump, "utf-8")
    alternativeJreDump = alternativeJreDump.split('\n')
    
    for index,entry in enumerate(alternativeJreDump):
        if '(SHA-256)' in entry:
            alias = alternativeJreDump[index-1].split(",")[0]
            sha256 = entry.split(" ")[3]
            alternativeJreCerts.append([alias,sha256])
    
    # Return the alias and SHA256 thumbprint for all certs 
    # in the SDDC Manager Trust stores.

    return commonsvcsCerts,alternativeJreCerts

def Reverse(lst):
    """
        Reverses the input list

        Args:
            lst (list): Input list

        Returns:
            list: Reversed List
    """
    new_lst = lst[::-1]
    return new_lst

def getRootCert_openssl(hostname, port):
    """
        Gets the Root certificate using the bash command:
        openssl s_client -connect <hostname>:443 -showcerts
        
        Args:
            hostname (str): Hostname/FQDN
            port (str): Port

        Returns:
            cert: Certificate
    """
    
    cmd = ['openssl','s_client','-connect',f'{hostname}:443','-showcerts']
    output = run_command(cmd)
    output = output.decode()
    outputList = output.split('\n')

    cert = '-----END CERTIFICATE-----\n'
    reversedCert=''
    printing = False
    for line in Reverse(outputList):
        if line.startswith('-----END CERTIFICATE-----'):
            printing = True
            continue
        elif line.startswith('-----BEGIN CERTIFICATE-----'):
            printing = False
            break
        
        if printing:
            cert = cert + line + '\n'
    
    cert = cert + '-----BEGIN CERTIFICATE-----'

    reversedCert = cert.split('\n')
    certList = Reverse(reversedCert)

    cert = '\n'.join(certList)

    return cert