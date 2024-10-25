#!/usr/bin/env python
"""
__author__ =  ["Laraib Kazi", "Tyler FitzGerald", "Keenan Matheny"]
__credits__ = ["Keenan Matheny", "Christopher Morrow", "Fouad Sethna", "Kevin Hagopian"]

"""

import sys
import requests
import logging
from sddc_manager.sddc_cfg.current_defaults import ssoAdmin, commonsvcsCerts, alternativeJreCerts, vcList
from sddc_manager.sddc_lib.certUtils import *
from sddc_manager.sddc_lib.authUtils import get_session_token, sso_prompt

logger = logging.getLogger(__name__)

def getVcTrustedRoots(vcenter, session_token):
    """
    Gets list of 'chain ids' for all entries in Trusted Roots
    Store of the vCenter Server

    Args:
        vcenter (str): FQDN of the vCenter
        session_token (str): API Session token for the vCenter

    Returns:
        trustedCerts (list): List of the Trusted Root Certificates
    """
    rootChainIds = []
    api_url = f'https://{vcenter}/api/vcenter/certificate-management/vcenter/trusted-root-chains'
    headers = {'vmware-api-session-id': session_token}
    response = requests.get(api_url, headers=headers, verify=False)
    for element in response.json():
        rootChainIds.append(element["chain"])
    
    # Gets list of certificates for each entry in 'chain ids'
    trustedCerts = []
    for chain in rootChainIds:
        api_url = f'https://{vcenter}/api/vcenter/certificate-management/vcenter/trusted-root-chains/{chain}'
        headers = {'vmware-api-session-id': session_token}
        response = requests.get(api_url, headers=headers, verify=False)
        output = response.json()["cert_chain"]
        splitOutput = output["cert_chain"][0].split('\n')
        trustedCert = '-----BEGIN CERTIFICATE-----\n'
        for line in splitOutput:
            if line.startswith('-----BEGIN CERTIFICATE-----'):
                printing = True
                continue
            elif line.startswith('-----END CERTIFICATE-----'):
                printing = False
                break
            if printing:
                trustedCert = trustedCert + line + '\n'
        trustedCert = trustedCert + '-----END CERTIFICATE-----'

        trustedCerts.append(trustedCert)
        
    return trustedCerts

def getVcRootCA(vcenter, session_token):
    """
    Identifies the VC Root Signing Certificate

    Args:
        vcenter (str): FQDN of the vCenter
        session_token (str): API Session token for the vCenter

    Returns:
        VcRootCACert (str): Root CA Signing Certificate for a given vCenter Server
    """
    # Get vCenter cert on 443:
    vcCert = getSslCert(vcenter,'443')
    vcCertObj = Cert(vcCert)
    
    # Get List of Trusted Certs from VC:
    trustedCerts = getVcTrustedRoots(vcenter, session_token) 

    vcAuthKey = vcCertObj.authkey.replace('keyid:','').replace('\n','')
    VcRootCACert = getSigningCert(trustedCerts, vcAuthKey)
                
    return VcRootCACert

def getSigningCert(trustedCertList,checkAuthKey):
    """
    Returns the Signing Certificate for a given Auth Key Id
    from a list of Trusted Certificates

    Args:
        trustedCertList (list): List of Trusted Certificates
        cert (str): Signing Certificate

    Returns:
        VcRootCACert (str): Root CA Signing Certificate for a given vCenter Server
    """
    for cert in trustedCertList:
        certObj = Cert(cert)
        if checkAuthKey == certObj.subjectkey:
            if (certObj.authkey == certObj.subjectkey) or (certObj.authkey is None):
                return cert
            else:
                checkAuthKey = certObj.authkey.replace('keyid:','').replace('\n','')
                getSigningCert(trustedCertList,checkAuthKey)  
       
def main(username,password):
    """
    Checks the certificate status (Trust, expiration, SAN) for
    all vCenters in VCF Inventory

    Args:
        username (str): SSO Admin Username
        password (str): SSO Admin password

    Returns:
        result (dict): Result of the Certificate Status Check
    """    
    # Get list of VCs:
    results = []
    # Cycle through list of VCs for checks:
    for vc in vcList:
        '''
        Checking if VC root exists in SDDC Trust stores
        '''
        # Getting VC API Token
        status, token = get_session_token(vc["hostname"], username, password)
        # Using Token to get VC Root via API
        vcRoot = getVcRootCA(vc["hostname"], token)
        vcRoot = Cert(vcRoot)
        # Checking against SDDC Trust Stores
        rootTrustCheck = sddcTrustCheck(commonsvcsCerts, alternativeJreCerts, vcRoot.sha256)

        # Get VC Cert on Port 443
        vcCert = getSslCert(vc["hostname"],'443')
        # Check if the Cert if expiring:
        expResult = checkCert(vcCert).expCheck()
        expCheck = {"title":f'Expiration Check',"result":expResult["status"], "details":expResult["details"]}
        # SAN Check for Cert:
        sanResult = checkCert(vcCert,vc["hostname"],vc["ip"]).sanCheck()
        sanCheck = {"title":f'Subject Alternative Name Check',"result":sanResult["status"], "details":sanResult["details"]}
        
        #return [rootTrustCheck, expCheck, sanCheck]
        checks = [rootTrustCheck, expCheck, sanCheck]
        results.append({'subheading': f'{vc["hostname"]}', 'checks': checks})
    return results
    
if __name__ == '__main__':
    if len(sys.argv) > 2:
        main(sys.argv[1], sys.argv[2])
    else:
        username = ssoAdmin
        password = sso_prompt()
        main(username,password)
    