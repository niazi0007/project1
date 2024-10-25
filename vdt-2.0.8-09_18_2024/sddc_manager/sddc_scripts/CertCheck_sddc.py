#!/usr/bin/env python
"""
__author__ =  ["Laraib Kazi", "Tyler FitzGerald", "Keenan Matheny"]
__credits__ = ["Keenan Matheny", "Christopher Morrow", "Fouad Sethna", "Kevin Hagopian"]

"""
from sddc_manager.sddc_cfg.current_defaults import sddcHostname, sddcIp, commonsvcsCerts, alternativeJreCerts
from sddc_manager.sddc_lib.certUtils import *

import logging

logger = logging.getLogger(__name__)

def main():
    """
    Checks the certificate status (Trust, expiration, SAN) for
    the SDDC Manager Certificate

    Args:
        None

    Returns:
        result (dict): Result of the Certificate Status Check
    """
    sddcMhostname = sddcHostname
    sddcRoot = getRootCert_openssl(sddcMhostname, '443')
    # Converting to SHA256 Thumbpring
    cert = Cert(sddcRoot)
    sddcRoot256 = cert.sha256
    # Checking against SDDC Trust Stores
    rootTrustCheck = sddcTrustCheck(commonsvcsCerts, alternativeJreCerts, sddcRoot256)
        
    # Get SDDC Cert on Port 443
    sddcCert = getSslCert(sddcMhostname,'443')
    # Check if the Cert if expiring:
    expResult = checkCert(sddcCert).expCheck()
    expCheck = {"title":'Expiration Check',"result":expResult["status"], "details":expResult["details"]}
    # SAN Check for Cert:
    sanResult = checkCert(sddcCert,sddcMhostname,sddcIp).sanCheck()
    sanCheck = {"title":'Subject Alternative Name Check',"result":sanResult["status"], "details":sanResult["details"]}
    
    return [rootTrustCheck, expCheck, sanCheck]
    
if __name__ == '__main__':
    main()
    