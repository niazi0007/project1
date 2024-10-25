#!/usr/bin/env python
"""
__author__ =  ["Laraib Kazi", "Tyler FitzGerald", "Keenan Matheny"]
__credits__ = ["Keenan Matheny", "Christopher Morrow", "Fouad Sethna", "Kevin Hagopian"]

"""

import logging
from sddc_manager.sddc_cfg.current_defaults import commonsvcsCerts, alternativeJreCerts
from sddc_manager.sddc_lib.certUtils import *
from sddc_manager.sddc_lib.inventoryUtils import listnsxtManagers

logger = logging.getLogger(__name__)
   
def main():
    """
    Checks the certificate status (Trust, expiration, SAN) for
    all NSX Managers in VCF Inventory

    Args:
        None

    Returns:
        result (dict): Result of the Certificate Status Check
    """
    # Get list of NSX Managers: 
    nsxList = listnsxtManagers() 
    results = []
    # Cycle through list of VCs for checks:
    for nsx in nsxList:
        # Checking if NSX root exists in SDDC Trust stores
        # Get NSX Root CA Cert
        nsxRoot = getRootCert_openssl(nsx["hostname"], '443')
        # Converting to SHA256 Thumbpring
        cert = Cert(nsxRoot)
        nsxRoot256 = cert.sha256
        # Checking against SDDC Trust Stores
        rootTrustCheck = sddcTrustCheck(commonsvcsCerts, alternativeJreCerts, nsxRoot256)

        # Get NSX Cert on Port 443
        nsxCert = getSslCert(nsx["hostname"],'443')
        # Check if the Cert if expiring:
        expResult = checkCert(nsxCert).expCheck()
        expCheck = {"title":'Expiration Check',"result":expResult["status"], "details":expResult["details"]}
        # SAN Check for Cert:
        sanResult = checkCert(nsxCert,nsx["hostname"],nsx["ip"]).sanCheck()
        sanCheck = {"title":'Subject Alternative Name Check',"result":sanResult["status"], "details":sanResult["details"]}
        
        checks = [rootTrustCheck, expCheck, sanCheck]
        results.append({'subheading': f'{nsx["hostname"]}', 'checks': checks})
    return results

if __name__ == '__main__':
    main()