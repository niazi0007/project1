#!/usr/bin/env python3
import sys
from vcenter.vc_lib.common import LDAPOps
from vcenter.vc_cfg.current_defaults import hostname, pnid

def connection_string_check(username, password):
    """
    Checks if the VMDIR STS connection string points to a bad provider.

    Args:
        username (str): The username to connect to the LDAP server.
        password (str): The password to authenticate with the LDAP server.

    Returns:
        dict: A dictionary containing the following fields:
            - title (str): The title of the result indicating if the local OS identity source exists or not.
            - result (str): The result of the check, either 'PASS' or 'WARN'.
            - Note (str): Additional details about the check if the local OS identity source does not exist.
            - documentation (str): A link to the documentation for more information.

    Raises:
        None.
    """
    title = "STS connection string okay"
    details = ""
    documentation = ""
    ldap_query = LDAPOps(username, password)
    connection_string = ""
    filter = f"(&(objectclass=vmwSTSIdentityStore)(vmwSTSProviderType=IDENTITY_STORE_TYPE_VMWARE_DIRECTORY))"
    connection_string = str(ldap_query.search(None, filter, ldap_attributes=['vmwSTSConnectionStrings'])[0].vmwSTSConnectionStrings)

    if any(x in connection_string.lower() for x in [hostname.lower(), pnid.lower(), 'localhost']):
        result = "PASS"
    else:
        result = "FAIL"
        title = f"STS connection string is incorrect ({connection_string})"
        details = "This could prevent services from starting after a recent decommission of another vCenter"
        documentation = "https://kb.vmware.com/s/article/91965"

    return {'title': title, 'result': result, 'Note': details, 'documentation': documentation}
def main(username, password):
    """
    Checks if a local OS identity source exists and returns the result.

    Args:
        username (str): The username to connect to the LDAP server.
        password (str): The password to authenticate with the LDAP server.

    Returns:
        dict: A dictionary containing the following fields:
            - title (str): The title of the result indicating if the local OS identity source exists or not.
            - result (str): The result of the check, either 'PASS' or 'WARN'.
            - Note (str): Additional details about the check if the local OS identity source does not exist.
            - documentation (str): A link to the documentation for more information.

    Raises:
        None.
    """    
    title = "Local OS identity source exists"
    details = ""
    documentation = ""
    ldap_query = LDAPOps(username, password)

    filter = f"(&(objectclass=vmwSTSIdentityStore)(vmwSTSProviderType=IDENTITY_STORE_TYPE_LOCAL_OS))"

    if ldap_query.search(None, filter):
        result = "PASS"
    else:
        result = "WARN"
        title = "Local OS identity source does NOT exist"
        details = "This can cause an issue in vCenter 8.0U2 and U2a with Storage Profiles."
        documentation = "https://kb.vmware.com/s/article/94870"

    return {'title': title, 'result': result, 'Note': details, 'documentation': documentation}