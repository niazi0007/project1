#!/usr/bin/env python
"""
__author__ =  ["Laraib Kazi", "Tyler FitzGerald"]

"""

import logging.config
from importlib import import_module
import requests
import urllib3
import json
import getpass
import logging

logger = logging.getLogger(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def sso_username():
    """
    Returns the SSO Administrator Username
    Default value is administrator@vsphere.local

    Args:
        None

    Returns:
        username (str): sso administrator username

    Raises:
        None
    """
    api_url = 'http://localhost/inventory/domains'
    api_type = "GET"
    response = requests.request(api_type, api_url, verify=False)
    # Setting default ssoName = vsphere.local
    ssoName=''
    try:
        for entry in json.loads(response.text):
            if entry["type"] == "MANAGEMENT":
                ssoName = (entry["ssoName"])
                break
    except:
        ssoName = 'vsphere.local'
    
    username = 'administrator@'+ssoName
    return username

def sso_prompt():
    """
    Promts for the password for the SSO Administrator User

    Args:
        None

    Returns:
        sso_password (str): SSO administrator password

    Raises:
        None
    """
    print('\n')
    sso_password = getpass.getpass('Provide password for %s: ' % sso_username())
    return sso_password

def get_session_token(vcenter, username, password):
    """
    Generates an API session token for the input vCenter server

    Args:
        vcenter (str): vCenter FQDN
        username (str): SSO admin username
        password (str): SSO admin password

    Returns:
        int: Response Status code from the API call
        str: vCenter API Session Token

    Raises:
        None
    """
    api_url = f"https://{vcenter}/rest/com/vmware/cis/session"
        
    response = requests.request("POST", api_url, auth=(username,password), verify=False)
    if response.status_code == 200:
        logger.debug("Session created successfully")
        session_token = response.json()["value"]
        return response.status_code, session_token
    else:
        logger.debug("Failed to create session")
        logger.debug("Response:", response.text)
        return 500, ''

def gen_token_sddc(sso_username, sso_password):
    """
    Generates an API session token for the SDDC Manager

    Args:
        sso_username (str): SSO admin username
        sso_password (str): SSO admin password
        
    Returns:
        str: SDDC Manager API Access Token

    Raises:
        None
    """
    header = {'Content-Type': 'application/json'}
    data = {"username": sso_username,"password": sso_password}
    api_type = "POST"
    api_url = "https://127.0.0.1/v1/tokens"

    response = requests.request(api_type,api_url,headers=header,data=json.dumps(data),verify=False)
    try:
        return(json.loads(response.text)["accessToken"])
    except:
        logger.debug("Failed to get Authentication Token from SDDC Manager.")
        return False