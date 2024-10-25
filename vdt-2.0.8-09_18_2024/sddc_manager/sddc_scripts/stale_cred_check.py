#!/usr/bin/env python
"""
__author__ =  ["Laraib Kazi", "Tyler FitzGerald"]
__credits__ = ["Keenan Matheny"]

"""

import logging
import requests
from sddc_manager.sddc_lib.authUtils import gen_token_sddc
from lib.vdt_formatter import bcolors

logger = logging.getLogger(__name__)

def getHostIds():
    """
    Gets all ESXi Host entity IDs
    
    Args:
        None

    Returns:
        list: A list of ESXi Host Entity IDs
    """
    api_url = 'http://localhost/inventory/hosts'
    hostIds = []
    try:
        response = requests.get(api_url)
        if response.status_code == 200:
            data = response.json()
            for host in data:
                host_id = host.get('id', 'N/A')
                hostIds.append(host_id)
            return hostIds
        else:
            logger.error(f"HTTP request failed with status code {response.status_code}")

    except Exception as e:
        logger.eror(f"An error occurred: {str(e)}")
        return None

def get_host_creds(access_token):
    """
    Gets all ESXi credential entries stored in the SDDC Manager
    
    Args:
        access_token (str): API access token for the SDDC Manager

    Returns:
        json: A json object with a list of ESXi Credential details
    """
    header = {'Authorization': f'Bearer {access_token}'}
    api_url = "https://localhost/v1/credentials?resourceType=ESXI"
    api_type = "GET"
    try:
        response = requests.request(api_type, api_url, headers=header, verify=False)
        if response.status_code == 200:
            data = response.json()["elements"]
            return data
        else:
            logger.error(f"HTTP request failed with status code {response.status_code}")
        
    except requests.exceptions.RequestException as e:
        logger.error(f'Error making the request: {e}')

def get_stale_host_creds(access_token):
    """
    Check for any stale credentials for ESXi hosts that are no longer
    in the SDDC Manager inventory
    
    Args:
        access_token (str): API access token for the SDDC Manager

    Returns:
        dict: A dictionary objects with the following keys:
            - title (str): The title of the result.
            - result (str): The status or result of the query.
            - details (str): Details of the specific that credentials for resources.
    """
    hostIds = getHostIds()
    hostCredInfo = get_host_creds(access_token)
    
    title = 'Stale Credentials for ESXi Hosts'
    details = ''
    
    for entry in hostCredInfo:
        if entry["resource"]["resourceId"] not in hostIds:
            details += f'{bcolors.WARNING}Stale Credential found for ESXi: {entry["resource"]["resourceName"]} | Credential ID: {entry["id"]}{bcolors.ENDC}'
    
    if details == '':
        result = 'PASS'
        details = 'No Stale ESXi Credentials detected.'
    else:
        result = 'FAIL'
    
    returnCheck = {"title":title, "result":result, "details":details}
    logger.info(f'Return: {returnCheck}')    
    return returnCheck 
    
def get_stale_creds(username, password):
    """
    Check for any stale credentials (i.e credentials for entities that are no longer
    available in SDDC Manager Inventory)

    Args:
        username (str): SSO Admin Username
        password (str): SSO Admin password

    Returns:
        list: A list of dictionary objects with the following keys:
            - title (str): The title of the result.
            - result (str): The status or result of the query.
            - details (str): Details of the specific that credentials for resources.
    """
    access_token = gen_token_sddc(username,password)
    
    host_cred_check = get_stale_host_creds(access_token)
    
    # TODO:
    # vc_cred_check
    # nsxt_cred_check
    # aria_cred_check
    # nsx_edge_cred_check
    
    returnCheck = [host_cred_check]
    logger.info(f'Final Return: {returnCheck}')    
    return returnCheck