#!/usr/bin/env python

import json
import requests
import urllib3
import logging
import ast
from lib.vdt_formatter import bcolors

from sddc_manager.sddc_cfg.current_defaults import isVxRail


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

def runRestAPIcall(api,type,headers,data=None):
    # Function to run auth API calls
    if data:
        response = requests.request(type, api, headers=headers, data=data, verify=False)
    else:
        response = requests.request(type, api, headers=headers, verify=False)
    return response.text

def getLocalEdgeClusters():
    """
    Gets a list of Edge Clusters from SDDC Manager Inventory

    Args:
        None

    Returns:
        json: Output containing a JSON list of all Edge Clusters in the VCF Inventory
    """
    api_url = f'http://localhost/inventory/nsxt-edgeclusters'
    api_type = "GET"
    response = requests.request(api_type,api_url,verify=False)
    localEdgeClusters = response.json()
    
    if localEdgeClusters == []:
        return False
    else:
        return True

def check_Host_inv():
    """
    Checks the Hosts inventory status with the SDDC Manager

    Args:
        None

    Returns:
        str: Hosts not in an ACTIVE state
    """ 
    header = {'Content-Type': 'application/json'}
    api_url = "http://localhost/inventory/hosts"
    api_type = "GET"

    try:
        apiResponse = runRestAPIcall(api_url,api_type,header)
        data = json.loads(apiResponse)
        erroredHosts = ''

        for entry in data:
            OpStatus = entry["status"]
            if OpStatus == "ERROR":
                OpId = entry["id"]
                resourceName = entry["hostName"]
                resourceStatus = entry["status"]
                erroredHosts += (f'{OpId} | {resourceName} | {bcolors.WARNING}{resourceStatus}{bcolors.ENDC}' + "\n")
        return erroredHosts

    except requests.exceptions.RequestException as e:
        return f"Error making the request: {e}"
    
def check_Domains():
    """
    Checks the Domains inventory status with the SDDC Manager

    Args:
        None

    Returns:
        str: Domains not in an ACTIVE state
    """ 
    header = {'Content-Type': 'application/json'}
    api_url = "http://localhost/inventory/domains"
    api_type = "GET"

    try:
        apiResponse = runRestAPIcall(api_url,api_type,header)
        data = json.loads(apiResponse)
        erroredDomains = ''

        for entry in data:
            OpStatus = entry["status"]
            if OpStatus == "ERROR":
                OpId = entry["id"]
                resourceName = entry["name"]
                resourceStatus = entry["status"]
                erroredDomains += (f'{OpId} | {resourceName} | {bcolors.FAIL}{resourceStatus}{bcolors.ENDC}' + "\n")
        return erroredDomains

    except requests.exceptions.RequestException as e:
        return f"Error making the request: {e}"
    
def check_cluster():
    """
    Checks the Clusters inventory status with the SDDC Manager

    Args:
        None

    Returns:
        str: Clusters not in an ACTIVE state
    """ 
    header = {'Content-Type': 'application/json'}
    api_url = "http://localhost/inventory/clusters"
    api_type = "GET"

    try:
        apiResponse = runRestAPIcall(api_url,api_type,header)
        data = json.loads(apiResponse)
        erroredClusters = ''

        for entry in data:
            OpStatus = entry["status"]
            if OpStatus == "ERROR":
                OpId = entry["id"]
                resourceName = entry["name"]
                resourceStatus = entry["status"]
                erroredClusters += (f'{OpId} | {resourceName} | {bcolors.FAIL}{resourceStatus}{bcolors.ENDC}' + "\n")
        return erroredClusters

    except requests.exceptions.RequestException as e:
        return f"Error making the request: {e}"
    
def check_vCenters():
    """
    Checks the vCenters inventory status with the SDDC Manager

    Args:
        None

    Returns:
        str: vCenters not in an ACTIVE state
    """ 
    header = {'Content-Type': 'application/json'}
    api_url = "http://localhost/inventory/vcenters"
    api_type = "GET"

    try:
        apiResponse = runRestAPIcall(api_url,api_type,header)
        data = json.loads(apiResponse)
        erroredvCenters = ''

        for entry in data:
            OpStatus = entry["status"]
            if OpStatus == "ERROR":
                OpId = entry["id"]
                resourceName = entry["hostName"]
                resourceStatus = entry["status"]
                erroredvCenters += (f'{OpId} | {resourceName} | {bcolors.FAIL}{resourceStatus}{bcolors.ENDC}' + "\n")
        return erroredvCenters

    except requests.exceptions.RequestException as e:
        return f"Error making the request: {e}"
    
def check_pscs():
    """
    Checks the PSC inventory status with the SDDC Manager

    Args:
        None

    Returns:
        str: PSC not in an ACTIVE state
    """ 
    header = {'Content-Type': 'application/json'}
    api_url = "http://localhost/inventory/pscs"
    api_type = "GET"

    try:
        apiResponse = runRestAPIcall(api_url,api_type,header)
        data = json.loads(apiResponse)
        erroredPscs = ''

        for entry in data:
            OpStatus = entry["status"]
            if OpStatus == "ERROR":
                OpId = entry["id"]
                resourceName = entry["hostName"]
                resourceStatus = entry["status"]
                erroredPscs += (f'{OpId} | {resourceName} | {bcolors.FAIL}{resourceStatus}{bcolors.ENDC}' + "\n")
        return erroredPscs

    except requests.exceptions.RequestException as e:
        return f"Error making the request: {e}"
    
def check_vxrail():
    """
    Checks the VxRail inventory status with the SDDC Manager

    Args:
        None

    Returns:
        str: VxRail not in an ACTIVE state
    """ 
    header = {'Content-Type': 'application/json'}
    api_url = "http://localhost/inventory/vxmanagers"
    api_type = "GET"

    try:
        apiResponse = runRestAPIcall(api_url,api_type,header)
        data = json.loads(apiResponse)

        if not data:
            return "No VxRail Managers found in inventory"
        
        erroredVxRails = ''

        for entry in data:
            OpStatus = entry["status"]
            if OpStatus == "ERROR":
                OpId = entry["id"]
                resourceName = entry["hostName"]
                resourceStatus = entry["status"]
                erroredVxRails += (f'{OpId} | {resourceName} | {bcolors.FAIL}{resourceStatus}{bcolors.ENDC}' + "\n")
        return erroredVxRails

    except requests.exceptions.RequestException as e:
        return f"Error making the request: {e}"
    
def check_nsxt_mgrs():
    """
    Checks the NSX Manager inventory status with the SDDC Manager

    Args:
        None

    Returns:
        str: NSX Manager not in an ACTIVE state
    """ 
    header = {'Content-Type': 'application/json'}
    api_url = "http://localhost/inventory/nsxt"
    api_type = "GET"

    try:
        apiResponse = runRestAPIcall(api_url,api_type,header)
        data = json.loads(apiResponse)
        erroredNsx = ''

        for entry in data:
            OpStatus = entry["status"]
            if OpStatus == "ERROR":
                OpId = entry["id"]
                resourceName = entry["clusterFqdn"]
                resourceStatus = entry["status"]
                erroredNsx += (f'{OpId} | {resourceName} | {bcolors.FAIL}{resourceStatus}{bcolors.ENDC}' + "\n")
        return erroredNsx

    except requests.exceptions.RequestException as e:
        return f"Error making the request: {e}"

def check_edges():
    """
    Checks the NSX Edge inventory status with the SDDC Manager

    Args:
        None

    Returns:
        str: NSX Edge not in an ACTIVE state
    """ 
    header = {'Content-Type': 'application/json'}
    api_url = "http://localhost/inventory/nsxt-edgeclusters"
    api_type = "GET"

    try:
        apiResponse = runRestAPIcall(api_url,api_type,header)
        data = json.loads(apiResponse)

        if not data:
            return "No NSX Edges found in inventory"

        erroredNsx = ''

        for entry in data:
            OpStatus = entry["status"]
            if OpStatus == "ERROR":
                OpId = entry["nsxtClusterId"]
                resourceName = entry["name"]
                resourceStatus = entry["status"]
                erroredNsx += (f'{OpId} | {resourceName} | {bcolors.FAIL}{resourceStatus}{bcolors.ENDC}' + "\n")
        return erroredNsx

    except requests.exceptions.RequestException as e:
        return f"Error making the request: {e}"

def main():
    """
    Runs the check for all inventory components
    and accumulates a list of final results

    Args:
        None

    Returns:
        list: List of dict objects containing results of various inventory checks
    """ 
    IsVxRail = ast.literal_eval(isVxRail)

    edgecheck = getLocalEdgeClusters()
    erroredHosts = check_Host_inv()
    erroredDomains = check_Domains()
    erroredvCenters= check_vCenters()
    erroredClusters = check_cluster()
    erroredPscs = check_pscs()
    if IsVxRail is True:
        erroredVxRail = check_vxrail()
    
    erroredNsxmgrs = check_nsxt_mgrs()

    if edgecheck is True:
        erroredNsxedges = check_edges()
    
    finalResult = []

    title='Host Status Check'
    if erroredHosts=='':
        resultDetails=f'All hosts are in an {bcolors.OKGREEN}ACTIVE{bcolors.ENDC} state.'
        result = "PASS"
    else:
        resultDetails = erroredHosts
        result = "FAIL"
    finalResult.append({"title":title, "result":result, "details":resultDetails})

    title='Domain Status Check'
    if erroredDomains=='':
        resultDetails=f'All domains are in an {bcolors.OKGREEN}ACTIVE{bcolors.ENDC} state.'
        result = "PASS"
    else:
        resultDetails = erroredDomains
        result = "FAIL"
    finalResult.append({"title":title, "result":result, "details":resultDetails})

    title='vCenter Status Check'
    if erroredvCenters=='':
        resultDetails=f'All vCenters are in an {bcolors.OKGREEN}ACTIVE{bcolors.ENDC} state.'
        result = "PASS"
    else:
        resultDetails = erroredvCenters
        result = "FAIL"
    finalResult.append({"title":title, "result":result, "details":resultDetails})

    title='PSCs Status Check'
    if erroredPscs=='':
        resultDetails=f'All PSCs are in an {bcolors.OKGREEN}ACTIVE{bcolors.ENDC} state.'
        result = "PASS"
    else:
        resultDetails = erroredPscs
        result = "FAIL"
    finalResult.append({"title":title, "result":result, "details":resultDetails})

    if IsVxRail is True:
        title='VxRail Status Check'    
        if erroredVxRail=='':
            resultDetails=f'All VxRail Managers are in an {bcolors.OKGREEN}ACTIVE{bcolors.ENDC} state.'
            result = "PASS"
        else:
            resultDetails = erroredVxRail
            result = "FAIL"
        finalResult.append({"title":title, "result":result, "details":resultDetails})
    
    title='Cluster Status Check'
    if erroredClusters=='':
        resultDetails=f'All Clusters are in an {bcolors.OKGREEN}ACTIVE{bcolors.ENDC} state.'
        result = "PASS"
    else:
        resultDetails = erroredClusters
        result = "FAIL"
    finalResult.append({"title":title, "result":result, "details":resultDetails})

    title='NSX Manager Status Check'
    if erroredNsxmgrs=='':
        resultDetails=f'All NSX Managers are in an {bcolors.OKGREEN}ACTIVE{bcolors.ENDC} state.'
        result = "PASS"
    else:
        resultDetails = erroredNsxmgrs
        result = "FAIL"
    finalResult.append({"title":title, "result":result, "details":resultDetails})

    if edgecheck is True:

        title='NSX Edge Status Check'
        if erroredNsxedges=='':
            resultDetails=f'All NSX Edges are in an {bcolors.OKGREEN}ACTIVE{bcolors.ENDC} state.'
            result = "PASS"
        else:
            resultDetails = erroredNsxedges
            result = "FAIL"
        finalResult.append({"title":title, "result":result, "details":resultDetails})
    
    return finalResult
