#!/usr/bin/env python
"""
__author__ =  ["Laraib Kazi", "Tyler FitzGerald"]
__credits__ = ["Sydney Young"]

"""
import requests
import urllib3
import json
import logging

logger = logging.getLogger(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def getMgmtVC():
    """
    Gets the Management WLD vCenter, IP address and version

    Args:
        None

    Returns:
        str: Management VC Hostname
        str: Management VC IP Address
        str: Management VC Version

    """
    api_url = 'http://localhost/inventory/vcenters'
    api_type = "GET"
    response = requests.request(api_type, api_url, verify=False)

    vcenters = json.loads(response.text)
    for entry in vcenters:        
        if entry["domainType"] == "MANAGEMENT":
            return entry["hostName"],entry["managementIpAddress"],entry["version"]

def listVCenters():
    """
    Gets a list of the vCenters in the SDDC Manager inventory
    
    Args:
        None

    Returns:
        list: List of dict objects with the vCenter hostnames and IP Addresses

    """
    api_url = 'http://localhost/inventory/vcenters'
    api_type = "GET"
    response = requests.request(api_type, api_url, verify=False)

    vcList = []
    vcenters = json.loads(response.text)
    for entry in vcenters:        
        vcList.append({"hostname":entry["hostName"],"ip":entry["managementIpAddress"]})
    
    # Returns a list of all the vCenters in the 
    # SDDC Manager Inventory
    return vcList

def listnsxtManagers():
    """
    Gets a list of the NSX Managers in the SDDC Manager inventory
    
    Args:
        None

    Returns:
        list: List of dict objects with the NSX Manager hostnames and IP Addresses (including the VIP)
        
    """
    api_url = 'http://localhost/inventory/nsxt'
    api_type = "GET"
    response = requests.request(api_type, api_url, verify=False)

    nsxManagerList = []
    nsxM = json.loads(response.text)
    for entry in nsxM:
        nsxManagerList.append({"hostname":entry["clusterFqdn"],"ip":entry["clusterIpAddress"]})   
        clusterDetails = entry["nsxtClusterDetails"]
        for manager in clusterDetails:
            nsxManagerList.append({"hostname":manager["fqdn"],"ip":manager["ipAddress"]})
    
    # Returns a list of all the NSX-T Managers and
    # NSX-T VIP in the SDDC Manager Inventory
    return nsxManagerList

def nsxManagerVIPList():
    """
    Gets a list of the NSX Manager VIPs in the SDDC Manager inventory
    
    Args:
        None

    Returns:
        list: List of NSX Manager VIP Hostnames

    """
    api_url = 'http://localhost/inventory/nsxt'
    api_type = "GET"
    response = requests.request(api_type, api_url, verify=False)

    nsxVIPList = []
    nsxM = json.loads(response.text)
    for entry in nsxM:
        nsxVIPList.append(entry["clusterFqdn"]) 
    
    return nsxVIPList

def vrslcmInfo():
    """
    Gets vRSLCM Info from local inventory API

    Returns:
        dict: A dictionary containing the following information:
            - hostname (string): Hostname of the vRSLCM Node
            - version (string): Version of the vRSLCM Node
            - status (string): Status of the vRSLCM Node
    """
    api_url = 'http://localhost/inventory/vrslcms'
    api_type = "GET"
    response = requests.request(api_type, api_url, verify=False)
    
    try:
        vrslcmResponse = response.json()[0]
        logger.debug(f'vRSLCM instance found: {vrslcmResponse}') 
        vrslcmHostname = vrslcmResponse['vrslcmNode']['hostName']
        vrslcmVersion = vrslcmResponse['version']
        vrslcmStatus = vrslcmResponse['status']
        return {'hostname':vrslcmHostname, 'version':vrslcmVersion, 'status':vrslcmStatus}
    except Exception as e:
        logger.error(f'Failed to get vRSLCM instance in SDDC Manager. Exception: {e}')
        return None
    
def vropsInfo():
    """
    Gets vROPs Info from local inventory API

    Returns:
        dict: A dictionary containing the following information:
            - loadbalancer (string): Hostname of the Load Balancer for vROPS
            - masterHostname (string): Hostname of the vROPS Master Node
            - version (string): Version of vROPS
            - status (string): Status of vROPS
    """
    api_url = 'http://localhost/inventory/vrops'
    api_type = "GET"
    response = requests.request(api_type, api_url, verify=False)
    
    try:
        vropsResponse = response.json()[0]
        logger.debug(f'vROPS instance found: {vropsResponse}') 
        vropsLBHostname = vropsResponse['loadBalancerHostname']
        vropsMasterHostname = vropsResponse['masterNode']['hostName']
        vropsVersion = vropsResponse['version']
        vropsStatus = vropsResponse['status']
        return {'loadbalancer':vropsLBHostname, 'masterHostname':vropsMasterHostname, 'version':vropsVersion, 'status':vropsStatus}
    except Exception as e:
        logger.error(f'Failed to get vROPS instance in SDDC Manager. Exception: {e}')
        return None

def vrliInfo():
    """
    Gets vRLI Info from local inventory API

    Returns:
        dict: A dictionary containing the following information:
            - loadbalancer (string): Hostname of the Load Balancer for vRLI
            - masterHostname (string): Hostname of the vRLI Master Node
            - version (string): Version of vRLI
            - status (string): Status of vRLI
    """
    api_url = 'http://localhost/inventory/vrlis'
    api_type = "GET"
    response = requests.request(api_type, api_url, verify=False)
    
    try:
        vrliResponse = response.json()[0]
        logger.debug(f'vRLI instance found: {vrliResponse}') 
        vrliLBHostname = vrliResponse['loadBalancerHostname']
        vrliMasterHostname = vrliResponse['masterNode']['hostName']
        vrliVersion = vrliResponse['version']
        vrliStatus = vrliResponse['status']
        return {'loadbalancer':vrliLBHostname, 'masterHostname':vrliMasterHostname, 'version':vrliVersion, 'status':vrliStatus}
    except Exception as e:
        logger.error(f'Failed to get vRLI instance in SDDC Manager. Exception: {e}')
        return None
    
def vraInfo():
    """
    Gets vRA Info from local inventory API

    Returns:
        dict: A dictionary containing the following information:
            - loadbalancer (string): Hostname of the Load Balancer for vRA
            - nodes (list): List of dicts for the vRA nodes
            - version (string): Version of vRA
            - status (string): Status of vRA
    """
    api_url = 'http://localhost/inventory/vras'
    api_type = "GET"
    response = requests.request(api_type, api_url, verify=False)
    
    try:
        vraResponse = response.json()[0]
        logger.debug(f'vRA instance found: {vraResponse}') 
        vraLBHostname = vraResponse['cafeLbHostname']
        vraNodes = vraResponse['cafeNodes']
        vraVersion = vraResponse['version']
        vraStatus = vraResponse['status']
        return {'loadbalancer':vraLBHostname, 'nodes':vraNodes, 'version':vraVersion, 'status':vraStatus}
    except Exception as e:
        logger.error(f'Failed to get vRA instance in SDDC Manager. Exception: {e}')
        return None

def wsaInfo():
    """
    Gets Workspace One Access Info from local inventory API

    Returns:
        dict: A dictionary containing the following information:
            - loadbalancer (string): Hostname of the Load Balancer for WSA
            - primaryHostname (string): Hostname of the WSA Primary Node
            - version (string): Version of WSA
            - status (string): Status of WSA
    """
    api_url = 'http://localhost/inventory/wsas'
    api_type = "GET"
    response = requests.request(api_type, api_url, verify=False)
    
    try:
        wsaResponse = response.json()[0]
        logger.debug(f'WSA instance found: {wsaResponse}') 
        wsaLBHostname = wsaResponse['lbHostname']
        wsaPrimaryHostname = wsaResponse['primaryNode']['hostName']
        wsaVersion = wsaResponse['version']
        wsaStatus = wsaResponse['status']
        return {'loadbalancer':wsaLBHostname, 'primaryHostname':wsaPrimaryHostname, 'version':wsaVersion, 'status':wsaStatus}
    except Exception as e:
        logger.error(f'Failed to get WSA instance in SDDC Manager. Exception: {e}')
        return None