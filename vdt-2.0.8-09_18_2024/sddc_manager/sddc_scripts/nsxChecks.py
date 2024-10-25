#!/usr/bin/env python
"""
__author__ =  ["Laraib Kazi", "Tyler FitzGerald"]
__credits__ = ["Keenan Matheny"]

"""
import json
import requests
import urllib3
from sddc_manager.sddc_lib.authUtils import gen_token_sddc
from sddc_manager.sddc_cfg.current_defaults import vcList, nsxVipList
from lib.vdt_formatter import bcolors


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import logging

logger = logging.getLogger(__name__)

def getNSXVIPAdminCredential(nsxVipFqdn,token):
    """
    Gets admin password for given NSX VIP

    Args:
        nsxVipFqdn (str): FQDN of the NSX VIP
        token (str): API Access Token for the SDDC Manager

    Returns:
        str: Password for the 'admin' user
    """ 
    api_url = f'https://localhost/v1/credentials?resourceName={nsxVipFqdn}&accountType=SYSTEM'
    api_type = "GET"
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.request(api_type,api_url,headers=headers, verify=False)
    systemCreds = json.loads(response.text)["elements"]
    for entry in systemCreds:
        if entry["credentialType"] == "API":
            adminPass = entry["password"]
            break
    
    return adminPass

def getComputeManagers(nsxVipFqdn,adminPass):
    """
    Gets a list of Compute Managers from NSX Inventory
    
    Args:
        nsxVipFqdn (str): FQDN of the NSX VIP
        adminPass (str): Password for the 'admin' user for NSX

    Returns:
        list: List of Compute Manager Names
    """
    api_url = f'https://{nsxVipFqdn}/api/v1/fabric/compute-managers'
    api_type = "GET"
    response = requests.request(api_type,api_url,auth=('admin',adminPass),verify=False)
    
    computeManagerList = []
    vCenters = json.loads(response.text)["results"]
    for entry in vCenters:
        computeManagerList.append(entry["server"])
        
    return computeManagerList

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
    
    return localEdgeClusters

def getEdgeClusters(nsxVipFqdn,adminPass):
    """
    Get a list of Edge Clusters from NSX Inventory

    Args:
        nsxVipFqdn (str): FQDN of the NSX VIP
        adminPass (str): Password for the 'admin' user for NSX

    Returns:
        json: Output containing a JSON list of all Edge Clusters in the NSX environment
    """
    api_url = f'https://{nsxVipFqdn}/api/v1/edge-clusters'
    api_type = "GET"
    response = requests.request(api_type,api_url,auth=('admin',adminPass),verify=False)
    nsxEdgeClusters = response.json()["results"]
    
    return nsxEdgeClusters

def getSharedNSXclusters():
    """
    Gets a list of the NSX Manager VIPs in the SDDC Manager inventory that are shared
    across WLDs
    
    Args:
        None

    Returns:
        list: List of dicts containing the NSX Manager VIP Hostnames and affiliated domainIds

    """
    api_url = 'http://localhost/inventory/nsxt'
    api_type = "GET"
    response = requests.request(api_type, api_url, verify=False)
    sharedNsxClusters = []
    
    for entry in response.json():
        if entry["shared"]=='true':
            sharedNsxClusters.append({"domainIds":entry["domainIds"], "clusterFqdn":entry["clusterFqdn"]})
    
    return sharedNsxClusters

def getDomains():
    """
    Gets a list of the Workload domains in the SDDC Manager inventory

    Returns:
        list : A list of dicts containing the domain ids and names
    """
    api_url = 'http://localhost/inventory/domains'
    api_type = "GET"
    response = requests.request(api_type, api_url, verify=False)
    domains = []
    
    for entry in response.json():
        domains.append({"id":entry["id"], "name":entry["name"]})
    
    return domains

def shared_nsxCluster_check():
    """
    Checks if there are any shared NSX Clusters
    
    Args:
        None

    Returns:
        dict: A dictionary with the following keys:
            - title (str): The title of the result.
            - result (str): Information level result.
            - details (str): Contain the information of the Shared NSX Cluster VIP FQDNs
                            and the Domain Names.
    """
    sharedNsxClusters = getSharedNSXclusters()
    sddcDomains = getDomains()
    
    title='Shared NSX Clusters'
    details=""
    
    if sharedNsxClusters == []:
        details='No Shared NSX Clusters.'
        logger.info(details)
    else:
        for cluster in sharedNsxClusters:
            sharedDomainNames = []
            for domainFromNsx in cluster["domainIds"]:
                for domain in sddcDomains:
                    if domainFromNsx==domain["id"]:
                        sharedDomainNames.append(domain["name"])
                        logger.debug(f'Shared Domain Id: {domain["id"]} corresponds to Shared Domain Name: {domain["name"]}')
            if sharedDomainNames != []:
                sharedDomains = (', '.join(domain for domain in sharedDomainNames))
                details += f'NSX Cluster {cluster["clusterFqdn"]} is shared between WLDs: {sharedDomains}\n'
                logger.info(f'NSX Cluster {cluster["clusterFqdn"]} is shared between WLDs: {sharedDomains}')
                
    return {"title":title, "result":'INFO', "details":details}
    
def compute_manager_check(username, password):
    """
    Checks if the compute managers in NSX Environments match the
    vCenter entries in the SDDC Manager 
    
    Args:
        username (str): SSO Admin Username
        password (str): SSO Admin password

    Returns:
        dict: A dictionary with the following keys:
            - title (str): The title of the result.
            - result (str): The status or result of the query.
            - details (str): Additional details about compute manager inventory check.
            - note (str): Additional notes for result.
    """
    access_token = gen_token_sddc(username,password)
    VipList = nsxVipList
    vCenterList = []
    for entry in vcList:
        vCenterList.append(entry["hostname"])
    computeManagerList = []
    
    for entry in VipList:
        adminPass = getNSXVIPAdminCredential(entry,access_token)
        computeManagerList = computeManagerList + getComputeManagers(entry,adminPass)

    details = ""
    notes = ""
    title = 'Compute Managers in NSX exist in VCF Inventory'
    
    for computeManager in computeManagerList:
        if computeManager in vCenterList:
            continue
        else:
            details += f'Compute Manager {computeManager} is NOT in SDDC Manager Inventory\n'
            #result.append({"title":title, "result":result, "details":details, "notes":notes})
    
    if details == "":       
        result = 'PASS'
        details = 'All Compute Managers in NSX are in SDDC Manager Inventory.'
    else:
        result = 'FAIL'
        notes = 'Please update the "server" entry in NSX to match the vCenter FQDN in SDDC Manager Inventory.'
    
    return {"title":title, "result":result, "details":details, "notes":notes}

def nsx_federation_check(username, password):
    """
    Check for the presence of an NSX Federation deployment

    Args:
        username (str): SSO Admin Username
        password (str): SSO Admin password

    Returns:
        dict: A dictionary with the following keys:
            - title (str): The title of the result.
            - result (str): The status or result of the query.
            - details (str): Additional details about the status of NSX Federation.
    """
    access_token = gen_token_sddc(username,password)
    VipList = nsxVipList
    
    details = ""
    result = 'INFO'
    title = 'NSX Federation Detection'
    
    for entry in VipList:
        adminPass = getNSXVIPAdminCredential(entry,access_token)
        
        api_url = f'https://{entry}/policy/api/v1/infra/full-sync-states'
        api_type = "GET"
        response = requests.request(api_type,api_url,auth=('admin',adminPass),verify=False)
        result_count = json.loads(response.text)["result_count"]
        
        if int(result_count) == 0:
            details += f'{entry} | No NSX Federation detected\n'
        else:
            details += f'{bcolors.WARNING}{entry} | NSX Federation detected{bcolors.ENDC}\n'
    
    return {"title":title, "result":result, "details":details} 

def transport_node_shortname_check(username, password):
    """
    Check for any shortnames detected in the transport node names
    instead of the expected FQDN

    Args:
        username (str): SSO Admin Username
        password (str): SSO Admin password

    Returns:
        dict: A dictionary with the following keys:
            - title (str): The title of the result.
            - result (str): The status or result of the query.
            - details (str): Details of the specific transport nodes names that are using shortnames. 
            - note (str): Additional notes for result.
    """
    access_token = gen_token_sddc(username,password)
    VipList = nsxVipList
    
    finalResult = []
    for entry in VipList:
        adminPass = getNSXVIPAdminCredential(entry,access_token)
    
        api_url = f'https://{entry}/api/v1/transport-nodes'
        api_type = "GET"
        response = requests.request(api_type,api_url,auth=('admin',adminPass),verify=False)
        transportNodes = response.json()["results"]

        title=f'Transport Nodes for {entry}'
        details=""
        notes=""
        
        for node in transportNodes:
            if node["node_deployment_info"]["resource_type"] == "HostNode":
                if node["node_deployment_info"]["fqdn"].lower() != node["display_name"].lower():
                    details += f'\n{bcolors.FAIL}Node FQDN: {node["node_deployment_info"]["fqdn"]} does not match display name: {node["display_name"]}{bcolors.ENDC}'
        
        if details == "":       
            result = 'PASS'
            details = 'FQDN matches the Display name for all Transport Nodes'
        else:
            result = 'FAIL'
            notes = 'Please update the "display name" for the Transport Node to the FQDN.'
        
        finalResult.append({"title":title, "result":result, "details":details, "notes":notes})
    
    return finalResult

def edgeCluster_Inventory(username,password):
    """
    Check for edge clusters in SDDC Manager Inventory and 
    NSX environments, and if they are consistent with each other

    Args:
        username (str): SSO Admin Username
        password (str): SSO Admin password

    Returns:
        dict: A dictionary with the following keys:
            - title (str): The title of the result.
            - result (str): The status or result of the query.
            - details (str): Details of the edge cluster status. 
            - note (str): Additional notes for result.
    """
    access_token = gen_token_sddc(username,password)
    logger.debug(f'SDDC Manager access token acquired: {access_token[:5]}******')
    
    VipList = nsxVipList
    
    localEdgeClusters = getLocalEdgeClusters()        
    
    localEdgeClusterIds = []
    if localEdgeClusters != []:
        for entry in localEdgeClusters:
            localEdgeClusterIds.append(entry["edgeClusterNsxtId"])
    else:
        logger.info('No Edge Cluster found in SDDC Manager Inventory.')
    
    finalResult = []
    for entry in VipList:
        adminPass = getNSXVIPAdminCredential(entry,access_token)
        title=f'Edge Clusters for {entry}'
        details=""
        notes=""
    
        nsxEdgeClusters = getEdgeClusters(entry,adminPass)
        
        if localEdgeClusters == [] and nsxEdgeClusters == []:
            logger.info('No Edge Cluster info found with SDDC Manager Inventory or within NSX Inventory.')
            result = 'INFO'  
            details = 'No Edge Clusters deployed.'
            finalResult.append({"title":title, "result":result, "details":details, "notes":notes})
            continue  
        
        nsx_to_local_error = False
        local_to_nsx_error = False
        
        nsxEdgeClusterIds = []
        if nsxEdgeClusters != []:
            for entry in nsxEdgeClusters:
                id = entry["id"]
                nsxEdgeClusterIds.append(id)     
                    
            for cluster in nsxEdgeClusters:
                if cluster["id"] not in localEdgeClusterIds:
                    details += f'{bcolors.WARNING}Edge Cluster: {cluster["display_name"]} in NSX Inventory not found in SDDC Manager Inventory{bcolors.ENDC}\n'
                    nsx_to_local_error = True
        else:
            logger.info(f'No Edge Cluster found in NSX Inventory for {entry}.')
        
        # TODO: Need to logic how to check local Edge CLuster Info against NSX Edge Cluster Info
        # if localEdgeClusters != []:
        #     for cluster in localEdgeClusters:
        #         if  cluster["edgeClusterNsxtId"] not in nsxEdgeClusterIds:
        #             details += f'{bcolors.FAIL}Edge Cluster: {cluster["name"]} in SDDC Manager Inventory not found in NSX Inventory{bcolors.ENDC}\n'
        #             local_to_nsx_error = True
                
        if details == "":
            result = 'PASS'
            details = 'All NSX Edge Clusters match SDDC Manager Edge Cluster Inventory.'
        elif nsx_to_local_error == True and local_to_nsx_error == False:
            result = 'WARN'
        else:
            result = 'FAIL'
        
        finalResult.append({"title":title, "result":result, "details":details})
    
    return finalResult

def edgeNode_mismatch(username,password):
    """
    Check for Edge Transport Node ID mismatch between the NSX Inventory
    and SDDC Manager Inventory

    Args:
        username (str): SSO Admin Username
        password (str): SSO Admin password

    Returns:
        dict: A dictionary with the following keys:
            - title (str): The title of the result.
            - result (str): The status or result of the query.
            - details (str): Details of the specific edge transport nodes that are mismatched. 
    """
    access_token = gen_token_sddc(username,password)
    logger.debug(f'SDDC Manager access token acquired: {access_token[:5]}******')
    
    VipList = nsxVipList
    
    localEdgeClusters = getLocalEdgeClusters()    
    if localEdgeClusters == []:
        logger.info('No Edge Cluster info found within SDDC Manager Inventory.')
        result = 'INFO'  
        details = 'No Edge Clusters found in SDDC Manager Inventory.'
        return {"title":'Edge Cluster Mismatch Check', "result":result, "details":details}
    
    finalResult = []
    for entry in VipList:
        adminPass = getNSXVIPAdminCredential(entry,access_token)
    
        api_url = f'https://{entry}/api/v1/transport-nodes'
        api_type = "GET"
        response = requests.request(api_type,api_url,auth=('admin',adminPass),verify=False)
        transportNodes = response.json()["results"]

        title=f'Edge Transport Nodes for {entry}'
        details=""
        
        edgeTransportNodes = []
        for node in transportNodes:
            if node["node_deployment_info"]["resource_type"] == "EdgeNode":
                id = node["node_deployment_info"]["id"]
                hostname = node["node_deployment_info"]["node_settings"]["hostname"]
                edgeTransportNodes.append({"id":id, "hostname":hostname})
        
        if edgeTransportNodes == []:
            logger.info('No Edge Cluster info found in NSX Inventory.')
            result = 'INFO'  
            details = 'No Edge Transport Nodes found in NSX Inventory'
            finalResult.append({"title":title, "result":result, "details":details})
            continue
        
        for node in edgeTransportNodes:
            nodeFound = False
            nodeIdMismatch = False
            for cluster in localEdgeClusters:
                for nsxtEdgeNode in cluster["nsxtEdgeNodes"]:
                    if node["hostname"].lower() == nsxtEdgeNode["hostName"].lower():
                        nodeFound = True
                        if node["id"] != nsxtEdgeNode["edgeNodeNsxtId"]:
                            nodeIdMismatch = True
                            details += f'{bcolors.FAIL}ID for {node["hostname"]} does not match the sourceId in SDDC Manager DB.{bcolors.ENDC}' + "\n"
            if (nodeFound == False) and (nodeIdMismatch == False):
                details += f'{bcolors.WARNING}{node["hostname"]} does not exist in SDDC Manager DB.{bcolors.ENDC}' + "\n"
        if details == "":
            result = 'PASS'
            details = 'All NSX Edge Transport Nodes match SDDC Manager Inventory.'
        else:
            result = 'FAIL'
        
        finalResult.append({"title":title, "result":result, "details":details})
    
    return finalResult