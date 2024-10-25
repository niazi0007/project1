__title__ = "ARIA SUITE INVENTORY STATUS"

import logging
import re
logger = logging.getLogger(__name__)

from sddc_manager.sddc_lib.inventoryUtils import vrslcmInfo, vraInfo, vrliInfo, vropsInfo, wsaInfo

def vrslcmCheck():
    """
    Gets status of the vRSLCM node
    
    Returns:
        dict: A dictionary objects containing following keys:
            - title (str): The title of the vRSLCM Check.
            - result (str): The result of the check function.
            - details (str): The formatted details of the vRSLCM Node.
            - documentation (str): Any KB, if applicable
    """  
    vrslcm = vrslcmInfo()
    title = 'Aria Suite Lifecycle'
    
    if vrslcm == None:
        result = 'INFO'
        details = 'No Aria Suite Lifecycle found'
        documentation = ''
    else:
        details = f'{vrslcm["hostname"]} | {vrslcm["version"]} | {vrslcm["status"]}'
        if vrslcm['status'].lower() == 'active':
            # Checking for issue in KB 95961/95790
            if re.search(r"\d{1}\.\d{1,2}\.\d{1,2}-\d{8}", vrslcm['version']):
                result = 'PASS'
                documentation = ''
            else:
                result = 'FAIL'
                documentation = 'https://kb.vmware.com/kb/95790'
        else:
            result = 'WARN'
            documentation = ''
    
    return {"title":title, "result":result,
            "details":details, "documentation":documentation}

def vraCheck():
    """
    Gets status of the vRA Instance
    
    Returns:
        dict: A dictionary objects containing following keys:
            - title (str): The title of the vRA Check.
            - result (str): The result of the check function.
            - details (str): The formatted details of the vRA Nodes.
    """  
    vra = vraInfo()
    title = 'Aria Automation'
    
    if vra == None:
        result = 'INFO'
        details = 'No Aria Automation found'
    else:
        details = f'{vra["version"]} | {vra["status"]}\n'
        details += f'Load Balancer: {vra["loadbalancer"]}\n'
        vraNodes = (', '.join(node["hostName"] for node in vra["nodes"]))
        details += f'Nodes: {vraNodes}'
        
        if vra["status"].lower() == 'active':
            result = 'PASS'
        else:
            result = 'WARN'
    
    return {"title":title, "result":result, "details":details}

def vropsCheck():
    """
    Gets status of the vROPS instance
    
    Returns:
        dict: A dictionary objects containing following keys:
            - title (str): The title of the vROPS Check.
            - result (str): The result of the check function.
            - details (str): The formatted details of the vROPS Nodes.
    """  
    vrops = vropsInfo()
    title = 'Aria Operations'
    
    if vrops == None:
        result = 'INFO'
        details = 'No Aria Operations found'
    else:
        details = f'{vrops["version"]} | {vrops["status"]}\n'
        details += f'Load Balancer: {vrops["loadbalancer"]}\n'
        details += f'Primary Node: {vrops["masterHostname"]}'
        if vrops["status"].lower() == 'active':
            result = 'PASS'
        else:
            result = 'WARN'
    
    return {"title":title, "result":result, "details":details}

def vrliCheck():
    """
    Gets status of the vRLI instance
    
    Returns:
        dict: A dictionary objects containing following keys:
            - title (str): The title of the vRLI Check.
            - result (str): The result of the check function.
            - details (str): The formatted details of the vRLI Nodes.
    """  
    vrli = vrliInfo()
    title = 'Aria Operations for Logs'
    
    if vrli == None:
        result = 'INFO'
        details = 'No Aria Operations for Logs found'
    else:
        details = f'{vrli["version"]} | {vrli["status"]}\n'
        details += f'Load Balancer: {vrli["loadbalancer"]}\n'
        details += f'Primary Node: {vrli["masterHostname"]}'
        if vrli["status"].lower() == 'active':
            result = 'PASS'
        else:
            result = 'WARN'
    
    return {"title":title, "result":result, "details":details}

def wsaCheck():
    """
    Gets status of the Workspace One Access instance
    
    Returns:
        dict: A dictionary objects containing following keys:
            - title (str): The title of the WSA Check.
            - result (str): The result of the check function.
            - details (str): The formatted details of the WSA Nodes.
    """  
    wsa = wsaInfo()
    title = 'Workspace One Access'
    
    if wsa == None:
        result = 'INFO'
        details = 'No Workspace One Access found'
    else:
        details = f'{wsa["version"]} | {wsa["status"]}\n'
        details += f'Load Balancer: {wsa["loadbalancer"]}\n'
        details += f'Primary Node: {wsa["primaryHostname"]}'
        if wsa["status"].lower() == 'active':
            result = 'PASS'
        else:
            result = 'WARN'
    
    return {"title":title, "result":result, "details":details}

def main():
    """
    Gets the details of all the Aria Suite Products deployed

    Returns:
        list: A list of dictionary objects containing following keys:
            - title (str): The title of the SDDC Manager information.
            - result (str): The result of the function.
            - details (str): The formatted details of the VCF Services.
            - documentation (str): Any KB, if applicable

    """  
    ariaResult = []
        
    vrslcmResult = vrslcmCheck()
    ariaResult.append(vrslcmResult)
    
    vraResult = vraCheck()
    ariaResult.append(vraResult)
    
    vropsResult = vropsCheck()
    ariaResult.append(vropsResult)
    
    vrliResult = vrliCheck()
    ariaResult.append(vrliResult)
    
    wsaResult = wsaCheck()
    ariaResult.append(wsaResult)
    
    # if vrslcmResult['result'] != 'INFO':
    #     ## No other vRealize products should exist ...
    
    return ariaResult

if __name__ == '__main__':
	main()