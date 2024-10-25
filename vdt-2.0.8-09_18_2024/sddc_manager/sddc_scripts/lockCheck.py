#!/usr/bin/env python
"""
__author__ =  ["Laraib Kazi", "Tyler FitzGerald"]
__credits__ = ["Keenan Matheny", "Christopher Morrow", "Fouad Sethna", "Kevin Hagopian"]

"""
__title__ = "LOCK CHECK"
import requests
import json
import logging

logger = logging.getLogger(__name__)

def runRestAPIcall(api,type):
    """
    Function to run no-auth API calls

    Args:
        api (str): API URL
        type (str): Type of API Call - GET|PUT|PATCH|DELETE

    Returns:
        str: Text response of the API call
    """
    api_url = api
    api_type = type
    response = requests.request(api_type, api_url, verify=False)
    
    return response.text

def deploymentLockCheck():
    """
    Checks for the presence of any deployment locks

    Args:
        None

    Returns:
        str: Deployment Lock resource ID
        str: Deployment Lock description
    """
    url='http://localhost/locks'
    apiResponse = runRestAPIcall(url,"GET")
    try:
        dLockResourceId = json.loads(apiResponse)["vcfClientContext"]["resourceId"]
        dLockdDescription = json.loads(apiResponse)["description"]
        return dLockResourceId,dLockdDescription
    except:
        return None,None
    
def resourceLockCheck():
    """
    Checks for the presence of any resource locks

    Args:
        None

    Returns:
        dict: dict object with the Resource Lock resource ID and Resource Lock Name
    """
    url='http://localhost/resource-locks'
    apiResponse = runRestAPIcall(url,"GET")
    try:
        rLock = {}
        for entry in json.loads(apiResponse)["elements"]:
            rLockResourceId = json.loads(entry)["elements"]["resourceId"]
            rLockdResourceName = json.loads(entry)["elements"]["resourceName"]
            rLock.append({"Resource ID":rLockResourceId,"Resource Name":rLockdResourceName})
        return rLock
    except:
        return None
    
def main():
    """
    Check for any deployment locks or resource locks
    in the SDDC Manager

    Args:
        None

    Returns:
        list: List of dicts with the Result of the deployment lock and resource lock status
    """ 
    dLockResourceId,dLockdDescription = deploymentLockCheck()
    if dLockResourceId:
        resultDetails = f'{dLockdDescription}. Resource Id: {dLockResourceId}'
        result = "FAIL"
    else:
        resultDetails = "No Deployment Locks detected."
        result = "PASS"
    
    dLockCheckResult = {"title":'Check for existing Deployment Locks',
                        "result":result, "details":resultDetails,}    
    
    rLock = resourceLockCheck()
    if rLock:
        resultDetails = f'Resource locks detected.{rLock}'
        result = "FAIL"
    else:
        resultDetails = "No Resource Locks detected."
        result = "PASS"
        
    rLockCheckResult = {"title":'Check for existing Resource Locks',
                        "result":result,"details":resultDetails}
    
    return [dLockCheckResult, rLockCheckResult]

if __name__ == '__main__':
    main()
