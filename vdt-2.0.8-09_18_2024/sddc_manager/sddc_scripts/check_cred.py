#!/usr/bin/env python
"""
__author__ =  ["Laraib Kazi", "Tyler FitzGerald"]
__credits__ = ["Keenan Matheny", "Christopher Morrow", "Fouad Sethna", "Kevin Hagopian"]

"""
import json
import requests
import urllib3
import sys
from sddc_manager.sddc_cfg.current_defaults import ssoAdmin
from sddc_manager.sddc_lib.authUtils import gen_token_sddc, sso_prompt
import logging

logger = logging.getLogger(__name__)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_credential_tasks(access_token):
    """
    Gets a list of all credential tasks that are not SUCCESSFUL
    or USER_CANCELLED. Details include:
    - opid
    - resource name
    - resource type
    - resource username
    - credential type (API|SSH)

    Args:
        access_token (str): API Access Token for the SDDC Manager

    Returns:
        list: List of dict objects with details of the failed credential task
    """
    header = {'Authorization': f'Bearer {access_token}'}
    api_url = "https://localhost/v1/credentials/tasks"
    api_type = "GET"

    try:
        response = requests.request(api_type, api_url, headers=header, verify=False)
        data = json.loads(response.text)
        erroredCredOps = []
        counter = 0
        for entry in data["elements"]:      
            OpStatus = entry["status"]
            if OpStatus == "SUCCESSFUL" or OpStatus == "USER_CANCELLED":
                break
            else:
                #counter+=1
                OpId = entry["id"]
                try:
                    subtaskInfo = entry["subTasks"][0]
                    resourceName = (subtaskInfo)["resourceName"]
                    resourceType = (subtaskInfo)["entityType"]
                    resourceUser = (subtaskInfo)["username"]
                    credType = (subtaskInfo)["credentialType"]
                    #erroredCredOps[counter]=(f'{OpId} | {resourceName} | {resourceType} | {resourceUser} | {credType}')
                    erroredCredOps.append(f'{OpId} | {resourceName} | {resourceType} | {resourceUser} | {credType}')
                except:
                    errorInfo = entry["errors"][0]
                    errorMessage = (errorInfo)["message"]
                    #erroredCredOps[counter]=(f'{OpId} | {errorMessage}')
                    erroredCredOps.append(f'{OpId} | {errorMessage}')
        return erroredCredOps

    except requests.exceptions.RequestException as e:
        return f"Error making the request: {e}"

def main(username, password):
    """
    Checks for any credential tasks that are not SUCCESSFUL
    or USER_CANCELLED and returns the dict result.

    Args:
        None

    Returns:
        dict: Result of the Credential Tasks Check
    """
    access_token = gen_token_sddc(username,password)        
    credentials_data = get_credential_tasks(access_token)
    
    if credentials_data==[]:
        resultDetails=f'No Invalid transactions for Credentials detected.'
        result = "PASS"
        documentation = ""
        notes = ""
    else:
        resultDetails = ""
        for entry in credentials_data:
            resultDetails += "- "+entry+ "\n"
        #resultDetails = json.dumps(credentials_data)
        result = "FAIL"
        documentation = "https://kb.vmware.com/s/article/90716"
        notes = "Please review the KB for additional troubleshooting and resolution."
    
    return {"title":'Check for Invalid Transaction Status on Credential Operations',
            "result":result,"details":resultDetails,
            "documentation":documentation,"notes":notes}
    
if __name__ == '__main__':
    if len(sys.argv) > 2:
        main(sys.argv[1], sys.argv[2])
    else:
        username = ssoAdmin
        password = sso_prompt()
        main(username,password)
    