__title__ = "SDDC MANAGER SERVICES CHECK"

import requests
import json
import logging
logger = logging.getLogger(__name__)

def vcfServices():
    """
    Gets status of the VCF Services on the SDDC Manager

    Returns:
        json: A Json object containing a list of VCF Services information
    """  
    logger.debug("Getting VCF Services Info")
    api_url = 'http://localhost/inventory/vcfservices'
    api_type = "GET"
    response = requests.request(api_type, api_url, verify=False)
    allServices = json.loads(response.text)
    return allServices

def main():
    """
    Get the details of all SDDC Manager VCF services

    Returns:
        list: A list of dictionary objects containing following keys:
            - title (str): The title of the SDDC Manager information.
            - result (str): The result of the function.
            - details (str): The formatted details of the VCF Services.

    """  
    serviceCheck = []
        
    allServices = vcfServices()
    for entry in allServices:
        if entry["status"] == "ACTIVE":
            result = 'PASS'
        else:
            result = 'FAIL'
        try:
            serviceCheck.append({"title":entry["description"],
                             "result":result,
                             "details":f'{entry["name"]} | {entry["version"]} | {entry["status"]}'})
        except:
            serviceCheck.append({"title":entry["name"],
                             "result":result,
                             "details":f'{entry["name"]} | {entry["version"]} | {entry["status"]}'})
    
    return serviceCheck

if __name__ == '__main__':
	main()