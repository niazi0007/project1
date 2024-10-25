#!/usr/bin/env python
"""
__author__ =  ["Laraib Kazi", "Tyler FitzGerald"]
__credits__ = ["Keenan Matheny"]

"""
import sys
import requests
import urllib3
from sddc_manager.sddc_cfg.current_defaults import ssoAdmin
from sddc_manager.sddc_lib.authUtils import gen_token_sddc, sso_prompt
from sddc_manager.sddc_lib.commandUtils import run_psql_command
import logging

logger = logging.getLogger(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

bad_bundles = ['a2a3eca9-d38c-4443-9b06-3e61ce7835b7','f4dfa80d-9924-42a4-88ae-cb008b0b7c32','062521b7-2219-4b7e-b91a-90f632f6c1ca',
               '4799bff9-3779-4698-a9a2-1bc27a26a8ef','cd939fb6-a651-47eb-8588-8929ccc2a186','eb91f89f-71a9-488c-8ec9-cc519f10d415',
               '5de85ec3-4bfd-4280-8880-0d5dcebc6fc8','a8c78116-dd72-4e70-8c4e-2c01b245f72b','bc2efce8-9917-4f98-b538-8dfdeeb500ef',
               '66b04b82-5741-40f8-8075-e9d38853404d','5962a6c8-db3c-49a2-a9db-ee6f4b89ff96','8b0617da-efef-4a2d-b104-a366e0de912e',
               'd8c65715-c9ce-4037-8aec-a90184c89cb8','17035c2a-9dc7-41d9-aaa1-4ee8e4eb941f','1fbb22fa-16e3-42bd-8541-6793086591d8',
               '18486122-ff28-45d4-8a67-781dbcdf44eb','7e3f416e-b5df-47de-b244-631d02cf0f0a','efd59dc2-6dba-456e-bc86-2959189becf4',
               '4201b90b-9a47-40fe-b540-c4d39d3e5d0f','dde897dd-d8d1-4e92-abf2-ce9c37785865','469fd795-f7c0-4e8f-82bb-259ad210ff7d',
               'a6998808-8211-4107-8876-ceba0a8f68ab','347a5902-7457-4133-becd-9b0f0c1a446a','aa7b16b1-d719-44b7-9ced-51bb02ca84f4',
               '069a847a-5333-43cf-aaad-d1e187062dba','06f166e3-b9a6-48ee-b45a-7ffcae9b89a9','5a3ba019-f06b-4521-92ad-8b88fbf1d034',
               'fb63ae17-a692-4e77-a556-e7cf8bb9d777','8253f874-ca73-4412-b534-ee0caeea9839','777185cd-2931-4e50-a0b2-812d8e184efd',
               '30681c74-8ca3-4215-9de4-5a07e670afe1','cd9c819e-619c-43e0-98f3-bc58398f5265','00f14bea-b101-4c8e-85a6-ca2976590121',
               '0bc81892-da52-4eb8-9b64-c65212b1ef5d','6f40b4b7-6115-4aa9-aee2-e305e12c8d7f','af500c1b-05f5-4881-8a6b-af1179185edb',
               'b4ae78ec-c47a-4b08-b1bf-0e46f531c419','f34ab1f2-c4d5-4d54-8067-01ecc4c67b07','7a762fea-4b32-4d7c-a537-c057a95304f7',
               'f9b7b029-e151-4270-b15c-f814566a3f15','fcd65dc9-9f34-4409-b8bd-18f68a477f38','c53e9053-ea2d-4bcf-acad-4624e6794f21',
               '93131677-e6b9-4bd7-9797-b4fc8eaa5317','4a9a0ec3-390c-4a37-aba9-552008703c33','ca0a25b5-272c-45d6-b33b-580139024db8',
               '5dc57fe6-2c23-49fc-967c-0bea1bfea0f1','eb1d24d4-b2fa-4258-ab21-a7adb1b91b36','2fbfcd08-288b-451a-b554-a6c573cb8259',
               '62977b58-cb16-4fee-a611-35d7ffa24f01','4482a398-2481-4743-b0c6-878a686637cc','80832d4c-26f8-42d4-8fa4-ed75170c661d',
               'b4a3b519-9c38-42a9-b4c9-9232c522fec1','f61da054-8949-4aed-9fe7-50ee35713b4d','239455c0-bf23-4162-86e0-189caf74c11c',
               '785d9906-31e9-42bd-9085-11913b6208ac','be0a79ea-d645-489b-85c1-751b4ec25518','10862c89-302f-43bd-9abb-6b4886fd5460',
               '3626262b-48e2-4a9a-a97b-de875e1f59e9','139fcd44-8c07-42ec-af91-89f9f3cba908','528f805d-2360-463d-b390-42146bb1457c',
               '63020c0d-26c2-4bc1-8190-8074d42a0548','55a8659b-962f-4766-9bb6-475a79db4b2d','b0b9a90f-fc79-4013-863c-2d6b01153107',
               '79350b84-fde3-4a27-a6d6-2ddfc38ec048','7bd2d25e-4b7c-4d8b-920a-e4063c93a55e','5f513e2c-e978-485d-83e8-3f36db439824',
               '85247935-6dfa-4f86-a319-5a0e8840be93','febca163-744c-4c18-9208-6d3751c4a20c','215b93fd-839a-4830-817c-0040790187b3',
               'a777f37a-ee5a-40ae-86da-c422d304a45e','1b56ec9b-7227-41f2-a311-65ff2d841f1a','411bea6a-b26c-4a15-9443-03f453c68752',
               'f751eaca-bc5f-48ec-bae6-2bfa3e87e0d9','7bf144b4-10a0-4d86-b4c8-f9e025440d3d','c4e5f4e3-6853-4e7c-adfe-c96912c5be9d',
               'c3472e8e-4886-47ca-9958-63125460e59c','499ee790-1da8-455e-9c54-2e2b96209158','acda07c2-c355-4001-b502-b49855dfbd17',
               'dc68f0ab-3b2d-401d-bb3f-b346223d92fc','034f77bc-1e9b-4d04-b691-0e2da065561d','4fa45796-b991-43f4-bac6-49197b2e84bf',
               '309b087d-ad56-41f4-8778-573cae212eb4','13de6faf-b64e-402f-bbb9-e1b11a8fbaaf','3fc9a931-f456-4c8d-93af-e2c04d110280',
               'd6a80c75-03b4-42f3-98af-2b7857e2850e','550a872a-43d7-4844-a9fc-8f13732e1faf','3d587f3d-9593-4ee6-b21a-3c11045d3049',
               '554abcd5-5b57-4070-b568-219042d6f58f','7171ab2e-01b0-4f02-bb07-895c6e158b06','a660bd0a-9c0d-4d12-8836-7ba1ceee7f86',
               'c4202263-34fa-4628-aa1c-5494200a5d48','47a630c8-1e74-4d59-a2ce-05d0c90fff6b','ca87c7a9-d235-4e36-85a0-e26ee1a311b3',
               '7ce6ca1a-63fc-4232-a871-ada796759533','7debd147-a3a6-418c-a6f4-5ba07c65b2c2','271eb824-e6f9-4941-86b8-c3d2cfb66bb9',
               'f9a00546-7b68-48ec-b876-608c7791c311','abf48876-2033-4ccb-b9fe-482ca5d57161','fa01cf91-246c-4b91-9cd5-ba2434468e56',
               '6dcb75f5-6fe8-463b-953e-9b0d92ee4116','8066d2b5-3355-43e2-9b7b-0bf35fe3f25f','be9b87f1-ad1e-442a-a79e-a53e7ad70cdf',
               '635fd984-44b1-49f5-bd11-eaf0352018c4','3e162fb2-d495-41d1-9e60-4387f4915082','e23b6372-9274-49d5-a94c-94f5a910b678',
               '468c2804-1992-4c4f-9847-255a99996dd4','35bea654-b032-435b-a2c1-aba83690e867','35160be8-866f-493c-835f-928063029f9a',
               '35160be8-866f-493c-835f-928063029f9a','9397c1fd-e832-491e-adda-94a309cb40a8','5167dc64-d6f6-487e-abfa-fe10f59b8392',
               '28032810-5fac-4c12-b9b6-e9c1322c036f','a5edb8c0-0166-4fc8-955f-4ad111e55a3c','c0aa83cf-f921-4de7-b2b7-f3abe1a1d32e',
               '23be82b4-f9c0-4c91-9faf-54da7e4bd319','83c282db-cb1d-43f5-a989-681224afea5f','a50a8dcb-b107-4498-a68c-227916aa4b9d',
               '01437167-3f1d-414e-a3b7-b280f12fa957']

def lcm_service_status():
    """
    Gets the status of the LCM service

    Args:
        None

    Returns:
        str: ACTIVE or FAILED status of the service
    """
    api_url = 'http://localhost/lcm/about'
    api_type = "GET"
    logger.debug(f'Making {api_type} API call on URL {api_url}')
    response = requests.request(api_type, api_url, verify=False)
    logger.debug(f'API Response Status Code: {response.status_code}')
    if response.status_code == 200:
        logger.debug('LCM Service is ACTIVE.')
        return "ACTIVE"
    else:
        logger.debug('LCM Service is FAILED.')
        return "FAILED"

def get_bundles_api(access_token):
    """
    Gets a list of the upgrade bundles ids on the SDDC Manager
    via an API call

    Args:
        access_token (str): API access token for the SDDC Manager

    Returns:
        list: List of stored upgrade bundle ids
    """
    headers = {
    'Content-Type': 'application/json',
    "Authorization": f"Bearer {access_token}"
    }
    api_url = 'http://localhost/v1/bundles'
    logger.debug(f'Making GET API call on URL {api_url}')
    response = requests.get(api_url, headers=headers)
    logger.debug(f'API Response Status Code: {response.status_code}')

    stored_bundles=[]
    if response.status_code == 200:
        api_data = response.json()
        for element in api_data.get('elements', []):
            bundle_id = element.get('id', 'N/A')
            stored_bundles.append(bundle_id)
    else:
        logger.error(f"Error: {response.status_code} - {response.text}")
    
    logger.debug(f'Returning: Stored Bundles: {stored_bundles}')
    return stored_bundles

def get_bundles_db():
    """
    Gets a list of the upgrade bundle ids on the SDDC Manager
    from the LCM Database

    Args:
        None

    Returns:
        list: List of stored upgrade bundle ids
    """
    query = "select bundle_id from bundle"
    logger.debug(f'Running psql command: {query}')
    stored_bundles = (run_psql_command('lcm', query)).decode()
    stored_bundles = stored_bundles.split("\n")
    logger.debug(f'Returning: Stored Bundles: {stored_bundles}')
    return stored_bundles
    
def main(username, password):
    """
    Checks if the SDDC Manager has an erroneous upgrade bundles 
    stored in LCM

    Args:
        username (str): SSO Admin Username
        password (str): SSO Admin password

    Returns:
        dict: Result of the upgrade bundle id check
    """
    logger.debug('Acquiring SDDC Manager access token.')
    access_token = gen_token_sddc(username, password)
    logger.debug(f'SDDC Manager access token acquired: {access_token[:5]}******')
    
    need_to_remove = []
    
    if lcm_service_status() == "ACTIVE":
        stored_bundles = get_bundles_api(access_token)
        logger.debug('LCM Service ACTIVE received. Stored bundles captured using API.')
    else:
        stored_bundles = get_bundles_db()
        logger.debug('LCM Service FAILED received. Stored bundles captured using DB Query.')
    
    for bundle in stored_bundles:
        if bundle in bad_bundles:
            logger.debug(f'Bad bundle Identified: {bundle}')
            need_to_remove.append(bundle)
    logger.debug(f'Final list of identified bad bundles: {need_to_remove}')
    
    if need_to_remove == []:
        result = 'PASS'
        details = "No erroneous bundles found."
        documentation = ''
        logger.info(f'{details}')
    else:
        result = 'FAIL'
        bundleDetails = 'Bundles to remove:'
        for entry in need_to_remove:
            bundleDetails += '\n' + entry
        logger.info(f'{bundleDetails}')
        
        details = 'Erroneous bundles identified. Please use KB mentioned below to remediate.'        
        documentation = 'https://kb.vmware.com/s/article/95536'
    
    returnCheck = {"title":"Erroneous Bundles in LCM","result":result,"details":details,"documentation":documentation}    
    logger.info(f'Final Return: {returnCheck}')    
    return returnCheck                
    
if __name__ == '__main__':
    if len(sys.argv) > 2:
        main(sys.argv[1], sys.argv[2])
    else:
        username = ssoAdmin
        password = sso_prompt()
        main(username,password)

