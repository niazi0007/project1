#!/usr/bin/env python
"""
__author__ =  ["Laraib Kazi", "Sydney Young"]
__credits__ = ["Tyler FitzGerald"]

"""
import logging
import os
import stat
import socket
import requests
import ast
from pathlib import Path

from sddc_manager.sddc_lib.authUtils import gen_token_sddc
from sddc_manager.sddc_cfg.current_defaults import isVxRail

logger = logging.getLogger(__name__)

CYELLOW = '\033[93m'
CEND = '\033[0m'

## Manifest Polling
def getManifestPolling():
    with open('/opt/vmware/vcf/lcm/lcm-app/conf/application-prod.properties') as f:
        lines = f.readlines()
        for row in lines:
            if 'lcm.core.enableManifestPolling' in row:
                if 'true':
                    details='LCM Manifest Polling is Enabled'
                    result='PASS'
                else:
                    details='LCM Manifest Polling is not Enabled'
                    result='FAIL'
    return {"title":'Check for LCM Manifest Polling',
            "result":result,"details":details}

## upgradeHelper file permission and ownership checks
def permission_ownership_Check():
    IsVxRail = ast.literal_eval(isVxRail)
    lcm_app_Path = "/opt/vmware/vcf/lcm/lcm-app/conf/"
    files_to_check1 = ["feature.properties","lcmManifest.json","VersionAlias.yml"]
    files_to_check2 = ["application-prod.properties","application.properties"]
    bundle_dir_Path = "/nfs/vmware/vcf/nfs-mount/bundle/"
    software_compatSet_file = "softwareCompatiblitySets.json"
    
    details: str = ''
    documentation: str = ''
    title: str = 'Check for LCM file and directory permissions and ownership'
    
    # Checking ownership of files:
    all_files = files_to_check1 + files_to_check2
    checkPassed1 = True
    for file in all_files:
        try:
            path = Path(lcm_app_Path+file)
            logger.debug(f'Checking file ownership for : {path}')
            if(path.owner()!='vcf_lcm' or path.group()!='vcf'):
                checkPassed1 = False
                logger.debug(f'File Owner: {path.owner()} | File Group: {path.group()}')
                logger.info(f'Incorrect ownership : {lcm_app_Path+file}')
                details+=f'Incorrect ownership : {lcm_app_Path+file}\n'
        except Exception as e:
            logger.info(f'Failed to check file ownership for : {path}. Error: {e}')
    
    try:
        path = Path(bundle_dir_Path)
        logger.debug(f'Checking ownership for : {path}')
        if(path.owner()!='vcf_lcm' or path.group()!='vcf'):
                checkPassed1 = False
                logger.debug(f'Directory Owner: {path.owner()} | Directory Group: {path.group()}')
                logger.info(f'Incorrect ownership : {path}')
                details+=f'Incorrect ownership : {path}\n'
    except Exception as e:
        logger.info(f'Failed to check ownership for : {path}. Error: {e}')
    
    if IsVxRail == True:
        try:     
            path = Path(bundle_dir_Path+software_compatSet_file)
            logger.debug(f'Checking ownership for : {path}')
            if(path.owner()!='vcf_lcm' or path.group()!='vcf'):
                    checkPassed1 = False
                    logger.debug(f'File Owner: {path.owner()} | File Group: {path.group()}')
                    logger.info(f'Incorrect ownership : {path}')
                    details+=f'Incorrect ownership : {path}\n'
        except:
            logger.info(f'Cannot find {software_compatSet_file}')
    
    if checkPassed1 == False:
        logger.debug('File ownership check failed.')
        documentation += f'Please update ownership for the above file(s) using the command: "chown vcf_lcm:lcm {CYELLOW}<filepath>{CEND}"\n'
    
    # Checking permissions of files:
    checkPassed2 = True
    for file in files_to_check1:
        try:
            logger.debug(f'Checking file permission for : {lcm_app_Path+file}')
            perms = oct(stat.S_IMODE(os.lstat(lcm_app_Path+file).st_mode))[-3:]
            if int(perms) < 600:
                checkPassed2 = False 
                logger.debug(f'File permissions : {str(perms)}')
                logger.info(f'Incorrect permissions : {lcm_app_Path+file}')
                details+=f'Incorrect permissions : {lcm_app_Path+file}\n'
        except:
            logger.info(f'Failed to check file permissions for : {path}. Error: {e}')
    
    try:
        logger.debug(f'Checking directory permission for : {bundle_dir_Path}')
        perms = oct(stat.S_IMODE(os.lstat(bundle_dir_Path).st_mode))[-3:]
        if int(perms) < 600:
                checkPassed2 = False
                logger.debug(f'Directory permissions : {str(perms)}')
                logger.info(f'Incorrect permissions : {bundle_dir_Path}')
                details+=f'Incorrect permissions : {bundle_dir_Path}\n'
    except Exception as e:
        logger.info(f'Failed to check directory permissions for : {path}. Error: {e}')
    
    if IsVxRail == True:                
        try:
            logger.debug(f'Checking file permission for : {bundle_dir_Path+software_compatSet_file}')
            perms = oct(stat.S_IMODE(os.lstat(bundle_dir_Path+software_compatSet_file).st_mode))[-3:]
            if int(perms) < 600:
                    checkPassed2 = False
                    logger.debug(f'File permissions : {str(perms)}')
                    logger.info(f'Incorrect permissions : {bundle_dir_Path+software_compatSet_file}')
                    details+=f'Incorrect permissions : {bundle_dir_Path+software_compatSet_file}\n'
        except:
            logger.info(f'Cannot find {software_compatSet_file}')
    
    if checkPassed2 == False:
        logger.debug(f'File permission check failed for {files_to_check1}.')
        documentation += f'\n  Please update permissions for the above file(s) using the command: "chmod 600 {CYELLOW}<filepath>{CEND}"\n  NOTE: 600 is the minimum required permission.\n'
    
    checkPassed3 = True
    for file in files_to_check2:
        try:
            logger.debug(f'Checking file permission for : {lcm_app_Path+file}')
            perms = oct(stat.S_IMODE(os.lstat(lcm_app_Path+file).st_mode))[-3:]
            if int(perms) < 400:
                checkPassed3 = False
                logger.debug(f'File permissions : {str(perms)}')
                logger.info(f'Incorrect permissions : {lcm_app_Path+file}')
                details+=f'Incorrect permissions : {lcm_app_Path+file}\n'
        except Exception as e:
            logger.info(f'Failed to check file permissions for : {path}. Error: {e}')
    
    if checkPassed3 == False:
        logger.debug(f'File permission check failed for {files_to_check2}.')
        documentation += f'\n  Please update permissions for the above file(s) using the command: "chmod 400 {CYELLOW}<filepath>{CEND}"\n  NOTE: 400 is the minimum required permission.\n'
    
    if checkPassed1 == True and checkPassed2 == True and checkPassed3 == True:
        result='PASS'
        details = f"File permissions and ownership are correct"
    else:
        result='FAIL'
    
    return {"title":title,"result":result,"details":details,"documentation":documentation}


## Depot Connection issues check
def depotConnectityTest():
    IsVxRail = ast.literal_eval(isVxRail)
    vmwareDepotUri: str = 'depot.vmware.com'
    port = 443
    timeout = 2
    details: str = ''
    title='Connectivity to Online Depots'

    try:
        socket.setdefaulttimeout(timeout)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((vmwareDepotUri, port))
        details += f'Connectivity to VMware Depot succeeded\n'
        logger.info('Connectivity to VMware Depot allowed')
        IsVmwareAccess = True
    except socket.error as ex:
        logger.info('Unable to connect to VMware Depot')
        details += f'Unable to connect to VMware Depot\n'
        IsVmwareAccess = False
        
    if IsVxRail:
        dellDepotUri: str = 'colu.emc.com'
        try:
            socket.setdefaulttimeout(timeout)
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((dellDepotUri, port))
            details += f'Connectivity to Dell Depot succeeded\n'
            logger.info('Connectivity to Dell Depot allowed')
            IsDellAccess = True
        except socket.error as ex:
            logger.info('Unable to connect to Dell Depot')
            details += f'Unable to connect to Dell Depot\n'
            IsDellAccess = False
    
    if IsVxRail == True:
        if (IsDellAccess == False) or (IsVmwareAccess == False):
            result = 'WARN'
        else:
            result = 'PASS'
    else:
        if (IsVmwareAccess == False):
            result = 'WARN'
        else:
            result = 'PASS'
    return {"title":title,"result":result,"details":details}

def checkDepotSettings(username, password):
    IsVxRail = ast.literal_eval(isVxRail)
    token = gen_token_sddc(username, password)
    title: str='Depot Configuration Check'
    details: str=''

    # Get current depot settings
    api_url = f'http://localhost/v1/system/settings/depot'
    headers = {'Accept': 'application/json', 'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(token)}
    logger.info(f'Attempting GET API Call with URL {api_url}')
    response = requests.request("GET", api_url, headers=headers, verify=False)
    try:    
        response.json()["vmwareAccount"]["status"] == "DEPOT_CONNECTION_SUCCESSFUL"
        details+=f'VMware depot connected successfully with user: {response.json()["vmwareAccount"]["username"]}\n'
        logger.info(f'VMware depot connected successfully with user: {response.json()["vmwareAccount"]["username"]}')
        isVmwareDepot = True
    except Exception as e:
        details+="VMware depot is not connected\n"
        isVmwareDepot = False
        logger.info(f'VMware depot not connected. Error: {e}')
        
    if IsVxRail:
        try:    
            response.json()["dellEmcSupportAccount"]["status"] == "DEPOT_CONNECTION_SUCCESSFUL"
            details+=f'Dell depot connected successfully with user: {response.json()["dellEmcSupportAccount"]["username"]}'
            logger.info(f'Dell depot connected successfully with user: {response.json()["dellEmcSupportAccount"]["username"]}')
            isDellDepot = True
        except Exception as e:
            details+="Dell depot is not connected"
            logger.info(f'Dell depot not connected. Error: {e}')
            isDellDepot = False
    
    if IsVxRail:
        if (isDellDepot == True) and (isVmwareDepot == True):
            result = 'PASS'
        else:
            result = 'WARN'
    else:
        if (isVmwareDepot == True):
            result = 'PASS'
        else:
            result = 'WARN'
    
    return {"title":title,"result":result,"details":details}

def proxyStatus(username, password):
    
    token = gen_token_sddc(username, password)
    title: str= 'LCM Proxy Configuration'
    details: str= ''
    api_url = f'http://localhost/v1/system/proxy-configuration'
    headers = {'Accept': 'application/json', 'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(token)}
    logger.info(f'Attempting GET API Call with URL {api_url}')
    response = requests.request("GET", api_url, headers=headers, verify=False)
    try:
        if response.json()["isConfigured"] == False:
            details+='No Proxy configured for LCM service.'
            logger.info('Proxy not configured for LCM.')
            result='INFO'
        else:
            details+=f'Proxy configured for LCM service in SDDC Manager.\nProxy Host: {response.json()["host"]}\n'
            logger.info('Proxy configured for LCM.')
            result='WARN'
            if response.json()["isEnabled"] == False:
                details+='Proxy is enabled'
            else:
                details+='Proxy is NOT enabled'
    except Exception as e:
        logger.info('proxy-configuration API failed to run.') 
        
    return {"title":title,"result":result,"details":details}
        
# #Firewall Check
# def fireWall():
#     check netcat command 
#     if result is open: 
#         result='PASS'
#     else: 
#         details='Connection Closed'
#         result='FAIL'
#     return {"title":'Check for Firewall Blocking 443',
#         "result":result,"details":details}

# #Depot Cert Missing
# def depotCert(): 
       
# #check proxy, if it exists needs to run cred check with other check
# def proxyCheck():
   
#     api_type = "GET"
#     api_url = "https:/localhost/v1/system/proxy-configuration" #??dis in 5.1 apis
#     headers = {'Accept': 'application/json', 'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(token)}
#     logger.info(f'Attempting {api_type} API Call with URL {api_url}')
#     response = requests.request(api_type, api_url, headers=headers, verify=False)
#     return response

#  #Incorrect Depot Credentials 
#  def incorrectCreds():

#     api_type = "GET"
#     api_url = "https://depot.vmware.com:443/PROD2/evo/vmw/index.v3"
#     response = requests.get(uri, auth=(user, password)) 



## Async Patching enabled
