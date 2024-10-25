#!/usr/bin/env python
__title__ = "VCHA CHECK"
import sys
import os
sys.path.append(os.environ['VMWARE_PYTHON_PATH'])
from pyVim.connect import SmartConnect
import ssl
import subprocess
from vcenter.vc_cfg.current_defaults import hostname
import logging
logger = logging.getLogger(__name__)

_DefaultCommmandEncoding = sys.getfilesystemencoding()

class getVcha(object):


    def __init__(self, username, password):
        """
     Initialize a connection to a server using provided username and password.

     Args:
         username (str): The username for the server connection.
         password (str): The password for the server connection.

     Raises:
         Exception: If unable to connect to the server.
    
     Returns:
         None
     """     
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            self.c = SmartConnect(host=hostname, user=username, pwd=password,sslContext=context)
        except Exception as e:
            print("Failed to connect to %s.  Is the server currently failing over?" % hostname)
            sys.exit(1)
        self.vcha = self.c.content.failoverClusterManager

    def is_enabled(self):
        """
     Check if the VCHA mode is enabled.

     Returns:
         bool: True if the VCHA mode is enabled, False otherwise.
        """
        vcha_mode = False
        try:
            vcha_mode = self.vcha.getClusterMode()
        except:
            pass
        return vcha_mode

    def health(self):
        """
     Checks the health status of the VCHA cluster.

     Returns a list of health check results.

     Returns:
         list: A list containing health check results in the following format:
             [
                 {
                     'title': The title of the health check,
                     'result': The result of the health check (PASS, FAIL, WARNING, INFO),
                     'details': Additional details if applicable
                 },
                 ...
             ]
        
             Each result dictionary represents a different health check.

     Raises:
         None
        """
        checks = []

        if self.is_enabled():
            details = ""

            cluster_health = self.vcha.GetVchaClusterHealth()
            health_Messages = cluster_health.healthMessages

            runtime_info = cluster_health.runtimeInfo

            mode = runtime_info.clusterMode
            mode = mode.upper()
            title = f"Cluster Mode Check [{mode}]"
            if mode != 'ENABLED':

                moderesult = "WARNING"
            else:
                moderesult = "PASS"

            checks.append({'title': title, 'result': moderesult})
            #####
            state = runtime_info.clusterState
            state = state.upper()
            title = f"Cluster State Check [{state}]"
            if state != 'HEALTHY':
                stateresult = "FAIL"

                for health_data in health_Messages:
                    details += f"{health_data}\n"

            else:
                stateresult = "PASS"

            checks.append({'title': title, 'result': stateresult, 'details': details})
            #####
            node_info = runtime_info.nodeInfo
            infocheck = {'subheading': "VCHA Node Check", 'checks': []}

            for node in node_info:
                title = f"{node.nodeRole} - {node.nodeIp}: {node.nodeState}"

                if node.nodeState == 'up':
                    noderesult = "PASS"
                else:
                    noderesult = "FAIL"
                infocheck['checks'].append({'title': title, 'result': noderesult})

            checks.append(infocheck)
            return checks

        else:
            return {'title': 'VCHA Health Check [Not Enabled]', 'result': 'INFO'}

def vcha_check(username, password):
    """
    Check the health status of vCHA.

    Args:
        username (str): The username for authentication.
        password (str): The password for authentication.

    Returns:
        str: The health status of vCHA.

    Raises:
        None.
    """    
    vcha = getVcha(username, password)
    return vcha.health()

