import sys
import os
import atexit
sys.path.append(os.environ['VMWARE_PYTHON_PATH'])
from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim, vmodl
from vcenter.vc_cfg.current_defaults import hostname
import ssl

class LoginCheckClusters(object):

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
            self.c = SmartConnect(host=hostname, user=username, pwd=password, sslContext=context)
            atexit.register(Disconnect, self.c)
        except Exception as e:
            print("Failed to connect to %s!" % hostname)
            sys.exit(1)

    def get_clusters(self):
        """
        Queries vpx API for list of clusters.

         Args:
             None

         Raises:
             Exception: If unable to connect to the server.

         Returns:
             dict: Returns a dictionary of all clusters with the cluster name as the key, and the cluster object as the value.
        """

        content = self.c.RetrieveContent()
        viewManager = content.GetViewManager()
        viewContainer = viewManager.CreateContainerView(content.rootFolder, [vim.ClusterComputeResource], True)
        entities = viewContainer.view
        viewContainer.Destroy()
        result = {}
        for entity in entities:
            result[entity.name] = entity

        return result
    def check_clusters_adv_opt(self):

        """
        Queries vpx API for list of clusters.

        Args:
            None

        Raises:
            Exception: If unable to connect to the server.

        Returns:
            dict: standard check dictionary with the following keys:
                - title (str): The title of the check.
                - result (str): The result of the check ('PASS', 'WARN', or 'FAIL').
                - details (str): Additional details about the check.
                - documentation (str): The URL for the documentation related to the check.
        """
        title = "Legacy SSL Cluster Settings Check"
        result = "PASS"
        details = ""
        documentation = ""
        kb = "https://kb.vmware.com/s/article/placeholder"
        badclusters = []
        clusters = self.get_clusters()
        for cluster in clusters:
            clusterObj = clusters.get(cluster)
            current_options = clusterObj.GetConfiguration().dasConfig.option
            current_values = [option for option in current_options
                              if option.key == 'das.config.vmacore.ssl.sslOptions']
            if len(current_values) > 0:
                badclusters.append(clusterObj.name)

        if len(badclusters) > 0:
            result = "FAIL"
            documentation = kb
            details = "Found legacy 'das.config.vmacore.ssl.sslOptions' value on clusters:"
            for cluster in badclusters:
                details+= f"\n\t- {cluster}"
        return {'title': title, 'result': result, 'details': details, 'documentation': documentation}

def check_legacy_ssl_options(username, password):

    myinit = LoginCheckClusters(username, password)
    return myinit.check_clusters_adv_opt()