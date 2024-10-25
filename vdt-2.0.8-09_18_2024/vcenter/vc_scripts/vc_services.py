#!/usr/bin/env python
__title__ = "VC SERVICES CHECK"

from vcenter.vc_cfg.current_defaults import service_status, version
from configparser import ConfigParser
import logging
logger = logging.getLogger(__name__)

def check_start_priority():

    title = 'Service Start Priority'
    result = 'PASS'
    details = ''
    documentation = ''
    parsed_config = ConfigParser()
    parsed_config.read("/etc/systemd/system/multi-user.target.wants/vmware-vmon.service")
    start_priority = parsed_config.get('Unit', 'After')
    if version.startswith('8.0.1') or version.startswith('8.0.0'):
        if 'vmdird.service' not in start_priority:
            result = 'WARN'
            details = f"Start priority is incorrect: {start_priority.replace(' ', ', ')}"
            documentation = "https://kb.vmware.com/s/article/89163"
    return {'title': title, 'result': result, 'details': details, 'documentation': documentation}

def run_services_check():
    """
    Perform a services check and return a dictionary with the result.

    Returns:
        dict: A dictionary containing the following keys:
            - 'title' (str): The title of the services check.
            - 'result' (str): The result of the services check. It can be 'PASS' or 'FAIL'.
            - 'details' (str): Additional details about the services check, if any.
    """    
    title = "Services Check"
    details = ""
    if len(service_status['STOPPED']) > 0 and len(service_status['RUNNING']) > 0:
        result = 'FAIL'
        stopped_services = '\n  '.join(service_status['STOPPED'])
        details = f"The following services are stopped:\n  {stopped_services}"

    elif len(service_status['RUNNING']) < 1:
        result = 'FAIL'
        details = "All services are stopped."

    elif len(service_status['STOPPED']) < 1:
        result = "PASS"

    return {'title': title, 'result': result, 'details': details}
