#!/usr/bin/env python
"""
__author__ =  ["Tyler FitzGerald"]
__credits__ = ["Laraib Kazi"]

"""
__title__ = "SYSLOG LOGROTATE CHECK"

import os
import logging
from datetime import datetime
 
logger = logging.getLogger(__name__)

def syslog_check():
    """
    Checks if syslog file exists on SDDC

    Args:
        None

    Returns:
        dict: Result of the syslog file check
    """  
    logger.debug("Checking for syslog logrotate")
    directory = "/etc/logrotate.d/"
    syslog_file = "syslog"

    file_path = os.path.join(directory, syslog_file)

    if os.path.exists(file_path):
        result = 'PASS'
        details = 'Syslog file is present on SDDC.'
        documentation = ''
        notes = ''
    else:
        result = 'WARN'
        details = 'Syslog file is not present on SDDC.'
        documentation = 'https://kb.vmware.com/s/article/89877'
        notes = 'Please reference the KB above to add syslog logrotate file.'
    
    return {"title":'Check if syslog file is present',
            "result":result, "details":details, "documentation":documentation, "notes":notes}