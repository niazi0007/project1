#!/usr/bin/env python
"""
__author__ =  ["Laraib Kazi", "Tyler FitzGerald", "Keenan Matheny"]
__credits__ = ["Keenan Matheny"]

"""

from sddc_manager.sddc_lib.commandUtils import run_psql_command, run_psql_command_full
from sddc_manager.sddc_cfg.current_defaults import sddcVersion
import logging

logger = logging.getLogger(__name__)

def manifestCount(): 
    """
    Checks the number of Manifest Files found in the SDDC Manager
    LCM DB.

    Args:
        None

    Returns:
        dict: Result of the Manifest File Count Check
    """
    sddcShortVersion = sddcVersion.split("-")[0]
    sddcShortVersion = int(sddcShortVersion.replace('.',''))
    query = "select count(*) from manifest"
    try:
        if sddcShortVersion < 5100:
            count = int(run_psql_command('lcm', query))
        else:
            count = int(run_psql_command_full('lcm', query))    
    except Exception as e:
        count = 0
    
    if count > 1:
        result = 'WARN'
        details = f'{count} Manifest files found in LCM DB.'
        documentation = 'https://kb.vmware.com/s/article/89877'
        notes = 'Please reference the KB above to clear out the extra manifest files.'
    elif count == 0:
        result = 'WARN'
        details = f'{count} Manifest files found in LCM DB.'
        documentation = ''
        notes = ''
    else:
        result = 'PASS'
        details = f'{count} Manifest file found in LCM DB.'
        documentation = ''
        notes = ''
    
    return {"title":'Check number of LCM Manifest Files in the DB',
            "result":result, "details":details, "documentation":documentation, "notes":notes}