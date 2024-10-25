#!/usr/bin/env python
"""
__author__ =  ["Laraib Kazi", "Tyler FitzGerald", "Keenan Matheny"]
__credits__ = ["Keenan Matheny"]

"""

from sddc_manager.sddc_lib.commandUtils import run_psql_command, run_psql_command_full
from sddc_manager.sddc_cfg.current_defaults import sddcVersion
import logging

logger = logging.getLogger(__name__)

def pantheonBundle(): 
    """
    Checks if Pantheon bundle exists in LCM DB. 

    Args:
        None

    Returns:
        dict: Result of the Pantheon Bundle Check
    """
    sddcShortVersion = sddcVersion.split("-")[0]
    sddcShortVersion = int(sddcShortVersion.replace('.',''))
    query = "SELECT bundle_id FROM upgrade WHERE upgrade_id IN (SELECT upgrade_id FROM upgrade_element WHERE resource_type='MULTI_SITE_SERVICE');"
    try:
        if sddcShortVersion < 5100:
            bundle_ids = (run_psql_command('lcm', query))
        else:
            bundle_ids = (run_psql_command_full('lcm', query))    
    except Exception as e:
        return bundle_ids
    
    count = len(bundle_ids)
    if count > 0:
        result = 'WARN'
        details = f'{count} Pantheon bundle(s) found in LCM DB'
        documentation = 'https://ikb.vmware.com/s/article/95633'
        notes = 'Please reference the KB above to clear out the Pantheon bundles.'

    else:
        result = 'PASS'
        details = f'No Pantheon bundles found in LCM.'
        documentation = ''
        notes = ''
    
    return {"title":'Check for Pantheon Bundles in LCM',
            "result":result, "details":details, "documentation":documentation, "notes":notes}