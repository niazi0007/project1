#!/usr/bin/env python
"""
__author__ =  ["Tyler FitzGerald", "Laraib Kazi", "Keenan Matheny"]
__credits__ = ["Keenan Matheny"]

"""

from sddc_manager.sddc_lib.commandUtils import run_psql_command, run_psql_command_full
from sddc_manager.sddc_cfg.current_defaults import sddcVersion
import logging

logger = logging.getLogger(__name__)

def credential_history(): 
    """
    Checks for high number of credential history. 

    Args:
        None

    Returns:
        dict: Result of the Credential History Check
    """
    sddcShortVersion = sddcVersion.split("-")[0]
    sddcShortVersion = int(sddcShortVersion.replace('.',''))
    query = "select count(*) from credentialhistory;"
    try:
        if sddcShortVersion < 5100:
            bundle_ids = (run_psql_command('platform', query))
        else:
            bundle_ids = (run_psql_command_full('platform', query))    
    except Exception as e:
        return bundle_ids
    
    count = len(bundle_ids)
    if count > 250:
        result = 'WARN'
        details = f'{count} credential_history records were found'
        documentation = 'https://ikb.vmware.com/s/article/95633'
        notes = 'Please reference the KB above to clear out the Pantheon bundles.'

    else:
        result = 'PASS'
        details = f'Expected number of credential history records.'
        documentation = ''
        notes = ''
    
    return {"title":'Check credential_history entries',
            "result":result, "details":details, "documentation":documentation, "notes":notes}