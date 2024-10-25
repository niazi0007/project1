#!/usr/bin/env python
"""
__author__ =  ["Laraib Kazi", "Tyler FitzGerald"]
__credits__ = ["Keenan Matheny"]

"""

import logging

from sddc_manager.sddc_lib.commandUtils import run_psql_command

logger = logging.getLogger(__name__)

def changelock(db):
    """
    Checks for any changelog locks on a DB

    Args:
        db (str): Name of the DB in SDDC Manager

    Returns:
        dict: Result of the DB Changelog Lock Check
    """
    query = 'select locked from databasechangeloglock'
    dbOut = str(run_psql_command(db, query))
    
    if 't' in dbOut:
        result = 'WARN'
        details = f'Changelog Lock detected for {db}.'
    else:
        result = 'PASS'
        details = f'No Changelog Lock detected for {db}.'
    
    return {"title":f'Changelog Lock for {db} database', "result":result, "details":details}

def main():
    """
    Runs the Changelog lock checks on the DBs in the SDDC Manager

    Args:
        None

    Returns:
        list: List of dicts with the Result of the DB Changelog Lock Check
    """
    result_dm = changelock('domainmanager')
    result_om = changelock('operationsmanager')
    result_lcm = changelock('lcm')
    result_platform = changelock('platform')
    
    return [result_dm,result_om,result_lcm,result_platform]
  
