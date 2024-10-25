#!/usr/bin/env python3
import subprocess
import logging
from vcenter.vc_lib.common import psqlQuery

logger = logging.getLogger(__name__)
title= "vCenter PostgresDB Check"

def run_command(command: str) -> str:
    """
    Run a command in the shell and return the output as a string.

    Args:
        command (str): The command to be run in the shell.

    Returns:
        str: The output of the command as a string.
    """    
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
    return result.stdout.decode('utf-8').strip()


def getLargestTables():
    """
    Retrieve information about the top 20 largest tables in a PostgreSQL database.

    Returns:
        dict: A dictionary with the following keys:
            - title (str): The title of the result.
            - result (str): The status or result of the query.
            - details (str): Additional details about the largest tables.
    """    
    title="Top 20 Largest Tables"
    result="INFO"
    details=""
    query = """SELECT nspname || '.' || relname AS "relation", pg_size_pretty(pg_total_relation_size(C.oid)) AS "total_size" FROM pg_class C LEFT JOIN pg_namespace N ON (N.oid = C.relnamespace) WHERE nspname NOT IN ('pg_catalog', 'information_schema') AND C.relkind <> 'i' AND nspname !~ '^pg_toast' ORDER BY pg_total_relation_size(C.oid) DESC LIMIT 20;"""
    output = psqlQuery(query, True)
    for line in output.splitlines():
        if "rows" not in line:
            details +="\n"+ line
    return {'title':title,'result':result,'details':details}

def getPostgresSize():
    """
    Get the size of the Postgres database.

    Returns:
        dict: A dictionary containing the following information:
            - 'title' (str): The title of the result.
            - 'result' (str): The result status.
            - 'details' (str): Additional details about the Postgres size, including:
                - The interpreted size by Postgres.
                - The size of the `/storage/db/vpostgres/` directory.
                - The size of the `/storage/seat/vpostgres/` directory.
    """    
    title="Total Postgres Size"
    result="INFO"
    dbsize= run_command("du -sh /storage/db/vpostgres/")
    dbseatsize = run_command("du -sh /storage/seat/vpostgres/")
    totaldbsizequery="select pg_size_pretty(pg_database_size('VCDB')) as vcdb_size;"
    totalpostgresssize = psqlQuery(totaldbsizequery, False).replace('B','').replace(' ','')

    details = f"\n{totalpostgresssize}\t Interpreted by Postgres\n{dbsize}\n{dbseatsize}"
    return {'title':title,'result':result,'details': details}

def main():
    """
    Runs two functions and returns their outputs in a list.

    Returns:
        list: A list containing the outputs of the two functions.
    """    
    output=[]
    output.append(getLargestTables())
    output.append(getPostgresSize())
    return output

if __name__ == '__main__':
    main()