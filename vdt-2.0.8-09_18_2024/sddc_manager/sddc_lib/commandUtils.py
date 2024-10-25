#!/usr/bin/env python
"""
__author__ =  ["Laraib Kazi", "Tyler FitzGerald"]

"""
import subprocess
import sys
import os
import argparse
import atexit
import logging.config
from importlib import import_module

_DefaultCommmandEncoding = sys.getfilesystemencoding()

workingdir = os.path.dirname(os.path.abspath(__file__))
scripts_dir = os.path.join(workingdir, 'scripts')

def run_command(cmd, stdin=None, encoding=_DefaultCommmandEncoding):
    """
    Run a command in a subprocess and return the output.

    Args:
        cmd (list): A list of command and arguments to run.
        stdin (str, optional): Standard input for the command. Defaults to None.
        encoding (str, optional): The encoding to use for the input. Defaults to the default command encoding.

    Returns:
        bytes: The output of the command as bytes.

    Raises:
        subprocess.CalledProcessError: If the command returns a non-zero exit status.
        subprocess.TimeoutExpired: If the command times out.
    """    

    process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    stdout, stderr = process.communicate(stdin)
    return stdout

# def run_command_2(cmd, stdin=None, quiet=False, close_fds=False,
#                 encoding=_DefaultCommmandEncoding, log_command=True):

#     process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
#                             stderr=subprocess.PIPE, stdin=subprocess.PIPE)
#     if sys.version_info[0] >= 3 and isinstance(stdin, str):
#         stdin = stdin.encode(encoding)
#     stdout, stderr = process.communicate(stdin)
#     return stdout.decode('utf-8'),stderr.decode('utf-8')

def run_psql_command(db, query):
    """
    Run a PostgreSQL query and return the output.

    Args:
        db (str): The name of the DB in postgres
        query (str): The SQL query to be executed.

    Returns:
        str: The output of the query.

    Raises:
        Exception: If there is an error executing the query or if the vPostgres service is not available.
    """
    cmd = ['psql', '-h', 'localhost', '-d', db, '-qAtX', 'postgres', '-c', query]
    output = run_command(cmd)
    return output

def run_psql_command_full(db, query):
    """
    Run a PostgreSQL query and return the output for SDDC Manager 5.1+

    Args:
        db (str): The name of the DB in postgres
        query (str): The SQL query to be executed.

    Returns:
        str: The output of the query.

    Raises:
        Exception: If there is an error executing the query or if the vPostgres service is not available.
    """
    cmd = ['/usr/pgsql/13/bin/psql', '-h', 'localhost', '-d', db, '-qAtX', 'postgres', '-c', query]
    output = run_command(cmd)
    return output