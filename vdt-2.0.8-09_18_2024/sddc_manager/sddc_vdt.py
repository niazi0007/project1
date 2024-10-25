#!/usr/bin/env python
"""
__author__ =  ["Laraib Kazi", "Tyler FitzGerald"]
__credits__ = ["Keenan Matheny", "Christopher Morrow", "Fouad Sethna", "Kevin Hagopian", "Kiran N"]
__license__ = "SPDX-License-Identifier: MIT"
__status__ = "Beta"
__copyright__ = "Copyright (C) 2024 Broadcom Inc."

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in the
Software without restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

import sys
import os
import logging
import datetime
import time
import configparser

from cfg.vdt_defaults import get_vdt_config
from lib.vdt_formatter import Formatter,ColorWrap,bcolors, escape_ansi
from lib.vdt_base import get_logger_enh
#from sddc_manager.sddc_cfg import sddc_defaults

default_loglevel = get_vdt_config()['logging'].get('level')

cfgfile = os.path.join(os.path.dirname(__file__), "sddc_cfg", "sddc_vdt.ini")
config = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
config.read(cfgfile)

logdir = config['logging'].get('logdir')
logname = config['logging'].get('logname')
loglevel = config['logging'].get('level')

warning_message = "\n\
    DISCLAIMER: This script is currently in its beta release phase.\n\
    As such, it may contain bugs, errors, or incomplete features.\n\
    Please use it with caution.\n"

title = f"VDT (v{config['vdt'].get('version')}) for SDDC Manager"

date_time = f"{datetime.date.today().strftime('%A, %B %d')} {time.strftime('%H:%M:%S', time.localtime())}"
runtime_info = f"{ColorWrap.title(title)}\n\tToday: {date_time}\n\tLog Level: {default_loglevel}\n{ColorWrap.warn(warning_message)}"

get_logger_enh(default_loglevel,logdir,logname)
logger = logging.getLogger(__name__)

def logandprint(string_text, level="info"):
    """
    Log and print a string message with a specified log level.

    Args:
        string_text (str): The string message to log and print.
        level (str, optional): The log level to use. Default is 'info'.

    Raises:
        None

    Returns:
        None
    """ 
    print(string_text)
    if level == "info":
        logger.info(escape_ansi(string_text))
    elif level == "error":
        logger.error(escape_ansi(string_text))
    if level == "debug":
        logger.debug(escape_ansi(string_text))
    if level == "warn":
        logger.warning(escape_ansi(string_text))
        
logandprint(runtime_info)
login_retry_limit = 3

# conf_path = sddc_defaults.defaults_file
# print(f' ... Loading Inventory | Please wait ...')
# logger.info(sddc_defaults.setDefaults())
# print(f' ... Completed! ...')

from sddc_manager.sddc_cfg.current_defaults import mgmtVcHostname, ssoAdmin
from sddc_manager.sddc_lib.authUtils import get_session_token, sso_prompt

def FailedLoginSkip():
    """
    Skip one or more checks due to login failure.

    Args:
        None

    Returns:
        None

    Raises:
        None
    """  
    logandprint("\t" + ColorWrap.fail("ERROR:") + " Due to login failure, one or more checks will be skipped.")

def authChecker(vc_hostname,username,password):
    """
    Test login with provided username and password.

    Args:
        vc_hostname (str): FQDN of the vCenter. This is the MGMT WLD vCenter.
        username (str): The username to use for login. 
        password (str): The password to use for login.

    """
    logger.debug('Verifying SSO Password ..')
    token,text = get_session_token(vc_hostname, username, password)

    if token == 200:
        authflag = True
        return username, password
    elif token == 401:
        logger.debug('Authentication failed due to incorrect credentials. No auth checks will be run.')
        authflag = False
        print(f'\n {bcolors.FAIL}[WARN] Authentication failed due to incorrect credentials.{bcolors.ENDC}')
    else:
        authflag = False
        logger.debug('Authentication failed due to MGMT VC Root Cert not being trusted. No auth checks will be run.')
        print(f'\n {bcolors.FAIL}[WARN] Authentication failed due to a certificate trust verification failure.{bcolors.ENDC}')    
    
    if authflag == False:
        answer = input("Would you like to continue?  Any check requiring authentication will not be run [Y|y|N|n] ")
        if answer.lower() == "n":
            sys.exit()
        elif answer.lower() == "y":
            return None, None
        else:
            logger.info("%s is not a valid answer. Please run again.")
            sys.exit()

def main():
    """
    Main function that performs a series of checks.

    Raises:
        None
    Returns:
        None
    """ 

    # if mgmtVcHostname == '':
    #     print(f'First Run detected. Inventory Files Generated.\nPlease re-run VDT.')
    #     sys.exit(0)
    
    password = sso_prompt()
    username,password=authChecker(mgmtVcHostname,ssoAdmin,password)
    #print(f'Found credentials: {username},{password}')
    
    Runner = Formatter(name=__name__, item_type='check', cfgfile=cfgfile, username=username,
                     password=password)
    report_location = Runner.generate_report(True, header=runtime_info)
    logandprint(f"""
    ---
Report location: {report_location}
JSON location:  {report_location}.json
Log location:  {os.path.join(logdir, config['logging'].get('logname'))}
Feedback Contact: vcf-gcs-sa-vdt.pdl@broadcom.com
    ---""")

if __name__ == '__main__':
    main()