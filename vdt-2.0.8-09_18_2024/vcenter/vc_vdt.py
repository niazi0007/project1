#!/usr/bin/env python
"""
__authors__ = ["Keenan Matheny", "Christopher Morrow", "Fouad Sethna", "Kevin Hagopian", "Kiran N"]
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
import ssl
import logging
import getpass
import datetime
import time
import configparser
from cfg.vdt_defaults import get_vdt_config
from lib.vdt_formatter import ColorWrap, escape_ansi
from lib.vdt_base import get_logger_enh
from lib.vdt_formatter import Formatter, ColorWrap
if os.getenv('VMWARE_PYTHON_PATH') not in sys.path:
    sys.path.append(os.getenv('VMWARE_PYTHON_PATH'))
import vmafd
default_loglevel = get_vdt_config()['logging'].get('level')

cfgfile = os.path.join(os.path.dirname(__file__), "vc_cfg", "vc_vdt.ini")
config = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
config.read(cfgfile)

logdir = config['logging'].get('logdir')
logname = config['logging'].get('logname')
loglevel = config['logging'].get('level')
title = config['vdt'].get('title')

date_time = f"{datetime.date.today().strftime('%A, %B %d')} {time.strftime('%H:%M:%S', time.localtime())}"
runtime_info = f"{ColorWrap.title(title)}\n\tToday: {date_time}\n\tLog Level: {loglevel}\n"

get_logger_enh(default_loglevel,logdir,logname)
logger = logging.getLogger(__name__)

sys.path.append(os.environ['VMWARE_PYTHON_PATH'])
from pyVmomi import (lookup, SoapStubAdapter, vmodl, dataservice,
                     SessionOrientedStub, Vim)
from pyVmomi.VmomiSupport import newestVersions

from vcenter.vc_cfg.current_defaults import httpsPort, service_status, sso_domain, version


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

    if level == "info":
        print(string_text)
        logger.info(escape_ansi(string_text))
    elif level == "error":
        logger.error(escape_ansi(string_text))
    if level == "debug":
        print(string_text)
        logger.debug(escape_ansi(string_text))
    if level == "warn":
        print(string_text)
        logger.warning(escape_ansi(string_text))

logandprint(runtime_info)
login_retry_limit = 3

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

def _update_vm_support():
    """
    Utility function to include vdt log directory in support bundles.
    """
    mfx = f"""
% Manifest name: vdt
% Manifest group: VirtualAppliance
% Manifest default: Enabled
# action Options file/command
copy IGNORE_MISSING {logdir}/*
    """
    vmsupportpath = os.path.join(os.environ['VMWARE_CFG_DIR'], 'vm-support','vdt.mfx')
    if not os.path.exists(vmsupportpath):
        try:
            answer = input(
                "When running this tool, a log file is created and included in all future log bundles.  Would you like to continue?[Yy|Nn]: ")
        except:
            answer = raw_input(
                "When running this tool, a log file is created and included in all future log bundles.  Would you like to continue?[Yy|Nn]: ")
        if answer.lower() == 'n':
            logandprint("Exiting.")
            sys.exit()
        elif answer.lower() == 'y':
            try:
                with open(vmsupportpath,"w+") as f:
                    f.writelines(mfx)
                logger.debug("vdt logs will be included in support bundles.")
            except:
                error_msg = "Couldn't add support bundle config file: %s" % vmsupportpath
                logger.error("You will have to collect vdt logs manually!  Error was: %s" % error_msg)
        else:
            logandprint("\nInvalid option.  Please try again.\n")
            sys.exit()
    else:
        logger.debug("%s already exists." % vmsupportpath)

def loadMachineCredentials():
    """
        Retrieve machine account and machine account password from vmafd.

        Returns:
            tuple: A tuple containing the machine account and machine account password from vmafd.

            The tuple has the format (username, password).

            If VMAFD is not running, it returns (None, None).

        Raises:
            None.
    """

    if 'vmafdd service required!' in sso_domain:
        print(sso_domain)
        logandprint("VMAFD not running.  checks requiring authentication may not run.", level="error")
        return None, None

    vmafdclient = vmafd.client('localhost')
    name = vmafdclient.GetMachineName()
    domain = vmafdclient.GetDomainName()
    username = '{}@{}'.format(name, domain)
    password = vmafdclient.GetMachinePassword()
    return username, password


def TestLogin(username=None, password=None, retry=0, userauth=False):

    """
    Test login with provided username and password.

    Args:
        username (str, optional): The username to use for login. If not provided, it prompts the user to enter the username.
        password (str, optional): The password to use for login. If not provided, it prompts the user to enter the password.
        retry (int, optional): The number of login retry attempts made. Default is 0.
        failout (bool, optional): If failed over from machine account creds to admin creds.

    Returns:
        tuple: A tuple containing the username, password, and success status.
            - username (str or None): The username used for login. If the login was not successful, returns None.
            - password (str or None): The password used for login. If the login was not successful, returns None.
            - success (bool): True if the login was successful, False otherwise.

    Raises:
        None

    Note:
        The function internally handles invalid user credentials and prompts for retry or exit options.
    """

    if not username:
        # username, password = prompt()
        if not userauth:
            username, password = loadMachineCredentials()
        else:
            username, password = prompt()
        if not username:
            success = False
            return None, None, success
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        try:
            stub = SoapStubAdapter(host='localhost', port=httpsPort, path='/sdk',
                                   version=newestVersions.GetName('vpx'), sslContext=context,
                                   httpConnectionTimeout=10)
        except:
            stub = SoapStubAdapter(host='localhost', port=httpsPort, path='/sdk',
                                   version=newestVersions.Get('vpx'), sslContext=context,
                                   httpConnectionTimeout=10)
        si = Vim.ServiceInstance('ServiceInstance', stub)
        sessionMgr = si.content.sessionManager
        sessionMgr.Login(username, password)
        logger.info("Login successful")
        rc = 1
    except Vim.fault.InvalidLogin:
        if retry < login_retry_limit:
            retry += 1
            logandprint("Invalid user credentials.  Please try again. [retry %s/%s] " % (retry, login_retry_limit), level="debug")
            return TestLogin(retry=retry, userauth=userauth)
        else:
            logandprint("Invalid user credentials.  Retry limit reached.\n", level="debug")
            if userauth:
                answer = input("Would you like to continue?  Any check requiring authentication will not be run [Yy|Nn] ")
                if answer.lower() == "n":
                    sys.exit()
                elif answer.lower() == "y":
                    rc = 0
                else:
                    print(f"{answer} is not a valid answer.  Please run again.")
                    sys.exit()
            else:
                rc = 0
    except Exception as e:
        logger.debug(str(e))
        logandprint("Error attempting login (not related to credentials).  Checks requiring authentication will not be run.", level="error")
        rc = 0

    if rc == 1:
        success = True
        return username, password, success
    else:
        success = False
        if not userauth:
            logandprint("Automatic login with machine account credentials failed")
        return None, None, success

def prompt():

    """
    Prompt the user for username and password.

    Returns:
        tuple: A tuple containing the username and password provided by the user.

        The tuple has the format (username, password).

        If VMAFD is not running, it returns (None, None).

    Raises:
        None.
    """    
    if 'vmafdd service required!' in sso_domain:
        print(sso_domain)
        logandprint("VMAFD not running.  checks requiring authentication may not run.", level="error")
        # input("Press any key to continue...\n")
        return None, None
    username = "administrator@" + sso_domain
    # Get password with no echo
    passwd = getpass.getpass("\nProvide password for %s: " % username)
    return username, passwd

def reqServicesStarted(services):
    """
    Check the status of requested services.

    Args:
        services (list or str): A list of services or a single service.

    Returns:
        int: 1 if all services are running, 2 if any service is disabled, 0 otherwise.

    Raises:
        None

    Note:
        - The function checks the status of services provided and returns a corresponding code.
        - If `services` is a list, it checks if all services are running or if any service is disabled.
        - If `services` is a string, it checks the status of that specific service.
        - The function assumes that the status of services is stored in the dictionary `service_status`.
    """    
    if isinstance(services, list):
        if all(service in service_status['RUNNING'] for service in services):
            return 1
        elif any(x in services for x in service_status['DISABLED']):
            return 2
        else:
            return 0
    elif isinstance(services, str):
        if services in service_status['RUNNING']:
            return 1
        elif services in service_status['DISABLED']:
            return 2
        else:
            return 0

def main():
    """
    Main function that performs a series of checks.

    Raises:
        None
    Returns:
        None
    """
    _update_vm_support()
    if version.startswith('8'):
        userauth = False
    else:
        print("\nMachine account credential auth is only available in VC 8+\n")
        userauth = True
    required_services = ['vmafdd', 'vmdird', 'vmware-stsd']
    if not reqServicesStarted(required_services):
        success = False
        username = ""
        password = ""
    else:
        username, password, success = TestLogin(userauth=userauth)
        if not success and not userauth:
            username, password, success = TestLogin(userauth=True)

    Runner = Formatter(name=__name__, item_type='check', cfgfile=cfgfile, username=username,
                     password=password)
    servicefail = False
    authfail = False

    for check in Runner.checks:

        check_params = Runner.cfg.get(f"check:{check}")
        if 'req_services' in check_params:

            if reqServicesStarted(check_params['req_services']) == 0:
                servicefail = True
                Runner.skipped.update({check_params['name']: {'reason': 'service not running', 'result': 'FAIL'}})

            elif reqServicesStarted(check_params['req_services']) == 2:
                Runner.skipped.update({check_params['name']: {'reason': 'service disabled', 'result': 'INFO'}})

        if not success:
            authfail = True
            if 'auth_req' in check_params:
                if check_params['auth_req'] == True:
                    if check_params['name'] not in Runner.skipped.keys():
                        Runner.skipped.update({check_params['name']: {'reason': 'authentication failure', 'result': "FAIL"}})

    if authfail:
        logandprint(f"{ColorWrap.warn('WARNING')}: Authentication failed!  Checks that require authentication will be skipped.")

    if servicefail:
        logandprint(f"{ColorWrap.warn('WARNING')}: Some required services aren't running!  Dependent checks will be skipped.")

    if authfail or servicefail:
        input("\n\nPress any key to continue with the remaining checks...\n\n")

    report_location = Runner.generate_report(True, header=runtime_info)
    logandprint(f"""
    ---
Report location: {report_location}
JSON location:  {report_location}.json
Log location:  {os.path.join(logdir, logname)}
Feedback Contact: vcf-gs-sa-vdt.PDL@broadcom.com
    ---""")

if __name__ == '__main__':
    main()


