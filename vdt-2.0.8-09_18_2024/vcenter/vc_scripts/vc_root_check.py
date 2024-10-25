#!/usr/bin/env python

import logging
logger = logging.getLogger(__name__)
import sys
import subprocess
from datetime import datetime, timedelta

NUM_DAYS_CRITICAL = 30
NUM_DAYS_WARNING = 60
NUM_DAYS_INFO = 90
CHECKS = {"CRITICAL" : NUM_DAYS_CRITICAL,
        "WARNING": NUM_DAYS_WARNING,
        "INFO": NUM_DAYS_INFO}

today = datetime.now()
today = today.strftime("%b %d, %Y")

_DefaultCommmandEncoding = sys.getfilesystemencoding()

def run_command(cmd, stdin=None, quiet=False, close_fds=False,
                encoding=_DefaultCommmandEncoding, log_command=True):

    """
    Run a command and capture its output.

    Args:
        cmd (str): The command to run.
        stdin (Optional[str]): The input to pass to the command. Default is None.
        quiet (bool): Whether to suppress the output of the command. Default is False.
        close_fds (bool): Whether to close all file descriptors except stdin, stdout, and stderr. Default is False.
        encoding (str): The encoding to use for stdin, stdout, and stderr. Default is the value of _DefaultCommandEncoding.
        log_command (bool): Whether to log the command before running it. Default is True.

    Returns:
        bytes: The output of the command as bytes.

    Note:
        The command is run as a subprocess and the output is returned. The output is passed through stdout, which means that stderr is not captured.

    Raises:
        None.
    """    
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    if sys.version_info[0] >= 3 and isinstance(stdin, str):
        stdin = stdin.encode(encoding)
    stdout, stderr = process.communicate(stdin)
    return stdout

def main():
    """
    This is the main function for checking the root account expiration.

    Returns:
        dict: A dictionary containing the following keys:
            - 'title' (str): The title of the check, including the expiration information.
            - 'result' (str): The result of the check, which can be 'PASS', 'WARNING', or 'FAIL'.
            - 'details' (str): Additional details about the check.
            - 'documentation' (str, optional): Documentation related to the check.

    Raises:
        ValueError: If the raw data from the command execution is not in the expected format.
    """    
    title = "Root Account Check"
    documentation = ""
    details = ""
    expire = ""
    cmd = ['/usr/bin/chage', '-l', 'root']
    raw_data = run_command(cmd).decode()
    for line in raw_data.splitlines():
        if 'Password expires' in line:
            expire = line.strip().split(':')[1].lstrip()
    if expire == 'never':
        title = f"{title} (Exp: never)"
        # details = "Root password never expires"
        result = "PASS"
    else:
        exp_date = datetime.strptime(expire, '%b %d, %Y')
        now = datetime.strptime(today, '%b %d, %Y')
        diff = exp_date - now
        exp_in_days = diff.days

        if exp_date <= now + timedelta(days=CHECKS.get("CRITICAL")):
            result = "FAIL"
        elif exp_date <= now + timedelta(days=CHECKS.get("WARNING")):
            result = "WARNING"
        else:
            result = "PASS"


        title = f"{title} (Exp: {exp_in_days} days)"
        documentation = "Please search for 'Change the Password of the Root User' in vCenter documentation."

    output = {'title': title, 'result': result, 'details': details}

    if documentation != "":
        output.update({'documentation': documentation})

    return output


if __name__ == '__main__':
    main()
