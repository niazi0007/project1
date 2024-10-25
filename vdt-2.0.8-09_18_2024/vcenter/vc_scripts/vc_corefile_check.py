#!/usr/bin/env python3
__title__ = "CORE FILE CHECK"
import os
import fnmatch
from datetime import datetime, timedelta
import time

import logging
logger = logging.getLogger(__name__)

today = datetime.now().strftime('%Y-%m-%dT%H:%M:%S')

threshold = 80
testkb="https://kb.vmware.com/s/article/1003564"
NUM_HOURS_CRITICAL = 12
CRITICAL_MESSAGE = """
These corefiles have been created within the last %s hours.  
Investigation is warranted. 

""" % NUM_HOURS_CRITICAL

NUM_HOURS_WARNING = 72
WARNING_MESSAGE = """ 
These core files have been created within %s to %s hours.
Investigation only warranted if there are many from the same service
and you are experiencing symptoms.  Otherwise, consider deleting them
at your discretion to reduce the size of log bundles.

""" % (NUM_HOURS_CRITICAL, NUM_HOURS_WARNING)

NUM_HOURS_INFO = None
INFO_MESSAGE = """ 
These core files are older than %s hours.  consider deleting them
at your discretion to reduce the size of log bundles.

""" % NUM_HOURS_WARNING




def evalRelevancy(files):
    """
    Evaluate the relevancy of a list of files based on their last modified date.

    Args:
        files (list): A list of file paths.

    Returns:
        tuple: A tuple containing the highest fail state and a dictionary of relevant file information. 
            The fail state is an integer representing the severity of the highest failure encountered. 
            The dictionary has three keys - 'CRITICAL', 'WARN', and 'INFO' - each containing a dictionary 
            with keys 'duration', 'message', 'failstate', and 'files'. 'duration' is the duration in hours 
            for the relevant check, 'message' is the associated message, 'failstate' is the fail state for 
            the check, and 'files' is a list of files that meet the relevancy criteria.

    Raises:
        None.
    """    
    highest_fail = 0
    
    CHECKS = {"CRITICAL" : 
        {"duration": NUM_HOURS_CRITICAL,
            "message" : CRITICAL_MESSAGE,
            "failstate" : 2,
            "files": []},
        "WARN": 
            {"duration": NUM_HOURS_WARNING,
            "message" : WARNING_MESSAGE,
            "failstate": 1,
            "files": []},
        "INFO": 
            {"duration": NUM_HOURS_INFO,
            "message" : INFO_MESSAGE,
            "failstate" : 0,
            "files": []}
        }

    def check_exists(filedetail):
        """
        Check if a file detail exists in a dictionary of files.

        Args:
            filedetail: A string representing the file detail to be checked.

        Returns:
            bool: True if the file detail exists in the dictionary of files, False otherwise.
        """        
        for check in CHECKS:
            if filedetail in CHECKS[check]['files']:
                return True
        return False

    def is_file_older(filename, delta):
        """
        Check if a file is older than a given time period.

        Args:
            filename (str): The name of the file.
            delta (timedelta): The time period to compare against.

        Returns:
            bool: True if the file is older than the given time period, False otherwise.
        """        
        cutoff = datetime.utcnow() - delta
        mtime = datetime.utcfromtimestamp(os.path.getmtime(file))

        if mtime > cutoff:
            return True
        return False

    for file in files:
        now = datetime.now()
        last_modified = getLastModifiedDate(file)
        time = os.path.getmtime(file)
        # time = datetime.strptime(time,'%Y-%m-%dT%H:%M:%S')
        size = getFileSize(file)
        if is_file_older(file, timedelta(hours=CHECKS["CRITICAL"].get("duration"))):
            # print("%s is greater than %s" %(time, now + timedelta(hours=CHECKS["CRITICAL"].get("duration"))))
            if CHECKS["CRITICAL"].get("failstate") > highest_fail:
                highest_fail = CHECKS["CRITICAL"].get("failstate")
            filedetail = "%s Size: %s Last Modified: %s" % (file, size, last_modified)
            if not check_exists(filedetail):
                CHECKS["CRITICAL"]['files'].append(filedetail)
            continue

        if is_file_older(file, timedelta(hours=CHECKS["WARN"].get("duration"))):
            # print("%s is greater than %s" %(time, now + timedelta(hours=CHECKS["WARN"].get("duration"))))
            if CHECKS["WARN"].get("failstate") > highest_fail:
                highest_fail = CHECKS["WARN"].get("failstate")
            filedetail = "%s Size: %s Last Modified: %s" % (file, size, last_modified)
            if not check_exists(filedetail):
                CHECKS["WARN"]['files'].append(filedetail)
            continue
        
        # print("LAST TOUCH: %s, NOW: %s" % (time, now))
        filedetail = "%s Size: %s Last Modified: %s" % (file, size, last_modified)
        if not check_exists(filedetail):
            CHECKS['INFO']['files'].append(filedetail)
    return highest_fail, CHECKS

def listCoreFiles(dirname, proc):
    """
    Find core files matching a specific process in a directory.

    Args:
        dirname (str): The directory to search for core files.
        proc (str): The name of the process.

    Yields:
        str: The path to each core file matching the process name.

    Raises:
        None
    """    
    for root,dirs,files in os.walk(dirname):
            for name in files:
                if 'core' in name and proc in name:
                    yield os.path.join(root,name)

def getMostRecent(dirname,proc):
    """
    Get the most recent file in a directory that matches the specified criteria.

    Args:
        dirname (str): The directory to search for files.
        proc (str): The criteria for selecting files.

    Returns:
        str: The path of the most recent file that matches the criteria.

    Raises:
        FileNotFoundError: If no file matching the criteria is found in the directory.
    """    
    latest = max(listCoreFiles(dirname,proc), key=os.path.getmtime)
    return latest

def getLastModifiedDate(filename):
    """
    Get the last modified date of a file.

    Args:
        filename (str): The name of the file.

    Returns:
        str: The last modified date of the file in the format 'YYYY-MM-DDTHH:MM:SS'.
    """    
    mod_time = os.path.getmtime(filename)
    return time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(mod_time))

def getFileSize(filename):
    
    """
    Get the size of a file in either megabytes (MB) or gigabytes (GB).

    Args:
        filename (str): The name of the file.

    Returns:
        str: The size of the file in megabytes or gigabytes, rounded to two decimal places.

    Raises:
        FileNotFoundError: If the specified file does not exist.
    """    
    original_size = os.path.getsize(filename)
    sizeform = "MB"
    filesize = original_size/(1024*1024)
    if filesize > 1024:
        sizeform = "GB"
        filesize = original_size/(1024*1024*1024)
    filesize = str(round(filesize,2)) + sizeform
    return filesize

def searchFiles(directory, pattern, ignorelist=[]):
    
    """
    Search for files in a directory matching a given pattern, ignoring specified directories.

    Args:
        directory (str): The directory to search in.
        pattern (str): The pattern to match the file names against.
        ignorelist (list): (optional) A list of directories to ignore during the search. Defaults to an empty list.

    Returns:
        list: A list of file paths that match the given pattern.

    Raises:
        None.
    """    
    filelist = []
    for root, dirnames, filenames in os.walk(directory):
        if not any(ignore in root for ignore in ignorelist):
            for filename in fnmatch.filter(filenames, pattern):
                filelist.append(os.path.join(root, filename))
    return filelist

def findHprofs():
    """
    Find HPROF files and evaluate their relevancy to determine their status.

    Returns:
        list: A list of dictionaries representing the result checks for the HPROF files. Each dictionary contains the following keys:
            - title: The title of the result check.
            - result: The result status of the HPROF files (either 'FAIL', 'WARN', or 'INFO').
            - details: The details or message associated with the result status.
            - Hprof Files: A string that lists the paths of the HPROF files.

        If no HPROF files are found, returns a dictionary with the following keys:
            - title: The title of the result check.
            - result: The result status indicating a 'PASS'.

    Raises:
        None.
    """    
    result_checks = []
    title = "HPROF File Check"
    vmware_log_path = '/var/log/vmware'
    core_path = '/storage/core'
    hprof_list = searchFiles(vmware_log_path, '*hprof*')
    hprof_list.extend(searchFiles(core_path, '*hprof*'))

    hprof_count = len(hprof_list)

    if hprof_count > 0:
        hprof_list = sorted(hprof_list, key=lambda f: -os.stat(f).st_mtime)
        highest_fail, checks = evalRelevancy(hprof_list)

        if len(checks['CRITICAL']['files']) > 0:
            result = "FAIL"
            details = CRITICAL_MESSAGE
            files = "\n" + "\n".join([x for x in checks['CRITICAL']['files']])
            result_checks.append({'title': title, 'result': result, 'details': details, 'Hprof Files': files})

        if len(checks['WARN']['files']) > 0:
            result = "WARN"
            details = WARNING_MESSAGE
            files = "\n" + "\n".join([x for x in checks['WARN']['files']])
            result_checks.append({'title': title, 'result': result, 'details': details, 'Hprof Files': files})
        
        if len(checks['INFO']['files']) > 0:
            result = "INFO"
            details = INFO_MESSAGE
            files = "\n" + "\n".join([x for x in checks['INFO']['files']])
            result_checks.append({'title': title, 'result': result, 'details': details, 'Hprof Files': files})
        
        return result_checks
    else:
        return {'title': title, 'result': 'PASS'}


def checkCores():
    """
    Check for core files and evaluate their relevance.

    Returns:
        list: A list of dictionaries containing information about the core files and their evaluation.

    Raises:
        None.
    """    
    result_checks = []
    title = "Core File Check"
    core_path = '/storage/core'
    core_list = searchFiles(core_path, 'core*', ignorelist=['software-update'])

    core_count = len(core_list)

    if core_count > 0:
        core_list = sorted(core_list, key=lambda f: -os.stat(f).st_mtime)
        highest_fail, checks = evalRelevancy(core_list)

        if len(checks['CRITICAL']['files']) > 0:
            result = "FAIL"
            details = CRITICAL_MESSAGE
            files = "\n" + "\n".join([x for x in checks['CRITICAL']['files']])
            result_checks.append({'title': title, 'result': result, 'details': details, 'Core Files': files})

        if len(checks['WARN']['files']) > 0:
            result = "WARNING"
            details = WARNING_MESSAGE
            files = "\n" + "\n".join([x for x in checks['WARN']['files']])
            result_checks.append({'title': title, 'result': result, 'details': details, 'Core Files': files})

        if len(checks['INFO']['files']) > 0:
            result = "INFO"
            details = INFO_MESSAGE
            files = "\n" + "\n".join([x for x in checks['INFO']['files']])
            result_checks.append({'title': title, 'result': result, 'details': details, 'Core Files': files})

        return result_checks

    else:

        return {'title': title, 'result': 'PASS'}
        
if __name__ == '__main__':
    setupLogging()
    # print(color_wrap("CORE FILE CHECK", 'title'))
    checkCores()
    findHprofs()