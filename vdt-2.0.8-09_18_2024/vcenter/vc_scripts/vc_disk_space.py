#!/usr/bin/env python
__title__ = "DISK CHECK"

import subprocess
import os

import logging
import re
from vcenter.vc_lib.common import Command
logger = logging.getLogger(__name__)

threshold = 80
testkb = "https://kb.vmware.com/s/article/76563"

class disk_stat(object):
    """
    A class representing disk statistics.
    """
    pass

def get_directory_size(directory):
    """
    Returns the size of the `directory` in bytes.
    """
    total = os.path.getsize(directory)
    for entry in os.listdir(directory):
        entry_path = os.path.join(directory, entry)
        try:
            if os.path.isfile(entry_path):
                # if it's a file, use stat() function
                total += os.path.getsize(entry_path)
            elif os.path.isdir(entry_path):
                total += get_directory_size(entry_path)
        except NotADirectoryError:
            # if `directory` isn't a directory, get the file size then

            logger.error(f"NOT A DIR: {entry_path}")
        except PermissionError:
            # if for whatever reason we can't open the folder, return 0
            pass
    return total

def format_size(number):
    """
    Format the size of a file or data in bytes to a human-readable format.

    Args:
        number (int): The size of the file or data in bytes.

    Returns:
        str: The formatted size, including the magnitude (MB or GB).
    """
    sizeform = "MB"
    filesize = number / (1024 * 1024)
    if filesize > 1024:
        sizeform = "GB"
        filesize = number / (1024 * 1024 * 1024)
    filesize = str(round(filesize, 2)) + sizeform
    return filesize

def get_largest_files(directory):
    """
    Get the largest files in a given directory.

    Args:
        directory (str): The path to the directory.

    Returns:
        str: A string representation of the largest files in the directory.

    Raises:
        None.

    Note:
        This function excludes any files with 'proc' in their name and skips symbolic links that do not exist.
    """
    output = "  Largest Files:\n"
    file_list = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if 'proc' not in file:
                filepath = os.path.join(root, file)
                if os.path.islink(filepath) and not os.path.exists(filepath):
                    continue
                else:
                    file_list.append((filepath, os.path.getsize(filepath)))
    file_list.sort(key=lambda x: x[1], reverse=True)
    file_list = file_list[:5]
    for order, file in enumerate(file_list):
        output += f"    - {file[0]} {format_size(file[1])}\n"
    return output

def get_largest_dir(mount):
    """
    Get the largest directories over 2GB within a specified mount point.

    Args:
        mount (str): The path of the mount point.

    Returns:
        list: A list of dictionaries containing information about the largest directories.
            Each dictionary has the following keys:
                - 'title': The name of the directory and its size.
                - 'result': The result of the check ('WARN' in this case).
                - 'details': Additional details about the largest files within the directory.

    Raises:
        None.
    """
    subheading = f"Directories over 2GB"
    checks = []

    sizes = []
    sizes.append((mount, get_directory_size(mount)))
    for directory in os.listdir(mount):
        dir_path = os.path.join(mount, directory)
        if os.path.isdir(dir_path):
            sizes.append((dir_path, get_directory_size(dir_path)))
    sizes.sort(key=lambda x: x[1], reverse=True)
    sizes = sizes[:5]
    for order, folder in enumerate(sizes):
        if folder[1] > 2147483648:
            if folder[0] != mount:
                checks.append({'title': f"{folder[0]}  {format_size(folder[1])}", "result": "WARN",
                               'details': get_largest_files(folder[0])})
    return checks

def run_vmafd_log_check():
    """
    Checks the log rotation configuration for VMAFD.

    Returns:
        dict: A dictionary with keys 'title', 'result', 'details', and optionally 'documentation'.
              - 'title': A string indicating the title of the check.
              - 'result': A string indicating the result of the check ('PASS', 'WARN', or 'FAIL').
              - 'details': A string providing details about the check result.
              - 'documentation': A string with the URL to the VMware KB (only included if the check fails).

    Exceptions:
        subprocess.CalledProcessError: If the 'lwregshell' command fails to execute, the function captures
                                       the exception, sets the result to 'WARN', and includes the error details.
    """
    title = "VMAFDD Log Rotation"
    result = "PASS"
    details = ""
    vmafdloglocation = ""
    regkey = "LogFile"
    cmd = ["/opt/likewise/bin/lwregshell", "list_values", "[HKEY_THIS_MACHINE\\Services\\vmafd\\Parameters]"]
    val_cmd = "/opt/likewise/bin/lwregshell ls '[HKEY_THIS_MACHINE\Services\vmafd\Parameters]' | grep DCName | awk '{print $2,$NF}'"
    try:
        output = subprocess.check_output(cmd, text=True)
    except subprocess.CalledProcessError as e:
        result = "WARN"
        details = 'command failed to run: /opt/likewise/bin/lwregshell list_values "[HKEY_THIS_MACHINE\\Services\\vmafd\\Parameters]"'
        return {'title': title, 'result': result, 'details': details}

    pattern = f"\\s*\"{regkey}\"\\s+REG_SZ\\s+(.+)"
    match = re.search(pattern, output)
    vmafdloglocation = match.group(1).strip()
    if result != "WARN" and vmafdloglocation != '"/var/log/vmware/vmafdd/vmafdd.log"':
        result = "FAIL"
        details = f"vmafdd has a misconfigured log rotation path: {vmafdloglocation}. This can cause it to fill up the partition."
        documentation = "https://kb.vmware.com/s/article/83238"
        return {'title': title, 'result': result, 'details': details, 'documentation': documentation}
    else:
        return {'title': title, 'result': result, 'details': details}

def getFilesystems(function):
    # list object that contains the mount points
    """
    Get information about filesystems.

    Args:
        function (str): Specifies the type of information to retrieve. Possible values are 'space' and 'inodes'.

    Returns:
        str: The output of the command executed to retrieve the information.

    Raises:
        None.
    """
    filesystems = []

    # runs the command
    if function == 'space':
        cmd = ['df']
    if function == 'inodes':
        cmd = ['df', '-i']
    diskinfo = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    output = diskinfo.communicate()[0]

    # decodes it from bytes to string
    output = output.decode()

    # return the list of mounts
    return output

def inodes(raw_data, exclude=None):
    """
    Check the inodes usage on a system.

    Args:
        raw_data (str): The raw data containing information about disk mounts.
        exclude (list, optional): A list of strings representing mounts to exclude from the check. Defaults to None.

    Returns:
        dict: A dictionary containing the title, result, and details of the inodes check.

    Raises:
        None

    Notes:
        This function parses the raw_data to extract information about disk mounts and calculates the percentage of used inodes for each mount. If exclude is provided, mounts containing any of the specified strings will be excluded from the check. The result will be 'PASS', 'WARN', or 'FAIL' based on the threshold. The details will contain information about each mount that exceeds the threshold.
    """
    title = "Inode Check"
    result = "PASS"
    details = ""

    list_mounts = [x for x in raw_data.strip().split('\n')[2:]]
    if exclude:
        list_mounts = [mount for mount in list_mounts if not any(excl in mount for excl in exclude)]
    for mount in list_mounts:

        stats = disk_stat()
        stats.mount = mount.split()[5]
        stats.total = int(mount.split()[1])
        stats.used = int(mount.split()[2])

        if stats.used != 0:
            perc = stats.used / stats.total * 100
            perc = round(perc)

        # return a string with a percent sign in front
        output = "%" + str(perc)

        # return a message that's useful
        if perc >= threshold:
            result = "WARN"
            if details == "":
                details += "\n"
            details += f"\n  ({output} used)\tpath: {stats.mount}"

    return {'title': title, 'result': result, 'details': details}

def space(raw_data, exclude=None):
    """
    Check the disk space usage and return the status.

    Args:
        raw_data (str): The raw output data from the disk space check command.
        exclude (list, optional): A list of strings to exclude from the check.

    Returns:
        dict: A dictionary containing the title, result, and additional information about the disk space check.

    Raises:
        None

    Documentation:
        The disk space check documentation can be found at: https://kb.vmware.com/s/article/76563
    """
    title = "Disk Space Check"
    result = "PASS"
    findings = []
    list_mounts = [x for x in raw_data.strip().split('\n')[2:]]
    if exclude:
        list_mounts = [mount for mount in list_mounts if not any(excl in mount for excl in exclude)]

    for mount in list_mounts:
        stats = disk_stat()
        stats.mount = mount.split()[5]
        # take the mount point that was passed to me, give me disk usage
        stats.used = int(mount.split()[2])
        stats.free = int(mount.split()[3])
        stats.total = stats.free + stats.used

        # get usage by dividing used by total, round to the nearest 2 places
        perc = stats.used / stats.total * 100
        perc = round(perc)

        # return a string with a percent sign in front
        output = "%" + str(perc)

        # return a message that's useful
        if perc >= threshold:
            findings.append(
                {'subheading': f"{title}: {stats.mount} ({output} Used)", 'checks': get_largest_dir(stats.mount)})

    if len(findings) > 0:
        return {'title': title, "result": "WARN", 'checks': findings,
                "documentation": "https://kb.vmware.com/s/article/76563"}
    else:
        return {'title': title, "result": result}

def run_diskspace_check():
    """
    Run a disk space check on the system.

    Returns:
        str: The details of the disk space check.
    """
    exclusion = ['archive']
    space_details = getFilesystems('space')
    return space(space_details, exclusion)

def run_inode_check():
    """
    Run the inode check on the filesystem and return the results.

    Returns:
        dict: A dictionary containing the inode details.

    Raises:
        None
    """
    exclusion = ['archive']
    inode_details = getFilesystems('inodes')
    return inodes(inode_details, exclusion)

