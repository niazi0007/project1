#!/usr/bin/env python3
from vcenter.vc_cfg.current_defaults import hostname, pnid
import logging

logger = logging.getLogger(__name__)
title = "vCenter PNID Check"


def main():
    """
    Run the vCenter PNID Check.

    Returns:
        list: A list containing a dictionary with the following keys:
            - title (str): The title of the check.
            - result (str): The result of the check ('PASS', 'WARN', or 'FAIL').
            - details (str): Additional details about the check.
            - documentation (str): The URL for the documentation related to the check.
    """    
    title = "vCenter PNID Check"
    result = ""
    severity = ""
    details = ""
    documentation = ""
    notes = ""

    if pnid != hostname:
        if pnid.lower() == hostname.lower():
            result = "WARN"
            details = f"The case of PNID ({pnid}) does not match the hostname ({hostname})."
            documentation = "https://kb.vmware.com/s/article/84355"
        else:
            result = "FAIL"
            details = f"The PNID ({pnid}) does not match the hostname ({hostname})!"
            documentation = "https://kb.vmware.com/s/article/2130599"
    else:
        result = "PASS"

    return [{'title': title, 'result': result, 'details': details, 'documentation': documentation}]


