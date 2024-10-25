#!/usr/bin/env python
__title__ = "Lookup Service Check"
from vcenter.vc_lib.lstool_scan import *
from vcenter.vc_lib.lstool_parse import *
from lib.vdt_formatter import ColorWrap
from vcenter.vc_cfg.current_defaults import machine_id
import json
import xml.etree.ElementTree as xml
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import logging
logger = logging.getLogger(__name__)

#REQUIRED SERVICES ARE VMAFD, VMDIR

class lsReport(object):

    """
    Runs lstool_parse and lstool_scan to identify problems in the SSO domain.

    Attributes:
        report (json): this is the output of lstool_scan.py
        report_file (str): path to destination scan results file.
    """

    def __init__(self):
        """
     Args:
         params (dict): Dictionary of local node parameters returned from utils.get_params().
         report_file (str): Path to destination scan results file.
     """

        parser = LSTool_Parse()
        lsJsonData = parser.parseData()
        scanner = LSTool_Scan(lsJsonData)
        self.report = scanner.execute(live=True)

    def generateReport(self):
        """
     This function outputs the problems found (if any) and dumps the report to self.report_file.
     """
        title = "Lookupservice Check"
        result = ""
        results = []

        for site in self.report:
            site_problems = []

            for node in self.report[site]:

                nodename = node
                output = self.report[site][node]['Problems Detected']
                if output != "No problems found.":
                    result = 'FAIL'
                    nodename = f"{ColorWrap.fail('[FAIL]')}    {node}"
                    checks = []
                    for problem in self.report[site][node]['Problems Detected']:
                        if problem:
                            title = problem
                            details = ""

                            if 'UNKNOWN' in node:
                                if not 'Node In Multiple Sites' in self.report[site][node]['Problems Detected']:
                                    title = "3rd party/Orphaned service registrations.  Additional investigation needed:"

                                    for service in self.report[site][node]['Services']:
                                        for x in self.report[site][node]['Services'][service]:
                                            if 'Service ID' in x.keys():
                                                serviceid = x['Service ID']
                                                details += f"Type: {service}, ID: {serviceid}"
                                else:
                                    details = self.report[site][node]['Problems Detected'][problem].get('Recommended Action')


                            else:
                                details = self.report[site][node]['Problems Detected'][problem].get('Recommended Action')

                            checks.append({'title': title, 'details': details, 'result': result})
                    site_problems.append({'subheading': nodename, 'checks': checks})

                else:

                    if 'UNKNOWN' in node:

                        result = 'WARNING'
                        title = "3rd party/Orphaned service registrations.  Additional investigation needed:"

                        for service in self.report[site][node]['Services']:
                            for x in self.report[site][node]['Services'][service]:
                                if 'Service ID' in x.keys():
                                    serviceid = x['Service ID']
                                    details += f"Type: {service}, ID: {serviceid}"
                        checks.append({'title': title, 'details': details, 'result': result})
                        site_problems.append({'subheading': nodename, 'checks': checks})

                    else:
                        site_problems.append({'subheading': f'{ColorWrap.ok("[PASS]")}    {nodename}', 'checks': []})
                        # site_problems.append({'title': nodename, 'result': 'PASS'})

            results.append({'subheading': f'SSO Site: {site}', 'checks': site_problems})
        return results

def getMachineIdFromVpxdCfg():
    """
    Returns the machine ID extracted from the vpxd.cfg file.

    Returns:
        str: The machine ID extracted from the vpxd.cfg file. If an error occurs during parsing, it returns 'FAILED TO PARSE VPXD.CFG'.
    """    
    try:
        vpxd = xml.parse("/etc/vmware-vpx/vpxd.cfg")
        sol_entry = vpxd.findall('.//name')
        vcsol = sol_entry[0].text
        vcsol = vcsol.replace('vpxd-','').split('@')[0]
    except:
        vcsol = "FAILED TO PARSE VPXD.CFG"
    return vcsol


def compareMachineID():
    """
    Compare the machine ID with the machine ID in the vpxd.cfg file.

    Returns a dictionary with the following keys:
        - title (str): The title of the machine ID check.
        - details (str): Additional details about the check.
        - result (str): The result of the machine ID check ('PASS' or 'FAIL').
        - documentation (str): A URL to additional documentation.

    Raises:
        None.

    Requires:
        - The function getMachineIdFromVpxdCfg() which retrieves the machine ID from the vpxd.cfg file.

    Returns:
        dict: A dictionary containing the result of the machine ID check.
    """    
    title = "Machine ID Check"
    vpxd_mid = getMachineIdFromVpxdCfg()
    result = "PASS"
    details = ""
    documentation = ""

    if "FAILED" in vpxd_mid:
        result = 'FAIL'
        details = "Failed to process the vpxd.cfg file!  Investigate the invalid XML"
        documentation = "https://kb.vmware.com/s/article/82751"
    elif machine_id != vpxd_mid:
        result = "FAIL"
        rec_cmd = "/usr/lib/vmware-vmafd/bin/vmafd-cli set-machine-id --server-name localhost --id %s" % vpxd_mid
        details = "Machine ID doesn't match vpxd.cfg\n  Current MID: %s\n  Correct MID: %s\n  Recommended command (service restart required): \n\t%s" % (
        machine_id, vpxd_mid, rec_cmd)
        documentation = "https://kb.vmware.com/s/article/71375"

    else:
        logger.debug("Machine ID matches vpxd solution user in vpxd.cfg")

    return {'title': title, 'details': details, 'result': result, 'documentation': documentation}
def run_lscheck():
    """
    Run the lscheck command and generate a report.

    Returns:
        str: The generated report.

    Raises:
        None.
    """    
    ls_report = lsReport()
    return ls_report.generateReport()

def run_machine_id_check():
    """
    Run machine ID check and return the result.

    Returns:
        bool: Result of the machine ID check.
    """    
    return compareMachineID()



