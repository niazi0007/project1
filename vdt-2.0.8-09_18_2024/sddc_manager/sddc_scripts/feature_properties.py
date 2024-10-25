import os
import logging

logger = logging.getLogger(__name__)

def check_feature_properties():
    """
    Checks if Migration artifacts exist in the feature.properties file

    Returns:
        dict: Result of the flag check
    """
    logger.debug("Checking for migration artifacts in feature.properties")
    file_path = "/home/vcf/feature.properties"

    if not os.path.exists(file_path):
        return {
            "title": "Check for Migration Artifacts",
            "result": "PASS",
            "details": "Migration artifacts not found",
            "documentation": "",
            "notes": ""
        }

    with open(file_path, "r") as file:
        content = file.read()

    flags_to_check = {
        "feature.lcm.store.target.version=false": False,
        "feature.vcf.isolated.wlds=false": False
    }

    found_flags = {}
    for flag, default_value in flags_to_check.items():
        if flag in content:
            found_flags[flag] = True
        else:
            found_flags[flag] = False

    return {
        "title": "Check for Migration Artifacts",
        "result": "FAIL" if all(found_flags.values()) else "FAIL",
        "details": "Flags found: {}".format(", ".join([flag for flag, found in found_flags.items() if found])),
        "documentation": "https://ikb.vmware.com/s/article/96362",
        "notes": "Please remove or comment out these flags"
    }
