import os, sys
import time
import configparser

mycwd = os.path.dirname(__file__)
CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'vdt.ini')


def set_vdt_config():
    """
    Set the configuration values for the VDT (Virtual Data Toolkit) module.

    This function reads the configuration file, modifies the 'root_path' value in the 'paths' section, and saves the updated configuration.

    Args:
        None

    Returns:
        None

    Raises:
        None
    """
    config = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
    config.read(CONFIG_FILE)
    config.set('paths', 'root_path', os.path.dirname(mycwd))
    with open(CONFIG_FILE, 'w') as configfile:
        config.write(configfile)


def get_vdt_config():
    """
    Read and return the VDT configuration from the specified file.

    Returns:
        configparser.ConfigParser: The VDT configuration.
    """
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    return config


DEFAULT_LOGDIR = "/var/log/vmware/vdt"
LOGNAME = "vdt.log"
# LOGNAME = str(time.strftime("vdt-report-%Y-%m-%d-%H%M%S"))
# PRODUCTS_PATH = os.path.join(os.getcwd(), "products")
