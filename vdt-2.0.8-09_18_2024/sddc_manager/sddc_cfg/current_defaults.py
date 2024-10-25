import os
import configparser
import ast
from . import sddc_defaults
sddc_defaults.setDefaults()

defaults_conf_file = os.path.join(os.path.dirname(__file__), 'defaults.ini')

config = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
config.read(defaults_conf_file)

mgmtVcHostname =  config.get('defaults','mgmtVcHostname')
mgmtVcIp = config.get('defaults','mgmtVcIp')
mgmtVcVersion = config.get('defaults','mgmtVcVersion')
ssoAdmin = config.get('defaults','ssoAdmin')
sddcHostname = config.get('defaults','sddcHostname')
sddcIp = config.get('defaults','sddcIp')
sddcVersion = config.get('defaults','sddcVersion')
isVxRail = config.get('defaults','isVxRail')
timeout = 20
retries = 3
commonsvcsCerts = ast.literal_eval(config.get('defaults','commonsvcsCerts'))
alternativeJreCerts = ast.literal_eval(config.get('defaults','alternativeJreCerts'))
vcList = ast.literal_eval(config.get('defaults','vcList'))
nsxVipList = ast.literal_eval(config.get('defaults','nsxVipList'))