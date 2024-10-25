import os, sys
import configparser
import ast
from . import vc_defaults
vc_defaults.setDefaults()

defaults_conf_file = os.path.join(os.path.dirname(__file__), 'defaults.ini')

config = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
config.read(defaults_conf_file)

ls_location = config.get('defaults', 'ls_location')
sso_domain = config.get('defaults', 'sso_domain')
pnid = config.get('defaults', 'pnid')
machine_id = config.get('defaults', 'machine_id')
sso_site = config.get('defaults', 'sso_site')
node_id = config.get('defaults', 'node_id')
httpPort = int(config.get('defaults', 'httpPort'))
httpsPort = int(config.get('defaults', 'httpsPort'))
ssl_trust = config.get('defaults', 'ssl_trust')
deploy_type = "embedded"
timeout = 20
retries = 3
version = config.get('defaults', 'version')
build = config.get('defaults', 'build')
service_status = ast.literal_eval(config.get('defaults', 'service_status'))
hostname = config.get('defaults', 'hostname')
