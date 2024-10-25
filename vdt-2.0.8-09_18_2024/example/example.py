import os
import configparser
import logging
from lib.vdt_base import get_logger_enh
from lib.vdt_formatter import Formatter, ColorWrap, escape_ansi
cfgfile = os.path.join(os.path.dirname(__file__), 'ex_cfg', 'example.ini')


logger = logging.getLogger(__name__)
def logandprint(string_text, level="info"):
    print(string_text)
    if level == "info":
        logger.info(escape_ansi(string_text))
    elif level == "error":
        logger.error(escape_ansi(string_text))
    if level == "debug":
        logger.debug(escape_ansi(string_text))
    if level == "warn":
        logger.warning(escape_ansi(string_text))
def set_config():
    config = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
    config.read(cfgfile)
    config.set('paths', 'root_path', os.path.dirname(__file__))
    with open(cfgfile, 'w') as configfile:
        config.write(configfile)

    logdir = config['logging'].get('logdir')
    logname = config['logging'].get('logname')
    loglevel = config['logging'].get('level')
    get_logger_enh(loglevel, logdir, logname)
    return config

def main():

    config = set_config()

    title = ColorWrap.title(config['vdt'].get('title'))
    header = f"\n\tThis is the example application showcasing additional products for VDT.\n"

    logandprint(title)
    logandprint(header)

    input("Press Enter to continue...")

    Runner = Formatter(name=__name__, item_type='check', cfgfile=cfgfile)
    Runner.generate_report()