#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys, os
import configparser
import importlib.util
import json
import time
import logging
import errno
import signal
import functools
import atexit
from logging.config import dictConfig
sys.path.append("..")

logger = logging.getLogger(__name__)
bypass = False
command_timeout = None

class CheckSkipped(Exception):
    """
    Exception class for check skipped errors.
    """    
    pass

class TimeoutError(Exception):
    """
    A custom exception class representing a timeout error.
    """    
    pass

def force_prompt(item_name="Check"):
    """
    Prompts the user to force a command.

    Args:
        item_name (str): The name of the item being prompted for. Defaults to 'Check'.

    Returns:
        bool: True if the user chooses to force the command, False otherwise.

    Raises:
        Exception: If the user enters an invalid answer.
    """    
    global bypass
    if item_name != "":
        item_name = "\"" + item_name + "\""
    if not get_force_flag():
        if not bypass:
            try:
                answer = input(
                    f"{item_name} timed out.  Would you like to force the command (and all subsequent commands)? [Yy|Nn] ")
            except:
                answer = raw_input(
                    "%s timed out.  Would you like to force the command (and all subsequent commands)? [Yy|Nn] " % item_name)
            if answer.strip().lower() == 'y':
                set_force_flag(True)
                return True

            elif answer.strip().lower() == 'n':
                bypass = True
                return False
            else:
                raise Exception(f"{answer} is not a valid answer.")
        else:
            return False

    else:
        return True

def set_force_flag(enabled=False):
    """
    Enable or disable the force flag for application termination.

    Args:
        enabled (bool, optional): Whether to enable or disable the force flag. 
                                 Defaults to False.

    Returns:
        None

    Raises:
        None
    """    
    atexit.register(set_force_flag)
    if enabled:
        os.environ['VDT_FORCE'] = "TRUE"
    else:
        if 'VDT_FORCE' in os.environ:
            del os.environ['VDT_FORCE']

def get_force_flag():
    """
    Determine if the force flag is set.

    Returns:
        bool: True if the force flag is set, False otherwise.
    """    
    if 'VDT_FORCE' in os.environ:
        return True
    else:
        return False

def _createDirs(dir_name):
    """
    Utility function to create a directory.

    Args:
        dir_name (str): The name of the directory.
    """
    if not os.path.exists(dir_name):
        os.makedirs(dir_name)

def _setFilename(name, logdir):
    """
    Sets filename in a helpful format

    Args:
        name (str): File name.
        file_type (str): File extension.

    Returns:
        str: String containing full file path compatible with Windows and appliance.
    """
    timestamp = str(time.strftime("%Y-%m-%d-%H%M%S"))
    if not name:
        name = "vdt"
    if not logdir:
        logdir = "."
    file_name = f"{name}-{timestamp}"
    path = logdir + '/' + file_name
    path = path.replace('\\', '/')
    return path, timestamp

class Base(object):


    def __init__(self, name="vdt_base", item_type=None, cfgfile=None):

        """
        Initialize an instance of the class with a name, item type, and configuration file.

        Args:
            name (str, optional): A string representing the name of the instance. Default is 'vdt_base'.
            item_type (str, optional): A string representing the item type of the instance. Default is None.
            cfgfile (str, optional): A string representing the path to the configuration file. Default is None.

        Raises:
            SystemExit: If no configuration file is provided.

        Attributes:
            name (str): The name of the instance.
            item_type (str): The item type of the instance.
            cfg (dict): A dictionary containing the configuration details from the cfgfile.
            logdir (str): The directory to save log files.
            logname (str): The name of the log file.
            loglevel (str): The log level.
            report_filename (str): The filename for reporting.
            vdt_items (list): A list of item names extracted from the configuration file.
            vdt_item (str): The name of the current item.
            skipped (dict): A dictionary to store skipped items.
            command_timeout (int): The timeout value for commands.

        Returns:
            None.
        """        
        self.name = name
        self.item_type = item_type
        if cfgfile is None:
            print("No configuration file!")
            sys.exit(9)

        self.cfg = self.read_cfg(cfgfile)
        if 'logging' in self.cfg:
            self.logdir = self.cfg['logging'].get('logdir', None)
            self.logname = self.cfg['logging'].get('logname', None)
            self.loglevel = self.cfg['logging'].get('level', None)
        else:
            self.logdir = self.logname = self.loglevel = None

        if self.logdir:
            _createDirs(self.logdir)

        get_logger_enh(level=self.loglevel, logdir=self.logdir, logname=self.logname)
        self.report_filename, self.timestamp = _setFilename(self.logname, self.logdir)
        self.vdt_items = [section.replace(f"{self.item_type}:", "") for section in self.cfg if
                          section.startswith(f'{self.item_type}:')]
        self.vdt_item = name
        self.skipped = {}

        if 'options' in self.cfg:
            if 'timeout' in self.cfg['options']:
                global command_timeout
                command_timeout = self.cfg['options'].get('timeout')

    def timeout(error_message=os.strerror(errno.ETIME)):
        #https://stackoverflow.com/a/2282656

        """
        A decorator that applies a timeout to a function.

        Args:
            error_message (str, optional): The error message to raise when the function times out. Defaults to the system error message for the ETIME error code.

        Returns:
            function: The decorated function.

        Raises:
            TimeoutError: If the decorated function exceeds the timeout limit.
        """        
        def decorator(func):

            """
            A decorator that adds a timeout functionality to a function.

            Args:
                func (function): The function to be decorated.

            Returns:
                function: The decorated function.

            Raises:
                TimeoutError: If the decorated function takes longer than the specified timeout.
            """            
            def _handle_timeout(signum, frame):
                """
                Handle a timeout signal by raising a TimeoutError.

                Args:
                    signum (int): The signal number of the timeout.
                    frame (frame): The current frame.
    
                Raises:
                    TimeoutError: If a timeout signal is received.
                """                
                raise TimeoutError(error_message)

            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                """
                Decorator that adds timeout functionality to a function.

                Args:
                    func (callable): The function to decorate.

                Returns:
                    callable: The decorated function.

                Raises:
                    TimeoutError: If the function execution exceeds the specified timeout.

                Note:
                    This decorator uses the signal module to enforce the timeout,
                    so it may not work correctly or be available on all platforms.
                    Use with caution.
                """                
                signal.signal(signal.SIGALRM, _handle_timeout)
                signal.alarm(command_timeout)
                try:
                    result = func(*args, **kwargs)
                finally:
                    signal.alarm(0)
                return result

            return wrapper

        return decorator

    @staticmethod
    def read_cfg(filenames):
        """
        Read from list of filenames - generate configparser object and extract out the relevant config.

        Args:
            filenames (list): List of filenames.

        Returns:
            dict: Config dictionary for the current process. (Dict can contain dicts or strings)
        """

        def json_eval(value):
            """
            Evaluate string value as JSON data and return an object or string

            Args:
                value (str): value from configuration section and key

            Returns:
                Union[str, dict, list]: original value or an object (dict, list) to store
            """
            value_eval = value.replace('\'', '\"')
            value_eval = value_eval.replace('(', '[')
            value_eval = value_eval.replace(')', ']')
            try:
                value_object = json.loads(value_eval)
                return value_object
            except Exception:
                return value

        config = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
        config.read(filenames)
        out_cfg = {}  # Output
        for section in config.sections():
            out_cfg[section] = {}
            for key in config.options(section):
                if config.get(section, key).lower() in ['true','false']:
                    out_cfg[section][key] = config.getboolean(section, key)
                else:
                    out_cfg[section][key] = json_eval(config.get(section, key))
        return out_cfg

    def item_config(self, vdt_item):
        """
        Get current Task config from config data.
        Entries in the config file which match [product:<name>]
        Are considered products.
        The current product name is stored in self.product.

        Returns:
            dict: The Task Configuration.

        Raises:
            Exception: If the Task Configuration cannot be loaded.
        """
        output = self.cfg.get(f'{self.item_type}:' + vdt_item)
        if output is None:
            raise Exception(f'No configuration data found for item: {vdt_item}.')
        logger.debug(f"CFG for {vdt_item} is: {output}")
        return output

    def get_all_items(self):
        """
        Return the list of all items.

        Returns:
            list: A list of all items.
        """        
        return self.vdt_items

    @timeout()
    def execute_with_timeout(self, *args, **kwargs):
        """
        Execute a function with a timeout.

        This decorator allows for executing a function with a specified timeout. If the function does not complete within the timeout, a TimeoutError will be raised.

        Args:
            *args: Positional arguments to pass to the function.
            **kwargs: Keyword arguments to pass to the function.

        Returns:
            The result of executing the function with the given arguments.

        Raises:
            TimeoutError: If the function does not complete within the specified timeout.
        """        
        return self.execute(*args, **kwargs)

    def execute(self, params, username=None, password=None):
        """
        Execute a script with optional authentication.

        Args:
            self: The instance of the class that has the execute method.
            params (dict): A dictionary containing the parameters for script execution.
                - name (str): The name of the script.
                - main_script (str): The path to the main script file.
                - main_func (str): The name of the main function in the script.
                - auth_req (bool): A flag indicating whether authentication is required.
            username (str, optional): The username for authentication. Defaults to None.
            password (str, optional): The password for authentication. Defaults to None.

        Returns:
            The result of executing the main function in the script.

        Raises:
            None.
        """        
        spec = importlib.util.spec_from_file_location(f"{params.get('name')}", params.get('main_script'))
        script_exec = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(script_exec)
        main_script = getattr(script_exec, params.get('main_func'))
        # if params.get('auth_req', 'false').lower() == 'true':
        if params.get('auth_req') == True:
            return main_script(username=username, password=password)
        else:
            return main_script()

    def safe_execute(self, vdt_item, username=None, password=None):
        """
        Invoke command execution with optional timeout.

        Args:
            vdt_item (any): The item for which the command execution is invoked.
            username (str, optional): The username for authentication. Defaults to None.
            password (str, optional): The password for authentication. Defaults to None.

        Returns:
            dict: A dictionary containing the title and result of the command execution.

        Raises:
            CheckSkipped: If the 'name' parameter of 'params' is in self.skipped, indicating that the execution should be skipped.
            TimeoutError: If the command execution times out and the bypass flag is not set.
        """        
        params = self.item_config(vdt_item)
        if params['name'] in self.skipped.keys():
            return {'title': f"'{params['name']}' Skipped [Reason: {self.skipped[params['name']]['reason']}]", 'result': f"{self.skipped[params['name']]['result']}"}
        else:
            if 'config_file' in params:
                itemconf = self.read_cfg(params['config_file'])
                get_logger_enh(level=itemconf['logging'].get('level'), logdir=itemconf['logging'].get('logdir'),
                               logname=itemconf['logging'].get('logname'))
            if not get_force_flag() and command_timeout:
                try:
                    return self.execute_with_timeout(params, username, password)
                    # return self.execute(params, username, password)
                except TimeoutError:
                    if bypass:
                        raise CheckSkipped
                    else:
                        if force_prompt(params.get('name')):
                            return self.execute(params, username, password)
                        else:
                            raise CheckSkipped
            else:
                return self.execute(params, username, password)

    def run_all(self, **kwargs):
        """
        Capture results (stdout, stderr, file list) - get objects.
        Returns a list of objects.
        Should be overridden in subclasses.
        Broken out to make testing easier.

        Args:
            kwargs: Additional arguments that can be added in subclasses.

        Returns:
            list: List of dictionaries representing each object.
        """
        for item in self.vdt_items:
            yield self.execute(item)

    def run(self, item, username=None, password=None):
        """
        Run a given item using the safe execute method.

        Args:
            item: The item to be executed.
            username (str, optional): The username for authentication. Defaults to None.
            password (str, optional): The password for authentication. Defaults to None.

        Returns:
            The result of the safe execute method.
        """        
        return self.safe_execute(item, username, password)

def get_logger_enh(level="DEBUG", logdir=None, logname=None):
    """
    Consistent test_log setup for classes

    Args:
        name (str): additional text included with unique 8-char string and username@host
        level (int): CRITICAL (50) to NOTSET (0)
        console (bool): enable logging to stderr
        syslog (tuple or bool): address and port for syslog service
        formatter (str): layout for process information included with test_log events
        isodatetime (bool): enable date and time stamp on test_log events

    Returns:
        getLogger object
    """
    LOGGING_CONFIG = {
        'version': 1,
        # 'disable_existing_loggers': True,
        'formatters': {
            'standard': {
                'format': '%(asctime)s %(levelname)s %(name)s %(funcName)s: %(message)s',
                'datefmt': '%Y-%m-%dT%H:%M:%S%Z'
            },
        },
        'loggers': {
            '': {  # root logger
                'handlers': ['console', 'default'],
                'level': f'{level}',
                'propagate': True
                }
            }
        }

    console = {'console': {'level': 'ERROR', 'formatter': 'standard', 'class': 'logging.StreamHandler'}}
    LOGGING_CONFIG['handlers'] = console

    if logdir and logname:
        path = logdir + '/' + logname
        filename = path.replace('\\', '/')
        _createDirs(logdir)
        default = {'default': {'level': f'{level}', 'formatter': 'standard', 'class': 'logging.handlers.RotatingFileHandler',
                               'filename': filename, 'mode': 'a', 'maxBytes': 1048576, 'backupCount': 10}}
        LOGGING_CONFIG['handlers'].update(default)

    dictConfig(LOGGING_CONFIG)
