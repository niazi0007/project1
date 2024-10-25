import sys
import threading
import shlex
import re
import subprocess as subproc
import logging
import ssl
import socket
import time
import ldap3 as ldap
from ldap3 import LEVEL, BASE


logger = logging.getLogger(__name__)
_DefaultCommmandEncoding = sys.getfilesystemencoding()

class RunCommand(object):
    # Based on jcollado's solution:
    # http://stackoverflow.com/questions/1191374/subprocess-with-timeout/4825933#4825933
    """
    A class representing a command to be executed.

    Attributes:
        cmd (str or list): The command to be executed. If a string, it will be split into a list of arguments.
        stdin (str): The input to be passed to the command's standard input.
        quiet (bool): If True, suppresses the output of the command.
        close_fds (bool): If True, closes all file descriptors before executing the command.
        encoding (str): The encoding to be used for the input and output of the command.
        shell (bool): If True, runs the command through the shell.
        response (str): The response to be passed to the command's standard input.
        command_timeout (int): The maximum time in seconds to wait for the command to complete.
    """
    def __init__(self, cmd, stdin=None, quiet=False, close_fds=False, encoding=_DefaultCommmandEncoding, shell=False,
                 response=None):
        """
        Initialize a Command object.

        Args:
            cmd (str or list): The command to execute. If it is a string, it will be split into a list of arguments.
            stdin (str or None): Input to be passed to the subprocess.
            quiet (bool): Flag indicating whether to suppress output from the subprocess.
            close_fds (bool): Flag indicating whether to close all file descriptors except stdin, stdout, and stderr.
            encoding (str): The character encoding to be used for the subprocess.
            shell (bool): Flag indicating whether the command should be executed through the shell.
            response (str or None): Output of the subprocess command.
            command_timeout (int): Timeout value in seconds for the command execution.

        Raises:
            None

        Returns:
            None
        """
        self.shell = shell
        self.stdin = stdin
        self.encoding = encoding
        try:
            if isinstance(cmd, basestring):
                cmd = shlex.split(cmd)
        except:
            if isinstance(cmd, str):
                cmd = shlex.split(cmd)
        self.cmd = cmd
        self.process = None
        self.error = None
        self.response = response

    def run(self):
        """
        Executes a command with optional input and captures the output and error streams.

        Raises an error if the Python version is less than 3 or the input stream is not a string.

        Returns:
            Tuple[str, str, bool]: A tuple containing the command output as a string, the error message as a string.

        Raises:
            TypeError: If the Python version is less than 3 or the input stream is not a string.
        """
        if sys.version_info[0] >= 3 and isinstance(self.stdin, str):
            self.stdin = self.stdin.encode(self.encoding)
        if self.response:
            self.process = subproc.Popen(self.cmd, stdout=subproc.PIPE, stderr=subproc.PIPE, stdin=subproc.PIPE,
                                         shell=self.shell)
            self.process.stdin.write(self.response.encode(self.encoding))
        else:
            self.process = subproc.Popen(self.cmd, stdout=subproc.PIPE, stderr=subproc.PIPE, stdin=self.stdin,
                                         shell=self.shell)
        self.output, self.error = self.process.communicate(self.stdin)

        return self.output.decode('utf-8'), self.error.decode('utf-8')
class FailedCommand(Exception):
    """
    Helps when handling command failures.
    """

    def __init__(self, cmd, error, msg="Command failed!"):
        """
        Initialize a CommandError instance.

        Args:
            cmd (str): The command that failed.
            error (str): The specific error message related to the failure.
            msg (str, optional): The custom error message to display. Defaults to 'Command failed!'.

        Raises:
            None.

        Returns:
            None.
        """        
        self.cmd = cmd
        self.error = error
        self.msg = msg
        super().__init__(self.msg)


class Command(object):
    # Based on jcollado's solution:
    # http://stackoverflow.com/questions/1191374/subprocess-with-timeout/4825933#4825933
    """
    A class representing a command to be executed.

    Attributes:
        cmd (str or list): The command to be executed. If a string, it will be split into a list of arguments.
        stdin (str): The input to be passed to the command's standard input.
        quiet (bool): If True, suppresses the output of the command.
        close_fds (bool): If True, closes all file descriptors before executing the command.
        encoding (str): The encoding to be used for the input and output of the command.
        shell (bool): If True, runs the command through the shell.
        response (str): The response to be passed to the command's standard input.
        command_timeout (int): The maximum time in seconds to wait for the command to complete.
    """    
    def __init__(self, cmd, stdin=None, quiet=False, close_fds=False, encoding=_DefaultCommmandEncoding, shell=False,
                 response=None, command_timeout=30):
        """
        Initialize a Command object.

        Args:
            cmd (str or list): The command to execute. If it is a string, it will be split into a list of arguments.
            stdin (str or None): Input to be passed to the subprocess.
            quiet (bool): Flag indicating whether to suppress output from the subprocess.
            close_fds (bool): Flag indicating whether to close all file descriptors except stdin, stdout, and stderr.
            encoding (str): The character encoding to be used for the subprocess.
            shell (bool): Flag indicating whether the command should be executed through the shell.
            response (str or None): Output of the subprocess command.
            command_timeout (int): Timeout value in seconds for the command execution.

        Raises:
            None

        Returns:
            None
        """        
        self.shell = shell
        self.stdin = stdin
        self.encoding = encoding
        try:
            if isinstance(cmd, basestring):
                cmd = shlex.split(cmd)
        except:
            if isinstance(cmd, str):
                cmd = shlex.split(cmd)
        self.cmd = cmd
        self.process = None
        self.error = None
        self.response = response
        self.command_timeout = command_timeout

    def run(self):
        """
        Run a command and return the output, error, and timeout status.

        Returns:
            Tuple[str, str, bool]: A tuple containing the command output as a string, the error message as a string, and a boolean indicating if the command timed out.

        Raises:
            None.
        """        
        timedout = False

        def target():
            """
            Executes a command with optional input and captures the output and error streams.

            Raises an error if the Python version is less than 3 or the input stream is not a string.

            Args:
                None

            Returns:
                None

            Raises:
                TypeError: If the Python version is less than 3 or the input stream is not a string.
            """            
            if sys.version_info[0] >= 3 and isinstance(self.stdin, str):
                self.stdin = self.stdin.encode(self.encoding)
            if self.response:
                self.process = subproc.Popen(self.cmd, stdout=subproc.PIPE, stderr=subproc.PIPE, stdin=subproc.PIPE,
                                             shell=self.shell)
                self.process.stdin.write(self.response.encode(self.encoding))
            else:
                self.process = subproc.Popen(self.cmd, stdout=subproc.PIPE, stderr=subproc.PIPE, stdin=self.stdin,
                                             shell=self.shell)
            self.output, self.error = self.process.communicate(self.stdin)

        thread = threading.Thread(target=target)
        thread.start()
        thread.join(self.command_timeout)
        if thread.is_alive():
            self.process.terminate()
            thread.join()
        if self.process.returncode != 0:
            if len(self.error.decode()) <= 0:
                timedout = True

        return self.output.decode('utf-8'), self.error.decode('utf-8'), timedout


def psqlQuery(query, return_all=False):
    """
    Run a PostgreSQL query and return the output.

    Args:
        query (str): The SQL query to be executed.
        return_all (bool, optional): If True, return all output. If False, return only the third line of the output. 
                                     Defaults to False.

    Returns:
        str: The output of the query.

    Raises:
        Exception: If there is an error executing the query or if the vPostgres service is not available.
    """    
    logger.debug("running SQL query: %s" % query)
    psqlpath = "/opt/vmware/vpostgres/current/bin/psql"
    cmd = [psqlpath, '-d', 'VCDB', 'postgres', '-c', query]
    try:
        output, errors, timeout = Command(cmd).run()
        if return_all:
            return output
        else:
            output = output.split('\n')[2]
            return output.strip()
    except:
        msg = "Requires vPostgres service!"
        return msg


def getStartup(service):
    """
    Get the startup type of a service.

    Args:
        service (str): The name of the service.

    Returns:
        str: The startup type of the service.

    Raises:
        Exception: If an error occurs while retrieving the startup type.
    """    
    result = ""
    logger.debug("Getting startup type of service %s" % service)
    if 'vmware-' in service and 'postgres' not in service and 'sts' not in service:
        service = service.replace('vmware-', '')
        if 'watchdog' in service:
            service = service.replace('-watchdog', '')
    try:
        result = str(getSrvStartType(service, quiet=True))
    except:
        result = "Automatic"
    if not result:
        result = "Automatic"
    logger.debug(result)
    return result


def getMultiServiceStatus(svcs=None):
    """
    Get the status of multiple services.

    Args:
        svcs (list, optional): A list of service names. Defaults to None.

    Returns:
        dict: A dictionary containing the status of each service.

    Raises:
        None.
    """    
    svcslist = ' '.join(svcs)
    logger.debug("Getting startup type of service %s" % svcslist)
    result = get_services_status(svcs)
    logger.debug(result)
    return result


def getSingleServiceStatus(service):
    """
    Get the status of a single service.

    Args:
        service (str): The name of the service.

    Returns:
        bool: True if the service is running, False otherwise.
    """    
    logger.debug("Getting status of service %s" % service)
    for x, y in get_services_status([service]).items():
        if len(y) == 2:
            status = y[0]
        else:
            status = y
    logger.debug(status)
    if status == 'RUNNING':
        return True
    else:
        return False


class CheckConnect(object):

    """
    A class for checking connectivity to a host on specific ports.

    Attributes:
        retry (int): The number of times to retry the connection check.
        delay (int): The number of seconds to wait between connection attempts.
        timeout (int): The timeout value in seconds for the connection attempt.
        ip (str): The IP address of the host to check.
        ports (list or int): The list of ports to check or a single port number.
        ptype (str): The type of protocol to use for the connection check.
        init_msg (str): The initial message for the connection check.

    Methods:
        TCP(port): Checks the TCP connectivity to the specified port.
        check(): Performs the connection check for all the specified ports.
    """    
    def __init__(self, ip, ports):
        #  Spec will be yaml parameters specific to the product
        """
        Initialize a PortChecker object.

        Args:
            ip (str): The IP address of the host to perform port checks on.
            ports (int or list): The port or list of ports to check on the host.

        Attributes:
            retry (int): The number of times to retry a failed port check.
            delay (int): The delay in seconds between retries.
            timeout (int): The timeout in seconds for each port check.
            ip (str): The IP address of the host to perform port checks on.
            ports (list): A list of ports to check on the host.
            ptype (str): The type of port check to perform.
            init_msg (str): The initialization message for the PortChecker object.
        """        
        self.retry = 1
        self.delay = 1
        self.timeout = 2
        self.ip = ip
        if isinstance(ports, int):
            self.ports = [ports]
        if isinstance(ports, list):
            self.ports = ports
        self.ptype = "TCP"

        self.init_msg = "Port check for host %s" % self.ip

    def TCP(self, port):
        """
        Test TCP connection on a specified port.

        Args:
            port (int): The port number to test the TCP connection.

        Returns:
            tuple: A tuple containing the return code (0 if successful, 1 if failed) and a message describing the test result.
        """        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        rc = 1
        try:
            response = s.connect((self.ip, int(port)))
            s.shutdown(socket.SHUT_RDWR)
            s.close()
            result = "tcp port test returned %s" % response
            logger.debug(result)
            rc = 0
        except Exception as e:
            result = "tcp port test failed. error was: %s" % e
            logger.debug(result)
        return rc, result

    def check(self):
        """
        Performs a TCP check on a list of ports.

        Returns a tuple of a success flag and a dictionary containing the result of each port check.

        Args:
            self: An instance of the class that this method is a part of.

        Returns:
            tuple: A tuple containing a boolean indicating whether all the checks were successful, and a dictionary that maps each checked port to its result ('success' or 'failed').
        """        
        output = {}
        success = True
        for port in self.ports:
            listening = False
            for attempt in range(self.retry):
                rc, result = self.TCP(port)
                if rc == 0:
                    listening = True
                    break
                else:
                    time.sleep(self.delay)
            if listening:
                output[str(port)] = "success"
            else:
                output[str(port)] = "failed"
                success = False
        return success, output


def sanitize_data(item, **kwargs):
    """
    Remove problematic characters from data
    :param item: data to process
    :type item: string or bytes object, list or dict
    :return: data suitable for printing as 'utf-8'
    :rtype: string
    All ANSI escapes, does not work on non-ansii escapes (use strict)
      re.compile(r'(\x9b|\x1b\[)[0-?]*[ -\/]*[@-~]')  # Includes colours
    Colors only
        re.compile(r'\x1b\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]') # Colours only
    Colours ok, all other escapes removed (above combined)
      re.compile(r'(?!\x1b\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K])((\x9b|\x1b\[)[0-?]*[ -\/]*[@-~])')
    Strict, only [a-zA-Z0-9] and common punctuation
        re.compile(r'[^\x20-\x7e]+')
    """
    if kwargs.get('strict', False):
        # Strict, only [a-zA-Z0-9] and common punctuation
        re_applied = re.compile(r'[^\x20-\x7e]+')
    elif kwargs.get('wizard', False):
        # Return only alphanumeric and '_'
        re_applied = re.compile(r'[^0-9a-zA-Z_]+')
        return re_applied.sub('', item)
    else:
        # Colours ok, all other escapes removed
        re_applied = re.compile(r'(?!\x1b\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K])((\x9b|\x1b\[)[0-?]*[ -/]*[@-~])')

    if isinstance(item, dict) or isinstance(item, list):
        return item
    if isinstance(item, bytes):
        item = item.decode('utf-8', 'ignore').strip()
    if isinstance(item, str):
        item = re_applied.sub('.', item)
        superfluous_newlines = re.compile(r'\n\s*\n')
        item = superfluous_newlines.sub('\n', item)
        return item
    else:
        return None


def getSslCert(hostname, port=443):
    """
    Gets SSL cert from host on port specified. Converts to
    string compatible with LS specs.

    Args:
        hostname (str): The hostname.
        port (int): The port.

    Returns:
        cert: The certificate string formatted for lookup service endpoints.
    """
    #  returns the cert trust value formatted for lstool
    logger.debug("Getting SSL certificate on %s:%s" % (hostname, port))
    socket.setdefaulttimeout(5)
    try:
        try:
            cert = ssl.get_server_certificate((hostname, port), ssl_version=ssl.PROTOCOL_TLS)

        except AttributeError:
            cert = ssl.get_server_certificate((hostname, port), ssl_version=ssl.PROTOCOL_SSLv23)

        except socket.timeout as e:
            raise Exception("Timed out getting certificate")

        except ConnectionRefusedError:
            # print("Connection refused while getting cert for host %s on port %s!" % (hostname, port))
            raise

        values = ['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----', '\n']

        for i in values:
            cert = cert.replace(i, '')
        logger.debug("Got certificate.")
        return cert

    except Exception as e:
        msg = ("[%s:%s]:%s"
               % (hostname, port, str(e)))
        raise Exception(msg)


class LDAPOps(object):

    """
    A class representing LDAP operations.

    Attributes:
        ldap_server_url (str): The URL of the LDAP server.
        server (ldap.Server): The LDAP server object.
        base_dn (str): The base DN (Distinguished Name) for the LDAP server.
        user (str): The LDAP user.
        password (str): The password for the LDAP user.
        connection (ldap.Connection): The connection to the LDAP server.
    """    
    def __init__(self, username, password):
        """
        Initialize an LDAP connection object.

        Args:
            username (str): The username for the LDAP connection.
            password (str): The password for the LDAP connection.

        Raises:
            Exception: If the LDAP connection fails.

        Attributes:
            ldap_server_url (str): The URL of the LDAP server.
            server (ldap.Server): The LDAP server object.
            base_dn (str): The base distinguished name for the LDAP search.
            user (str): The user distinguished name for the LDAP connection.
            password (str): The password for the LDAP connection.
            connection (ldap.Connection): The LDAP connection object.
        """        
        from vcenter.vc_cfg.current_defaults import sso_domain
        self.ldap_server_url = 'ldap://localhost:389'
        self.server = ldap.Server(self.ldap_server_url, get_info=ldap.ALL)
        base_dn_convert = sso_domain.split('.')
        self.base_dn = f"dc={',dc='.join(base_dn_convert)}"
        if "administrator" in username.lower():
            self.user = 'CN=' + username.split('@')[0] + ',cn=Users,' + self.base_dn
        else:
            self.user = 'CN=' + username.split('@')[0] + ',ou=Domain Controllers,' + self.base_dn
        self.password = password
        try:
            self.connection = ldap.Connection(self.server,
                                              user=self.user,
                                              password=self.password,
                                              auto_bind=True,
                                              auto_encode=False)
        except Exception as e:
            logger.error('open ldap connection failed: {0}'.format(e))
            raise e

    def close(self):

        """
        Close the LDAP connection.

        Raises:
            Exception: If closing the connection fails.
        """        
        try:
            self.connection.unbind()
            if self.connection.result["result"] != 0:
                logger.error("Error closing connection. Error Msg: " +
                      self.connection.result["message"])
        except Exception as e:
            logger.error('close ldap connection failed: {0}'.format(e))
            raise e

    def search(self, base_dn, ldap_filter, ldap_attributes=None, search_level=None):
        """
        Searches for entries in LDAP database based on provided parameters.

        Args:
            base_dn (str): The base distinguished name (DN) for the LDAP search.
            ldap_filter (str): The filter string for the LDAP search.
            ldap_attributes (list, optional): A list of attributes to include in the search result. Defaults to ['*'].
            search_level (str, optional): The search level for the LDAP search. Defaults to None.

        Returns:
            list: A list of entries found in the LDAP search.

        Raises:
            Exception: If any error occurs during the LDAP search or connection handling.
        """        
        if not base_dn:
            base_dn = self.base_dn
        if not ldap_attributes:
            ldap_attributes = ['*']

        result = False
        try:
            if self.connection is None:
                logger.debug("No ldap connection")
            else:
                self.connection.bind()
                if search_level:
                    result = self.connection.search(base_dn,
                                                    ldap_filter,
                                                    attributes=ldap_attributes,
                                                    search_scope=LEVEL)
                else:
                    result = self.connection.search(base_dn,
                                                    ldap_filter,
                                                    attributes=ldap_attributes)
                # result = self.connection.search(base_dn,ldap_filter)
                if not result:
                    logger.debug("LDAP Search failed.Error Message: " +
                          self.connection.result["message"])
                else:
                    return self.connection.entries
        except Exception as e:
            logger.error('ldap search failed: {0}'.format(e))
            raise e
        finally:
            try:
                self.connection.unbind()
                if self.connection.result["result"] != 0:
                    logger.error("Error closing connection. Error Msg: " +
                          self.connection.result["message"])
            except Exception as e:
                logger.error('close ldap connection failed: {0}'.format(e))
                raise e
