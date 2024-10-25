import json
import os
import logging
from vcenter.vc_lib.common import LDAPOps
from vcenter.vc_cfg.current_defaults import machine_id, version
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from vcenter.vc_lib.cert_utils import GetVecs

logger = logging.getLogger(__name__)

class NoSolutionUsersFound(Exception):
    pass


class SolUserDetails(LDAPOps):
    """
    A class extending LDAP operations to determine solution user details.

    Attributes:
        solusermap (dict): map of groups and users that are it's members.
        usersgroups (dict): map of users and to which groups they belong.
    """
    def __init__(self, username, password):
        """
        Initialize an LDAP connection object with the purpose of correcting identity store attributes.

        Args:
            username (str): The username for the LDAP connection.
            password (str): The password for the LDAP connection.

        Attributes:
            solusermap (dict): map of groups and users that are it's members.
            usersgroups (dict): map of users and to which groups they belong.

        """
        super().__init__(username, password)
        self.solusermap = {}
        self.usersgroups = {}

    def strip_dn(self, string):

        """
        Strips the DN of an entry and removes cn= value.

        Returns:
            str: Value of DN object without 'cn='

        Raises:
            None
        """
        return str(string).split(',', 1)[0].replace('CN=', '').replace('cn=', '')

    def get_soluser_cert(self, soluser):
        """
        Returns parsed solution user certificate in pem format from encoded value in vmdir

        Returns:
            str: the certificate in pem format

        Raises:
            None
        """
        ldapfilter = f"(&(objectclass=vmwServicePrincipal)(sAMAccountName={soluser}))"
        ldapattribute = ["userCertificate"]

        try:
            cert_value = self.search(None, ldapfilter, ldap_attributes=ldapattribute)
            if cert_value:
                if isinstance(cert_value[0].userCertificate.value, bytes):
                    cert = x509.load_der_x509_certificate(cert_value[0].userCertificate.value, default_backend())
                    return cert.public_bytes(encoding=serialization.Encoding.PEM).decode('utf8')
        except Exception as e:
            logger.error(e)
            return None
            # print(str(x.userCertificate))

    def group_exists(self, group):
        ldapfilter = f"(&(objectclass=group)(sAMAccountName={group}))"
        connection_string = self.search(None, ldapfilter)
        if connection_string:
            return True
        else:
            return False

    def get_users(self):
        """
        populates a map of users with their respective groups, the certificate in vmdir, and the certificate
        in vecs.

        Returns:
            None
        Raises:
            None
        """

        ldapfilter = f"(objectclass=vmwServicePrincipal)"
        connection_string = self.search(None, ldapfilter)
        getvecs = GetVecs(
            ignore_list=['MACHINE_SSL_CERT', 'TRUSTED_ROOTS', 'TRUSTED_ROOT_CRLS', 'SMS', 'data-encipherment',
                         'APPLMGMT_PASSWORD'])
        start_line = "-----BEGIN CERTIFICATE-----"

        storelist = getvecs.GetVecsStores()
        solution_users = []
        for entry in connection_string:
            solusername = self.strip_dn(entry.entry_dn)

            if machine_id:
                solusertype = solusername.replace(f"-{machine_id}", '')
                if machine_id in solusername:
                    solution_users.append(solusername)
                    if solusertype in storelist:
                        vmdir_cert = self.get_soluser_cert(solusername)
                        logger.debug(f"vmdir_cert: {vmdir_cert}")
                        vecs_cert = getvecs.GetVecsCert(solusertype, solusertype)
                        if vecs_cert.count(start_line) > 1:
                            vecs_cert = start_line + vecs_cert.split(start_line)[1]
                        logger.debug(f"vecs_cert: {vmdir_cert}")
                        self.solusermap[solusername] = {'vmdir_cert': vmdir_cert, 'vecs_cert': vecs_cert}
        if machine_id:
            if len(solution_users) < 1:
                raise NoSolutionUsersFound(f"No solution users found matching machine ID: {machine_id}")

        return self.solusermap
        # return self.usersgroups

class RunSolutionUserChecks(object):
    def __init__(self, username, password):

        """
        Obtains information on all solution users and executes checks against them.

        Args:
            username (str): The username for the LDAP connection.
            password (str): The password for the LDAP connection.

        Attributes:
            soluser_perm_map (dict): map of the expected group membership of solution users.
            solutionusers (dict): Current solution user details.
        """

        with open(os.path.join(os.path.dirname(__file__), "soluser_map.json")) as f:
            self.soluser_perm_map = json.load(f)
        self.ldap_connection = SolUserDetails(username, password)
        self.solutionusers = self.ldap_connection.get_users()

    def sol_user_cert_check(self, soluser):

        """
        Compares the solution user certificate in vmdir with the respective certificate in vecs (if applicable).

        Returns:
            dict: check findings in standard format.

        Raises:
            None
        """

        title = soluser
        result = ""
        documentation = ""
        details = ""
        vmdir_cert = self.solutionusers[soluser].get('vmdir_cert').strip()
        vecs_cert = self.solutionusers[soluser].get('vecs_cert').strip()
        if vmdir_cert != vecs_cert:
            logger.debug(f"Final compare for solution user: {soluser}:\n vmdir = {vmdir_cert}\n vecs = {vecs_cert}")
            result = "FAIL"
            details = f"The certificate in vecs for {soluser} doesn't match the certificate in vmdir!  Please use lsdoctor -u to resolve."
            documentation = "https://kb.vmware.com/s/article/80469"
        else:
            result = "PASS"
            title = f"{title}: vecs and vmdir match"

        return {'title': title, 'result': result, 'details': details, 'documentation': documentation}

    def build_check(self):

        """
        Loops through solution users and builds the nested checks for each.

        Returns:
            dict: check findings in standard format with each solution user as a subheading.

        Raises:
            None
        """

        check_result = []

        for soluser in self.solutionusers:
            check_result.append(self.sol_user_cert_check(soluser))

        return check_result

def sol_user_check(username, password):
    """
    Checks if the VMDIR STS connection string points to a bad provider.

    Args:
        username (str): The username to connect to the LDAP server.
        password (str): The password to authenticate with the LDAP server.

    Returns:
        dict: A dictionary containing the following fields:
            - title (str): The title of the result indicating if the local OS identity source exists or not.
            - result (str): The result of the check, either 'PASS' or 'WARN'.
            - Note (str): Additional details about the check if the local OS identity source does not exist.
            - documentation (str): A link to the documentation for more information.

    Raises:
        None.
    """
    title = "Solution User Check"
    details = ""
    documentation = ""
    sol_checks = RunSolutionUserChecks(username, password)
    return sol_checks.build_check()
