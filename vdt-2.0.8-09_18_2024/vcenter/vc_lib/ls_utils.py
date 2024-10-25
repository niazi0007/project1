import sys
import tempfile
import logging
import os
from contextlib import contextmanager
import socket
import time
import traceback
import ssl

try:
    import httplib
except ImportError:
    import http.client as httplib
try:
    import urllib.parse as urlparse
    from urllib.request import Request, urlopen
    from urllib.error import URLError, HTTPError
except ImportError:
    import urlparse
    from urllib2 import Request, urlopen
    from urllib2 import URLError, HTTPError
sys.path.append(os.environ['VMWARE_PYTHON_PATH'])
from pyVmomi import (lookup, SoapStubAdapter, vmodl, dataservice,
                     SessionOrientedStub, Vim)

from pyVim import sso

VMWARE_PRODUCT_ID = 'com.vmware.cis'
SSO_TYPE_ID = 'cs.identity'
EP_SSO_PROTOCOL = 'wsTrust'
EP_SSO_TYPE_ID = 'com.vmware.cis.cs.identity.sso'
AUTHZ_TYPE_ID = 'cs.authorization'
EP_AUTHZ_PROTOCOL = 'vmomi'
EP_AUTHZ_TYPE_ID = 'com.vmware.cis.authorization.server'
SYSTEM_HOSTNAME = socket.getfqdn()
SERVICE_INFO_PROPERTIES = ["serviceVersion", "serviceId", "siteId",
                           "serviceNameResourceKey", "serviceNameDefault",
                           "serviceDescriptionResourceKey", "serviceDescriptionDefault",
                           "vendorNameResourceKey", "vendorNameDefault",
                           "vendorProductInfoResourceKey", "vendorProductInfoDefault",
                           "ownerId", "nodeId", ]

logger = logging.getLogger(__name__)
class SsoClient(object):
    """
    Simple class with methods to create security context for privileged requests.
    """

    def __init__(self, sts_url, sts_cert_data, uname, passwd, cert=None,
                 key=None):
        """
        Args:
            sts_url (TYPE): Description
            sts_cert_data (TYPE): Description
            uname (TYPE): Description
            passwd (TYPE): Description
            cert (Optional): Description
            key (Optional): Description
        """
        logger.debug("Setting SSO client")
        self._uname = uname
        self._passwd = passwd
        self._sts_url = sts_url
        self._sts_cert_file = None
        self._key_file = None
        self._cert_file = None
        self._saml_token = None

        with tempfile.NamedTemporaryFile(delete=False) as tempfp:
            tempfp.write(sts_cert_data.encode('utf-8'))
            self._sts_cert_file = tempfp.name

        if key:
            with tempfile.NamedTemporaryFile(delete=False) as tempfp:
                tempfp.write(key.encode('utf-8'))
                self._key_file = tempfp.name

        if cert:
            with tempfile.NamedTemporaryFile(delete=False) as tempfp:
                tempfp.write(cert.encode('utf-8'))
                self._cert_file = tempfp.name

    def _update_saml_token(self):
        """
        Helper method which fetches SAML token by talking to sts service
        and updates self._saml_token
        """
        sts_auth = sso.SsoAuthenticator(
            self._sts_url)

        if self._uname and self._passwd:
            # Bearer token based on given user credentials.
            self._saml_token = sts_auth.get_bearer_saml_assertion(
                self._uname, self._passwd, token_duration=120)
        else:
            # Get HOK token based on given service user cert and key.
            self._saml_token = sts_auth.get_hok_saml_assertion(
                self._cert_file, self._key_file, delegatable=True,
                token_duration=120)

    @contextmanager
    def securityctx_modifier(self, soapStub):
        """
        Appends the security context to give soap stub adapter. It caches the
        SAML token, but refreshes it on a SecurityError exception.

        Args:
            soapStub (TYPE): Description
        """
        for retry in range(0, 2):
            try:
                if self._uname and self._passwd:
                    if not self._saml_token:
                        self._update_saml_token()
                    soapStub.samlToken = self._saml_token
                    yield
                else:
                    if not self._saml_token:
                        self._update_saml_token()

                    def _requestModifier(request):

                        """
                        Modify the request by adding SAML context.

                        Args:
                            request: The request object.
    
                        Returns:
                            The modified request object.

                        Raises:
                            None.
                        """                        
                        return sso.add_saml_context(request, self._saml_token,
                                                    self._key_file)

                    # Each request must be signed with soluser's private key.
                    with soapStub.requestModifier(_requestModifier):
                        soapStub.samlToken = self._saml_token
                        yield
                break
            except vmodl.fault.SecurityError as ex:
                self._saml_token = None
                logging.error('Security error: %s' % ex)
            finally:
                soapStub.samlToken = None

    def cleanup(self):
        """
        Delete temp cert and private key files.
        """
        if self._sts_cert_file:
            os.unlink(self._sts_cert_file)
            self._sts_cert_file = None
        if self._key_file:
            os.unlink(self._key_file)
            self._key_file = None
        if self._cert_file:
            os.unlink(self._cert_file)
            self._cert_file = None

    def __del__(self):
        """
        Cleanup and destroy the object.
        """        
        self.cleanup()


class LookupServiceClient(object):
    """
    Implements helper methods to talk to lookup service.

    Attributes:
        service_content (API): content returned by interaction with LS API
    """

    def _retry_request(req_method, *args, **kargs):

        """
        Retries a request using a given request method.

        Args:
            req_method (function): The request method to be retried.
            *args: Positional arguments to be passed to the request method.
            **kwargs: Keyword arguments to be passed to the request method.

        Returns:
            The result of the request method.

        Raises:
            socket.error: If there is a socket error during the request.
            sys.exit: If the maximum number of retries is reached and all retry attempts fail.
        """        
        def do_retry(self, *args, **kargs):

            """
            Retry a function call multiple times.

            Args:
                self: The instance of the class.
    
                *args: Any number of positional arguments to be passed to the function being called.
    
                **kargs: Any number of keyword arguments to be passed to the function being called.

            Returns:
                The return value of the function being called.

            Raises:
                socket.error: If there is an error during the function call.
    
            Notes:
                - This function retries the function call for a specified number of times.
                - If the function call is successful, the result is returned.
                - If the function call raises a socket error, the function retries after a delay, for the specified number of times.
                - If all retries fail, a connection timeout error is logged and the program exits.
            """            
            for retry in range(0, self._retry_count):
                try:
                    return req_method(self, *args, **kargs)
                except socket.error as e:
                    logger.info("retrying request...")
                    if retry == self._retry_count - 1:
                        logger.error("CONNECTION TIMEOUT!  Error was: %s" % e)
                        sys.exit(1)
                    time.sleep(self._retry_delay)

        return do_retry

    @_retry_request
    def _init_service_content(self):
        """
        Initializes service content from LS API.
        """
        logger.debug("getting service instance...")
        si = lookup.ServiceInstance("ServiceInstance", self._stub)
        try:
            self.service_content = si.RetrieveServiceContent()
        except Exception as e:
            # logger.error("Failed to talk to the lookup service!  STS may not be functioning properly -- Error was: %s" % e)
            raise SystemExit(
                "ERROR: Failed to talk to the lookup service!  STS may not be functioning properly -- Error was: %s" % e)
        logger.debug("Got service content.")

    def __init__(self, ls_url, retry_count=1, retry_delay=0):
        """
        Args:
            ls_url (TYPE): Description
            retry_count (int, optional): Description
            retry_delay (int, optional): Description
        """
        logger.debug("Setting up lookup service client")
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        self._retry_count = retry_count
        self._retry_delay = retry_delay
        self._sso_client = None
        logger.debug("Getting stub...")
        self._stub = SoapStubAdapter(url=ls_url, ns='lookup/2.0', sslContext=context)
        self._init_service_content()

    def set_sso_client(self, sso_client):
        """
        This needs to be called before invoking any privileged request.

        Args:
            sso_client (sso_client object): sso_client object
        """
        self._sso_client = sso_client

    def get_sts_endpoint_data(self):
        """
        Returns a tuple of sts url and sts node sslTrust.
        """
        logger.debug("Get STS data...")
        sts_endpoints = self.get_service_endpoints(
            SSO_TYPE_ID, ep_protocol=EP_SSO_PROTOCOL, ep_type=EP_SSO_TYPE_ID)

        if not sts_endpoints:
            raise Exception("Unable to get sts url from LS")
        return (sts_endpoints[0].url, sts_endpoints[0].sslTrust[0])

    def _privileged_request(req_method, *args, **kargs):

        """
        Make a privileged request with added security context.

        Args:
            req_method (function): The request method to be modified.
            *args: Positional arguments to be passed to the request method.
            **kargs: Keyword arguments to be passed to the request method.

        Returns:
            The result of the modified request method.

        Raises:
            socket.error: If there is a socket error during the request.
            Any other exception: If there is an exception during the request.
        """        
        def add_securityctx_to_requests(self, *args, **kargs):

            """
            Add security context to requests and retry if there is a socket error.

            Args:
                *args: Variable length arguments passed to the request method.
                **kargs: Keyword arguments passed to the request method.

            Returns:
                The result of the request method.

            Raises:
                socket.error: If there is a socket error during the request.
                Raises the last encountered socket error if the maximum retry count is reached.
            """            
            for retry in range(0, self._retry_count):
                try:
                    with self._sso_client.securityctx_modifier(self._stub):
                        return req_method(self, *args, **kargs)
                except socket.error:
                    logger.info("retrying request...")
                    if retry == self._retry_count - 1:
                        raise
                    time.sleep(self._retry_delay)

        return add_securityctx_to_requests

    @_privileged_request
    def register_service(self, svc_id, svc_create_spec):
        """
        Requires an API formatted spec and the service ID you want to register

        Args:
            svc_id (str): Service ID to register
            svc_create_spec (spec object): API formatted spec
        """
        logger.debug("registering service %s" % svc_id)
        self.service_content.serviceRegistration.Create(svc_id,
                                                        svc_create_spec)

    @_privileged_request
    def reregister_service(self, svc_id, svc_set_spec):
        """
        This will set the service registration (specified by service ID)
        to the newly provided API formatted spec

        Args:
            svc_id (str): Service ID
            svc_set_spec (spec object): API formatted spec
        """
        logger.debug("reregistering service %s" % svc_id)
        self.service_content.serviceRegistration.Set(svc_id, svc_set_spec)

    @_privileged_request
    def unregister_service(self, svc_id):
        """
        This will delete the service registration specified by service ID

        Args:
            svc_id (str): Service ID
        """
        try:
            logger.debug("unregistering service %s" % svc_id)
            self.service_content.serviceRegistration.Delete(svc_id)
        except Exception as e:
            sException = str(e)
            logging.warning('Failed to unregister_service [%s]: %s, sys.exc_info()[1]' % (svc_id,
                                                                                          sys.exc_info()[1]))
            logging.warning('Failed to unregister_service [%s]: %s, str(e)' % (svc_id, sException))
            logging.warning('Failed to unregister_service [%s]: %s, repr(e)' % (svc_id, repr(e)))
            logging.warning('Failed to unregister_service [%s]: %s, traceback.format_exc()' %
                            (svc_id, traceback.format_exc()))
            if 'not found' in sException and 'Entry with name' in sException:
                logging.warning('Failed to unregister service %s because service entry not found, '
                                'bypass the error' % svc_id)
                pass
            else:
                logging.error('Failed to unregister service %s, esclate the error' % svc_id)
                raise

    @_retry_request
    def get_service_info_list(self, svc_id=None, search_filter=None):
        """
        Returns a list of service info objects corresponding to given service
        id or search filter.

        Args:
            svc_id (Optional[None]): optionally return for specific service
            search_filter (Optional[None]): filter results

        Returns:
            ServiceInfo: API formatted list of services.
        """

        info_list = []

        if svc_id:
            logger.debug("getting service info for svc_id: %s" % svc_id)
            info_result = self.service_content.serviceRegistration.Get(svc_id)
            if info_result:
                info_list.append(info_result)
        else:
            logger.debug("getting service info with filter: %s" % search_filter)
            info_list.extend(self.service_content.serviceRegistration.List(
                search_filter))
        return info_list

    def get_local_endpointurl(self, service_endpoint):

        """
        Gets the local endpoint URL for a given service endpoint.

        Args:
            service_endpoint (ServiceEndpoint): The service endpoint to search for the local URL.

        Returns:
            str: The local endpoint URL if found, or None if not found.
        """        
        for ep_attr in service_endpoint.endpointAttributes:
            if ep_attr.key == 'cis.common.ep.localurl':
                return ep_attr.value
        return None

    def get_service_info_list_ex(self, pnid=None, machine_id=None):
        """
        Returns a list of service info objects corresponding given pnid
        or machine id.

        Args:
            pnid (str, optional): primary network identifier or FQDN of desired machine
            machine_id (str, optional): Machine ID of desired machine

        Returns:
            List[ServiceInfo]: API formatted list of services
        """
        result = []
        search_filter = lookup.ServiceRegistration.Filter()
        for svcinfo in self.get_service_info_list(search_filter=search_filter):
            if machine_id:
                for attr in svcinfo.serviceAttributes:
                    if (attr.key == 'com.vmware.cis.cm.HostId' and
                            attr.value == machine_id):
                        result.append(svcinfo)
                        break
            elif pnid and svcinfo.serviceEndpoints:
                for serviceEndpoint in svcinfo.serviceEndpoints:
                    url_comps = urlparse.urlparse(serviceEndpoint.url)
                    if url_comps.hostname == pnid.lower():
                        result.append(svcinfo)
                        break
        return result

    @_retry_request
    def get_service_endpoints(self, svc_typeid, ep_protocol=None, ep_type=None,
                              local_nodeid=None):
        """
        Retrieve service end-points according to given filter criteria consisting of service type id, endpoint protocol name, and endpoint type id. If local_nodeid (==vmdir.ldu-guid) is specified, then local URLs are applied to service info if present on the same node and returned.

        Args:
            svc_typeid (str): Filter by service type
            ep_protocol (None, optional): Filter by endpoint protocol
            ep_type (None, optional): Filter by endpoint type
            local_nodeid (None, optional): Specify the node ID or LDU guid

        Returns:
            list of ServiceInfo: API formatted list of services
        """
        filterCriteria = lookup.ServiceRegistration.Filter()
        filterCriteria.serviceType = lookup.ServiceRegistration.ServiceType()
        filterCriteria.serviceType.product = VMWARE_PRODUCT_ID
        filterCriteria.serviceType.type = svc_typeid

        if ep_protocol is not None or ep_type is not None:
            filterCriteria.endpointType = \
                lookup.ServiceRegistration.EndpointType()
            if ep_protocol is not None:
                filterCriteria.endpointType.protocol = ep_protocol
            if ep_type is not None:
                filterCriteria.endpointType.type = ep_type

        serviceRegistration = self.service_content.serviceRegistration
        result = serviceRegistration.List(filterCriteria)
        if not result:
            return None

        if not local_nodeid:
            return result[0].serviceEndpoints

        for service_info in result:
            # Apply local url to service registered with local node.
            if service_info.nodeId == local_nodeid:
                for service_ep in service_info.serviceEndpoints:
                    local_url = self.get_local_endpointurl(service_ep)
                    if local_url:
                        service_ep.url = local_url
                return service_info.serviceEndpoints
        return result[0].serviceEndpoints

    @staticmethod
    def _copy_svcspec(svcinfo, mutable_spec):
        """
        Copies svc info field values to corresponding mutable spec fields.

        Args:
            svcinfo (object): The svcinfo object.
            mutable_spec (object): The mutable_spec object.
        """
        mutable_spec.serviceVersion = svcinfo.serviceVersion
        mutable_spec.vendorNameResourceKey = svcinfo.vendorNameResourceKey
        mutable_spec.vendorNameDefault = svcinfo.vendorNameDefault
        mutable_spec.serviceNameResourceKey = svcinfo.serviceNameResourceKey
        mutable_spec.serviceNameDefault = svcinfo.serviceNameDefault
        mutable_spec.serviceDescriptionResourceKey = \
            svcinfo.serviceDescriptionResourceKey
        mutable_spec.serviceDescriptionDefault = \
            svcinfo.serviceDescriptionDefault
        mutable_spec.serviceEndpoints = svcinfo.serviceEndpoints
        mutable_spec.serviceAttributes = svcinfo.serviceAttributes

    @staticmethod
    def _svcinfo_to_setspec(svcinfo):
        """
        Construct a set spec based on given svc info object.

        Args:
            svcinfo (ls spec): service info in LS API format
        """
        rereg_spec = lookup.ServiceRegistration.SetSpec()
        LookupServiceClient._copy_svcspec(svcinfo, rereg_spec)
        return rereg_spec

    def get_machine_id(self, svcinfo):
        """
        Helper function to get machine id of a service from LS service info.
        This exists because sadly the nodeId field of service info object
        doesn't hold the machine id, instead it is set to vmdir.ldu-guid.
        Instead the machine id is held in com.vmware.cis.cm.HostId key.

        Args:
            svcinfo (ls spec): service info in LS API format
        """
        for attr in svcinfo.serviceAttributes:
            if attr.key == 'com.vmware.cis.cm.HostId':
                return attr.value
        return None


### Transformation utilities ###
def _serviceAttribute2Dict(attr):
    """
    Transform utility for LS spec to dictionary and reverse.
    """
    result = {
        "key": attr.key,
        "value": attr.value
    }
    return result


def _getSslCert(hostname, port):
    """
    Gets SSL cert from host on port specified.  Converts to
    string compatible with LS specs.

    Args:
        hostname (str): hostname.
        port (int): port.

    Returns:
        str: certificate string formatted for lookup service endpoints.
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


def _dict2serviceAttribute(d):
    """
    Transform utility for LS spec to dictionary and reverse.
    """
    attr = lookup.ServiceRegistration.Attribute()
    attr.key = d["key"]
    attr.value = d["value"]
    return attr


def _serviceType2Dict(serviceType):
    """
    Transform utility for LS spec to dictionary and reverse.
    """
    result = {
        "product": serviceType.product,
        "type": serviceType.type
    }
    return result


def _dict2ServiceType(d):
    """
    Transform utility for LS spec to dictionary and reverse.
    """
    svcType = lookup.ServiceRegistration.ServiceType()
    svcType.product = d['product']
    svcType.type = d['type']
    return svcType


def _serviceEndpoint2Dict(endpoint):
    """
    Transform utility for LS spec to dictionary and reverse.
    """
    result = {
        "url": endpoint.url,
        "sslTrust": endpoint.sslTrust,
        "endpointType": {
            "protocol": endpoint.endpointType.protocol,
            "type": endpoint.endpointType.type,
        },
        "endpointAttributes": [_serviceAttribute2Dict(a) for a in endpoint.endpointAttributes]
    }
    return result


def _dict2ServiceEndpoint(d):
    """
    Transform utility for LS spec to dictionary and reverse.
    """
    endpoint = lookup.ServiceRegistration.Endpoint()
    endpoint.url = d["url"]
    endpoint.sslTrust = d["sslTrust"]

    endpoint.endpointType = lookup.ServiceRegistration.EndpointType()
    endpoint.endpointType.protocol = d["endpointType"]["protocol"]
    endpoint.endpointType.type = d["endpointType"]["type"]

    endpoint.endpointAttributes = [_dict2serviceAttribute(a) for a in d["endpointAttributes"]]
    return endpoint


def _serviceInfo2Dict(serviceInfo):
    """
    Transform utility for LS spec to dictionary and reverse.
    """
    result = {}
    for prop in SERVICE_INFO_PROPERTIES:
        result[prop] = getattr(serviceInfo, prop)

    result.update({
        "serviceEndpoints": [_serviceEndpoint2Dict(e) for e in serviceInfo.serviceEndpoints],
        "serviceAttributes": [_serviceAttribute2Dict(a) for a in serviceInfo.serviceAttributes],
        "serviceType": _serviceType2Dict(serviceInfo.serviceType),
    })
    return result


def _dictToServiceCreateSpec(service):
    """
    Transform utility for LS spec to dictionary and reverse.
    """
    create_spec = lookup.ServiceRegistration.CreateSpec()
    PRUNE_PROPERTIES = ["serviceId", "siteId"]

    for prop in SERVICE_INFO_PROPERTIES:
        if prop not in PRUNE_PROPERTIES:
            setattr(create_spec, prop, service[prop])

    create_spec.serviceEndpoints = [_dict2ServiceEndpoint(e) for e in service["serviceEndpoints"]]
    create_spec.serviceType = _dict2ServiceType(service["serviceType"])
    create_spec.serviceAttributes = [_dict2serviceAttribute(a) for a in service["serviceAttributes"]]
    return create_spec


class LookupServiceClientHelper(object):
    """
    This class simplifies the interaction with the lookup service
    even further. A wrapper for LookupServiceClient class.

    Attributes:
        lsClient (LookupServiceClient object): Connection to LS.
        psc (str): FQDN of PSC.
        ssoClient (SsoClient object): SSO client.
    """

    def __init__(self, psc, username=None, password=None):
        """
        Parameters:
            psc (str): The PNID of the PSC we want to talk to
            username (Optional[str]): Admin username we will use to login
            password (Optional[str]): Password to the admin user
        """

        lookup_service_endpoint = "https://%s/lookupservice/sdk" % psc

        self.lsClient = LookupServiceClient(lookup_service_endpoint)
        self.ssoClient = None
        self.psc = psc

        if username or password:
            self.stsUrl, self.stsCertData = self.lsClient.get_sts_endpoint_data()
            ssoClientObj = SsoClient(self.stsUrl, self.stsCertData, username, password)
            self.lsClient.set_sso_client(ssoClientObj)
            try:
                sso.SsoAuthenticator(self.stsUrl).get_bearer_saml_assertion(username, password)
            except (sso.SoapException, Exception) as e:
                msg = 'Failed to validate sso credential. Error:\n%s\n\nExiting.' % e._fault_string
                logger.debug(msg)
                raise

    def _getHostId(self, svcInfoObjs):

        """
        Get the host ID from the service information objects.

        Args:
            svcInfoObjs (list): A list of service information objects.

        Returns:
            str or None: The host ID if found, None otherwise.
        """        
        hostId = None
        for svcInfo in svcInfoObjs:
            hostId = self.lsClient.get_machine_id(svcInfo)
            if hostId is not None:
                break
        return hostId

    def getAll(self):
        """
        This will get all the service registrations in the SSO domain.
        This is done by providing an empty search_filter and calling
        'get_service_info_list'. Returns a dictionary of services.

        Returns:
            services (dict): A dictionary of services.
        """

        logging.debug("Getting all services from LS.")
        search_filter = lookup.ServiceRegistration.Filter()
        svcInfoObjs = self.lsClient.get_service_info_list(search_filter=search_filter)
        # Transform the services to dictionary
        services = [_serviceInfo2Dict(s) for s in svcInfoObjs]
        return services

    def getPnid(self, pnid):
        """
        This method gets all services for a given PNID (or FQDN) by passing
        a 'pnid' value to get_service_info_list_ex. Returns a dictionary of services,
        as well as the hostId detected. hostId is to help us with finding services
        that do not have a node ID.

        Args:
            pnid (str): primary network identifier (FQDN) we want to look for

        Returns:
            Dict: dictionary of services as well as the hostID
        """
        logging.debug("Getting all services from LS for PNID: %s." % pnid)
        svcInfoObjs = self.lsClient.get_service_info_list_ex(pnid=pnid)

        # Get first not none machineId as hostId
        hostId = self._getHostId(svcInfoObjs)
        # Transform the services to dictionary
        services = [_serviceInfo2Dict(s) for s in svcInfoObjs]
        return services, hostId

    def getNode(self, node):
        """
        This method searches for all services matching a particular LDU GUID
        aka "Node ID". We pass a 'nodeId' filter to 'get_service_info_list'.
        Returns a dictionary of services.

        Args:
            node (str): The node ID or 'ldu guid' we are looking for.

        Returns: 
            dict: Dictionary of filtered services.
        """
        logging.debug("Getting all services from LS for node ID: %s" % node)
        search_filter = lookup.ServiceRegistration.Filter(nodeId=node)
        svcInfoObjs = self.lsClient.get_service_info_list(search_filter=search_filter)
        # Transform the services to dictionary
        services = [_serviceInfo2Dict(s) for s in svcInfoObjs]
        return services

    def getSite(self, site):
        """
        Allows us to get all services in a particular SSO site.
        Passes a filter with 'siteId' specified (site parameter passed to
        this function).  Returns dictionary of services.

        Args:
            site (str): The SSO site for which we want to return services.

        Returns:
            services (dict): Dictionary of filtered services.
        """
        logging.debug("Getting all services from LS in Site: %s" % site)
        search_filter = lookup.ServiceRegistration.Filter(siteId=site)
        svcInfoObjs = self.lsClient.get_service_info_list(search_filter=search_filter)
        # Transform the services to dictionary
        services = [_serviceInfo2Dict(s) for s in svcInfoObjs]
        return services

    def unregisterServices(self, services):
        """
        Unregister all services for given VC in LookupService.
        Accepts a dictionary of services, then loops through the
        service IDs and sends them to 'unregister_service'.

        Args:
            services (dict): Dictionary of services to unregister.
        """
        for service in services:
            serviceId = service["serviceId"]
            self.lsClient.unregister_service(serviceId)

    def unregisterPnid(self, pnid):
        """
        Unregister all services for given VC in LookupService. Sends
        'pnid' parameter to 'get_service_info_list_ex', then loops through
        the returned dictionary and sends each service ID to 'unregister_service'

        Args:
            pnid (str): Primary network identifier (FQDN) for which we want to
            unregister all services.
        """
        logging.debug("unregistering all services from LS for PNID: %s" % pnid)
        svcInfoObjs = self.lsClient.get_service_info_list_ex(pnid=pnid)
        if not svcInfoObjs:
            logger.info("No services to unregister")
            return

        for service in svcInfoObjs:
            svc_id = service.serviceId
            try:
                self.lsClient.unregister_service(svc_id)
                logger.info("Service %s has been successfully unregistered" % svc_id)
            except Exception:
                logger.error('Failed to unregister service %s.', svc_id)

    def register(self, svc_id, spec):
        """
        Accepts the service ID and dictionary formatted spec provided. The spec is then converted from dictionary to API formatted spec. Then, the service ID and API formatted spec are sent to 'register_service'.

        Args:
            svc_id (str): This is the service ID of the service you want to register.
            spec (dict): This is a dictionary formatted spec of the service.
        """
        formatted_spec = _dictToServiceCreateSpec(spec)
        try:
            self.lsClient.register_service(svc_id, formatted_spec)
            logger.debug("Service %s has been successfully registered" % svc_id)
        except Exception:
            logger.error('Failed to register service %s.', svc_id)

    def unregister(self, svc_id):
        """
        Passes the provided service ID (svc_id) to 'unregister_service'.

        Args:
            svc_id (str): This is the service ID of the service you want to unregister.
        """
        self.lsClient.unregister_service(svc_id)
        logger.debug("Service %s has been successfully unregistered" % svc_id)

    def registerServices(self, services):
        """
        Register given services in the LookupService.

        Args:
            services (TYPE): Dictionary of services to register
        """
        if not services:
            logger.info("No services to register")
            return

        for service in services:
            serviceId = service["serviceId"]
            createSpec = _dictToServiceCreateSpec(service)
            try:
                self.lsClient.register_service(serviceId, createSpec)
                logger.info("Service %s has been successfully registered", serviceId)
            except Exception:
                logger.error('Failed to register service %s.', serviceId)

    def reregister(self, pnid, services):
        """
        Unregister all existing services for given VC in LS and reregister
        the given services. Unregisters all services for given PNID and
        registers new ones based on the dictionary of services passed to it.

        Args:
            pnid (str): Primary network identifier (FQDN) for which we want to
                unregister all services.
            services (str): Dictionary of services we will register.
        """
        self.unregisterPnid(pnid)
        self.registerServices(services)

    def cleanup(self):

        """
        Clean up the SSO client.
        """        
        if self.ssoClient:
            self.ssoClient.cleanup()
