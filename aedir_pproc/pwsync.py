# -*- coding: ascii -*-
"""
aedir_pproc.pwsync - slapd-sock listener for password synchronisation

This demon intercepts password changes (Password modify extended operation)
and sends the clear-text password to e.g. MS AD
"""

#-----------------------------------------------------------------------
# Imports
#-----------------------------------------------------------------------

import crypt
import logging
import os
import sys
import queue
import threading
import time
from collections import OrderedDict

from pyasn1.type.univ import OctetString, Sequence
from pyasn1.type.namedtype import NamedTypes, OptionalNamedType
from pyasn1.type.tag import Tag, tagClassContext, tagFormatSimple
from pyasn1.codec.ber import decoder as pyasn1_decoder
from pyasn1.error import PyAsn1Error

import ldap0
import ldap0.functions
from ldap0.res import SearchResultEntry
from ldap0.dn import DNObj
from ldap0.functions import strf_secs as ldap_strf_secs
from ldap0.ldapurl import LDAPUrl
from ldap0.lock import LDAPLock
from ldap0.pw import unicode_pwd
from ldap0.ldapobject import ReconnectLDAPObject

from slapdsock.ldaphelper import LocalLDAPConn
from slapdsock.handler import SlapdSockHandler
from slapdsock.service import SlapdSockThreadingServer

from aedir import init_logger

from .__about__ import __version__

#-----------------------------------------------------------------------
# Configuration constants
#-----------------------------------------------------------------------

# UIDs and peer GIDS of peers which are granted access
# (list of int/strings)
ALLOWED_UIDS = [0, 'ae-dir-slapd']
ALLOWED_GIDS = [0]

# String with octal representation of socket permissions
SOCKET_PERMISSIONS = '0666'

# Trace level for ldap0 logging
LDAP0_TRACE_LEVEL = int(os.environ.get('LDAP0_TRACE_LEVEL', 0))

# Number of times connecting to local LDAPI is retried before sending a
# failed response for a query
LDAP_MAXRETRYCOUNT = 10
# Time to wait before retrying to connect within one query
LDAP_RETRYDELAY = 0.1

# SASL authz-ID to be sent along with SASL/EXTERNAL bind
#LDAP_SASL_AUTHZID = 'dn:uid=simple_bind_proxy,dc=example,dc=com'
LDAP_SASL_AUTHZID = None

# Time in seconds for which normal LDAP searches will be valid in cache
LDAP_CACHE_TTL = 5.0
# Time in seconds for which pwdPolicy and oathHOTPParams entries will be
# valid in cache
LDAP_LONG_CACHE_TTL = 20 * LDAP_CACHE_TTL

# Timeout in seconds when connecting to local and remote LDAP servers
# used for ldap0.OPT_NETWORK_TIMEOUT and ldap0.OPT_TIMEOUT
LDAP_TIMEOUT = 3.0

# attribute containing username
LDAP_USERNAME_ATTR = 'uid'

# Timeout in seconds for the server (Unix domain) socket
SOCKET_TIMEOUT = 2 * LDAP_TIMEOUT

# Logging formats
SYS_LOG_FORMAT = '%(name)s %(levelname)s %(message)s'
CONSOLE_LOG_FORMAT = '%(name)s %(asctime)s %(levelname)s %(message)s'

# Base number for floating average value of response delay
AVERAGE_COUNT = 100

# Default log level to use
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()

# Time (seconds) for assuming an userPassword+OTP value to be valid in cache
CACHE_TTL = -1.0

DEBUG_VARS = [
    'user_dn',
]

# Error messages
if __debug__:
    DEBUG_VARS.extend([
        'old_passwd',
        'new_passwd',
    ])

#-----------------------------------------------------------------------
# Classes and functions
#-----------------------------------------------------------------------

class DictQueue(queue.Queue):
    """
    modified Queue class which internally stores items in a dict
    """

    def _init(self, maxsize):
        self.queue = OrderedDict()

    # Put a new item in the queue
    def _put(self, item):
        key, value = item
        self.queue[key] = value

    # Get an item from the queue
    def _get(self):
        key, value = self.queue.popitem()
        return (key, value)


class PWSyncWorker(threading.Thread, LocalLDAPConn):
    """
    Thread class for the password synchronization worker
    """
    passwd_update_delay = 1.0
    source_id_attr = 'uid'
    target_filter_format = '({0}={1})'
    target_id_attr = 'uid'
    target_password_attr = 'userPassword'
    target_password_encoding = 'utf-8'

    def __init__(
            self,
            target_ldap_url,
            que,
        ):
        self._target_ldap_url = target_ldap_url
        if target_ldap_url.attrs is not None and \
           len(target_ldap_url.attrs) == 2:
            self.target_id_attr, self.target_password_attr = target_ldap_url.attrs
        self.logger = init_logger(self.__class__.__name__)
        self._queue = que
        threading.Thread.__init__(self, name=self.__class__.__module__+self.__class__.__name__)
        LocalLDAPConn.__init__(self, self.logger)
        self._target_conn = None
        self._target_conn_lock = LDAPLock(
            desc='target_conn() in %s' % (repr(self.__class__))
        )
        # end of PWSyncWorker.__init__()

    def target_conn(self):
        """
        open and cache target connection
        """
        if isinstance(self._target_conn, ReconnectLDAPObject):
            self.logger.debug(
                'Existing LDAP connection to %s (%s)',
                repr(self._target_conn.uri),
                repr(self._target_conn),
            )
            return self._target_conn
        try:
            self.logger.debug(
                'Open connection to %r as %r',
                self._target_ldap_url.connect_uri(),
                self._target_ldap_url.who,
            )
            self._target_conn_lock.acquire()
            try:
                self._target_conn = ReconnectLDAPObject(
                    self._target_ldap_url.connect_uri(),
                    trace_level=LDAP0_TRACE_LEVEL,
                    cache_ttl=LDAP_CACHE_TTL,
                    retry_max=LDAP_MAXRETRYCOUNT,
                    retry_delay=LDAP_RETRYDELAY,
                )
                self._target_conn.simple_bind_s(
                    self._target_ldap_url.who or '',
                    (self._target_ldap_url.cred or '').encode('utf-8'),
                )
            except ldap0.LDAPError as ldap_error:
                self._target_conn = None
                self.logger.error(
                    'LDAPError during connecting to %r: %s',
                    self.ldapi_uri,
                    ldap_error,
                )
                raise ldap_error
            else:
                self.logger.info(
                    'Successfully bound to %s as %s',
                    self._target_conn.uri,
                    self._target_conn.whoami_s(),
                )
        finally:
            self._target_conn_lock.release()
        return self._target_conn
        # end of target_conn()

    def _check_password(self, user_dn, new_passwd):
        self.logger.debug('Check password of %r', user_dn)
        ldapi_conn = self.get_ldapi_conn()
        try:
            user_entry = ldapi_conn.read_s(
                user_dn,
                attrlist=['userPassword']
            )
        except ldap0.LDAPError as ldap_error:
            self.logger.warning('LDAPError checking password of %r: %s', user_dn, ldap_error)
            return False
        if not user_entry:
            self.logger.warning('No search result reading %r', user_dn)
            return False
        try:
            user_password_hash = ldap0.cidict.CIDict(user_entry.entry_as)['userPassword'][0][7:]
        except (KeyError, IndexError):
            self.logger.warning('No userPassword in %r', user_dn)
            return False
        if __debug__:
            self.logger.debug('user_password_hash = %r', user_password_hash)
        # Compare password with local hash in attribute userPassword
        crypt_hash = crypt.crypt(
            new_passwd,
            user_password_hash.decode('ascii').rsplit('$', 1)[0],
        )
        return user_password_hash == crypt_hash
        # end of _check_password()

    def get_target_id(self, source_dn):
        """
        determine target identifier based on user's source DN
        """
        self.logger.debug('Determine target ID for %r', source_dn)
        rdn_attr_type, uid = list(DNObj.from_str(source_dn).rdn_attrs().items())[0]
        if rdn_attr_type.lower() != self.source_id_attr:
            # check accepted attribute in RDN
            self.logger.warning(
                'RDN attribute %r is not %r => ignore password change of %r',
                rdn_attr_type,
                self.source_id_attr,
                source_dn,
            )
            return None
        self.logger.debug('Extracted %s=%r from source_dn=%r', self.source_id_attr, uid, source_dn)
        target_filter = self.target_filter_format.format(self.target_id_attr, uid)
        self.logger.debug('Searching target entry with %r', target_filter)
        target_conn = self.target_conn()
        ldap_result = target_conn.search_s(
            self._target_ldap_url.dn,
            self._target_ldap_url.scope or ldap0.SCOPE_SUBTREE,
            target_filter,
            attrlist=['1.1'],
            sizelimit=8,
        )
        # strip LDAPv3 referrals received
        ldap_result = [
            res
            for res in ldap_result
            if isinstance(res, SearchResultEntry)
        ]
        self.logger.debug('ldap_result=%r', ldap_result)
        if len(ldap_result) != 1:
            return None
        return ldap_result[0].dn_s
        # end of PWSyncWorker.get_target_id()

    def _encode_target_password(self, password):
        """
        encode argument password for target system
        """
        if self.target_password_attr.lower() == 'unicodepwd':
            return unicode_pwd(password.encode('utf-8'))
        return password.encode(self.target_password_encoding)

    def _update_target_password(self, target_id, old_passwd, new_passwd, req_time):
        """
        write new password to target
        """
        target_conn = self.target_conn()
        target_conn.modify_s(
            target_id,
            [(
                ldap0.MOD_REPLACE,
                self.target_password_attr.encode('ascii'),
                [self._encode_target_password(new_passwd)],
            )]
        )
        # end of PWSyncWorker._update_target_password()

    def run(self):
        """
        Thread runner function
        """
        while True:
            user_dn, val = self._queue.get()
            old_passwd, new_passwd, req_time = val
            self.logger.debug(
                'Received password change for %r (at %s)',
                user_dn,
                ldap_strf_secs(req_time),
            )
            try:
                sleep_time = max(
                    0,
                    time.time()-req_time+self.passwd_update_delay
                )
                self.logger.debug(
                    'Deferring syncing password for %r for %f secs',
                    user_dn,
                    sleep_time,
                )
                time.sleep(sleep_time)
                if not self._check_password(user_dn, new_passwd):
                    # simply ignore wrong passwords
                    self.logger.warning('Ignoring wrong password for %r', user_dn)
                    continue
                target_id = self.get_target_id(user_dn)
                if target_id is None:
                    # simply ignore non-existent targets
                    self.logger.warning(
                        'No target ID found for %r => ignore password change',
                        user_dn,
                    )
                    continue
                self.logger.debug('Try to sync password for %r to %r', user_dn, target_id)
                self._update_target_password(target_id, old_passwd, new_passwd, req_time)
            except Exception:
                self.logger.error(
                    'Error syncing password for %r:\n',
                    user_dn,
                    exc_info=True,
                )
            else:
                self.logger.info('Synced password for %r to %r', user_dn, target_id)
            self._queue.task_done()
        # end of PWSyncWorker.run()


class PasswdModifyRequestValue(Sequence):
    """
    PasswdModifyRequestValue ::= SEQUENCE {
        userIdentity [0] OCTET STRING OPTIONAL
        oldPasswd [1] OCTET STRING OPTIONAL
        newPasswd [2] OCTET STRING OPTIONAL }
    """

    class UserIdentity(OctetString):
        """
        userIdentity [0] OCTET STRING OPTIONAL
        """
        tagSet = OctetString.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatSimple, 0))

    class OldPasswd(OctetString):
        """
        oldPasswd [1] OCTET STRING OPTIONAL
        """
        tagSet = OctetString.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatSimple, 1))

    class NewPasswd(OctetString):
        """
        newPasswd [2] OCTET STRING OPTIONAL
        """
        tagSet = OctetString.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatSimple, 2))

    componentType = NamedTypes(
        OptionalNamedType('userIdentity', UserIdentity()),
        OptionalNamedType('oldPasswd', OldPasswd('')),
        OptionalNamedType('newPasswd', NewPasswd('')),
    )


class PassModHandler(SlapdSockHandler):

    """
    Handler class which extracts new userPassword value
    from EXTENDED operation
    """

    def do_extended(self, request):
        """
        Handle EXTENDED operation
        """
        if request.oid != '1.3.6.1.4.1.4203.1.11.1':
            # ignore all other extended operations
            return 'CONTINUE'
        try:
            decoded_value, _ = pyasn1_decoder.decode(
                request.value,
                asn1Spec=PasswdModifyRequestValue(),
            )
            try:
                user_dn = str(decoded_value.getComponentByName('userIdentity'))
            except PyAsn1Error:
                user_dn = request.binddn
            self._log(
                logging.INFO,
                'Intercepted PASSMOD operation for %r',
                user_dn,
            )
            old_passwd = str(decoded_value.getComponentByName('oldPasswd')) or None
            new_passwd = str(decoded_value.getComponentByName('newPasswd')) or None
        except Exception as err:
            self._log(
                logging.ERROR,
                'Unhandled exception processing PASSMOD request: %r',
                err,
                exc_info=True
            )
        else:
            # push the password change into queue
            self.server.pwsync_queue.put((
                user_dn,
                (old_passwd, new_passwd, time.time()),
            ))
        return 'CONTINUE' # end of do_modify()


class PassModServer(SlapdSockThreadingServer):

    """
    This is used to pass in more parameters to the server instance
    """
    ldapi_authz_id = LDAP_SASL_AUTHZID
    ldap_retry_max = LDAP_MAXRETRYCOUNT
    ldap_retry_delay = LDAP_RETRYDELAY
    ldap_cache_ttl = LDAP_CACHE_TTL

    def __init__(
            self,
            server_address,
            RequestHandlerClass,
            average_count,
            socket_timeout,
            socket_permissions,
            allowed_uids,
            allowed_gids,
            pwsync_queue,
            bind_and_activate=True,
            log_vars=None,
        ):
        self._ldap_conn = None
        self.pwsync_queue = pwsync_queue
        SlapdSockThreadingServer.__init__(
            self,
            server_address,
            RequestHandlerClass,
            init_logger(self.__class__.__name__),
            average_count,
            socket_timeout,
            socket_permissions,
            allowed_uids,
            allowed_gids,
            bind_and_activate,
            monitor_dn=None,
            log_vars=log_vars,
        )


#-----------------------------------------------------------------------
# Main
#-----------------------------------------------------------------------

def run():
    """
    The main script
    """

    script_name = os.path.abspath(sys.argv[0])
    pwsync_queue = DictQueue()

    my_logger = init_logger(os.path.basename(script_name))

    my_logger.info(
        'Starting %s %s (log level %d)',
        script_name,
        __version__,
        my_logger.level
    )

    if __debug__:
        my_logger.error(
            '!!! Running in debug mode (log level %d)! '
            'Secret data will be logged! Don\'t do that!!!',
            my_logger.level
        )

    try:
        socket_path = sys.argv[1]
        local_ldap_uri = sys.argv[2]
        target_ldap_url = sys.argv[3]
        target_password_filename = sys.argv[4]
    except IndexError:
        my_logger.error('Not enough arguments => abort')
        sys.exit(1)

    try:
        local_ldap_uri_obj = LDAPUrl(local_ldap_uri)
        target_ldap_url_obj = LDAPUrl(target_ldap_url)
    except ValueError as err:
        my_logger.error('%s  => abort', err)
        sys.exit(1)

    cacert_filename = ldap0.functions.get_option(ldap0.OPT_X_TLS_CACERTFILE)
    if not cacert_filename:
        my_logger.error('No CA certificate file defined => abort')
        sys.exit(1)

    try:
        with open(cacert_filename, 'r') as cacert_file:
            cacert = cacert_file.read()
    except IOError as err:
        my_logger.error('Error reading CA cert file %r: %s => abort', cacert_filename, err)
        sys.exit(1)
    else:
        my_logger.debug('Using CA cert file %r (%d bytes)', cacert_filename, len(cacert))

    # read target password from file
    try:
        with open(target_password_filename, 'r', encoding='utf-8') as target_password_file:
            target_ldap_url_obj.cred = target_password_file.read()
    except IOError as err:
        my_logger.error(
            'Error reading target password file %r: %s => abort',
            target_password_filename,
            err
        )
        sys.exit(1)
    else:
        my_logger.debug('Using target password file %r', target_password_filename)

    # initialize password sync consumer thread
    pwsync_worker = PWSyncWorker(
        target_ldap_url_obj,
        pwsync_queue,
    )
    pwsync_worker.ldapi_uri = local_ldap_uri_obj.connect_uri()
    pwsync_worker.daemon = True
    pwsync_worker.start()

    try:
        slapd_sock_listener = PassModServer(
            socket_path,
            PassModHandler,
            AVERAGE_COUNT,
            SOCKET_TIMEOUT, SOCKET_PERMISSIONS,
            ALLOWED_UIDS, ALLOWED_GIDS,
            pwsync_queue,
            log_vars=DEBUG_VARS,
        )
        slapd_sock_listener.ldapi_uri = local_ldap_uri_obj.connect_uri()
        slapd_sock_listener.ldap_trace_level = LDAP0_TRACE_LEVEL
        try:
            slapd_sock_listener.serve_forever()
        except KeyboardInterrupt:
            my_logger.warning('Received interrupt signal => shutdown')
    finally:
        my_logger.debug('Remove socket path %s', repr(socket_path))
        try:
            os.remove(socket_path)
        except OSError:
            pass

    # end of main()


if __name__ == '__main__':
    run()
