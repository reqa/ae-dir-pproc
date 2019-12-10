# -*- coding: utf-8 -*-
"""
aedir_pproc.pwd.expreset - Remove expired msPwdResetObject attributes
"""

from __future__ import absolute_import

from ..__about__ import __version__, __author__, __license__

# from Python's standard lib
import sys
import os
import time
import smtplib
import email.utils
from socket import getfqdn

# mailutil is optional dependency of module aedir
# => provoke first fail here before doing anything else
import mailutil

# from ldap0 package
import ldap0
import ldap0.functions

# the separate mailutil module
import mailutil

# the separate python-aedir module
import aedir.process

# Import constants from configuration module
from aedirpwd_cnf import \
    APP_PATH_PREFIX, \
    FILTERSTR_EXPIRE, \
    FILTERSTR_NO_WELCOME_YET, \
    FILTERSTR_USER, \
    NOTIFY_EMAIL_SUBJECT, \
    NOTIFY_EMAIL_TEMPLATE, \
    NOTIFY_OLDEST_TIMESPAN, \
    NOTIFY_SUCCESSFUL_MOD, \
    PWD_ADMIN_LEN, \
    SERVER_ID, \
    SMTP_DEBUGLEVEL, \
    SMTP_FROM, \
    SMTP_LOCALHOSTNAME, \
    SMTP_URL, \
    WEB_CTX_HOST

#-----------------------------------------------------------------------
# Classes and functions
#-----------------------------------------------------------------------

class AEDIRPwdJob(aedir.process.AEProcess):
    """
    Job instance
    """
    script_version = __version__
    notify_oldest_timespan = NOTIFY_OLDEST_TIMESPAN
    user_attrs = [
        'objectClass',
        'uid',
        'cn',
        'displayName',
        'description',
        'mail',
        'creatorsName',
    ]
    admin_attrs = [
        'objectClass',
        'uid',
        'cn',
        'mail'
    ]

    def __init__(self, server_id):
        aedir.process.AEProcess.__init__(self)
        self.host_fqdn = getfqdn()
        self.server_id = server_id
        self.notification_counter = 0
        self._smtp_conn = None
        self.logger.debug('running on %r with (serverID %r)', self.host_fqdn, self.server_id)

    def _get_time_strings(self):
        """
        Determine
        1. oldest possible last timestamp (sounds strange, yeah!)
        2. and current time
        """
        current_time = time.time()
        return (
            ldap0.functions.strf_secs(current_time-self.notify_oldest_timespan),
            ldap0.functions.strf_secs(current_time)
        )

    def _expire_pwd_reset(self, last_run_timestr, current_run_timestr):
        """
        Remove expired msPwdResetObject attributes
        """
        expired_pwreset_filter = FILTERSTR_EXPIRE.format(currenttime=current_run_timestr)
        ldap_results = self.ldap_conn.search_s(
            self.ldap_conn.search_base,
            ldap0.SCOPE_SUBTREE,
            filterstr=expired_pwreset_filter,
            attrlist=[
                'objectClass',
                'msPwdResetExpirationTime',
                'msPwdResetTimestamp',
                'msPwdResetAdminPw',
            ],
        )
        self.logger.debug(
            '%d expired password resets found with %r',
            len(ldap_results),
            expired_pwreset_filter,
        )
        for res in ldap_results:
            self.logger.debug('Found %r: %r', res.dn_s, res.entry_as)
            # Prepare the modification list
            ldap_mod_list = [
                # explictly delete by value
                (ldap0.MOD_DELETE, b'objectClass', [b'msPwdResetObject']),
                (ldap0.MOD_DELETE, b'msPwdResetTimestamp', [res.entry_as['msPwdResetTimestamp'][0]]),
                (
                    ldap0.MOD_DELETE,
                    b'msPwdResetExpirationTime',
                    [res.entry_as['msPwdResetExpirationTime'][0]]
                ),
                # delete whole value no matter what
                (ldap0.MOD_DELETE, b'msPwdResetEnabled', None),
                (ldap0.MOD_DELETE, b'msPwdResetPasswordHash', None),
            ]
            if PWD_ADMIN_LEN or 'msPwdResetAdminPw' in res.entry_as:
                ldap_mod_list.append(
                    (ldap0.MOD_DELETE, b'msPwdResetAdminPw', None),
                )
            # Actually perform the modify operation
            try:
                self.ldap_conn.modify_s(res.dn_s, ldap_mod_list)
            except ldap0.LDAPError as ldap_error:
                self.logger.warning(
                    'LDAPError removing msPwdResetObject attrs in %r: %s',
                    res.dn_s,
                    ldap_error
                )
            else:
                self.logger.info(
                    'Removed msPwdResetObject attributes from %r',
                    res.dn_s,
                )
            # end of expire_pwd_reset()

    def run_worker(self, state):
        """
        Run the job
        """
        last_run_timestr, current_run_timestr = self._get_time_strings()
        self._expire_pwd_reset(last_run_timestr, current_run_timestr)
        return current_run_timestr # end of run_worker()


def main():
    with AEDIRPwdJob(SERVER_ID) as ae_process:
        ae_process.run(max_runs=1)


if __name__ == '__main__':
    main()
