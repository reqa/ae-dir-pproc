#!/usr/bin/python
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
    SMTP_TLSARGS, \
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
        expiration_filterstr = (
            FILTERSTR_EXPIRE.format(currenttime=current_run_timestr)
        ).encode('utf-8')
        ldap_results = self.ldap_conn.search_s(
            self.ldap_conn.find_search_base(),
            ldap0.SCOPE_SUBTREE,
            filterstr=expiration_filterstr,
            attrlist=[
                'objectClass',
                'msPwdResetExpirationTime',
                'msPwdResetTimestamp',
                'msPwdResetAdminPw',
            ],
        )
        for ldap_dn, ldap_entry in ldap_results:
            self.logger.debug('Found %r: %r', ldap_dn, ldap_entry)
            # Prepare the modification list
            ldap_mod_list = [
                # explictly delete by value
                (
                    ldap0.MOD_DELETE,
                    'objectClass',
                    ['msPwdResetObject']
                ),
                (
                    ldap0.MOD_DELETE,
                    'msPwdResetTimestamp',
                    [ldap_entry['msPwdResetTimestamp'][0]]
                ),
                (
                    ldap0.MOD_DELETE,
                    'msPwdResetExpirationTime',
                    [ldap_entry['msPwdResetExpirationTime'][0]]
                ),
                # delete whole value no matter what
                (ldap0.MOD_DELETE, 'msPwdResetEnabled', None),
                (ldap0.MOD_DELETE, 'msPwdResetPasswordHash', None),
            ]
            if PWD_ADMIN_LEN or 'msPwdResetAdminPw' in ldap_entry:
                ldap_mod_list.append(
                    (ldap0.MOD_DELETE, 'msPwdResetAdminPw', None),
                )
            # Actually perform the modify operation
            try:
                self.ldap_conn.modify_s(ldap_dn, ldap_mod_list)
            except ldap0.LDAPError as ldap_error:
                self.logger.warn(
                    'LDAPError removing msPwdResetObject attrs in %r: %s',
                    ldap_dn,
                    ldap_error
                )
            else:
                self.logger.info(
                    'Removed msPwdResetObject attributes from %r',
                    ldap_dn,
                )
            return # end of expire_pwd_reset()

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
