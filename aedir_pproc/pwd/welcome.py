# -*- coding: ascii -*-
"""
aedir_pproc.pwd.welcome -- Send welcome e-mail to new users which have not set a password yet
"""

import os
import os.path
import sys
import time

import ldap0
import ldap0.functions

import aedir.process

# Import constants from configuration module
sys.path.append(os.path.dirname(os.environ.get('AEDIRPWD_CFG', '/opt/ae-dir/etc/ae-dir-pwd/aedirpwd_cnf.py')))
from aedirpwd_cnf import (
    APP_PATH_PREFIX,
    FILTERSTR_NO_WELCOME_YET,
    FILTERSTR_USER,
    WELCOME_EMAIL_SUBJECT,
    WELCOME_EMAIL_TEMPLATE,
    WELCOME_OLDEST_TIMESPAN,
    WELCOME_SUCCESSFUL_MOD,
    PWD_LDAP_URL,
    SMTP_DEBUGLEVEL,
    SMTP_FROM,
    SMTP_LOCALHOSTNAME,
    SMTP_TLS_CACERTS,
    SMTP_URL,
    WEB_CTX_HOST,
)

from ..__about__ import __version__
from . import PWD_USER_ATTRS, PWD_ADMIN_ATTRS

#-----------------------------------------------------------------------
# Classes and functions
#-----------------------------------------------------------------------

class AEWelcomeMailer(aedir.process.AEProcess):
    """
    Job instance
    """
    script_version = __version__

    def __init__(self):
        aedir.process.AEProcess.__init__(self)
        self.ldap_url = PWD_LDAP_URL

    @staticmethod
    def _get_time_strings():
        """
        Determine
        1. oldest possible last timestamp (sounds strange, yeah!)
        2. and current time
        """
        current_time = time.time()
        return (
            ldap0.functions.strf_secs(current_time-WELCOME_OLDEST_TIMESPAN),
            ldap0.functions.strf_secs(current_time)
        )

    def _welcome_notifications(self, last_run_timestr, current_run_timestr):
        """
        Send welcome e-mail to new users which have not set a password yet
        """
        nopassword_filterstr = (
            FILTERSTR_NO_WELCOME_YET.format(
                currenttime=current_run_timestr,
                lasttime=last_run_timestr,
            )
        )
        self.logger.debug(
            'User search filter: %r',
            nopassword_filterstr,
        )
        ldap_results = self.ldap_conn.search_s(
            self.ldap_conn.search_base,
            ldap0.SCOPE_SUBTREE,
            filterstr=nopassword_filterstr,
            attrlist=PWD_USER_ATTRS,
        )
        if not ldap_results:
            self.logger.debug('No results => no notifications')
            return

        notification_counter = 0

        with self.smtp_connection(
                SMTP_URL,
                local_hostname=SMTP_LOCALHOSTNAME,
                ca_certs=SMTP_TLS_CACERTS,
                debug_level=SMTP_DEBUGLEVEL,
            ) as smtp_conn:

            for ldap_res in ldap_results:
                to_addr = ldap_res.entry_s['mail'][0]
                self.logger.debug(
                    'Prepare welcome notification for %r sent to %r',
                    ldap_res.dn_s,
                    to_addr,
                )
                msg_attrs = {
                    'ldap_uri': str(self.ldap_conn.ldap_url_obj.connect_uri()),
                    'search_base': self.ldap_conn.search_base,
                    'user_uid': ldap_res.entry_s['uid'][0],
                    'user_cn': ldap_res.entry_s.get('cn', [''])[0],
                    'user_displayname': ldap_res.entry_s.get('displayName', [''])[0],
                    'user_description': ldap_res.entry_s.get('description', [''])[0],
                    'emailadr': to_addr,
                    'fromaddr': SMTP_FROM,
                    'user_dn': ldap_res.dn_s,
                    'web_ctx_host': WEB_CTX_HOST or self.host_fqdn,
                    'app_path_prefix': APP_PATH_PREFIX,
                    'admin_cn': 'unknown',
                    'admin_mail': 'unknown',
                }
                admin_dn = ldap_res.entry_s['creatorsName'][0]
                try:
                    admin_res = self.ldap_conn.read_s(
                        admin_dn,
                        filterstr=FILTERSTR_USER,
                        attrlist=PWD_ADMIN_ATTRS,
                    )
                except (ldap0.NO_SUCH_OBJECT, ldap0.INSUFFICIENT_ACCESS) as ldap_err:
                    self.logger.warning(
                        'Error reading admin entry %r referenced by %r: %s',
                        admin_dn,
                        ldap_res.dn_s,
                        ldap_err,
                    )
                else:
                    if admin_res is None:
                        self.logger.warning(
                            'Empty result reading admin entry %r referenced by %r',
                            admin_dn,
                            ldap_res.dn_s,
                        )
                    else:
                        self.logger.debug(
                            'Read admin entry %r: %r',
                            admin_dn,
                            admin_res.entry_s,
                        )
                        if admin_res is not None:
                            msg_attrs['admin_cn'] = admin_res.entry_s.get('cn', ['unknown'])[0]
                            msg_attrs['admin_mail'] = admin_res.entry_s.get('mail', ['unknown'])[0]
                self.send_simple_message(
                    smtp_conn,
                    SMTP_FROM,
                    to_addr,
                    WELCOME_EMAIL_SUBJECT,
                    WELCOME_EMAIL_TEMPLATE,
                    msg_attrs,
                )
                notification_counter += 1
                if WELCOME_SUCCESSFUL_MOD:
                    self.ldap_conn.modify_s(ldap_res.dn_s, WELCOME_SUCCESSFUL_MOD)

        if notification_counter:
            self.logger.info('Sent %d welcome notifications', notification_counter)

        # end of welcome_notifications()

    def run_worker(self, state):
        """
        Run the job
        """
        last_run_timestr, current_run_timestr = self._get_time_strings()
        self._welcome_notifications(last_run_timestr, current_run_timestr)
        return current_run_timestr
        # end of run_worker()
