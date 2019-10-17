# -*- coding: utf-8 -*-
"""
aedir_pproc.welcome -- Send welcome e-mail to new users which have not set a password yet
"""

from __future__ import absolute_import

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

from .__about__ import __version__, __author__, __license__

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
    PWD_LDAP_URL, \
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
    ldap_url = PWD_LDAP_URL
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
            FILTERSTR_EXPIRE.format(
                currenttime=current_run_timestr,
                lasttime=last_run_timestr,
                serverid=self.server_id,
            )
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

    def _send_welcome_message(self, to_addr, smtp_message_tmpl, msg_attrs):
        """
        Send single welcome message for a user
        """
        self.logger.debug('msg_attrs = %r', msg_attrs)
        smtp_conn = self._smtp_connection(
            SMTP_URL,
            local_hostname=SMTP_LOCALHOSTNAME,
            tls_args=SMTP_TLSARGS,
            debug_level=SMTP_DEBUGLEVEL
        )
        smtp_message = smtp_message_tmpl.format(**msg_attrs)
        smtp_subject = NOTIFY_EMAIL_SUBJECT.format(**msg_attrs)
        self.logger.debug('smtp_subject = %r', smtp_subject)
        self.logger.debug('smtp_message = %r', smtp_message)
        try:
            smtp_conn.send_simple_message(
                SMTP_FROM,
                [to_addr.encode('utf-8')],
                'utf-8',
                (
                    ('From', SMTP_FROM),
                    ('Date', email.utils.formatdate(time.time(), True)),
                    ('Subject', smtp_subject),
                    ('To', to_addr),
                ),
                smtp_message,
            )
        except smtplib.SMTPRecipientsRefused as smtp_error:
            self.logger.error(
                'Recipient %r rejected: %s',
                to_addr,
                smtp_error
            )
        else:
            self.logger.info(
                'Sent notification for user %r with e-mail address %r',
                msg_attrs['user_displayname'],
                to_addr,
            )
            self.notification_counter += 1
        return # end of _send_welcome_message()

    def _welcome_notifications(self, last_run_timestr, current_run_timestr):
        """
        Send welcome e-mail to new users which have not set a password yet
        """
        nopassword_filterstr = (
            FILTERSTR_NO_WELCOME_YET.format(
                currenttime=current_run_timestr,
                lasttime=last_run_timestr,
                serverid=self.server_id,
            )
        ).encode('utf-8')
        self.logger.debug(
            'User search filter: %r',
            nopassword_filterstr,
        )
        ldap_results = self.ldap_conn.search_s(
            self.ldap_conn.find_search_base(),
            ldap0.SCOPE_SUBTREE,
            filterstr=nopassword_filterstr,
            attrlist=self.user_attrs,
        )
        if not ldap_results:
            self.logger.debug('No results => no notifications')
            return

        for ldap_dn, ldap_entry in ldap_results:
            to_addr = ldap_entry['mail'][0].decode('utf-8')
            self.logger.debug(
                'Prepare notification for %r sent to %r',
                ldap_dn,
                to_addr,
            )
            smtp_message_tmpl = open(
                NOTIFY_EMAIL_TEMPLATE, 'rb'
            ).read().decode('utf-8')
            msg_attrs = {
                'ldap_uri':str(self.ldap_conn.ldap_url_obj.initializeUrl()),
                'user_uid':ldap_entry['uid'][0].decode('utf-8'),
                'user_cn':ldap_entry.get('cn', [''])[0].decode('utf-8'),
                'user_displayname':ldap_entry.get(
                    'displayName', ['']
                )[0].decode('utf-8'),
                'user_description':ldap_entry.get(
                    'description', ['']
                )[0].decode('utf-8'),
                'emailadr':to_addr,
                'fromaddr':SMTP_FROM,
                'user_dn':ldap_dn.decode('utf-8'),
                'web_ctx_host':(
                    WEB_CTX_HOST or self.host_fqdn
                ).decode('ascii'),
                'app_path_prefix':APP_PATH_PREFIX,
                'admin_cn':u'unknown',
                'admin_mail':u'unknown',
            }
            admin_dn = ldap_entry['creatorsName'][0]
            try:
                admin_entry = self.ldap_conn.read_s(
                    admin_dn,
                    filterstr=FILTERSTR_USER.encode('utf-8'),
                    attrlist=self.admin_attrs,
                ) or {}
            except (ldap0.NO_SUCH_OBJECT, ldap0.INSUFFICIENT_ACCESS) as ldap_err:
                self.logger.warning(
                    'Error reading admin entry %r referenced by %r: %s',
                    admin_dn,
                    ldap_dn,
                    ldap_err,
                )
                admin_entry = {}
            else:
                if not admin_entry:
                    self.logger.warning(
                        'Empty result reading admin entry %r referenced by %r',
                        admin_dn,
                        ldap_dn,
                    )
            msg_attrs['admin_cn'] = admin_entry.get(
                'cn', ['unknown']
            )[0].decode('utf-8')
            msg_attrs['admin_mail'] = admin_entry.get(
                'mail', ['unknown']
            )[0].decode('utf-8')
            self._send_welcome_message(to_addr, smtp_message_tmpl, msg_attrs)
            if NOTIFY_SUCCESSFUL_MOD:
                self.ldap_conn.modify_s(ldap_dn, NOTIFY_SUCCESSFUL_MOD)
        if self.notification_counter:
            self.logger.info('Sent %d notifications', self.notification_counter)
        return # endof welcome_notifications()

    def run_worker(self, state):
        """
        Run the job
        """
        last_run_timestr, current_run_timestr = self._get_time_strings()
        self._expire_pwd_reset(last_run_timestr, current_run_timestr)
        self._welcome_notifications(last_run_timestr, current_run_timestr)
        return current_run_timestr # end of run_worker()


def main():
    with AEDIRPwdJob(SERVER_ID) as ae_process:
        ae_process.run(max_runs=1)


if __name__ == '__main__':
    main()
