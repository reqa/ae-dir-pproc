# -*- coding: utf-8 -*-
"""
aedir_pproc.pwd.welcome -- Send welcome e-mail to new users which have not set a password yet
"""

# from Python's standard lib
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

# the separate python-aedir module
import aedir.process

# Import constants from configuration module
from aedirpwd_cnf import (
    APP_PATH_PREFIX,
    FILTERSTR_NO_WELCOME_YET,
    FILTERSTR_USER,
    NOTIFY_EMAIL_SUBJECT,
    NOTIFY_EMAIL_TEMPLATE,
    NOTIFY_OLDEST_TIMESPAN,
    NOTIFY_SUCCESSFUL_MOD,
    PWD_LDAP_URL,
    SMTP_DEBUGLEVEL,
    SMTP_FROM,
    SMTP_LOCALHOSTNAME,
    SMTP_TLS_CACERTS,
    SMTP_URL,
    WEB_CTX_HOST,
)

from ..__about__ import __version__

#-----------------------------------------------------------------------
# Classes and functions
#-----------------------------------------------------------------------

class AEWelcomeMailer(aedir.process.AEProcess):
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

    def __init__(self):
        aedir.process.AEProcess.__init__(self)
        self.ldap_url = PWD_LDAP_URL

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

    def _send_welcome_message(self, smtp_conn, to_addr, smtp_message_tmpl, msg_attrs):
        """
        Send single welcome message for a user
        """
        self.logger.debug('msg_attrs = %r', msg_attrs)
        smtp_message = smtp_message_tmpl.format(**msg_attrs)
        smtp_subject = NOTIFY_EMAIL_SUBJECT.format(**msg_attrs)
        self.logger.debug('smtp_subject = %r', smtp_subject)
        self.logger.debug('smtp_message = %r', smtp_message)
        try:
            smtp_conn.send_simple_message(
                SMTP_FROM,
                [to_addr],
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
                'Sent welcome notification for user %r to %r',
                msg_attrs['user_displayname'],
                to_addr,
            )
        # end of _send_welcome_message()

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
            attrlist=self.user_attrs,
        )
        if not ldap_results:
            self.logger.debug('No results => no notifications')
            return

        notification_counter = 0

        with open(NOTIFY_EMAIL_TEMPLATE, 'r', encoding='utf-8') as tfile:
            smtp_message_tmpl = tfile.read()

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
                        attrlist=self.admin_attrs,
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
                self._send_welcome_message(smtp_conn, to_addr, smtp_message_tmpl, msg_attrs)
                notification_counter += 1
                if NOTIFY_SUCCESSFUL_MOD:
                    self.ldap_conn.modify_s(ldap_res.dn_s, NOTIFY_SUCCESSFUL_MOD)

        if notification_counter:
            self.logger.info('Sent %d welcome notifications', notification_counter)

        return # endof welcome_notifications()

    def run_worker(self, state):
        """
        Run the job
        """
        last_run_timestr, current_run_timestr = self._get_time_strings()
        self._welcome_notifications(last_run_timestr, current_run_timestr)
        return current_run_timestr
        # end of run_worker()
