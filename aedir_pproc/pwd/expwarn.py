# -*- coding: utf-8 -*-
"""
aedir_pproc.pwd.expwarn - send password expiry warnings via e-mail
"""

from __future__ import absolute_import

from ..__about__ import __version__, __author__, __license__

# from Python's standard lib
import os
import sys
import smtplib
import time
import email.utils
from email.header import Header as email_Header

# mailutil is optional dependency of module aedir
# => provoke first fail here before doing anything else
import mailutil

# the separate python-aedir module
import aedir.process

# from ldap0
import ldap0
import ldap0.functions

#-----------------------------------------------------------------------
# Configuration constants
#-----------------------------------------------------------------------

# LDAP filter string to be used to search for pwdPolicy entries
PWDPOLICY_FILTER = (
    '(&'
        '(objectClass=pwdPolicy)'
        '(&(pwdMaxAge=*)(!(pwdMaxAge=0)))'
        '(pwdExpireWarning=*)'
        '(!(pwdAllowUserChange=FALSE))'
    ')'
)

# Filter string templates
PWD_EXPIRYWARN_FILTER_TMPL = (
    '(&'
        '(objectClass=aeUser)'
        '(aeStatus=0)'
        '(uid=*)'
        '(displayName=*)'
        '(mail=*)'
        '(pwdPolicySubentry={pwdpolicy})'
        '(pwdChangedTime>={pwdchangedtime_ge})'
        '(pwdChangedTime<={pwdchangedtime_le})'
    ')'
)

# Filter string template for finding an active user entry
# mainly used to inform about who did something and send e-mail to
FILTERSTR_USER = '(&(objectClass=aeUser)(aeStatus=0)(displayName=*)(mail=*))'

# Maximum timespan to search for password-less entries in the past
NOTIFY_OLDEST_TIMESPAN = 1.75 * 86400.0

# Import constants from configuration module
from aedirpwd_cnf import \
    APP_PATH_PREFIX, \
    SMTP_DEBUGLEVEL, \
    SMTP_FROM, \
    SMTP_LOCALHOSTNAME, \
    SMTP_TLS_CACERTS, \
    SMTP_URL, \
    TEMPLATES_DIRNAME, \
    USER_MAIL_ENABLED, \
    WEB_CTX_HOST

# E-Mail subject for notification message
PWD_EXPIRYWARN_MAIL_SUBJECT = u'Password of Æ-DIR account "{user_uid}" will expire soon!'
# E-Mail body template file for notification message
PWD_EXPIRYWARN_MAIL_TEMPLATE = os.path.join(TEMPLATES_DIRNAME, 'pwd_expiry_warning.txt')


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
        'modifiersName',
    ]

    def __init__(self):
        aedir.process.AEProcess.__init__(self)
        self.notification_counter = 0
        self._smtp_conn = None

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

    def run_worker(self, state):
        """
        Run the job
        """
        last_run_timestr, current_run_timestr = self._get_time_strings()
        self._send_password_expiry_notifications(last_run_timestr, current_run_timestr)
        return current_run_timestr # end of run_worker()

    def _get_pwd_policy_entries(self):
        """
        Search all pwdPolicy entries with expiring passwords (pwdMaxAge set)
        """
        ldap_pwdpolicy_results = self.ldap_conn.search_s(
            self.ldap_conn.search_base,
            ldap0.SCOPE_SUBTREE,
            filterstr=PWDPOLICY_FILTER,
            attrlist=[
                'cn',
                'pwdMaxAge',
                'pwdExpireWarning'
            ],
        )
        if not ldap_pwdpolicy_results:
            self.logger.error('No pwdPolicy entries found => nothing to do => abort')
        pwd_policy_list = [
            (res.dn_s, int(res.entry_s['pwdMaxAge'][0]), int(res.entry_s['pwdExpireWarning'][0]))
            for res in ldap_pwdpolicy_results
        ]
        self.logger.debug('Found %d pwdPolicy entries: %s', len(pwd_policy_list), pwd_policy_list)
        return pwd_policy_list # enf of _get_pwd_policy_entries()

    def _send_password_expiry_notifications(self, last_run_timestr, current_run_timestr):
        """
        send password expiry warning e-mails
        """
        current_time = ldap0.functions.strp_secs(current_run_timestr)

        pwd_policy_list = self._get_pwd_policy_entries()
        pwd_expire_warning_list = []

        for pwd_policy, pwd_max_age, pwd_expire_warning in pwd_policy_list:
            filterstr_inputs_dict = {
                'pwdpolicy': pwd_policy,
                'pwdchangedtime_ge': ldap0.functions.strf_secs(current_time-pwd_max_age),
                'pwdchangedtime_le': ldap0.functions.strf_secs(current_time-(pwd_max_age-pwd_expire_warning)),
            }
            self.logger.debug('filterstr_inputs_dict = %s', filterstr_inputs_dict)

            pwd_expirywarn_filter = PWD_EXPIRYWARN_FILTER_TMPL.format(**filterstr_inputs_dict)

            self.logger.debug(
                'Search users for password expiry warning with %r',
                pwd_expirywarn_filter
            )
            ldap_results = self.ldap_conn.search_s(
                self.ldap_conn.search_base,
                ldap0.SCOPE_SUBTREE,
                filterstr=pwd_expirywarn_filter,
                attrlist=self.user_attrs,
            )

            for res in ldap_results:
                to_addr = res.entry_s['mail'][0]
                self.logger.debug('Prepare password expiry notification for %r sent to %r', res.dn_s, to_addr)
                pwd_expire_warning_list.append({
                    'user_uid': res.entry_s['uid'][0],
                    'user_cn': res.entry_s.get('cn', [''])[0],
                    'user_displayname': res.entry_s.get('displayName', [''])[0],
                    'user_description': res.entry_s.get('description', [''])[0],
                    'emailaddr': to_addr,
                    'fromaddr': SMTP_FROM,
                    'user_dn': res.dn_s,
                    'web_ctx_host': WEB_CTX_HOST,
                    'app_path_prefix': APP_PATH_PREFIX,
                })

        self.logger.debug('pwd_expire_warning_list = %s', pwd_expire_warning_list)

        if not pwd_expire_warning_list:
            self.logger.info('No results => no password expiry notifications')
        elif USER_MAIL_ENABLED is not True:
            self.logger.info(
                'Sending e-mails is disabled => Supressed %d password expiry notifications to %s',
                len(pwd_expire_warning_list),
                ', '.join([user_data['user_uid'] for user_data in pwd_expire_warning_list]),
            )
        else:
            # Read mail template file
            with open(PWD_EXPIRYWARN_MAIL_TEMPLATE, 'rb') as template_file:
                smtp_message_tmpl = template_file.read().decode('utf-8')
            smtp_conn = self._smtp_connection(
                SMTP_URL,
                local_hostname=SMTP_LOCALHOSTNAME,
                ca_certs=SMTP_TLS_CACERTS,
                debug_level=SMTP_DEBUGLEVEL,
            )
            notified_users = []
            for user_data in pwd_expire_warning_list:
                to_addr = user_data['emailaddr']
                smtp_message = smtp_message_tmpl.format(**user_data)
                smtp_subject = PWD_EXPIRYWARN_MAIL_SUBJECT.format(**user_data)
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
                except smtplib.SMTPRecipientsRefused as smtp_err:
                    self.logger.error('Recipient %r rejected: %s', to_addr, smtp_err)
                    continue
                else:
                    notified_users.append(user_data['user_uid'])
            self.logger.info(
                'Sent %d password expiry notifications: %s',
                len(notified_users),
                ', '.join(notified_users),
            )


def main():
    with AEDIRPwdJob() as ae_process:
        ae_process.run(max_runs=1)


if __name__ == '__main__':
    main()
