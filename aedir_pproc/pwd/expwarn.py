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
FILTERSTR_USER = ur'(&(objectClass=aeUser)(aeStatus=0)(displayName=*)(mail=*))'

# Maximum timespan to search for password-less entries in the past
NOTIFY_OLDEST_TIMESPAN = 1.75 * 86400.0

# Import constants from configuration module
from aedirpwd_cnf import \
    APP_PATH_PREFIX, \
    PWD_LDAP_URL, \
    SMTP_DEBUGLEVEL, \
    SMTP_FROM, \
    SMTP_LOCALHOSTNAME, \
    SMTP_TLSARGS, \
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
        'modifiersName',
    ]
    admin_attrs = [
        'objectClass',
        'uid',
        'cn',
        'mail'
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
            self.ldap_conn.find_search_base(),
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
            (dn, int(entry['pwdMaxAge'][0]), int(entry['pwdExpireWarning'][0]))
            for dn, entry in ldap_pwdpolicy_results
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
                self.ldap_conn.find_search_base(),
                ldap0.SCOPE_SUBTREE,
                filterstr=pwd_expirywarn_filter,
                attrlist=self.user_attrs,
            )

            for ldap_dn, ldap_entry in ldap_results:
                to_addr = ldap_entry['mail'][0].decode('utf-8')
                self.logger.debug('Prepare notification for %r sent to %r', ldap_dn, to_addr)
                default_headers = (
                    ('From', SMTP_FROM),
                    ('Date', email.utils.formatdate(time.time(), True)),
                )
                user_data = {
                    'user_uid':ldap_entry['uid'][0].decode('utf-8'),
                    'user_cn':ldap_entry.get('cn', [''])[0].decode('utf-8'),
                    'user_displayname':ldap_entry.get('displayName', [''])[0].decode('utf-8'),
                    'user_description':ldap_entry.get('description', [''])[0].decode('utf-8'),
                    'emailaddr':to_addr,
                    'fromaddr':SMTP_FROM,
                    'user_dn':ldap_dn.decode('utf-8'),
                    'web_ctx_host':(WEB_CTX_HOST).decode('ascii'),
                    'app_path_prefix':APP_PATH_PREFIX,
                }
                user_data['admin_cn'] = u'unknown'
                user_data['admin_mail'] = u'unknown'
                for admin_dn_attr in ('modifiersName', 'creatorsName'):
                    try:
                        _, admin_entry = self.ldap_conn.search_s(
                            ldap_entry[admin_dn_attr][0],
                            ldap0.SCOPE_BASE,
                            filterstr=FILTERSTR_USER.encode('utf-8'),
                            attrlist=self.admin_attrs,
                        )[0]
                    except ldap0.LDAPError as ldap_err:
                        self.logger.debug(
                            'LDAPError reading %r: %r: %s',
                            admin_dn_attr,
                            ldap_entry[admin_dn_attr][0],
                            ldap_err,
                        )
                    except IndexError:
                        self.logger.debug(
                            'No real admin referenced in %r: %r',
                            admin_dn_attr,
                            ldap_entry[admin_dn_attr][0],
                        )
                    else:
                        user_data['admin_cn'] = admin_entry.get('cn', [''])[0].decode('utf-8')
                        user_data['admin_mail'] = admin_entry.get('mail', [''])[0].decode('utf-8')
                        self.logger.debug(
                            'Admin displayName read from %r: %r',
                            admin_dn_attr,
                            user_data['admin_cn'],
                        )
                        break
                pwd_expire_warning_list.append(user_data)

        self.logger.debug('pwd_expire_warning_list = %s', pwd_expire_warning_list)

        if not pwd_expire_warning_list:
            self.logger.info('No results => no notifications')
        elif USER_MAIL_ENABLED is not True:
            self.logger.info(
                'Sending e-mails is disabled => supressed %d notifications',
                len(pwd_expire_warning_list),
            )
        else:
            # Read mail template file
            with open(PWD_EXPIRYWARN_MAIL_TEMPLATE, 'rb') as template_file:
                smtp_message_tmpl = template_file.read().decode('utf-8')
            smtp_conn = self._smtp_connection(
                SMTP_URL,
                local_hostname=SMTP_LOCALHOSTNAME,
                tls_args=SMTP_TLSARGS,
                debug_level=SMTP_DEBUGLEVEL
            )
            notification_counter = 0
            for user_data in pwd_expire_warning_list:
                to_addr = user_data['emailaddr']
                smtp_message = smtp_message_tmpl.format(**user_data)
                smtp_subject = PWD_EXPIRYWARN_MAIL_SUBJECT.format(**user_data)
                self.logger.debug('smtp_subject = %r', smtp_subject)
                self.logger.debug('smtp_message = %r', smtp_message)
                try:
                    smtp_conn.send_simple_message(
                        SMTP_FROM,
                        [to_addr.encode('utf-8')],
                        'utf-8',
                        default_headers+(
                            ('Subject', smtp_subject),
                            ('To', to_addr),
                        ),
                        smtp_message,
                    )
                except smtplib.SMTPRecipientsRefused, smtp_err:
                    self.logger.error('Recipient %r rejected: %s', to_addr, smtp_err)
                    continue
                else:
                    notification_counter += 1
            self.logger.info('Sent %d notifications', notification_counter)


def main():
    with AEDIRPwdJob() as ae_process:
        ae_process.run(max_runs=1)


if __name__ == '__main__':
    main()
