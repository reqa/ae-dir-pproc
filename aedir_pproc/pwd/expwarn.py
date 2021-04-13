# -*- coding: utf-8 -*-
"""
aedir_pproc.pwd.expwarn - send password expiry warnings via e-mail
"""

# from Python's standard lib
import os
import time
from smtplib import SMTPRecipientsRefused

# from ldap0
import ldap0
import ldap0.functions

# the separate python-aedir module
import aedir.process

# Import constants from configuration module
from aedirpwd_cnf import (
    APP_PATH_PREFIX,
    SMTP_DEBUGLEVEL,
    SMTP_FROM,
    SMTP_LOCALHOSTNAME,
    SMTP_TLS_CACERTS,
    SMTP_URL,
    TEMPLATES_DIRNAME,
    USER_MAIL_ENABLED,
    WEB_CTX_HOST,
)

from ..__about__ import __version__
from . import PWD_USER_ATTRS

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

# attributes to read from pwdPolicy entries
PWDPOLICY_ATTRS = ['cn', 'pwdMaxAge', 'pwdExpireWarning']

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

    def __init__(self):
        aedir.process.AEProcess.__init__(self)
        self.notification_counter = 0

    def _get_pwd_policy_entries(self):
        """
        Search all pwdPolicy entries with expiring passwords (pwdMaxAge set)
        """
        ldap_pwdpolicy_results = self.ldap_conn.search_s(
            self.ldap_conn.search_base,
            ldap0.SCOPE_SUBTREE,
            filterstr=PWDPOLICY_FILTER,
            attrlist=PWDPOLICY_ATTRS,
        )
        if not ldap_pwdpolicy_results:
            self.logger.error('No pwdPolicy entries found => nothing to do => abort')
        pwd_policy_list = [
            (res.dn_s, int(res.entry_s['pwdMaxAge'][0]), int(res.entry_s['pwdExpireWarning'][0]))
            for res in ldap_pwdpolicy_results
        ]
        self.logger.debug('Found %d pwdPolicy entries: %s', len(pwd_policy_list), pwd_policy_list)
        return pwd_policy_list # enf of _get_pwd_policy_entries()

    def _send_password_expiry_notifications(self, current_time):
        """
        send password expiry warning e-mails
        """

        pwd_policy_list = self._get_pwd_policy_entries()
        pwd_expire_warning_list = []

        for pwd_policy, pwd_max_age, pwd_expire_warning in pwd_policy_list:
            filterstr_inputs_dict = {
                'pwdpolicy': pwd_policy,
                'pwdchangedtime_ge': ldap0.functions.strf_secs(current_time-pwd_max_age),
                'pwdchangedtime_le': ldap0.functions.strf_secs(
                    current_time-(pwd_max_age-pwd_expire_warning)
                ),
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
                attrlist=PWD_USER_ATTRS,
            )

            for res in ldap_results:
                to_addr = res.entry_s['mail'][0]
                self.logger.debug(
                    'Prepare password expiry notification for %r sent to %r',
                    res.dn_s,
                    to_addr,
                )
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

            with self.smtp_connection(
                    SMTP_URL,
                    local_hostname=SMTP_LOCALHOSTNAME,
                    ca_certs=SMTP_TLS_CACERTS,
                    debug_level=SMTP_DEBUGLEVEL,
                ) as smtp_conn:
                notified_users = []
                for user_data in pwd_expire_warning_list:
                    to_addr = user_data['emailaddr']
                    try:
                        self.send_simple_message(
                            smtp_conn,
                            SMTP_FROM,
                            to_addr,
                            PWD_EXPIRYWARN_MAIL_SUBJECT,
                            PWD_EXPIRYWARN_MAIL_TEMPLATE,
                            user_data,
                            raise_refused=True,
                        )
                    except SMTPRecipientsRefused:
                        continue
                    else:
                        notified_users.append(user_data['user_uid'])
                self.logger.info(
                    'Sent %d password expiry notifications: %s',
                    len(notified_users),
                    ', '.join(notified_users),
                )

    def run_worker(self, state):
        """
        Run the job
        """
        current_time = time.time()
        self._send_password_expiry_notifications(current_time)
        return ldap0.functions.strf_secs(current_time)
        # end of run_worker()


def main():
    """
    run the process
    """
    with AEDIRPwdJob() as ae_process:
        ae_process.run(max_runs=1)


if __name__ == '__main__':
    main()
