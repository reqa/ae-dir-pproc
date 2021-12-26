# -*- coding: ascii -*-
"""
aedir_pproc.pwd.web.views - methods views
"""

import time
import socket
import smtplib
import hashlib
import email.utils

import ldap0
import ldap0.functions
from ldap0.filter import escape_str as escape_filter
from ldap0.err import PasswordPolicyException, PasswordPolicyExpirationWarning
from ldap0.controls.ppolicy import PasswordPolicyControl
from ldap0.controls.sessiontrack import SessionTrackingControl
from ldap0.controls.sessiontrack import SESSION_TRACKING_FORMAT_OID_USERNAME
from ldap0.controls.deref import DereferenceControl
from ldap0.pw import random_string

from wtforms import Form

from flask import current_app, request, render_template
from flask.views import MethodView

import mailutil

import aedir

from . import RequestLogAdaptor
from .forms import (
    CheckPasswordForm,
    ChangePasswordForm,
    RequestPasswordResetForm,
    FinishPasswordResetForm,
    ViewUserForm,
)

USER_ATTRS = [
    'objectClass',
    'uid',
    'cn',
    'mail',
    'displayName',
    'pwdChangedTime',
    'pwdPolicySubentry',
]

PWDPOLICY_EXPIRY_ATTRS = [
    'pwdMaxAge',
    'pwdExpireWarning',
]

MSPWDRESET_ATTRS = [
    'msPwdResetAdminPw',
    'msPwdResetEnabled',
    'msPwdResetExpirationTime',
    'msPwdResetTimestamp',
]

MSPWDRESETPOLICY_ATTRS = [
    'msPwdResetAdminPwLen',
    'msPwdResetEnabled',
    'msPwdResetHashAlgorithm',
    'msPwdResetMaxAge',
    'msPwdResetPwLen',
]

# request control for dereferencing password policy entry's attributes
PWDPOLICY_DEREF_CONTROL = DereferenceControl(
    True,
    {
        'pwdPolicySubentry': [
            'pwdAllowUserChange',
            'pwdAttribute',
            'pwdMinAge',
            'pwdMinLength',
            'msPwdChangeNotification',
        ]+PWDPOLICY_EXPIRY_ATTRS+MSPWDRESETPOLICY_ATTRS,
    }
)

AEPERSON_ATTRS = [
    'aeDept',
    'aeLocation',
    'cn',
    'departmentNumber',
    'l',
    'mobile',
    'o',
    'ou',
    'street',
    'telephoneNumber',
]

# request control for dereferencing aePerson entry's attributes
VIEWUSER_DEREF_CONTROL = DereferenceControl(
    True,
    {
        'aePerson': AEPERSON_ATTRS,
        'pwdPolicySubentry': [
            'pwdAllowUserChange',
            'pwdAttribute',
            'pwdMinAge',
            'pwdMinLength',
        ]+PWDPOLICY_EXPIRY_ATTRS+MSPWDRESETPOLICY_ATTRS,
    },
)

#-----------------------------------------------------------------------
# utility functions
#-----------------------------------------------------------------------

HASH_OID2NAME = {
    '1.2.840.113549.2.5':'md5',        # [RFC3279]
    '1.3.14.3.2.26':'sha1',            # [RFC3279]
    '2.16.840.1.101.3.4.2.4':'sha224', # [RFC4055]
    '2.16.840.1.101.3.4.2.1':'sha256', # [RFC4055]
    '2.16.840.1.101.3.4.2.2':'sha384', # [RFC4055]
    '2.16.840.1.101.3.4.2.3':'sha512', # [RFC4055]
}

def pwd_hash(pw_clear, hash_algo_oid):
    """
    Generate un-salted hash as hex-digest
    """
    return hashlib.new(
        HASH_OID2NAME[hash_algo_oid],
        pw_clear.encode('utf-8'),
    ).hexdigest()

def read_template_file(filename):
    """
    return UTF-8 encoded text file as decoded Unicode string
    """
    with open(filename, 'rb') as file_obj:
        file_content = file_obj.read().decode('utf-8')
    return file_content


#-----------------------------------------------------------------------
# The web application
#-----------------------------------------------------------------------

class Default(MethodView):
    """
    Handle default index request
    """

    def __init__(self, *args, **kwargs):
        MethodView.__init__(self, *args, **kwargs)
        self.logger = RequestLogAdaptor(
            current_app.logger,
            {
                'remote_ip': request.remote_addr,
                'req_class': '.'.join((self.__class__.__module__, self.__class__.__name__)),
                'req_id': id(request),
            }
        )
        self.logger.debug(
            '%s request from %s (via %s)',
            request.method,
            request.remote_addr,
            '>'.join(request.access_route),
        )
        self.form = None
        self.ldap_url = aedir.AEDirUrl(current_app.config['PWD_LDAP_URL'])
        self.ldap_conn = None
        self.user_ldap_conn = None

    def get(self):
        """
        Simply display the entry landing page
        """
        return render_template('default.html')


class BaseApp(Default):
    """
    Request handler base class which is not used directly
    """

    post_form = Form

    def __init__(self, *args, **kwargs):
        Default.__init__(self, *args, **kwargs)
        self.filterstr_template = '(|)'

    def _sess_track_ctrl(self):
        """
        return LDAPv3 session tracking control representing current user
        """
        return SessionTrackingControl(
            request.remote_addr,
            request.host,
            SESSION_TRACKING_FORMAT_OID_USERNAME,
            str(id(self)),
        )

    def search_user_entry(self, inputs):
        """
        Search a user entry for the user specified by username
        """
        filterstr_inputs_dict = {
            'currenttime': escape_filter(ldap0.functions.strf_secs(time.time())),
        }
        for key, value in inputs.items():
            filterstr_inputs_dict[key] = escape_filter(value)
        filterstr = (
            self.filterstr_template.format(**filterstr_inputs_dict)
        )
        self.logger.debug(
            '.search_user_entry() base=%r filterstr=%r',
            self.ldap_conn.ldap_url_obj.dn,
            filterstr,
        )
        try:
            user = self.ldap_conn.find_unique_entry(
                self.ldap_conn.ldap_url_obj.dn,
                ldap0.SCOPE_SUBTREE,
                filterstr=filterstr,
                attrlist=USER_ATTRS+MSPWDRESET_ATTRS,
                req_ctrls=[PWDPOLICY_DEREF_CONTROL],
            )
        except ldap0.LDAPError as ldap_err:
            self.logger.warning(
                '.search_user_entry() search failed: %s',
                ldap_err,
            )
            raise
        if user.ctrls:
            user.entry_b.update(
                user.ctrls[0].derefRes['pwdPolicySubentry'][0].entry_b
            )
        self.logger.debug('.search_user_entry() returns %r', user.dn_s, user.entry_s)
        return user.dn_s, user.entry_s
        # end of BaseApp.search_user_entry()

    @staticmethod
    def smtp_conn():
        """
        opens and returns SMTP connection object
        """
        return mailutil.smtp_connection(
            current_app.config['SMTP_URL'],
            local_hostname=current_app.config['SMTP_LOCALHOSTNAME'],
            ca_certs=current_app.config['SMTP_TLS_CACERTS'],
            debug_level=current_app.config['SMTP_DEBUGLEVEL'],
        )

    def _send_changepw_notification(self, username, user_dn, user_entry):
        """
        send e-mail to user to notify about a password change
        """
        notification_enabled = user_entry.get(
            'msPwdChangeNotification',
            [str(current_app.config['CHANGEPW_NOTIFICATION_ENABLED'])]
        )[0].upper() == 'TRUE'
        if not notification_enabled:
            self.logger.debug('Notification for password change disabled => no e-mail')
            return
        default_headers = (
            ('From', current_app.config['SMTP_FROM']),
            ('Date', email.utils.formatdate(time.time(), True)),
        )

        with self.smtp_conn() as smtp_conn:
            to_addr = user_entry['mail'][0]
            user_data = {
                'username': username,
                'remote_ip': request.remote_addr,
                'userdn': user_dn,
                'web_ctx_host': request.host,
                'app_path_prefix': current_app.config['APPLICATION_ROOT'],
            }
            smtp_message = read_template_file(
                current_app.config['EMAIL_TEMPLATE_NOTIFICATION']
            ).format(**user_data)
            smtp_subject = current_app.config['EMAIL_SUBJECT_NOTIFICATION'].format(**user_data)
            smtp_conn.send_simple_message(
                current_app.config['SMTP_FROM'],
                [to_addr],
                'utf-8',
                default_headers+(
                    ('Subject', smtp_subject),
                    ('To', to_addr),
                ),
                smtp_message,
            )
            self.logger.info('Sent change notification to %s', to_addr)

        # end of BaseApp._send_pw_change_notification()

    def _open_ldap_conn(self):
        """
        Open LDAP connection
        """
        try:
            self.ldap_conn = aedir.AEDirObject(current_app.config['PWD_LDAP_URL'], trace_level=0)
        except ldap0.LDAPError as ldap_err:
            self.logger.error(
                'Error connecting to %r: %s',
                current_app.config['PWD_LDAP_URL'],
                ldap_err,
            )
            raise
        self.logger.debug(
            'Successfully bound to %r as %r',
            self.ldap_conn.ldap_url_obj.connect_uri(),
            self.ldap_conn.whoami_s(),
        )
        # end of BaseApp._open_ldap_conn()

    def _close_ldap_conn(self):
        """
        Close LDAP connection
        """
        self.logger.debug(
            'Unbind from %r',
            self.ldap_conn.ldap_url_obj.connect_uri(),
        )
        try:
            self.ldap_conn.unbind_s()
        except (AttributeError, ldap0.LDAPError) as ldap_err:
            self.logger.warning(
                'Error during unbinding from %r: %s',
                self.ldap_conn.ldap_url_obj.connect_uri(),
                ldap_err,
            )
        # end of BaseApp._close_ldap_conn()

    def handle_user_request(self, user_dn, user_entry):
        """
        nothing to be done herein
        """
        raise NotImplementedError

    def post(self):
        """
        handle POST request processing input form

        mainly this opens and binds LDAP connection for user
        """
        self.form = self.post_form(request.form, csrf_enabled=False)
        if not self.form.validate():
            self.logger.error(
                'Input form data not valid (%s): %s',
                self.form.__class__.__name__,
                self.form.errors,
            )
            self.logger.error(
                'Invalid form data: %s',
                self.form.data,
            )
            return render_template('error.html', message='Invalid input!')
        try:
            self._open_ldap_conn()
        except ldap0.LDAPError as ldap_err:
            self.logger.error(
                'LDAPError connecting to %r: %s',
                self.ldap_url.connect_uri(),
                ldap_err,
            )
            return render_template('error.html', message='Internal error!')
        try:
            # search user entry
            user_dn, user_entry = self.search_user_entry({
                field.name: field.data
                for field in self.form
                if isinstance(field.data, str) and field.data
            })
        except ValueError as err:
            self.logger.warning('Invalid input: %s', err)
            res = render_template('error.html', message='Invalid input!')
        except ldap0.LDAPError:
            res = render_template('error.html', message='Searching the user account failed!')
        else:
            # Call specific handler for LDAP user
            res = self.handle_user_request(user_dn, user_entry)
        self._close_ldap_conn()
        return res
        # end of BaseApp.POST()


class CheckPassword(BaseApp):
    """
    Handler for checking user's password
    """

    post_form = CheckPasswordForm

    def __init__(self, *args, **kwargs):
        BaseApp.__init__(self, *args, **kwargs)
        self.filterstr_template = current_app.config['FILTERSTR_CHANGEPW']

    def get(self):
        """
        handle GET request by returning input form
        with username pre-filled
        """
        return render_template(
            'checkpw_form.html',
            username=request.args.get('username', ''),
            message='',
        )

    def handle_user_request(self, user_dn, user_entry):
        """
        check the user password with simple bind request and
        display password expiry information
        """
        current_time = time.time()
        try:
            self.ldap_conn.simple_bind_s(
                user_dn,
                self.form.password.data.encode('utf-8'),
                req_ctrls=[
                    PasswordPolicyControl(),
                    self._sess_track_ctrl(),
                ]
            )
        except ldap0.INVALID_CREDENTIALS as ldap_err:
            self.logger.warning(
                'Binding as %r failed: %s',
                user_dn,
                ldap_err,
            )
            return render_template(
                'checkpw_form.html',
                username=self.form.username.data,
                message='Wrong password!',
            )
        except PasswordPolicyExpirationWarning as ppolicy_error:
            expire_time_str = time.strftime(
                current_app.config['TIME_DISPLAY_FORMAT'],
                time.localtime(current_time+ppolicy_error.timeBeforeExpiration)
            )
            self.logger.info(
                'Password of %r will expire soon at %r (%d seconds)',
                user_dn,
                expire_time_str,
                ppolicy_error.timeBeforeExpiration,
            )
            return render_template(
                'changepw_form.html',
                username=self.form.username.data,
                message='Password will expire soon at {0}. Change it now!'.format(expire_time_str),
            )
        except PasswordPolicyException as ppolicy_error:
            self.logger.warning('Password policy error: %s', ppolicy_error)
            return render_template(
                'changepw_form.html',
                username=self.form.username.data,
                message=str(ppolicy_error),
            )
        except ldap0.LDAPError as ldap_err:
            self.logger.warning(
                'LDAP error checking password of %r: %s',
                user_dn,
                ldap_err,
            )
            return render_template('error.html', message='Internal error!')
        # Try to display until when password is still valid
        try:
            pwd_max_age = int(user_entry['pwdMaxAge'][0])
        except (ValueError, KeyError):
            valid_until = 'unknown'
        else:
            pwd_changed_timestamp = ldap0.functions.strp_secs(user_entry['pwdChangedTime'][0])
            expire_timestamp = pwd_changed_timestamp+pwd_max_age
            valid_until = time.strftime(
                current_app.config['TIME_DISPLAY_FORMAT'],
                time.localtime(expire_timestamp)
            )
            self.logger.info(
                'User %r checked own password, valid until %s.',
                user_dn,
                valid_until,
            )
        # Finally render output page with success message
        return render_template(
            'checkpw_action.html',
            username=self.form.username.data,
            userdn=user_dn,
            valid_until=valid_until,
        )


class ChangePassword(BaseApp):
    """
    Handler for changing user's own password
    """

    post_form = ChangePasswordForm

    def __init__(self, *args, **kwargs):
        BaseApp.__init__(self, *args, **kwargs)
        self.filterstr_template = current_app.config['FILTERSTR_CHANGEPW']

    def get(self):
        """
        handle GET request by returning input form
        with username pre-filled
        """
        return render_template(
            'changepw_form.html',
            username=request.args.get('username', ''),
            message='',
        )

    def _check_pw_input(self, user_entry):
        if self.form.newpassword1.data != self.form.newpassword2.data:
            return 'New password values differ!'
        if 'pwdMinLength' in user_entry:
            pwd_min_len = int(user_entry['pwdMinLength'][0])
            if len(self.form.newpassword1.data) < pwd_min_len:
                self.logger.warning(
                    'Password of %r not long enough, only got %d chars.',
                    user_entry['uid'][0],
                    len(self.form.newpassword1.data),
                )
                return 'New password must be at least %d characters long!' % (pwd_min_len)
        if 'pwdChangedTime' in user_entry and 'pwdMinAge' in user_entry:
            pwd_changed_timestamp = ldap0.functions.strp_secs(user_entry['pwdChangedTime'][0])
            pwd_min_age = int(user_entry['pwdMinAge'][0])
            next_pwd_change_timespan = pwd_changed_timestamp + pwd_min_age - time.time()
            if next_pwd_change_timespan > 0:
                self.logger.warning('Password of %r is too young to change!', user_entry['uid'][0])
                return 'Password is too young to change! You can try again after %d secs.' % (
                    next_pwd_change_timespan
                )
        return None
        # end of ChangePassword._check_pw_input()

    def handle_user_request(self, user_dn, user_entry):
        """
        set new password
        """
        pw_input_check_msg = self._check_pw_input(user_entry)
        if not pw_input_check_msg is None:
            return render_template(
                'changepw_form.html',
                username=self.form.username.data,
                message=pw_input_check_msg,
            )
        try:
            self.ldap_conn.simple_bind_s(
                user_dn,
                self.form.password.data.encode('utf-8'),
                req_ctrls=[self._sess_track_ctrl()],
            )
            self.ldap_conn.passwd_s(
                user_dn,
                None,
                self.form.newpassword1.data.encode('utf-8'),
                req_ctrls=[self._sess_track_ctrl()],
            )
        except ldap0.INVALID_CREDENTIALS as ldap_err:
            self.logger.warning('Old password of %r wrong: %s', user_dn, ldap_err)
            res = render_template(
                'changepw_form.html',
                username=self.form.username.data,
                message='Old password wrong!',
            )
        except ldap0.CONSTRAINT_VIOLATION as ldap_err:
            self.logger.warning('Changing password of %r failed: %s', user_dn, ldap_err)
            res = render_template(
                'changepw_form.html',
                username=self.form.username.data,
                message='Password rules violation: {0}'.format(
                    ldap_err.args[0]['info'].decode('utf-8'),
                ),
            )
        except ldap0.LDAPError as ldap_err:
            self.logger.warning('LDAP error: %s', ldap_err)
            res = render_template('error.html', message='Internal error!')
        else:
            self._send_changepw_notification(self.form.username.data, user_dn, user_entry)
            self.logger.info('User %r changed own password.', user_dn)
            res = render_template(
                'changepw_action.html',
                username=self.form.username.data,
                userdn=user_dn,
                ldap_uri=self.ldap_conn.ldap_url_obj.connect_uri(),
            )
        return res
        # end of ChangePassword.handle_user_request()


class RequestPasswordReset(BaseApp):
    """
    Handler for starting password reset procedure
    """

    # Declaration for the change password input form
    post_form = RequestPasswordResetForm

    def __init__(self, *args, **kwargs):
        BaseApp.__init__(self, *args, **kwargs)
        self.filterstr_template = current_app.config['FILTERSTR_REQUESTPW']

    def get(self):
        """
        handle GET request by returning input form
        with username pre-filled
        """
        return render_template(
            'requestpw_form.html',
            username=request.args.get('username', ''),
            message='',
        )

    def _get_admin_mailaddrs(self, user_dn):
        try:
            ldap_results = self.ldap_conn.get_zoneadmins(
                user_dn,
                attrlist=['mail'],
                suppl_filter='(mail=*)',
            )
        except ldap0.LDAPError:
            admin_addrs = None
        else:
            admin_addrs = [
                res.entry_s['mail'][0]
                for res in ldap_results or []
            ]
        return sorted(set(admin_addrs or current_app.config['PWD_ADMIN_MAILTO']))
        # end of RequestPasswordReset._get_admin_mailaddrs()

    def _send_pw(self, username, user_dn, user_entry, temp_pwd_clear):
        """
        send e-mails to user and zone-admins
        """
        default_headers = (
            ('From', current_app.config['SMTP_FROM']),
            ('Date', email.utils.formatdate(time.time(), True)),
        )
        pwd_admin_len = int(
            user_entry.get(
                'msPwdResetAdminPwLen',
                [str(current_app.config['PWD_ADMIN_LEN'])]
            )[0]
        )

        with self.smtp_conn() as smtp_conn:

            if pwd_admin_len:
                # First send notification to admin
                #---------------------------------
                user_data_admin = {
                    'username': username,
                    'temppassword2': temp_pwd_clear[len(temp_pwd_clear)-pwd_admin_len:],
                    'remote_ip': request.remote_addr,
                    'fromaddr': current_app.config['SMTP_FROM'],
                    'userdn': user_dn,
                    'userdispname': user_entry['displayName'][0],
                    'web_ctx_host': request.host,
                    'app_path_prefix': current_app.config['APPLICATION_ROOT'],
                    'ldap_uri': self.ldap_conn.ldap_url_obj.connect_uri(),
                }
                smtp_message = read_template_file(
                    current_app.config['EMAIL_TEMPLATE_ADMIN']
                ).format(**user_data_admin)
                smtp_subject = current_app.config['EMAIL_SUBJECT_ADMIN'].format(**user_data_admin)
                admin_addrs = self._get_admin_mailaddrs(user_dn)
                admin_to = ','.join(sorted(admin_addrs))
                smtp_conn.send_simple_message(
                    current_app.config['SMTP_FROM'],
                    admin_addrs,
                    'utf-8',
                    default_headers+(
                        ('Subject', smtp_subject),
                        ('To', admin_to),
                    ),
                    smtp_message,
                )
                self.logger.info('Sent password reset admin notification to %s', admin_to)
            else:
                admin_addrs = []

            # Now send (rest of) clear-text password to user
            #-----------------------------------------------
            to_addr = user_entry['mail'][0]
            user_data_user = {
                'username': username,
                'temppassword1': temp_pwd_clear[:len(temp_pwd_clear)-pwd_admin_len],
                'remote_ip': request.remote_addr,
                'fromaddr': current_app.config['SMTP_FROM'],
                'userdn': user_dn,
                'web_ctx_host': request.host,
                'app_path_prefix': current_app.config['APPLICATION_ROOT'],
                'ldap_uri': self.ldap_conn.ldap_url_obj.connect_uri(),
                'admin_email_addrs': '\n'.join(admin_addrs),
            }
            smtp_message = read_template_file(
                current_app.config['EMAIL_TEMPLATE_PERSONAL']
            ).format(**user_data_user)
            smtp_subject = current_app.config['EMAIL_SUBJECT_PERSONAL'].format(**user_data_user)
            smtp_conn.send_simple_message(
                current_app.config['SMTP_FROM'],
                [to_addr],
                'utf-8',
                default_headers+(
                    ('Subject', smtp_subject),
                    ('To', to_addr),
                ),
                smtp_message,
            )
            self.logger.info('Sent reset password to %s', to_addr)

        # end of RequestPasswordReset._send_pw()

    def handle_user_request(self, user_dn, user_entry):
        """
        add password reset object class and attributes
        to user's entry and send e-mails
        """
        current_time = time.time()
        temp_pwd_len = int(
            user_entry.get(
                'msPwdResetPwLen',
                [str(current_app.config['PWD_LENGTH'])]
            )[0]
        )
        pwd_admin_len = int(
            user_entry.get(
                'msPwdResetAdminPwLen',
                [str(current_app.config['PWD_ADMIN_LEN'])]
            )[0]
        )
        temp_pwd_clear = random_string(current_app.config['PWD_TMP_CHARS'], temp_pwd_len)
        temp_pwd_hash = pwd_hash(
            temp_pwd_clear,
            user_entry.get(
                'msPwdResetHashAlgorithm',
                [current_app.config['PWD_TMP_HASH_ALGO']]
            )[0],
        )
        pwd_expire_timespan = int(
            user_entry.get(
                'msPwdResetMaxAge',
                [str(current_app.config['PWD_EXPIRETIMESPAN'])]
            )[0]
        )
        ldap_mod_list = [
            (ldap0.MOD_REPLACE, b'msPwdResetPasswordHash', [temp_pwd_hash.encode('ascii')]),
            (
                ldap0.MOD_REPLACE,
                b'msPwdResetTimestamp',
                [ldap0.functions.strf_secs(current_time).encode('ascii')]
            ),
            (
                ldap0.MOD_REPLACE,
                b'msPwdResetExpirationTime',
                [ldap0.functions.strf_secs(current_time+pwd_expire_timespan).encode('ascii')],
            ),
            (
                ldap0.MOD_REPLACE,
                b'msPwdResetEnabled',
                [
                    user_entry.get(
                        'msPwdResetEnabled',
                        [current_app.config['PWD_RESET_ENABLED']]
                    )[0].encode('ascii')
                ],
            ),
        ]
        old_objectclasses = [
            oc.lower()
            for oc in user_entry['objectClass']
        ]
        if not 'mspwdresetobject' in old_objectclasses:
            ldap_mod_list.append((ldap0.MOD_ADD, b'objectClass', [b'msPwdResetObject']))
        if pwd_admin_len:
            ldap_mod_list.append(
                (
                    ldap0.MOD_REPLACE,
                    b'msPwdResetAdminPw',
                    [temp_pwd_clear[-pwd_admin_len:].encode('utf-8')],
                )
            )
        try:
            self.ldap_conn.modify_s(
                user_dn,
                ldap_mod_list,
                req_ctrls=[self._sess_track_ctrl()],
            )
        except ldap0.LDAPError:
            res = render_template('error.html', message='Internal error!')
        else:
            try:
                self._send_pw(
                    self.form.username.data,
                    user_dn,
                    user_entry,
                    temp_pwd_clear,
                )
            except (socket.error, socket.gaierror, smtplib.SMTPException) as mail_error:
                self.logger.error(
                    'Error sending reset e-mail to user %r: %s',
                    self.form.username.data,
                    mail_error,
                )
                res = render_template(
                    'requestpw_form.html',
                    username=self.form.username.data,
                    message='Error sending e-mail via SMTP!',
                )
            else:
                res = render_template(
                    'requestpw_action.html',
                    username=self.form.username.data,
                    email=self.form.email.data,
                    userdn=user_dn,
                    message='',
                )
        return res
        # end of .handle_user_request()


class FinishPasswordReset(ChangePassword):
    """
    Handler for finishing password reset procedure
    """

    post_form = FinishPasswordResetForm

    def __init__(self, *args, **kwargs):
        ChangePassword.__init__(self, *args, **kwargs)
        self.filterstr_template = '(&(msPwdResetEnabled=TRUE)%s)' % (
            current_app.config['FILTERSTR_RESETPW']
        )

    def get(self):
        """
        handle GET request by returning input form with username and
        1st temporary password part pre-filled
        """
        try:
            self._open_ldap_conn()
        except ldap0.LDAPError:
            return render_template('error.html', message='Internal LDAP error!')
        try:
            _, user_entry = self.search_user_entry({'username': request.args['username']})
        except ldap0.LDAPError:
            return render_template('error.html', message='Error searching user!')
        self._close_ldap_conn()
        pwd_admin_len = int(
            user_entry.get(
                'msPwdResetAdminPwLen',
                [str(current_app.config['PWD_ADMIN_LEN'])]
            )[0]
        )
        return render_template(
            'resetpw_form.html',
            username=request.args.get('username', ''),
            pwd_admin_len=pwd_admin_len,
            temppassword1=request.args.get('temppassword1', ''),
            message='',
        )
        # end of FinishPasswordReset.GET()

    def _ldap_user_operations(self, user_dn, user_entry, temp_pwd_hash, new_password_ldap):
        pwd_admin_len = int(
            user_entry.get(
                'msPwdResetAdminPwLen',
                [str(current_app.config['PWD_ADMIN_LEN'])]
            )[0]
        )
        ldap_mod_list = [
            (ldap0.MOD_DELETE, attr_type.encode('ascii'), attr_values)
            for attr_type, attr_values in (
                ('objectClass', [b'msPwdResetObject']),
                ('msPwdResetPasswordHash', [temp_pwd_hash.encode('ascii')]),
                ('msPwdResetTimestamp', None),
                ('msPwdResetExpirationTime', None),
                ('msPwdResetEnabled', None),
            )
        ]
        if pwd_admin_len:
            ldap_mod_list.append(
                (ldap0.MOD_DELETE, b'msPwdResetAdminPw', None)
            )
        try:
            self.ldap_conn.modify_s(
                user_dn,
                ldap_mod_list,
                req_ctrls=[self._sess_track_ctrl()],
            )
        except ldap0.LDAPError as ldap_err:
            self.logger.warning(
                'Modifying entry %r failed: %s',
                user_dn,
                ldap_err,
            )
            raise
        try:
            self.ldap_conn.passwd_s(
                user_dn,
                None,
                new_password_ldap,
                req_ctrls=[self._sess_track_ctrl()],
            )
        except ldap0.LDAPError as ldap_err:
            self.logger.warning(
                'passwd_s() failed for %r: %s',
                user_dn,
                ldap_err,
            )
            raise
        # end of FinishPasswordReset._ldap_user_operations()

    def handle_user_request(self, user_dn, user_entry):
        """
        set new password if temporary reset password matches
        """
        temppassword1 = self.form.temppassword1.data
        temppassword2 = self.form.temppassword2.data
        pwd_admin_len = int(
            user_entry.get(
                'msPwdResetAdminPwLen',
                [str(current_app.config['PWD_ADMIN_LEN'])]
            )[0]
        )
        temp_pwd_hash = pwd_hash(
            ''.join((temppassword1, temppassword2)),
            user_entry.get('msPwdResetHashAlgorithm', [current_app.config['PWD_TMP_HASH_ALGO']])[0],
        )
        pw_input_check_msg = self._check_pw_input(user_entry)
        if not pw_input_check_msg is None:
            return render_template(
                'resetpw_form.html',
                username=self.form.username.data,
                pwd_admin_len=pwd_admin_len,
                temppassword1=self.form.temppassword1.data,
                message=pw_input_check_msg,
            )
        try:
            self._ldap_user_operations(
                user_dn,
                user_entry,
                temp_pwd_hash,
                self.form.newpassword1.data.encode('utf-8'),
            )
        except ldap0.NO_SUCH_ATTRIBUTE:
            self.logger.warning('Temporary password of %r wrong!', user_dn)
            res = render_template(
                'resetpw_form.html',
                username=self.form.username.data,
                pwd_admin_len=pwd_admin_len,
                temppassword1=self.form.temppassword1.data,
                message='Temporary password wrong!',
            )
        except ldap0.CONSTRAINT_VIOLATION as ldap_err:
            self.logger.warning(
                'Password constraints for %r violated: %s',
                user_dn,
                ldap_err,
            )
            res = render_template(
                'requestpw_form.html',
                username=self.form.username.data,
                message=(
                    'Constraint violation (password rules): {0}'
                    ' / You have to request password reset again!'
                ).format(ldap_err.args[0]['info'].decode('utf-8'))
            )
        except ldap0.LDAPError:
            res = render_template('error.html', message='Internal error!')
        else:
            self._send_changepw_notification(self.form.username.data, user_dn, user_entry)
            self.logger.info('Password reset completed for %r.', user_dn)
            res = render_template(
                'resetpw_action.html',
                username=self.form.username.data,
                userdn=user_dn,
                message='',
            )
        return res
        # end of FinishPasswordReset.handle_user_request()


class ViewUser(BaseApp):
    """
    Handler for viewing user entry with contact information
    and 2nd reset password part
    """

    post_form = ViewUserForm

    def __init__(self, *args, **kwargs):
        BaseApp.__init__(self, *args, **kwargs)
        self.filterstr_template = current_app.config['FILTERSTR_CHANGEPW']

    def get(self):
        """
        handle GET request by returning input form
        with username pre-filled
        """
        return render_template(
            'viewuser_form.html',
            username=request.args.get('username', ''),
            othername=request.args.get('othername', ''),
            message='',
        )

    def handle_user_request(self, user_dn, user_entry):
        """
        set new password
        """
        try:
            self.ldap_conn.simple_bind_s(
                user_dn,
                self.form.password.data.encode('utf-8'),
                req_ctrls=[self._sess_track_ctrl()],
            )
            other = self.ldap_conn.find_unique_entry(
                self.ldap_conn.ldap_url_obj.dn,
                ldap0.SCOPE_SUBTREE,
                filterstr=current_app.config['FILTERSTR_CHANGEPW'].format(
                    username=escape_filter(self.form.othername.data),
                ),
                attrlist=USER_ATTRS+MSPWDRESET_ATTRS,
                req_ctrls=[VIEWUSER_DEREF_CONTROL, self._sess_track_ctrl(),],
            )
            if other.ctrls:
                for deref_attr in ('aePerson', 'pwdPolicySubentry'):
                    if deref_attr in other.ctrls[0].derefRes:
                        other.entry_b.update(
                            other.ctrls[0].derefRes[deref_attr][0].entry_b
                        )
            self.logger.debug('Found %r: %r', other.dn_s, other.entry_s)
        except ldap0.INVALID_CREDENTIALS as ldap_err:
            self.logger.warning('Password of %r wrong: %s', user_dn, ldap_err)
            res = render_template(
                'viewuser_form.html',
                username=self.form.username.data,
                othername=self.form.othername.data,
                message='Admin password wrong!',
            )
        except ldap0.LDAPError as ldap_err:
            self.logger.warning('LDAP error: %s', ldap_err)
            res = render_template('error.html', message='Internal error!')
        else:
            self.logger.debug(
                'Show user %r (%r) to %r.',
                self.form.othername.data,
                other.dn_s,
                self.form.username.data,
            )
            res = render_template(
                'viewuser_action.html',
                displayname=other.entry_s['displayName'][0],
                resetpending='msPwdResetObject' in other.entry_s['objectClass'],
                resetpassword=other.entry_s.get('msPwdResetAdminPw', [None])[0],
                resetexpiration=other.entry_s.get('msPwdResetExpirationTime', [None])[0],
                resetentry={
                    at: avs[0]
                    for at, avs in other.entry_s.items()
                },
            )
        return res
        # end of ViewUser.handle_user_request()
