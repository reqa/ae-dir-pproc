# -*- coding: utf-8 -*-
"""
aedir_pproc.pwd.web - AE-DIR password self-service web application
"""

from __future__ import absolute_import

from ..__about__ import __version__, __author__, __license__

# from Python's standard lib
import re
import sys
import os
import time
import socket
import smtplib
import hashlib

from urllib.parse import quote_plus as url_quote_plus

import email.utils

# web.py
import web

# from ldap0 package
import ldap0
import ldap0.functions
import ldap0.filter
from ldap0.err import PasswordPolicyException, PasswordPolicyExpirationWarning
from ldap0.controls.ppolicy import PasswordPolicyControl
from ldap0.controls.sessiontrack import SessionTrackingControl
from ldap0.controls.sessiontrack import SESSION_TRACKING_FORMAT_OID_USERNAME
from ldap0.controls.deref import DereferenceControl
from ldap0.pw import random_string

# mail utility module
import mailutil

# AE-DIR module
import aedir

# Import constants from configuration module
from aedirpwd_cnf import \
    PWD_LDAP_URL, WEB_CONFIG_DEBUG, WEB_ERROR, \
    APP_PATH_PREFIX, LAYOUT, TEMPLATES_DIRNAME, \
    EMAIL_SUBJECT_ADMIN, EMAIL_SUBJECT_PERSONAL, EMAIL_TEMPLATE_ADMIN, \
    EMAIL_TEMPLATE_PERSONAL, TIME_DISPLAY_FORMAT, \
    FILTERSTR_CHANGEPW, FILTERSTR_REQUESTPW, FILTERSTR_RESETPW, \
    PWD_ADMIN_LEN, PWD_ADMIN_MAILTO, PWD_EXPIRETIMESPAN, PWD_LENGTH, \
    PWD_RESET_ENABLED, PWD_TMP_CHARS, PWD_TMP_HASH_ALGO, \
    SMTP_DEBUGLEVEL, SMTP_FROM, SMTP_LOCALHOSTNAME, SMTP_TLSARGS, SMTP_URL

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
        'pwdPolicySubentry':[
            'pwdAllowUserChange',
            'pwdAttribute',
            'pwdMinAge',
            'pwdMinLength',
        ]+PWDPOLICY_EXPIRY_ATTRS+MSPWDRESETPOLICY_ATTRS,
    }
)

# initialize a custom logger
APP_LOGGER = aedir.init_logger(
    log_name=os.path.basename(sys.argv[0]),
)

# Mapping of request URL path to Python handler class
URL2CLASS_MAPPING = (
    '/', 'Default',
    '/checkpw', 'CheckPassword',
    '/changepw', 'ChangePassword',
    '/requestpw', 'RequestPasswordReset',
    '/resetpw', 'FinishPasswordReset',
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

RENDER = web.template.render(TEMPLATES_DIRNAME, base=LAYOUT)

# Safety check for URL chars
if PWD_TMP_CHARS != url_quote_plus(PWD_TMP_CHARS):
    raise ValueError('URL special chars in PWD_TMP_CHARS: %r' % (PWD_TMP_CHARS))

# Set some webpy configuration vars
if not WEB_CONFIG_DEBUG:
    web.config.debug = False

# Declaration for text input field for 'username'
USERNAME_FIELD = web.form.Textbox(
    'username',
    web.form.notnull,
    web.form.regexp('^[a-zA-Z0-9._-]+$', u'Invalid user name.'),
    description=u'User name:'
)

# Declaration for text input field for 'email'
EMAIL_FIELD = web.form.Textbox(
    'email',
    web.form.notnull,
    web.form.regexp(
        r'^[a-zA-Z0-9@.+=/_ -]+@[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*$',
        u'Invalid e-mail address.'
    ),
    description=u'E-mail address:'
)

# Declaration for text input field for old password
USERPASSWORD_FIELD = web.form.Password(
    'oldpassword',
    web.form.notnull,
    web.form.regexp(r'^.*$', u''),
    description=u'Old password'
)

TEMP1PASSWORD_FIELD = web.form.Password(
    'temppassword1',
    web.form.notnull,
    web.form.regexp(
        u'^[%s]+$' % (re.escape(PWD_TMP_CHARS),),
        u'Invalid input format.'
    ),
    description=u'Temporary password part #1'
)

TEMP2PASSWORD_FIELD = web.form.Password(
    'temppassword2',
    #web.form.notnull,
    web.form.regexp(
        r'^[%s]*$' % (re.escape(PWD_TMP_CHARS),),
        u'Invalid input format.'
    ),
    description=u'Temporary password part #2'
)

# Declarations for new password fields

VALID_NEWPASSWORD_REGEXP = web.form.regexp(r'^.+$', u'Passwort rules violated!')

NEWPASSWORD1_FIELD = web.form.Password(
    'newpassword1',
    web.form.notnull,
    VALID_NEWPASSWORD_REGEXP,
    description=u'New password'
)

NEWPASSWORD2_FIELD = web.form.Password(
    'newpassword2',
    web.form.notnull,
    VALID_NEWPASSWORD_REGEXP,
    description=u'New password (repeat)'
)


def add_http_headers():
    """
    Add more HTTP headers to response
    """
    csp_value = ' '.join((
        "child-src 'none';",
        "connect-src 'none';",
        "default-src 'none';",
        "font-src 'self';",
        "form-action 'self';",
        "frame-ancestors 'none';",
        "frame-src 'none';",
        "img-src 'self' data:;",
        "script-src 'none';",
        "style-src 'self';",
    ))
    for header, value in (
            ('Cache-Control', 'no-store,no-cache,max-age=0,must-revalidate'),
            ('X-XSS-Protection', '1; mode=block'),
            ('X-DNS-Prefetch-Control', 'off'),
            ('X-Content-Type-Options', 'nosniff'),
            ('X-Frame-Options', 'deny'),
            ('Server', 'unknown'),
            ('Content-Security-Policy', csp_value),
            ('X-Webkit-CSP', csp_value),
            ('X-Content-Security-Policy', csp_value),
            ('Referrer-Policy', 'same-origin'),
        ):
        web.header(header, value)
    return # end of add_http_headers()


class Default(object):
    """
    Handle default index request
    """
    ldap_url = aedir.AEDirUrl(PWD_LDAP_URL)
    logger = APP_LOGGER

    def __init__(self):
        self.remote_ip = web.ctx.env.get(
            'FORWARDED_FOR',
            web.ctx.env.get('HTTP_X_FORWARDED_FOR', web.ctx.ip)
        )
        self.logger.debug(
            '%s() %s request from %s (via %s)',
            self.__class__.__name__,
            web.ctx.env['REQUEST_METHOD'],
            self.remote_ip,
            web.ctx.ip,
        )
        add_http_headers()
        self.ldap_conn = None
        self.form = None
        return # end of __init__()

    def GET(self):
        """
        handle GET request by returning default entry page
        """
        return RENDER.default()


class BaseApp(Default):
    """
    Request handler base class which is not used directly
    """
    post_form = web.form.Form()
    get_form = web.form.Form(USERNAME_FIELD)
    logger = APP_LOGGER
    filterstr_template = '(|)'

    def _sess_track_ctrl(self, username='-/-'):
        """
        return LDAPv3 session tracking control representing current user
        """
        return SessionTrackingControl(
            self.remote_ip,
            web.ctx.homedomain,
            SESSION_TRACKING_FORMAT_OID_USERNAME,
            username,
        )

    def search_user_entry(self, inputs):
        """
        Search a user entry for the user specified by username
        """
        filterstr_inputs_dict = {
            'currenttime': ldap0.filter.escape_str(ldap0.functions.strf_secs(time.time())),
        }
        for key, value in inputs.items():
            filterstr_inputs_dict[key] = ldap0.filter.escape_str(value)
        filterstr = (
            self.filterstr_template.format(**filterstr_inputs_dict)
        )
        self.logger.debug(
            '%s.search_user_entry() base=%r filterstr=%r',
            self.__class__.__name__,
            self.ldap_conn.ldap_url_obj.dn,
            filterstr,
        )
        try:
            user = self.ldap_conn.find_unique_entry(
                self.ldap_conn.ldap_url_obj.dn,
                ldap0.SCOPE_SUBTREE,
                filterstr=filterstr,
                attrlist=USER_ATTRS,
                req_ctrls=[PWDPOLICY_DEREF_CONTROL],
            )
        except ldap0.LDAPError as ldap_err:
            self.logger.warn(
                '%s.search_user_entry() search failed: %s',
                self.__class__.__name__,
                ldap_err,
            )
            raise
        if user.ctrls:
            user.entry_b.update(
                user.ctrls[0].derefRes['pwdPolicySubentry'][0].entry_b
            )
        return user.dn_s, user.entry_s

    def _open_ldap_conn(self):
        """
        Open LDAP connection
        """
        try:
            self.ldap_conn = aedir.AEDirObject(PWD_LDAP_URL, trace_level=0)
        except ldap0.LDAPError as ldap_err:
            self.logger.error(
                '%s - Error connecting to %r: %s',
                self.__class__.__name__, PWD_LDAP_URL, ldap_err,
            )
            raise
        self.logger.debug(
            '%s - Successfully bound to %r as %r',
            self.__class__.__name__,
            self.ldap_conn.ldap_url_obj.connect_uri(),
            self.ldap_conn.whoami_s(),
        )
        return # end of _open_ldap_conn()

    def _close_ldap_conn(self):
        """
        Close LDAP connection
        """
        self.logger.debug(
            '%s - Unbind from %r',
            self.__class__.__name__,
            self.ldap_conn.ldap_url_obj.connect_uri(),
        )
        try:
            self.ldap_conn.unbind_s()
        except (AttributeError, ldap0.LDAPError) as ldap_err:
            self.logger.warn(
                '%s - Error during unbinding from %r: %s',
                self.__class__.__name__,
                self.ldap_conn.ldap_url_obj.connect_uri(),
                ldap_err,
            )
        return # end of _close_ldap_conn()

    def handle_user_request(self, user_dn, user_entry):
        """
        nothing to be done herein
        """
        raise NotImplementedError

    def POST(self):
        """
        handle POST request processing input form

        mainly this opens and binds LDAP connection for user
        """
        self.form = self.post_form()
        if not self.form.validates():
            return RENDER.error('Invalid input!')
        try:
            self._open_ldap_conn()
        except ldap0.LDAPError:
            return RENDER.error(u'Internal error!')
        try:
            # search user entry
            user_dn, user_entry = self.search_user_entry(dict([
                (i.name, i.get_value())
                for i in self.form.inputs
            ]))
        except ValueError:
            res = RENDER.error(u'Invalid input!')
        except ldap0.LDAPError:
            res = RENDER.error(u'Error searching user!')
        else:
            # Call specific handler for LDAP user
            res = self.handle_user_request(user_dn, user_entry)
        self._close_ldap_conn()
        return res


class CheckPassword(BaseApp):
    """
    Handler for checking user's password
    """

    filterstr_template = FILTERSTR_CHANGEPW

    post_form = web.form.Form(
        USERNAME_FIELD,
        USERPASSWORD_FIELD,
        web.form.Button('submit', type='submit', description=u'Check password'),
    )

    def GET(self):
        """
        handle GET request by returning input form
        with username pre-filled
        """
        try:
            get_input = web.input(username=u'')
        except UnicodeError:
            return RENDER.checkpw_form(u'', u'Invalid input')
        else:
            return RENDER.checkpw_form(get_input.username, u'')

    def handle_user_request(self, user_dn, user_entry):
        """
        check the user password with simple bind request and
        display password expiry information
        """
        current_time = time.time()
        try:
            self.ldap_conn.simple_bind_s(
                user_dn,
                self.form.d.oldpassword.encode('utf-8'),
                req_ctrls=[
                    PasswordPolicyControl(),
                    self._sess_track_ctrl(),
                ]
            )
        except ldap0.INVALID_CREDENTIALS as ldap_err:
            self.logger.warn(
                '%s.handle_user_request() binding as %r failed: %s',
                self.__class__.__name__,
                user_dn,
                ldap_err,
            )
            return RENDER.checkpw_form(self.form.d.username, u'Wrong password!')
        except PasswordPolicyExpirationWarning as ppolicy_error:
            expire_time_str = time.strftime(
                TIME_DISPLAY_FORMAT,
                time.localtime(current_time+ppolicy_error.timeBeforeExpiration)
            )
            self.logger.info(
                '%s.handle_user_request() Password of %r will expire soon at %r (%d seconds)',
                self.__class__.__name__,
                user_dn,
                expire_time_str,
                ppolicy_error.timeBeforeExpiration,
            )
            return RENDER.changepw_form(
                self.form.d.username,
                u'Password will expire soon at %s. Change it now!' % (expire_time_str)
            )
        except PasswordPolicyException as ppolicy_error:
            return RENDER.changepw_form(
                self.form.d.username,
                str(ppolicy_error)
            )
        except ldap0.LDAPError:
            return RENDER.error(u'Internal error!')
        # Try to display until when password is still valid
        try:
            pwd_max_age = int(user_entry['pwdMaxAge'][0])
        except (ValueError, KeyError):
            valid_until = u'unknown'
        else:
            pwd_changed_timestamp = ldap0.functions.strp_secs(user_entry['pwdChangedTime'][0])
            expire_timestamp = pwd_changed_timestamp+pwd_max_age
            valid_until = time.strftime(
                TIME_DISPLAY_FORMAT,
                time.localtime(expire_timestamp)
            )
        # Finally render output page with success message
        return RENDER.checkpw_action(
            self.form.d.username,
            user_dn,
            valid_until
        )


class ChangePassword(BaseApp):
    """
    Handler for changing user's own password
    """

    filterstr_template = FILTERSTR_CHANGEPW

    post_form = web.form.Form(
        USERNAME_FIELD,
        USERPASSWORD_FIELD,
        NEWPASSWORD1_FIELD,
        NEWPASSWORD2_FIELD,
        web.form.Button(
            'submit',
            type='submit',
            description=u'Change password'
        ),
    )

    def GET(self):
        """
        handle GET request by returning input form
        with username pre-filled
        """
        try:
            get_input = web.input(username=u'')
        except UnicodeError:
            return RENDER.changepw_form(u'', u'Invalid input')
        else:
            return RENDER.changepw_form(get_input.username, u'')

    def _check_pw_input(self, user_entry):
        if self.form.d.newpassword1 != self.form.d.newpassword2:
            return u'New password values differ!'
        if 'pwdMinLength' in user_entry:
            pwd_min_len = int(user_entry['pwdMinLength'][0])
            if len(self.form.d.newpassword1) < pwd_min_len:
                return u'New password must be at least %d characters long!' % (pwd_min_len)
        if 'pwdChangedTime' in user_entry and 'pwdMinAge' in user_entry:
            pwd_changed_timestamp = ldap0.functions.strp_secs(user_entry['pwdChangedTime'][0])
            pwd_min_age = int(user_entry['pwdMinAge'][0])
            next_pwd_change_timespan = pwd_changed_timestamp + pwd_min_age - time.time()
            if next_pwd_change_timespan > 0:
                return u'Password is too young to change! You can try again after %d secs.' % (
                    next_pwd_change_timespan
                )
        return None # end of _check_pw_input()

    def handle_user_request(self, user_dn, user_entry):
        """
        set new password
        """
        pw_input_check_msg = self._check_pw_input(user_entry)
        if not pw_input_check_msg is None:
            return RENDER.changepw_form(self.form.d.username, pw_input_check_msg)
        try:
            self.ldap_conn.simple_bind_s(
                user_dn,
                self.form.d.oldpassword.encode('utf-8'),
                req_ctrls=[self._sess_track_ctrl()],
            )
            self.ldap_conn.passwd_s(
                user_dn,
                None,
                self.form.d.newpassword1.encode('utf-8'),
                req_ctrls=[self._sess_track_ctrl(user_dn)],
            )
        except ldap0.INVALID_CREDENTIALS:
            res = RENDER.changepw_form(
                self.form.d.username,
                u'Old password wrong!',
            )
        except ldap0.CONSTRAINT_VIOLATION as ldap_err:
            res = RENDER.changepw_form(
                self.form.d.username,
                u'Password rules violation: {0}'.format(
                    ldap_err.args[0]['info'].decode('utf-8'),
                ),
            )
        except ldap0.LDAPError:
            res = RENDER.error(u'Internal error!')
        else:
            res = RENDER.changepw_action(
                self.form.d.username,
                user_dn,
                self.ldap_conn.ldap_url_obj.connect_uri()
            )
        return res


class RequestPasswordReset(BaseApp):
    """
    Handler for starting password reset procedure
    """

    filterstr_template = FILTERSTR_REQUESTPW

    # Declaration for the change password input form
    post_form = web.form.Form(
        USERNAME_FIELD,
        EMAIL_FIELD,
        web.form.Button(
            'submit',
            type='submit',
            description=u'Set new password'
        ),
    )

    def GET(self):
        """
        handle GET request by returning input form
        with username pre-filled
        """
        try:
            get_input = web.input(username=u'')
        except UnicodeError:
            return RENDER.requestpw_form(u'', u'Invalid input')
        else:
            return RENDER.requestpw_form(get_input.username, u'')

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
        return sorted(set(admin_addrs or PWD_ADMIN_MAILTO))

    def _send_pw(self, username, user_dn, user_entry, temp_pwd_clear):
        """
        send e-mails to user and zone-admins
        """
        smtp_conn = mailutil.smtp_connection(
            SMTP_URL,
            local_hostname=SMTP_LOCALHOSTNAME,
            tls_args=SMTP_TLSARGS,
            debug_level=SMTP_DEBUGLEVEL
        )
        to_addr = user_entry['mail'][0]
        default_headers = (
            ('From', SMTP_FROM),
            ('Date', email.utils.formatdate(time.time(), True)),
        )
        #-----------------------------------------------------------------------
        # First send notification to admin if pwd_admin_len is non-zero
        #-----------------------------------------------------------------------
        pwd_admin_len = int(user_entry.get('msPwdResetAdminPwLen', [str(PWD_ADMIN_LEN)])[0])
        if pwd_admin_len:
            user_data_admin = {
                'username': username,
                'temppassword2': temp_pwd_clear[len(temp_pwd_clear)-pwd_admin_len:],
                'remote_ip': self.remote_ip,
                'fromaddr': SMTP_FROM,
                'userdn': user_dn,
                'web_ctx_host': web.ctx.host,
                'app_path_prefix': APP_PATH_PREFIX,
                'ldap_uri': self.ldap_conn.ldap_url_obj.connect_uri(),
            }
            smtp_message = read_template_file(EMAIL_TEMPLATE_ADMIN).format(**user_data_admin)
            smtp_subject = EMAIL_SUBJECT_ADMIN.format(**user_data_admin)
            admin_addrs = self._get_admin_mailaddrs(user_dn)
            smtp_conn.send_simple_message(
                SMTP_FROM,
                admin_addrs,
                'utf-8',
                default_headers+(
                    ('Subject', smtp_subject),
                    ('To', ','.join(admin_addrs)),
                ),
                smtp_message,
            )
        else:
            admin_addrs = []

        #-----------------------------------------------------------------------
        # Now send (rest of) clear-text password to user
        #-----------------------------------------------------------------------

        user_data_user = {
            'username': username,
            'temppassword1': temp_pwd_clear[:len(temp_pwd_clear)-pwd_admin_len],
            'remote_ip': self.remote_ip,
            'fromaddr': SMTP_FROM,
            'userdn': user_dn,
            'web_ctx_host': web.ctx.host,
            'app_path_prefix': APP_PATH_PREFIX,
            'ldap_uri': self.ldap_conn.ldap_url_obj.connect_uri(),
            'admin_email_addrs': u'\n'.join(admin_addrs),
        }
        smtp_message = read_template_file(EMAIL_TEMPLATE_PERSONAL).format(**user_data_user)
        smtp_subject = EMAIL_SUBJECT_PERSONAL.format(**user_data_user)
        smtp_conn.send_simple_message(
            SMTP_FROM,
            [to_addr],
            'utf-8',
            default_headers+(
                ('Subject', smtp_subject),
                ('To', to_addr),
            ),
            smtp_message,
        )
        smtp_conn.quit()
        return # _send_pw()

    def handle_user_request(self, user_dn, user_entry):
        """
        add password reset object class and attributes
        to user's entry and send e-mails
        """
        current_time = time.time()
        temp_pwd_len = int(user_entry.get('msPwdResetPwLen', [str(PWD_LENGTH)])[0])
        pwd_admin_len = int(user_entry.get('msPwdResetAdminPwLen', [str(PWD_ADMIN_LEN)])[0])
        temp_pwd_clear = random_string(PWD_TMP_CHARS, temp_pwd_len)
        temp_pwd_hash = pwd_hash(
            temp_pwd_clear,
            user_entry.get(
                'msPwdResetHashAlgorithm',
                [PWD_TMP_HASH_ALGO]
            )[0],
        )
        pwd_expire_timespan = int(
            user_entry.get(
                'msPwdResetMaxAge',
                [str(PWD_EXPIRETIMESPAN)]
            )[0]
        )
        ldap_mod_list = [
            (ldap0.MOD_REPLACE, b'msPwdResetPasswordHash', [temp_pwd_hash.encode('ascii')]),
            (ldap0.MOD_REPLACE, b'msPwdResetTimestamp', [ldap0.functions.strf_secs(current_time).encode('ascii')]),
            (
                ldap0.MOD_REPLACE,
                b'msPwdResetExpirationTime',
                [ldap0.functions.strf_secs(current_time+pwd_expire_timespan).encode('ascii')],
            ),
            (
                ldap0.MOD_REPLACE,
                b'msPwdResetEnabled',
                [user_entry.get('msPwdResetEnabled', [PWD_RESET_ENABLED])[0].encode('ascii')],
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
            res = RENDER.error(u'Internal error!')
        else:
            try:
                self._send_pw(
                    self.form.d.username,
                    user_dn,
                    user_entry,
                    temp_pwd_clear,
                )
            except (socket.error, socket.gaierror, smtplib.SMTPException) as mail_error:
                self.logger.error(
                    'Error sending reset e-mail to user %r: %s',
                    self.form.d.username,
                    mail_error,
                )
                res = RENDER.requestpw_form(
                    self.form.d.username,
                    u'Error sending e-mail via SMTP!',
                )
            else:
                res = RENDER.requestpw_action(
                    self.form.d.username,
                    self.form.d.email,
                    user_dn
                )
        return res


class FinishPasswordReset(ChangePassword):
    """
    Handler for finishing password reset procedure
    """

    filterstr_template = '(&(msPwdResetEnabled=TRUE)%s)' % (FILTERSTR_RESETPW)

    get_form = web.form.Form(
        USERNAME_FIELD,
        TEMP1PASSWORD_FIELD,
    )

    post_form = web.form.Form(
        USERNAME_FIELD,
        TEMP1PASSWORD_FIELD,
        TEMP2PASSWORD_FIELD,
        NEWPASSWORD1_FIELD,
        NEWPASSWORD2_FIELD,
        web.form.Button(
            'submit',
            type='submit',
            description=u'Change password'
        ),
    )

    def GET(self):
        """
        handle GET request by returning input form with username and
        1st temporary password part pre-filled
        """
        get_input = web.input(username=u'', temppassword1=u'')
        if not get_input.username or not get_input.temppassword1:
            return RENDER.error(u'Invalid input')
        try:
            self._open_ldap_conn()
        except ldap0.LDAPError:
            return RENDER.error(u'Internal LDAP error!')
        try:
            _, user_entry = self.search_user_entry({'username': get_input.username})
        except ldap0.LDAPError:
            return RENDER.error(u'Error searching user!')
        self._close_ldap_conn()
        pwd_admin_len = int(user_entry.get('msPwdResetAdminPwLen', [str(PWD_ADMIN_LEN)])[0])
        return RENDER.resetpw_form(
            get_input.username,
            pwd_admin_len,
            get_input.temppassword1,
            u''
        ) # end of FinishPasswordReset.GET()

    def _ldap_user_operations(self, user_dn, user_entry, temp_pwd_hash, new_password_ldap):
        pwd_admin_len = int(user_entry.get('msPwdResetAdminPwLen', [str(PWD_ADMIN_LEN)])[0])
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
                req_ctrls=[self._sess_track_ctrl(user_dn)],
            )
        except ldap0.LDAPError as ldap_err:
            self.logger.warn(
                '%s modify_s() failed for %r: %s',
                self.__class__.__name__,
                user_dn,
                ldap_err,
            )
            raise
        try:
            self.ldap_conn.passwd_s(
                user_dn,
                None,
                new_password_ldap,
                req_ctrls=[self._sess_track_ctrl(user_dn)],
            )
        except ldap0.LDAPError as ldap_err:
            self.logger.warn(
                '%s passwd_s() failed for %r: %s',
                self.__class__.__name__,
                user_dn,
                ldap_err,
            )
            raise
        return

    def handle_user_request(self, user_dn, user_entry):
        """
        set new password if temporary reset password matches
        """
        temppassword1 = self.form.d.temppassword1
        temppassword2 = self.form.d.temppassword2
        pwd_admin_len = int(user_entry.get('msPwdResetAdminPwLen', [str(PWD_ADMIN_LEN)])[0])
        temp_pwd_hash = pwd_hash(
            u''.join((temppassword1, temppassword2)),
            user_entry.get('msPwdResetHashAlgorithm', [PWD_TMP_HASH_ALGO])[0],
        )
        pw_input_check_msg = self._check_pw_input(user_entry)
        if not pw_input_check_msg is None:
            return RENDER.resetpw_form(
                self.form.d.username,
                pwd_admin_len,
                self.form.d.temppassword1,
                pw_input_check_msg,
            )
        try:
            self._ldap_user_operations(
                user_dn,
                user_entry,
                temp_pwd_hash,
                self.form.d.newpassword1.encode('utf-8'),
            )
        except ldap0.NO_SUCH_ATTRIBUTE:
            res = RENDER.resetpw_form(
                self.form.d.username,
                pwd_admin_len,
                self.form.d.temppassword1,
                u'Temporary password(s) wrong!',
            )
        except ldap0.CONSTRAINT_VIOLATION as ldap_err:
            res = RENDER.requestpw_form(
                self.form.d.username,
                (
                    u'Constraint violation (password rules): {0}'
                    u' / You have to request password reset again!'
                ).format(ldap_err.args[0]['info'].decode('utf-8'))
            )
        except ldap0.LDAPError:
            res = RENDER.error(u'Internal error!')
        else:
            res = RENDER.resetpw_action(self.form.d.username, user_dn)
        return res

application = web.application(URL2CLASS_MAPPING, globals(), autoreload=bool(WEB_ERROR)).wsgifunc()

def main():
    """
    run the web application
    """
    # Initialize web application
    APP_LOGGER.debug('Starting web application script %r', sys.argv[0])
    app = web.application(URL2CLASS_MAPPING, globals(), autoreload=bool(WEB_ERROR))
    # Change to directory where the script is located
    APP_LOGGER.debug('chdir to %r', TEMPLATES_DIRNAME)
    os.chdir(TEMPLATES_DIRNAME)
    # Set error handling
    if not WEB_ERROR:
        APP_LOGGER.debug('switch off debugging')
        app.internalerror = False
    # Start the internal web server
    APP_LOGGER.info(
        'Script %r starts %r instance listening on %r',
        sys.argv[0],
        app.__class__.__name__,
        sys.argv[1],
    )
    app.run()


if __name__ == '__main__':
    main()
