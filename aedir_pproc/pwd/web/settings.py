# -*- coding: ascii -*-
"""
aedir_pproc.pwd.web.settings - Configuration defaults
"""

import os.path
import secrets

# URL path prefix used when generating URLs in e-mails
# handy for reverse proxy setups
APPLICATION_ROOT = '/pwd'

# generate a 64-bytes random secret
APP_SECRET = secrets.token_bytes(64)

# default log level
LOG_LEVEL = 'info'

# logger name
LOG_NAME = 'aedir_pproc.pwd.web'

# path of logging config file
LOG_CONFIG = None

# number of proxy levels
# see https://werkzeug.palletsprojects.com/en/1.0.x/middleware/proxy_fix/
PROXY_LEVEL = 0

# LDAP-URL describing the connection parameters and bind information
PWD_LDAP_URL = (
    'ldapi://%2Fopt%2Fae-dir%2Frun%2Fslapd%2Fldapi/ou=ae-dir??sub??trace=0,x-saslmech=EXTERNAL'
)

# Filter string templates for the various use-cases
# String-keyed dictionary with input field names used
FILTERSTR_CHANGEPW = '(&(objectClass=aeUser)(aeStatus=0)(uid={username}))'
FILTERSTR_REQUESTPW = '(&(objectClass=aeUser)(aeStatus=0)(uid={username})(mail={email}))'
FILTERSTR_RESETPW = (
    '(&'
    '(objectClass=aeUser)'
    '(aeStatus=0)'
    '(uid={username})'
    '(objectClass=msPwdResetObject)'
    '(msPwdResetTimestamp<={currenttime})'
    '(msPwdResetExpirationTime>={currenttime})'
    ')'
)

# Filter string template for finding an active user entry
# mainly used to inform about who did something and send e-mail to
FILTERSTR_USER = '(&(objectClass=aeUser)(aeStatus=0)(displayName=*)(mail=*))'

# Initial value for Boolean attribute 'msPwdResetEnabled'
# Setting this to 'FALSE' enables you to let an admin set this manually
# before the user can set a new password
PWD_RESET_ENABLED = 'TRUE'

# Name of directory containing all the template files
TEMPLATES_DIRNAME = 'templates/en'

# Format string for displaying date and time
TIME_DISPLAY_FORMAT = '%Y-%m-%d %H:%M:%S'

# Length of generated temporary passwords
PWD_LENGTH = 64

# Number of chars of generated temporary passwords to be store
# in attribute 'msPwdResetAdminPw'
PWD_ADMIN_LEN = 8

# Where to send admin notification if PWD_ADMIN_LEN is non-zero
# and responsible zone admins cannot be determined
PWD_ADMIN_MAILTO = [
  'ae-admins@example.com',
]

# Number of seconds a temporary password is valid
PWD_EXPIRETIMESPAN = 600

# Hash algorithm used for the temporary passwords
PWD_TMP_HASH_ALGO = '2.16.840.1.101.3.4.2.3' # sha512 [RFC4055]

# Characters used for the temporary passwords
PWD_TMP_CHARS = 'abcdefghijkmnopqrstuvwxyzABCDEFGHIJKLMNPQRSTUVWXYZ23456789'

# Filename of template for sending reset password to user
EMAIL_SUBJECT_PERSONAL = 'Your temporary reset password for "{username}"'
EMAIL_TEMPLATE_PERSONAL = os.path.join(TEMPLATES_DIRNAME, 'requestpw_user.txt')

# Filename of template for sending password reset info to admin
EMAIL_SUBJECT_ADMIN = 'Password reset for "{username}" needs help'
EMAIL_TEMPLATE_ADMIN = os.path.join(TEMPLATES_DIRNAME, 'requestpw_admin.txt')

# Filename of template for sending password change notification to user
EMAIL_SUBJECT_NOTIFICATION = 'Password of your account "{username}" was changed!'
EMAIL_TEMPLATE_NOTIFICATION = os.path.join(TEMPLATES_DIRNAME, 'changepw_notification.txt')

# Specifies whether a user shall be informed about a password change via e-mail
CHANGEPW_NOTIFICATION_ENABLED = False

# SMTP server used as smart host (SMTP relay)
SMTP_URL = 'smtp://mail.example.com/?STARTTLS'

# Specifies whether a AE-DIR instance should send e-mail notifications to users or not
USER_MAIL_ENABLED = False

# Specifies a recipient address which should be checked by every run of
# aedir_pproc.pwd.expwarn for monitoring the SMTP connection
SMTP_CHECK = True

# Debug level for SMTP messages sent to stderr
SMTP_DEBUGLEVEL = 0

# Hostname to be sent in EHLO request,
# set to None for automatically using the local hostname
SMTP_LOCALHOSTNAME = 'ae-dir-suse-p1.vnet1.local'

# Path name of file containing CA certificates used to validate TLS server certs
SMTP_TLS_CACERTS = '/opt/ae-dir/etc/my-ae-dir-testca-2017-06.pem'

# From address in sent e-mail
SMTP_FROM = 'ae-admins@example.com'

# Filter string templates
FILTERSTR_EXPIRE = (
    '(&'
        '(objectClass=msPwdResetObject)'
        '(!(msPwdResetExpirationTime={currenttime}))'
        '(msPwdResetExpirationTime<={currenttime})'
    ')'
)
FILTERSTR_NO_WELCOME_YET = (
    '(&'
        '(objectClass=aeUser)'
        '(aeStatus=0)'
        '(uid=*)'
        '(mail=*)'
        '(entryCSN:CSNSIDMatch:={serverid})'
        '(aeTag=pub-tag-no-welcome-yet)'
        '(modifyTimestamp>={lasttime})'
    ')'
)

# Maximum timespan to search for new entries in the past
# to send welcome e-mail
WELCOME_OLDEST_TIMESPAN = 86400.0

# E-Mail subject for notification message
WELCOME_EMAIL_SUBJECT = 'New \xC6-DIR account "{user_uid}" added/activated for {user_cn}'
# E-Mail body template file for notification message
WELCOME_EMAIL_TEMPLATE = '/opt/ae-dir/etc/ae-dir-pwd/templates/en/welcome_user_email.txt'

# modifications to be applied to user entry after successfully sending e-mail
WELCOME_SUCCESSFUL_MOD = [
    (1, b'aeTag', [b'pub-tag-no-welcome-yet'])
]
