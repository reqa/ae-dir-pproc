# -*- coding: ascii -*-
"""
aedir_pproc.pwd.web.forms - forms declarations
"""

from wtforms import Form, validators
from wtforms.fields import StringField, PasswordField, SubmitField
try:
    from wtforms.fields import EmailField
except ImportError:
    from wtforms.fields.html5 import EmailField


USERNAME_REGEX = '^[a-zA-Z0-9._-]+$'
TEMP_PASSWORD_REGEX = '^[a-zA-Z0-9_-]*$'

USERNAME_FIELD = StringField(
    'User name',
    [
        validators.Length(min=2, max=40),
        validators.InputRequired(),
        validators.Regexp(USERNAME_REGEX),
    ],
)

USERPASSWORD_FIELD = PasswordField(
    'User password',
    [
        validators.InputRequired(),
    ],
)

NEWPASSWORD1_FIELD = PasswordField(
    'New password',
    [
        validators.InputRequired(),
    ],
)

NEWPASSWORD2_FIELD = PasswordField(
    'New password (repeat)',
    [
        validators.InputRequired(),
    ],
)


class CheckPasswordForm(Form):
    """
    form declaration for
    """
    username = USERNAME_FIELD
    password = USERPASSWORD_FIELD
    submit = SubmitField()


class ChangePasswordForm(Form):
    """
    form declaration for
    """
    username = USERNAME_FIELD
    password = USERPASSWORD_FIELD
    newpassword1 = NEWPASSWORD1_FIELD
    newpassword2 = NEWPASSWORD2_FIELD
    submit = SubmitField()


class RequestPasswordResetForm(Form):
    """
    form declaration for
    """
    username = USERNAME_FIELD
    email = EmailField(
        'E-mail address',
        [
            validators.InputRequired(),
        ],
    )
    submit = SubmitField()


class FinishPasswordResetForm(Form):
    """
    form declaration for
    """
    username = USERNAME_FIELD
    temppassword1 = PasswordField(
        'Temporary password part #1',
        [
            validators.InputRequired(),
            validators.Regexp(TEMP_PASSWORD_REGEX),
        ],
    )
    temppassword2 = PasswordField(
        'Temporary password part #2',
        [
            validators.Regexp(TEMP_PASSWORD_REGEX),
        ],
    )
    newpassword1 = NEWPASSWORD1_FIELD
    newpassword2 = NEWPASSWORD2_FIELD
    submit = SubmitField()


class ViewUserForm(Form):
    """
    form declaration for
    """
    username = USERNAME_FIELD
    password = USERPASSWORD_FIELD
    othername = StringField(
        'View user name',
        [
            validators.Length(min=2, max=40),
            validators.InputRequired(),
            validators.Regexp(USERNAME_REGEX),
        ],
    )
    submit = SubmitField()
