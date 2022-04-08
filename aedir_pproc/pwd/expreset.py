# -*- coding: ascii -*-
"""
aedir_pproc.pwd.expreset - Remove expired msPwdResetObject attributes
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
    FILTERSTR_EXPIRE,
    PWD_ADMIN_LEN,
)

from ..__about__ import __version__

#-----------------------------------------------------------------------
# Classes and functions
#-----------------------------------------------------------------------

class AEPwdResetExpiration(aedir.process.AEProcess):
    """
    Job instance
    """
    script_version = __version__
    reset_attrs = [
        'objectClass',
        'msPwdResetExpirationTime',
        'msPwdResetTimestamp',
        'msPwdResetAdminPw',
    ]

    def run_worker(self, state):
        """
        Remove expired msPwdResetObject attributes
        """
        current_run_timestr = ldap0.functions.strf_secs(time.time())
        expired_pwreset_filter = FILTERSTR_EXPIRE.format(currenttime=current_run_timestr)
        ldap_results = self.ldap_conn.search_s(
            self.ldap_conn.search_base,
            ldap0.SCOPE_SUBTREE,
            filterstr=expired_pwreset_filter,
            attrlist=self.reset_attrs,
        )
        self.logger.debug(
            '%d expired password resets found with %r',
            len(ldap_results),
            expired_pwreset_filter,
        )
        for res in ldap_results:
            self.logger.debug('Found %r: %r', res.dn_s, res.entry_as)
            # Prepare the modification list
            ldap_mod_list = [
                # explictly delete by value
                (ldap0.MOD_DELETE, b'objectClass', [b'msPwdResetObject']),
                (
                    ldap0.MOD_DELETE,
                    b'msPwdResetTimestamp',
                    [res.entry_as['msPwdResetTimestamp'][0]]
                ),
                (
                    ldap0.MOD_DELETE,
                    b'msPwdResetExpirationTime',
                    [res.entry_as['msPwdResetExpirationTime'][0]]
                ),
                # delete whole value no matter what
                (ldap0.MOD_DELETE, b'msPwdResetEnabled', None),
                (ldap0.MOD_DELETE, b'msPwdResetPasswordHash', None),
            ]
            if PWD_ADMIN_LEN or 'msPwdResetAdminPw' in res.entry_as:
                ldap_mod_list.append(
                    (ldap0.MOD_DELETE, b'msPwdResetAdminPw', None),
                )
            # Actually perform the modify operation
            try:
                self.ldap_conn.modify_s(res.dn_s, ldap_mod_list)
            except ldap0.LDAPError as ldap_error:
                self.logger.warning(
                    'LDAPError removing msPwdResetObject attrs in %r: %s',
                    res.dn_s,
                    ldap_error
                )
            else:
                self.logger.info(
                    'Removed msPwdResetObject attributes from %r',
                    res.dn_s,
                )

        return current_run_timestr
        # end of run_worker()
