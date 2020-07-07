# -*- coding: utf-8 -*-
"""
aedir_pproc.pwd.expreset - Remove expired msPwdResetObject attributes
"""

# from Python's standard lib
import time

# from ldap0 package
import ldap0
import ldap0.functions

# the separate python-aedir module
import aedir.process

# Import constants from configuration module
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


def main():
    """
    run the process
    """
    with AEPwdResetExpiration() as ae_process:
        ae_process.run(max_runs=1)


if __name__ == '__main__':
    main()
