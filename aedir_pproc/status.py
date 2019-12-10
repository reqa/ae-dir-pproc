# -*- coding: utf-8 -*-
"""
aedir_pproc.status - updates aeStatus of expired AE-DIR entries (aeObject)
"""

from __future__ import absolute_import

#-----------------------------------------------------------------------
# Imports
#-----------------------------------------------------------------------

import os
import time

import ldap0
import aedir
import aedir.process

from .__about__ import __version__, __author__, __license__

#-----------------------------------------------------------------------
# Classes and functions
#-----------------------------------------------------------------------

class AEStatusUpdater(aedir.process.AEProcess):
    """
    Status update process class
    """
    script_version = __version__

    def __init__(self):
        aedir.process.AEProcess.__init__(self)
        self.aeobject_counter = 0
        self.modify_counter = 0
        self.error_counter = 0

    def exit(self):
        """
        Log a summary of actions and errors, mainly counters
        """
        self.logger.debug('Found %d auto-expiry AE-DIR entries', self.aeobject_counter)
        if self.modify_counter:
            self.logger.info('Modifed %d auto-expiry AE-DIR entries.', self.modify_counter)
        if self.error_counter:
            self.logger.error('%d errors.', self.error_counter)

    def run_worker(self, state):
        """
        the main program
        """
        current_time_str = ldap0.functions.strf_secs(time.time())
        self.logger.debug('current_time_str = %r', current_time_str)
        expiry_filter = (
          '(&'
            '(objectClass=aeObject)'
            '(aeNotAfter<={0})'
            '(|'
              '(&(aeStatus<=0)(aeExpiryStatus>=1))'
              '(&(aeStatus<=1)(aeExpiryStatus>=2))'
            ')'
          ')'
        ).format(current_time_str)
        self.logger.debug('expiry_filter = %r', expiry_filter)
        try:
            msg_id = self.ldap_conn.search(
                self.ldap_conn.search_base,
                ldap0.SCOPE_SUBTREE,
                expiry_filter,
                attrlist=['aeStatus', 'aeExpiryStatus'],
            )
        except ldap0.LDAPError as ldap_error:
            self.logger.warning('LDAPError searching %r: %s', expiry_filter, ldap_error)
            return
        # process LDAP results
        for ldap_res in self.ldap_conn.results(msg_id):
            for aeobj in ldap_res.rdata:
                self.aeobject_counter += 1
                modlist = [
                    (ldap0.MOD_DELETE, b'aeStatus', aeobj.entry_as['aeStatus']),
                    (ldap0.MOD_ADD, b'aeStatus', aeobj.entry_as['aeExpiryStatus']),
                ]
                try:
                    self.ldap_conn.modify_s(
                        aeobj.dn_s,
                        [
                            (ldap0.MOD_DELETE, b'aeStatus', aeobj.entry_as['aeStatus']),
                            (ldap0.MOD_ADD, b'aeStatus', aeobj.entry_as['aeExpiryStatus']),
                        ]
                    )
                except ldap0.LDAPError as ldap_error:
                    self.logger.warning('LDAPError modifying %r: %s', aeobj.dn_s, ldap_error)
                    self.error_counter += 1
                else:
                    self.logger.info('Updated aeStatus in %r: %s', aeobj.dn_s, modlist)
                    self.modify_counter += 1
        return # end of run_worker()


def main():
    with AEStatusUpdater() as ae_process:
        ae_process.run(max_runs=1)


if __name__ == '__main__':
    main()
