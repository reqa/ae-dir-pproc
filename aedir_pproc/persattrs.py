# -*- coding: utf-8 -*-
"""
aedir_pproc.persattrs - Sync the personnel attributes (cn, sn, givenName, mail)
from aePerson to aeUser entries
"""

#-----------------------------------------------------------------------
# Imports
#-----------------------------------------------------------------------

from __future__ import absolute_import

# Modules from Python's standard library
import sys
import time

# from ldap0 package
import ldap0
import ldap0.modlist
import ldap0.functions
import ldap0.filter
from ldap0.base import encode_list

import aedir
import aedir.process

from .__about__ import __version__, __author__, __license__

#-----------------------------------------------------------------------
# Constants (configuration)
#-----------------------------------------------------------------------

# List of attributes copied from aePerson to aeUser entries
AEDIR_AEPERSON_ATTRS = [
    'cn',
    'givenName',
    'sn',
    'mail',
    'aeStatus'
]

# Exception class used for catching all exceptions
aedir.process.CatchAllException = Exception

#-----------------------------------------------------------------------
# Classes and functions
#-----------------------------------------------------------------------


class SyncProcess(aedir.process.TimestampStateMixin, aedir.process.AEProcess):
    """
    The sync process
    """
    script_version = __version__

    def __init__(self, state_filename):
        aedir.process.AEProcess.__init__(self)
        self.state_filename = state_filename
        self.aeperson_counter = 0
        self.modify_counter = 0
        self.error_counter = 0
        self.deactivate_counter = 0

    def exit(self):
        """
        Log a summary of actions and errors, mainly counters
        """
        self.logger.debug('Found %d aePerson entries', self.aeperson_counter)
        if self.modify_counter:
            self.logger.info(
                'Updated %d AE-DIR entries (%d deactivated).',
                self.modify_counter,
                self.deactivate_counter
            )
        else:
            self.logger.debug('No modifications.')
        if self.error_counter:
            self.logger.error('%d errors.', self.error_counter)

    def run_worker(self, last_run_timestr):
        """
        the main worker part
        """

        current_time_str = ldap0.functions.strf_secs(time.time())
        self.logger.debug(
            'current_time_str=%r last_run_timestr=%r',
            current_time_str,
            last_run_timestr,
        )

        # Update aeUser entries
        #-----------------------------------------------------------------------

        aeperson_filterstr = (
            '(&(objectClass=aePerson)(modifyTimestamp>={0})(!(modifyTimestamp>={1})))'
        ).format(
            last_run_timestr,
            current_time_str,
        )

        self.logger.debug(
            'Searching in %r with filter %r',
            self.ldap_conn.search_base,
            aeperson_filterstr,
        )
        msg_id = self.ldap_conn.search(
            self.ldap_conn.search_base,
            ldap0.SCOPE_SUBTREE,
            aeperson_filterstr,
            attrlist=AEDIR_AEPERSON_ATTRS,
        )

        for ldap_res in self.ldap_conn.results(msg_id):

            for aeperson in ldap_res.rdata:

                self.aeperson_counter += 1

                aeuser_results = self.ldap_conn.search_s(
                    self.ldap_conn.search_base,
                    ldap0.SCOPE_SUBTREE,
                    '(&(objectClass=aeUser)(aePerson=%s))' % (ldap0.filter.escape_str(aeperson.dn_s)),
                    attrlist=AEDIR_AEPERSON_ATTRS+['uid', 'uidNumber', 'displayName'],
                )

                # Process the aeUser entries
                for aeuser in aeuser_results:

                    new_aeuser_entry = {}
                    new_aeuser_entry.update(aeperson.entry_s)
                    del new_aeuser_entry['aeStatus']
                    new_aeuser_entry['displayName'] = ['{cn} ({uid}/{uidNumber})'.format(
                        cn=aeperson.entry_s['cn'][0],
                        uid=aeuser.entry_s['uid'][0],
                        uidNumber=aeuser.entry_s['uidNumber'][0],
                    )]

                    # Check whether aeStatus must be updated
                    # First preserve old status
                    aeperson_status = int(aeperson.entry_s['aeStatus'][0])
                    aeuser_status = int(aeuser.entry_s['aeStatus'][0])
                    if aeperson_status > 0 and aeuser_status <= 0:
                        new_aeuser_entry['aeStatus'] = ['1']
                        self.deactivate_counter += 1
                    else:
                        new_aeuser_entry['aeStatus'] = aeuser.entry_s['aeStatus']

                    # Generate diff of general person attributes
                    modlist = ldap0.modlist.modify_modlist(
                        aeuser.entry_as,
                        {
                            at: encode_list(avs)
                            for at, avs in new_aeuser_entry.items()
                        },
                        ignore_attr_types=['uid', 'uidNumber']
                    )

                    if not modlist:
                        self.logger.debug(
                            'Nothing to do in %r => skipped',
                            aeuser.dn_s,
                        )
                        continue

                    self.logger.debug(
                        'Update existing entry %r: %r',
                        aeuser.dn_s,
                        modlist,
                    )
                    try:
                        self.ldap_conn.modify_s(aeuser.dn_s, modlist)
                    except ldap0.LDAPError as ldap_err:
                        self.logger.error(
                            'LDAP error modifying %r with %r: %s',
                            aeuser.dn_s,
                            modlist,
                            ldap_err,
                        )
                        self.error_counter += 1
                    else:
                        self.logger.info(
                            'Updated entry %r: %r',
                            aeuser.dn_s,
                            modlist,
                        )
                        self.modify_counter += 1

        return current_time_str # end of run_worker()


def main():
    with SyncProcess(sys.argv[1]) as ae_process:
        ae_process.run(max_runs=1)


if __name__ == '__main__':
    main()
