# -*- coding: ascii -*-
"""
aedir_pproc.persattrs - Sync the personnel attributes (cn, sn, givenName, mail)
from aePerson to aeUser entries
"""

#-----------------------------------------------------------------------
# Imports
#-----------------------------------------------------------------------

import time

import ldap0
import ldap0.modlist
import ldap0.functions
import ldap0.filter
from ldap0.base import encode_list

import aedir
import aedir.process

from .__about__ import __version__

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

AEOBJECT_EXPIRY_FILTER_TMPL = (
    '(&'
        '(objectClass=aeObject)'
        '(aeNotAfter<={now})'
        '(|'
            '(&(aeStatus<=0)(aeExpiryStatus>=1))'
            '(&(aeStatus<=1)(aeExpiryStatus>=2))'
        ')'
    ')'
)

# Exception class used for catching all exceptions
aedir.process.CatchAllException = Exception

#-----------------------------------------------------------------------
# Classes and functions
#-----------------------------------------------------------------------


class AEObjectUpdater(aedir.process.TimestampStateMixin, aedir.process.AEProcess):
    """
    The sync process
    """
    script_version = __version__

    def __init__(self, state_filename):
        aedir.process.AEProcess.__init__(self)
        self.state_filename = state_filename
        self.aeobject_counter = 0
        self.aeperson_counter = 0
        self.deactivate_counter = 0
        self.error_counter = 0
        self.expired_counter = 0
        self.modify_counter = 0

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
        self.logger.debug('Found %d auto-expiry AE-DIR entries', self.aeobject_counter)
        if self.expired_counter:
            self.logger.info('Modifed %d auto-expiry AE-DIR entries.', self.expired_counter)
        if self.error_counter:
            self.logger.error('%d errors.', self.error_counter)

    def _expire_entries(self, current_time_str):
        """
        run aeStatus updates
        """
        expiry_filter = AEOBJECT_EXPIRY_FILTER_TMPL.format(now=current_time_str)
        self.logger.debug('expiry_filter = %r', expiry_filter)
        try:
            msg_id = self.ldap_conn.search(
                self.ldap_conn.search_base,
                ldap0.SCOPE_SUBTREE,
                expiry_filter,
                attrlist=['aeStatus', 'aeExpiryStatus'],
            )
        except ldap0.LDAPError as ldap_error:
            self.logger.error('LDAPError searching %r: %s', expiry_filter, ldap_error)
            return
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
                    self.logger.info('Expired aeStatus in %r: %s', aeobj.dn_s, modlist)
                    self.expired_counter += 1
        # end of _expire_entries()

    def _update_pers_attrs(self, last_run_timestr, current_time_str):
        """
        update aeUser person attributes
        """

        aeperson_filterstr = (
            '(&(objectClass=aePerson)(modifyTimestamp>={0})(!(modifyTimestamp>={1})))'
        ).format(
            last_run_timestr,
            current_time_str,
        )
        self.logger.debug('aeperson_filterstr = %r', aeperson_filterstr)

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
                    '(&(objectClass=aeUser)(aePerson={0}))'.format(
                        ldap0.filter.escape_str(aeperson.dn_s),
                    ),
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

        # end of _update_pers_attrs()

    def run_worker(self, last_run_timestr):
        """
        the main program
        """
        current_time_str = ldap0.functions.strf_secs(time.time())
        self.logger.debug(
            'current_time_str=%r last_run_timestr=%r',
            current_time_str,
            last_run_timestr,
        )
        self._update_pers_attrs(last_run_timestr, current_time_str)
        self._expire_entries(current_time_str)
        return current_time_str
