# -*- coding: ascii -*-
"""
aedir_pproc.groups - Performs two tasks:
1. Removes inactive members from static group entries referenced by 'memberOf'.
2. Updates all static aeGroup entries which contain attribute 'memberURL'
"""

#-----------------------------------------------------------------------
# Imports
#-----------------------------------------------------------------------

import ldap0
import ldap0.base
import ldap0.filter
from ldap0.filter import compose_filter, map_filter_parts
from ldap0.controls.deref import DereferenceControl
import ldap0.ldapurl
import aedir
import aedir.process

from .__about__ import __version__

#-----------------------------------------------------------------------
# Configuration constants
#-----------------------------------------------------------------------

# Attribute containing the group members references
MEMBER_ATTR = 'member'
# Attribute containing the LDAP URLs to be searched
MEMBEROF_ATTR = 'memberOf'
# Attribute containing the LDAP URLs to be searched
MEMBERURL_ATTR = 'memberURL'
# Attribute containing the group members' uid values
MEMBER_ATTRS_MAP = {
    'aeGroup': ('memberUid', 'uid'),
    'aeMailGroup': ('rfc822MailMember', 'mail'),
}
MEMBER_ATTRS = [attr[0] for attr in MEMBER_ATTRS_MAP.values()]
USER_ATTRS = [attr[1] for attr in MEMBER_ATTRS_MAP.values()]

#-----------------------------------------------------------------------
# Classes and functions
#-----------------------------------------------------------------------

class AEGroupUpdater(aedir.process.AEProcess):
    """
    Group update process class
    """
    script_version = __version__
    deref_person_attrs = ('aeDept', 'aeLocation')

    @staticmethod
    def _member_zones_filter(aegroup_entry):
        """
        construct a filter from attribute 'aeMemberZone' if present in aegroup_entry
        """
        try:
            member_zones = aegroup_entry['aeMemberZone']
        except KeyError:
            res = ''
        else:
            res = compose_filter('|', map_filter_parts('entryDN:dnSubordinateMatch:', member_zones))
        return res


    def _update_members(
            self,
            group_dn,
            member_map_attr,
            old_members,
            new_members,
            old_member_attr_values,
            new_member_attr_values,
        ):
        """
        update attribute 'member' and additional membership attribute
        """
        mod_list = []
        add_members = new_members - old_members
        if add_members:
            mod_list.append(
                (ldap0.MOD_ADD, MEMBER_ATTR, list(add_members)),
            )

        remove_members = old_members - new_members
        if remove_members:
            mod_list.append(
                (ldap0.MOD_DELETE, MEMBER_ATTR, list(remove_members)),
            )

        remove_member_attr_values = old_member_attr_values - new_member_attr_values
        if remove_member_attr_values:
            mod_list.append(
                (ldap0.MOD_DELETE, member_map_attr, list(remove_member_attr_values)),
            )

        add_member_attr_values = new_member_attr_values - old_member_attr_values
        if add_member_attr_values:
            mod_list.append(
                (ldap0.MOD_ADD, member_map_attr, list(add_member_attr_values)),
            )

        if mod_list:
            try:
                self.ldap_conn.modify_s(
                    group_dn,
                    [
                        (mod, at.encode('ascii'), ldap0.base.encode_list(avl))
                        for mod, at, avl in mod_list
                    ],
                )
            except ldap0.LDAPError as ldap_error:
                self.logger.error(
                    'LDAPError modifying %r: %s mod_list = %r',
                    group_dn,
                    ldap_error,
                    mod_list,
                )
            else:
                self.logger.debug(
                    'Updated %r: mod_list = %r',
                    group_dn,
                    mod_list,
                )
                self.logger.info(
                    (
                        'Updated member values of group entry %r: '
                        'add_members=%d '
                        'add_member_attr_values=%d '
                        'remove_members=%d '
                        'remove_member_attr_values=%d'
                    ),
                    group_dn,
                    len(add_members),
                    len(add_member_attr_values),
                    len(remove_members),
                    len(remove_member_attr_values),
                )
        else:
            self.logger.debug('Nothing to be done with %r', group_dn)
        # end of _update_members()

    def fix_static_groups(self):
        """
        1. Removes obsolete 'member' and other member values and
        2. adds missing other member values
        in all active static aeGroup entries
        """
        for group_object_class, member_attrs in MEMBER_ATTRS_MAP.items():
            member_map_attr, member_user_attr = member_attrs
            msg_id = self.ldap_conn.search(
                self.ldap_conn.search_base,
                ldap0.SCOPE_SUBTREE,
                '(&(objectClass={0})(!({1}=*))(aeStatus=0))'.format(
                    group_object_class,
                    MEMBERURL_ATTR,
                ),
                attrlist=[
                    MEMBER_ATTR,
                    member_map_attr,
                ],
                req_ctrls=[
                    DereferenceControl(
                        True,
                        {
                            MEMBER_ATTR: [
                                'aeStatus',
                                MEMBEROF_ATTR,
                                member_user_attr
                            ],
                        }
                    )
                ],
            )

            for ldap_results in self.ldap_conn.results(msg_id):

                for ldap_group in ldap_results.rdata:

                    if not ldap_group.ctrls:
                        continue

                    member_deref_result = ldap_group.ctrls[0].derefRes[MEMBER_ATTR]

                    old_members = set(ldap_group.entry_s.get(MEMBER_ATTR, []))
                    old_member_attr_values = set(ldap_group.entry_s.get(member_map_attr, []))
                    new_members = set()
                    new_member_attr_values = set()
                    for deref_res in member_deref_result:
                        if int(deref_res.entry_s['aeStatus'][0]) <= 0:
                            new_members.add(deref_res.dn_s)
                            try:
                                new_member_attr_values.add(deref_res.entry_s[member_user_attr][0])
                            except KeyError:
                                self.logger.error(
                                    'Attribute %r not found in entry %r: %r',
                                    member_user_attr,
                                    deref_res.dn_s,
                                    deref_res.entry_s,
                                )

                    self._update_members(
                        ldap_group.dn_s,
                        member_map_attr,
                        old_members,
                        new_members,
                        old_member_attr_values,
                        new_member_attr_values
                    )

        # end of fix_static_groups()

    def _constrained_persons(self, aegroup_entry):
        """
        return list of DNs of valid aePerson entries
        """
        deref_attrs = []
        person_filter_parts = ['(objectClass=aePerson)(aeStatus=0)']
        for deref_attr_type in self.deref_person_attrs:
            try:
                deref_attr_values = aegroup_entry[deref_attr_type]
            except KeyError:
                pass
            else:
                deref_attrs.append(deref_attr_type)
                person_filter_parts.append(
                    compose_filter(
                        '|',
                        map_filter_parts(deref_attr_type, deref_attr_values),
                    )
                )
        if not deref_attrs:
            return None
        ldap_result = self.ldap_conn.search_s(
            self.ldap_conn.search_base,
            ldap0.SCOPE_SUBTREE,
            '(&{0})'.format(''.join(person_filter_parts)),
            attrlist=['1.1'],
        ) or []
        res = {
            res.dn_s.lower()
            for res in ldap_result
        }
        return res
        # end of _constrained_persons()

    def empty_archived_groups(self):
        """
        2. remove all members from archived groups
        """
        msg_id = self.ldap_conn.search(
            self.ldap_conn.search_base,
            ldap0.SCOPE_SUBTREE,
            '(&(objectClass=aeGroup)(aeStatus=2)({0}=*))'.format(MEMBER_ATTR),
            attrlist=[
                'structuralObjectClass',
                MEMBER_ATTR,
            ]+MEMBER_ATTRS,
            attrsonly=True,
        )
        for ldap_results in self.ldap_conn.results(msg_id):
            for group in ldap_results.rdata:
                self.logger.debug('Archived group with members: %r', group.dn_s)
                mod_list = [
                    (ldap0.MOD_DELETE, attr.encode('ascii'), None)
                    for attr in [MEMBER_ATTR] + MEMBER_ATTRS
                    if attr in group.entry_s
                ]
                try:
                    self.ldap_conn.modify_s(group.dn_s, mod_list)
                except ldap0.LDAPError as ldap_error:
                    self.logger.error(
                        'LDAPError modifying %r: %s mod_list = %r',
                        group.dn_s,
                        ldap_error,
                        mod_list,
                    )
                else:
                    self.logger.info(
                        'Removed all member attributes from %r: mod_list = %r',
                        group.dn_s,
                        mod_list,
                    )
        # end of empty_archived_groups()

    def update_memberurl_groups(self):
        """
        3. Update all active aeGroup entries which contain attribute 'memberURL'
        """
        dynamic_groups = self.ldap_conn.search_s(
            self.ldap_conn.search_base,
            ldap0.SCOPE_SUBTREE,
            '(&({0}=*)(aeStatus=0))'.format(MEMBERURL_ATTR),
            attrlist=[
                'aeDept',
                'aeLocation',
                'aeMemberZone',
                'structuralObjectClass',
                MEMBER_ATTR,
                MEMBERURL_ATTR,
            ]+MEMBER_ATTRS,
        )
        for dyn_group in dynamic_groups:

            self.logger.debug('Processing group entry %r ...', dyn_group.dn_s)

            group_object_class = dyn_group.entry_s['structuralObjectClass'][0]
            member_map_attr, member_user_attr = MEMBER_ATTRS_MAP[group_object_class]
            self.logger.debug(
                'group_object_class=%r member_map_attr=%r member_user_attr=%r',
                group_object_class, member_map_attr, member_user_attr
            )

            old_members = set(dyn_group.entry_s.get(MEMBER_ATTR, []))
            old_member_attr_values = set(dyn_group.entry_s.get(member_map_attr, []))
            new_members = set()
            new_member_attr_values = set()

            person_dn_set = self._constrained_persons(dyn_group.entry_s)
            self.logger.debug('person_dn_set = %r', person_dn_set)
            if person_dn_set is None:
                person_filter_part = ''
            else:
                person_filter_part = '(&(objectClass=aeUser)(aePerson=*))'
            self.logger.debug('person_filter_part = %r', person_filter_part)

            for member_url in dyn_group.entry_s[MEMBERURL_ATTR]:

                self.logger.debug('member_url = %r', member_url)
                member_url_obj = ldap0.ldapurl.LDAPUrl(member_url)
                dyn_group_filter = '(&{0}(!(entryDN={1})){2}{3})'.format(
                    member_url_obj.filterstr,
                    dyn_group.dn_s,
                    self._member_zones_filter(dyn_group.entry_s),
                    person_filter_part,
                )
                self.logger.debug('dyn_group_filter = %r', dyn_group_filter)

                if member_url_obj.attrs:
                    server_ctrls = [DereferenceControl(
                        True,
                        {
                            member_url_obj.attrs[0]:[
                                'aeStatus',
                                'aePerson',
                                member_user_attr,
                            ],
                        }
                    )]
                else:
                    server_ctrls = None

                try:
                    msg_id = self.ldap_conn.search(
                        member_url_obj.dn,
                        member_url_obj.scope or ldap0.SCOPE_SUBTREE,
                        dyn_group_filter,
                        attrlist=[
                            'cn',
                            'aeStatus',
                            'aePerson',
                        ]+(member_url_obj.attrs or [])+USER_ATTRS,
                        req_ctrls=server_ctrls,
                    )
                    for ldap_results in self.ldap_conn.results(msg_id):
                        for group in ldap_results.rdata:
                            if (
                                    person_dn_set is not None and
                                    group.entry_s['aePerson'][0].lower() not in person_dn_set
                                ):
                                continue
                            if not member_url_obj.attrs or \
                               member_url_obj.attrs[0].lower() == 'entrydn':
                                member_deref_results = [group]
                            elif member_url_obj.attrs and not group.ctrls:
                                self.logger.debug(
                                    'ignoring empty %r: %r',
                                    group.dn_s,
                                    group.entry_s
                                )
                                continue
                            else:
                                member_deref_results = group.ctrls[0].derefRes[MEMBER_ATTR]
                            for deref_res in member_deref_results:
                                if int(deref_res.entry_s['aeStatus'][0]) <= 0:
                                    new_members.add(deref_res.dn_s)
                                    try:
                                        new_member_attr_values.add(
                                            deref_res.entry_s[member_user_attr][0]
                                        )
                                    except KeyError:
                                        self.logger.error(
                                            'Attribute %r not found in entry %r: %r',
                                            member_user_attr,
                                            deref_res.dn_s,
                                            deref_res.entry_s,
                                        )

                except ldap0.LDAPError as ldap_error:
                    self.logger.error(
                        'LDAPError searching members for %r with %r and %r: %s',
                        dyn_group.dn_s,
                        member_url,
                        dyn_group_filter,
                        ldap_error,
                    )
                    continue

            self._update_members(
                dyn_group.dn_s,
                member_map_attr,
                old_members,
                new_members,
                old_member_attr_values,
                new_member_attr_values
            )
        # end of update_memberurl_groups()

    def run_worker(self, state):
        """
        the main program
        """
        self.logger.debug('invoke empty_archived_groups()')
        self.empty_archived_groups()
        self.logger.debug('invoke update_memberurl_groups()')
        self.update_memberurl_groups()
        self.logger.debug('invoke fix_static_groups()')
        self.fix_static_groups()
        # end of run_worker()
