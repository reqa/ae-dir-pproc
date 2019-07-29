# -*- coding: utf-8 -*-
"""
Module package aedir_update

Author: Michael Ströder <michael@stroeder.com>
"""

from __future__ import absolute_import

from .__about__ import __version__, __author__, __license__

import os

# set LDAPRC env var *before* importing ldap0
os.environ['LDAPRC'] = '/opt/ae-dir/etc/ldap.conf'

# from ldap0 package
import ldap0
