# -*- coding: utf-8 -*-
"""
package/install aedir_pproc
"""

import sys
import os
from setuptools import setup, find_packages

PYPI_NAME = 'aedir_pproc'

BASEDIR = os.path.dirname(os.path.realpath(__file__))

sys.path.insert(0, os.path.join(BASEDIR, PYPI_NAME))
import __about__

setup(
    name=PYPI_NAME,
    license=__about__.__license__,
    version=__about__.__version__,
    description='Tools for status, group and attrs updates in AE-DIR',
    author=__about__.__author__,
    author_email=__about__.__mail__,
    maintainer=__about__.__author__,
    maintainer_email=__about__.__mail__,
    url='https://www.ae-dir.com/',
    download_url='https://pypi.org/project/%s/#files' % (PYPI_NAME),
    keywords=['LDAP', 'LDAPv3', 'OpenLDAP', 'AE-DIR', 'Æ-DIR'],
    packages=find_packages(exclude=['tests']),
    package_dir={'': '.'},
    test_suite='tests',
    python_requires='>=3.6',
    include_package_data=True,
    data_files=[],
    install_requires=[
        'setuptools',
        'aedir>=1.3.1',
        'mailutil>=0.4.0',
        'web.py>=0.40',
    ],
    zip_safe=False,
)
