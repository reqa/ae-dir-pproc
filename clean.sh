#!/bin/sh

python setup.py clean --all
rm -r MANIFEST .coverage dist/aedir_pproc* build/* *.egg-info .tox .eggs docs/.build/*
rm aedir_pproc/*.py? aedir_pproc/pwd/*.py? tests/*.py? *.py?
find -name __pycache__ | xargs -n1 -iname rm -r name
rm -r slapdtest-[0-9]*
