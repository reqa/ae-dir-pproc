#!/bin/sh

python3 setup.py clean --all
rm -rf MANIFEST .coverage dist/aedir_pproc* build/* *.egg-info .tox .eggs docs/.build/* .mypy_cache
rm -f aedir_pproc/*.py? aedir_pproc/pwd/*.py? tests/*.py? *.py?
find -name __pycache__ | xargs -iname rm -r name
rm -rf slapdtest-[0-9]*
