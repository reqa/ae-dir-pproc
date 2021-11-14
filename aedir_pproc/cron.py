# -*- coding: ascii -*-
"""
aedir_pproc.cron - CRON run entry point
"""

import sys

from .update import AEObjectUpdater
from .groups import AEGroupUpdater


def main():
    """
    run the process
    """
    with AEObjectUpdater(sys.argv[1]) as ae_object_updater:
        ae_object_updater.run(max_runs=1)
    with AEGroupUpdater() as ae_group_updater:
        ae_group_updater.run(max_runs=1)


if __name__ == '__main__':
    main()
