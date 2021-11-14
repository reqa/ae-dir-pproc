# -*- coding: ascii -*-
"""
aedir_pproc.pwd.cron -- CRON run entry point
"""

from .expreset import AEPwdResetExpiration
from .welcome import AEWelcomeMailer


def main():
    """
    run processes
    """
    with AEPwdResetExpiration() as ae_expreset_process:
        ae_expreset_process.run(max_runs=1)
    with AEWelcomeMailer() as ae_welcome_mailer:
        ae_welcome_mailer.run(max_runs=1)


if __name__ == '__main__':
    main()
