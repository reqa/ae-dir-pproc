# -*- coding: ascii -*-
"""
aedir_pproc.pwd.web - password self-service web application
"""

import os
import logging
import logging.config
from urllib.parse import quote_plus as url_quote_plus

#---------------------------------------------------------------------------
# constants
#---------------------------------------------------------------------------

# more complex HTTP security header values
HTTP_CSP_HEADER = ' '.join((
    "base-uri 'none';",
    "child-src 'none';",
    "connect-src 'none';",
    "default-src 'none';",
    "font-src 'self';",
    "form-action 'self';",
    "frame-ancestors 'none';",
    "frame-src 'none';",
    "img-src 'self' data:;",
    "media-src 'none';",
    "object-src 'none';",
    "script-src 'none';",
    "style-src 'self';",
    "require-trusted-types-for 'script';",
))
HTTP_PERMISSIONS_POLICY_HEADER = ', '.join((
    'accelerometer=(none)',
    'ambient-light-sensor=(none)',
    'camera=(none)',
    'clipboard-read=(none)',
    'clipboard-write=(none)',
    'display-capture'
    'geolocation=(none)',
    'gyroscope=(none)',
    'magnetometer=(none)',
    'microphone=(none)',
    'midi=(none)',
    'notifications=(none)',
    'push=(none)',
    'speaker-selection=(none)',
))

HTTP_HEADERS = (
    ('Cache-Control', 'no-store,no-cache,max-age=0,must-revalidate'),
    ('X-XSS-Protection', '1; mode=block'),
    ('X-DNS-Prefetch-Control', 'off'),
    ('X-Content-Type-Options', 'nosniff'),
    ('X-Frame-Options', 'deny'),
    ('Server', 'unknown'),
    ('Content-Security-Policy', HTTP_CSP_HEADER),
    ('X-Webkit-CSP', HTTP_CSP_HEADER),
    ('X-Content-Security-Policy', HTTP_CSP_HEADER),
    ('Referrer-Policy', 'same-origin'),
    ('Permissions-Policy', HTTP_PERMISSIONS_POLICY_HEADER),
    ('Cross-Origin-Embedder-Policy', 'require-corp'),
    ('Cross-Origin-Opener-Policy', 'same-origin'),
    ('Cross-Origin-Resource-Policy', 'same-site'),
)

#---------------------------------------------------------------------------
# basic functions and classes
#---------------------------------------------------------------------------

class RequestLogAdaptor(logging.LoggerAdapter):
    """
    wrapper for adding more request-specific information to log messages
    """

    def process(self, msg, kwargs):
        return (
            'IP=%s CLASS=%s REQID=%d - %s' % (
                self.extra['remote_ip'],
                self.extra['req_class'],
                self.extra['req_id'],
                msg,
            ),
            kwargs,
        )


def validate_config(cfg):
    """
    validate some config parameters
    """
    # Safety check for URL chars
    if cfg['PWD_TMP_CHARS'] != url_quote_plus(cfg['PWD_TMP_CHARS']):
        raise ValueError(
            'URL special chars in PWD_TMP_CHARS: %r' % (cfg['PWD_TMP_CHARS'],)
        )
