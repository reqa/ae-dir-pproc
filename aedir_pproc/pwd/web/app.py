# -*- coding: ascii -*-
"""
aedir_pproc.pwd.web.app - the application entry point
"""

import os
import logging
import logging.config

from werkzeug.middleware.proxy_fix import ProxyFix

import flask.logging
from flask import Flask

from . import validate_config, HTTP_HEADERS
from .views import (
    Default,
    CheckPassword,
    ChangePassword,
    RequestPasswordReset,
    FinishPasswordReset,
    ViewUser,
)

def create_app(test_config=None):
    """
    initialize Flask instance
    """
    _app = Flask(
        __name__,
        template_folder='templates',
    )

    # initialize config
    _app.config.from_object('{0}.settings'.format(__name__.rsplit('.', 1)[0]))
    _app.config.from_envvar('AEDIRPWD_CFG', silent=False)

    _app.secret_key = _app.config['APP_SECRET']

    # initialize logging
    if _app.config['LOG_NAME'] is not None:
        _app.logger.name = _app.config['LOG_NAME']
    if _app.config['LOG_CONFIG'] is not None:
        if os.path.isfile(_app.config['LOG_CONFIG']):
            logging.config.fileConfig(_app.config['LOG_CONFIG'], disable_existing_loggers=True)
            _app.logger.removeHandler(flask.logging.default_handler)
            _app.logger.debug('Loaded logging config from %s', _app.config['LOG_CONFIG'])
        else:
            _app.logger.warning('No logging config file %s', _app.config['LOG_CONFIG'])
    if 'LOG_LEVEL' in os.environ:
        _app.logger.setLevel(os.environ['LOG_LEVEL'].upper())

    validate_config(_app.config)

    _app.template_folder = _app.config['TEMPLATES_DIRNAME']

    # URL routing
    _app.add_url_rule(
        '/',
        view_func=Default.as_view('default'),
        methods=('GET',),
    )
    _app.add_url_rule(
        '/checkpw',
        view_func=CheckPassword.as_view('checkpw'),
        methods=('GET', 'POST'),
    )
    _app.add_url_rule(
        '/changepw',
        view_func=ChangePassword.as_view('changepw'),
        methods=('GET', 'POST'),
    )
    _app.add_url_rule(
        '/requestpw',
        view_func=RequestPasswordReset.as_view('requestpw'),
        methods=('GET', 'POST'),
    )
    _app.add_url_rule(
        '/resetpw',
        view_func=FinishPasswordReset.as_view('resetpw'),
        methods=('GET', 'POST'),
    )
    _app.add_url_rule(
        '/viewuser',
        view_func=ViewUser.as_view('viewuser'),
        methods=('GET', 'POST'),
    )

    if _app.config['PROXY_LEVEL'] > 0:
        # see https://werkzeug.palletsprojects.com/en/1.0.x/middleware/proxy_fix/
        _app.logger.info('Using ProxyFix wrapper with %d proxy layers', _app.config['PROXY_LEVEL'])
        _app.wsgi_app = ProxyFix(
            _app.wsgi_app,
            x_for=_app.config['PROXY_LEVEL'],
            x_proto=_app.config['PROXY_LEVEL'],
            x_host=_app.config['PROXY_LEVEL'],
        )

    @_app.after_request
    def add_headers(response):
        """
        add HTTP headers to response
        """
        for header, value in HTTP_HEADERS:
            response.headers[header] = value
        return response

    return _app
