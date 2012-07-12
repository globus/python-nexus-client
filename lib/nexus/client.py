"""
Client for interacting with Nexus.
"""
import base64
from datetime import datetime
import hashlib
import json
import logging
from subprocess import Popen, PIPE
import time
import urllib
import urlparse

import yaml
import nexus.token_utils as token_utils
from nexus.utils import (
        read_openssh_public_key,
        read_openssh_private_key,
        canonical_time,
        b64encode,
        sha1_base64)
import requests
import rsa

log = logging.getLogger()

class NexusClient(object):
    """
    Root object for interacting with the Nexus service
    """

    def __init__(self, config=None, config_file=None):
        if config_file is not None:
            with open(config_file, 'r') as cfg:
                self.config = yaml.load(cfg.read())
        elif config is not None:
            self.config = config
        else:
            raise AttributeError("No configuration was specified")
        self.server = self.config['server']
        cache_config = self.config.get('cache', {
                    'class': 'nexus.token_utils.InMemoryCache',
                    'args': [],
                    })
        self.api_key = self.config['api_key']
        self.api_secret = self.config['api_secret']
        cache_class = cache_config['class']
        self.verify_ssl = self.config.get('verify_ssl', True)
        mod_name = '.'.join(cache_class.split('.')[:-1])
        mod = __import__(mod_name)
        for child_mod_name in mod_name.split('.')[1:]:
            mod = getattr(mod, child_mod_name)
        cache_impl_class = getattr(mod, cache_class.split('.')[-1])
        self.cache = cache_impl_class(*cache_config.get('args', []))
        self.cache = token_utils.LoggingCacheWrapper(self.cache)

    def authenticate_user(self, token):
        """
        Authenticate a user based on the token they provide.

        :param token: An authentication token provided by the client.

        :return: True if the authentication is valid, else False
        """
        try:
            return token_utils.validate_token(token, self.cache, self.verify_ssl)
        except ValueError:
            log.exception("ValueError")
            return None

    def generate_request_url(self, username=None):
        """
        In order for the user to authorize the client to access his data, he
        must first go to the custom url provided here.

        :param username: (Optional) This will pre-populate the user's info in the form

        :return: A custom authorization url
        """
        query_params = {
                "response_type": "code",
                "client_id": self.api_key,
                }
        if username is not None:
            query_params['username'] = username
        parts = ('https', self.server, '/authorize',
                urllib.urlencode(query_params), None)
        return urlparse.urlunsplit(parts)

    def get_access_token_from_code(self, code):
        """
        After receiving a code from the end user, this method will acquire an
        access token from the server which can be used for subsequent requests.

        :param code: The code which the user received after authenticating with the server and authorizing the client.

        :return: Tuple containing (access_token, refresh_token, expire_time)
        """
        url_parts = ('https', self.server, '/token', None, None)
        result = token_utils.request_access_token(self.api_key,
                self.api_secret, code, urlparse.urlunsplit(url_parts))
        return (
                result.access_token,
                result.refresh_token,
                time.mktime(datetime.utcnow().timetuple()) + result.expires_in
                )

    def request_access_token(self, password=None):
        """
        This is designed to support section 4.4 of the OAuth 2.0 spec:

        "The client can request an access token using only its client
         credentials (or other supported means of authentication) when the
         client is requesting access to the protected resources under its
         control"
        """
        key_file = self.config.get('private_key_file', '~/.ssh/id_rsa')
        private_key = read_openssh_private_key(key_file, password)
        headers = {
            'X-Nexus-UserId': self.api_key,
            'X-Nexus-Sign': '1.0',
        }
        timestamp = canonical_time(datetime.now())
        headers['X-Nexus-Timestamp'] = timestamp
        body = 'grant_type=client_credentials'
        hashed_body = base64.b64encode(hashlib.sha1(body).digest())
        path = '/token'
        hashed_path = base64.b64encode(hashlib.sha1(path).digest())
        method = 'POST'
        to_sign = ("Method:{0}\n"
            "Hashed Path:{1}\n"
            "X-Nexus-Content-Hash:{2}\n"
            "X-Nexus-Timestamp:{3}\n"
            "X-Nexus-UserId:{4}")
        to_sign = to_sign.format(method,
                hashed_path,
                hashed_body,
                headers['X-Nexus-Timestamp'],
                headers['X-Nexus-UserId'])
        print to_sign
        value = rsa.sign(to_sign, private_key, 'SHA-256')
        sig = b64encode(value)
        string_sig = ""
        for i, line in enumerate(sig):
            string_sig = string_sig + line
            headers['X-Nexus-Authorization-{0}'.format(i)] = line
        url_parts = ('https', self.server, '/token', None, None)
        url = urlparse.urlunsplit(url_parts)
        response = requests.post(url, data={'grant_type':
            'client_credentials'}, headers=headers, verify=self.verify_ssl)
        return response

