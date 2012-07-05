"""
Client for interacting with Nexus.
"""
from datetime import datetime
import time
import logging
import urllib
import urlparse

import yaml
import nexus.token_utils as token_utils

log = logging.getLogger()

class NexusClient(object):
    """
    Root object for interacting with the Nexus service
    """

    def __init__(self, config=None, config_file=None):
        if config_file is not None:
            with open(config_file, 'r') as cfg:
                config = yaml.load(cfg.read())
        elif config is not None:
            self.config = config
        else:
            raise AttributeError("No configuration was specified")
        self.server = config['server']
        cache_config = self.config.get('cache', {
                    'class': 'nexus.token_utils.InMemoryCache',
                    'args': [],
                    })
        self.api_key = config['api_key']
        self.api_secret = config['api_secret']
        cache_class = cache_config['class']
        self.verify_ssl = config.get('verify_ssl', True)
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
