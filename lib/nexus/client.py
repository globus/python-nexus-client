"""
Client for interacting with Nexus.
"""
import logging

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
        self.authorize_url = config['authorize_url']
        cache_config = self.config.get('cache', {
                    'class': 'nexus.token_utils.InMemoryCache',
                    'args': [],
                    })
        cache_class = cache_config['class']
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
            token_utils.validate_token(token, self.cache)
            return True
        except ValueError:
            log.exception("ValueError")
            return False

