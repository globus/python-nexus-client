__author__ = 'Mattias Lidman'

import unittest
from nose.plugins.attrib import attr
from nexus.go_rest_client import GlobusOnlineRestClient
from nexus.go_rest_client import UnexpectedRestResponseError


class TestMergedClient(unittest.TestCase):

    def setUp(self):
        # NOTE: shared_secret needs to be filled out to run the tests. Deleted because 
        # it shouldn't be in the commit history of a repo that will later be made public.
        
        self.shared_secret = 'test'
        
        self.config = {
                "cache": {
                    "class": "nexus.token_utils.InMemoryCache",
                    "args": []
                    },
                "server": "graph.api.go.sandbox.globuscs.info",
                "client": "I am not a client",
                "client_secret": "I am not a secret", 
                }

        self.go_rest_client = GlobusOnlineRestClient(config=self.config)
        # Random numbers added to avoid overwriting some real user since these
        # tests may be run against a real server.
        self.default_username = 'mattias32180973219765321905174'

    @attr('functional')
    def test_issue_request(self):
        self.config['server'] = 'www.google.com'
        rest_client = GlobusOnlineRestClient(config=self.config)
        response, content = rest_client._issue_rest_request('')
        self.config['server'] = "graph.api.go.sandbox.globuscs.info"
   
    @attr('go_rest_test')
    def test_user_management(self):
        username = self.default_username
        password = self.go_rest_client.default_password

        # In case the user already exists on the server we're testing against:
        try:
            self.go_rest_client.username_password_login(username)
            self.go_rest_client.delete_user(username)
        except UnexpectedRestResponseError:
            pass

        # Create user using POST. 
        response, content = self.go_rest_client.post_user(username, 
            'Mattias Lidman', 'foo@bar.com', password)
        self.assertEquals(response['status'], '201', msg='Content: ' + str(content))
        self.assertEquals(content['username'], username)
        
        # Test signout
        self.go_rest_client.logout()
        response, content = self.go_rest_client.get_user(username)
        self.assertEquals(response['status'], '403')
        
        # Test signin, wrong password
        response, content = self.go_rest_client.username_password_login(username,
            password='wrong_password')
        self.assertEquals(response['status'], '403')
        
        # Test signin, right password
        response, content = self.go_rest_client.username_password_login(username)
        self.assertEquals(response['status'], '200')
        self.assertEquals(content['username'], username)
        
        # Test editing user and adding some custom fields using PUT.
        params = {'fullname' : 'newFullName', 'email' : 'new@email.com', 'custom_fields' :  
            {'custom_field1' : 'custom value 1', 'custom_field2' : 'custom value 2'}}
        response, content = self.go_rest_client.put_user(username, **params)
        response, content = self.go_rest_client.get_user(username, fields=['fullname', 'email'],
            custom_fields=['custom_field1', 'custom_field2'])
        self.assertEquals(content['fullname'], 'newFullName')
        self.assertEquals(content['email'], 'new@email.com')
        self.assertEquals(content['custom_fields']['custom_field1'], 'custom value 1')
        self.assertEquals(content['custom_fields']['custom_field2'], 'custom value 2')
        
        # Test delete
        self.go_rest_client.username_password_login(username)
        self.go_rest_client.delete_user(username)
        response, content = self.go_rest_client.username_password_login(username)
        self.assertEquals(response['status'], '403')
        
        # Test creating a user with the helper function.
        response, content = self.go_rest_client.simple_create_user(username)
        self.assertEquals(response['status'], '201')
        response, content = self.go_rest_client.username_password_login(username, 'sikrit')
        self.assertEquals(response['status'], '200')

    @attr('go_rest_test')
    def test_user_login_methods(self):
        username = 'testuser'
        password = 'sikrit'

        response, content = self.go_rest_client.get_user(username)
        if response['status'] == '404':
            self.go_rest_client.simple_create_user(username)

        # Test username/password login:
        response, content = self.go_rest_client.get_user(username)
        self.assertEquals(response['status'], '403')
        response, content = self.go_rest_client.username_password_login(
            username, password=password)
        self.assertEquals(response['status'], '200')
        response, content = self.go_rest_client.get_user(username)
        self.assertEquals(response['status'], '200')

        # Get user's OAuth secret, then logout:
        response, content = self.go_rest_client.get_user_secret(username)
        self.assertEquals(response['status'], '200')
        secret = content['secret']
        self.go_rest_client.logout()
        response, content = self.go_rest_client.get_user(username)
        self.assertEquals(response['status'], '403')

        # Test login using OAuth headers:
        response, content = self.go_rest_client.username_oauth_secret_login(
            username, secret)
        self.assertEquals(response['status'], '200')
        response, content = self.go_rest_client.get_user(username)
        self.assertEquals(response['status'], '200')
        self.go_rest_client.logout()
        response, content = self.go_rest_client.get_user(username)
        self.assertEquals(response['status'], '403')

