__author__ = 'Mattias Lidman'

import unittest
from nose.plugins.attrib import attr
from nexus.go_rest_client import GlobusOnlineRestClient
from nexus.go_rest_client import UnexpectedRestResponseError
from test_config_file import config

class TestMergedClient(unittest.TestCase):

    def setUp(self):
        # NOTE: shared_secret needs to be filled out to run the tests. Deleted because 
        # it shouldn't be in the commit history of a repo that will later be made public.
        
        self.shared_secret = 'test'
        
        self.config = config

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
            'Mattias Lidman', 'testuseremail100@gmail.com', password)
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
        response, content = self.go_rest_client.post_user(username, 'Test User', 'testuseremail100@gmail.com', 'sikrit')
        self.assertEquals(response['status'], '201')
        response, content = self.go_rest_client.username_password_login(username, 'sikrit')
        self.assertEquals(response['status'], '200')

    @attr('go_rest_test')
    def test_user_login_methods(self):
        username = 'testuser'
        password = 'sikrit'

        response, content = self.go_rest_client.get_user(username)
        if response['status'] == '404':
            self.go_rest_client.post_user(username, 'Test User', 'testuseremail100@gmail.com', 'sikrit') 

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

    @attr('go_rest_test')
    def test_rsa_key_methods(self):
        username = 'testuser'
        password = 'sikrit'
        key_alias = 'test_key'


        self.go_rest_client.username_password_login(username, password)

        with open('test_rsa_key.pub') as key_file:
                rsa_key = key_file.readline()

        # Test posting an rsa_key
        response, content = self.go_rest_client.post_rsa_key(key_alias, rsa_key=rsa_key)
        self.assertEquals(response['status'], '201')

        # Test getting the rsa_key_list()
        response, content = self.go_rest_client.get_rsa_key_list()
        self.assertEquals(response['status'], '200')

        key_id = None
        for key in content:
            if key['alias'] == key_alias and key['ssh_key'] == rsa_key:
                key_id = key['credential_key']
        self.assertIsNotNone(key_id, msg="Couldn't find the posted rsa_key in the key list")

        # Test deleting an rsa_key
        response, content = self.go_rest_client.delete_rsa_key(key_id)
        self.assertEquals(response['status'], '200')

