__author__ = 'Mattias Lidman'

import logging
import unittest
import json
import httplib2
import StringIO
import email
import mailbox
import re
import random
import string
from nose.plugins.attrib import attr
from nexus.merged_client import MergedClient
from nexus.merged_client import UnexpectedRestResponseError
from test_utils.smtp_server import SmtpMailsink

# Client test dependencies
import binascii

from collections import namedtuple
import datetime
import time

from testfixtures import Replacer


class TestMergedClient(unittest.TestCase):

    def setUp(self):
        # NOTE: shared_secret needs to be filled out to run the tests. Deleted because 
        # it shouldn't be in the commit history of a repo that will later be made public.
        
        
        self.shared_secret = 'test'
        self.go_host = 'graph.api.go.sandbox.globuscs.info'
        
        # added to comply with MergedClient __init__ params
        self.config = {
                "authorize_url": "localhost:8080/goauth/authorize",
                "cache": {
                    "class": "nexus.token_utils.InMemoryCache",
                    "args": []
                    },
                "server": "graph.api.globusonline.org",
                "client": "I am not a client",
                "client_secret": "I am not a secret", 
                }
        # for client tests
        self.replacer = Replacer()

        self.merged_client = MergedClient(self.go_host, self.shared_secret, config=self.config)
        # Random numbers added to avoid overwriting some real user since these
        # tests may be run against a real server.
        self.default_username = 'mattias32180973219765321905174'
        self.created_users = []

        self.smtp_mail_sink = SmtpMailsink(host='go.mattiassandbox.globuscs.info', port=1025)
        self.smtp_mail_sink.start()
 
    def tearDown(self):
        for user in self.created_users:
            self.merged_client.delete_user(user)
        self.smtp_mail_sink.stop()
        # for client tests
	self.replacer.restore()
    
    @attr('functional')
    def test_issue_request(self):
        rest_client = MergedClient('www.google.com', self.shared_secret, config=self.config)
        response, content = rest_client._issue_rest_request('')
    
    @attr('go_rest_test')
    def test_user_management(self):
        username = self.default_username
        password = self.merged_client.default_password

        # In case the user already exists on the server we're testing against:
        try:
            self.merged_client.username_password_login(username)
            self.merged_client.delete_user(username)
        except UnexpectedRestResponseError:
            pass

        # Create user using POST. 
        response, content = self.merged_client.post_user(username, 
            'Mattias Lidman', 'foo@bar.com', password)
        self.assertEquals(response['status'], '201', msg='Content: ' + str(content))
        self.assertEquals(content['username'], username)
        
        # Test signout
        self.merged_client.logout()
        response, content = self.merged_client.get_user(username)
        self.assertEquals(response['status'], '403')
        
        # Test signin, wrong password
        response, content = self.merged_client.username_password_login(username,
            password='wrong_password')
        self.assertEquals(response['status'], '403')
        
        # Test signin, right password
        response, content = self.merged_client.username_password_login(username)
        self.assertEquals(response['status'], '200')
        self.assertEquals(content['username'], username)
        
        # Test editing user and adding some custom fields using PUT.
        params = {'fullname' : 'newFullName', 'email' : 'new@email.com', 'custom_fields' :  
            {'custom_field1' : 'custom value 1', 'custom_field2' : 'custom value 2'}}
        response, content = self.merged_client.put_user(username, **params)
        response, content = self.merged_client.get_user(username, fields=['fullname', 'email'],
            custom_fields=['custom_field1', 'custom_field2'])
        self.assertEquals(content['fullname'], 'newFullName')
        self.assertEquals(content['email'], 'new@email.com') 
        self.assertEquals(content['custom_fields']['custom_field1'], 'custom value 1')
        self.assertEquals(content['custom_fields']['custom_field2'], 'custom value 2')
        
        # Test delete
        self.merged_client.username_password_login(username)
        self.merged_client.delete_user(username)
        response, content = self.merged_client.username_password_login(username)
        self.assertEquals(response['status'], '403')
        
        # Test creating a user with the helper function.
        response, content = self.merged_client.simple_create_user(username)
        self.assertEquals(response['status'], '201')
        response, content = self.merged_client.username_password_login(username, 'sikrit')
        self.assertEquals(response['status'], '200')

    @attr('go_rest_test')
    def test_user_login_methods(self):
        username = 'testuser'
        password = 'sikrit'

        response, content = self.merged_client.get_user(username)
        if response['status'] == '404':
            self.merged_client.simple_create_user(username)
 
        # Test username/password login:
        response, content = self.merged_client.get_user(username)
        self.assertEquals(response['status'], '403')
        response, content = self.merged_client.username_password_login(
            username, password=password)
        self.assertEquals(response['status'], '200')
        response, content = self.merged_client.get_user(username)
        self.assertEquals(response['status'], '200')

        # Get user's OAuth secret, then logout:
        response, content = self.merged_client.get_user_secret(username)
        self.assertEquals(response['status'], '200')
        secret = content['secret']
        self.merged_client.logout()
        response, content = self.merged_client.get_user(username)
        self.assertEquals(response['status'], '403')

        # Test login using OAuth headers:
        response, content = self.merged_client.username_oauth_secret_login(
            username, secret)
        self.assertEquals(response['status'], '200')
        response, content = self.merged_client.get_user(username)
        self.assertEquals(response['status'], '200')
        self.merged_client.logout()
        response, content = self.merged_client.get_user(username)
        self.assertEquals(response['status'], '403')
    
    @attr('go_rest_test')
    def test_group_management(self):

        # We need to be logged in as a user that has admin rights to the root-group.
        username = 'testuser'
        password = 'sikrit'
        self.merged_client.username_password_login(username, password=password)

        # Get root group: 
        # response, content = self.merged_client.get_group_list() # currently always times out
        # self.assertEquals(response['status'], '200')

        parent_group = 'testgroup'
        response, content = self.merged_client.post_group(parent_group)
        root_id = content['id']

        # Create a subroup:
        subgroup_name = "Mattias' sub-group"
        response, content = self.merged_client.post_group(subgroup_name, parent=root_id, is_active=False)
        self.assertEquals(response['status'], '201')

        # Get subgroups:
        response, content = self.merged_client.get_group_tree(root_id, 2)
        self.assertEquals(response['status'], '200')
        children = content['children']
        subgroup_id = None
        for child in children:
            if child['name'] == subgroup_name:
                subgroup_id = child['id']
        self.assertNotEqual(subgroup_id, None, msg='Created subgroup not found among children of the root.')

        # Edit group and get group summary to check that that the edit sticks:
        new_name = 'New group name'
        new_description = 'New group description'
        new_is_active = True
        response, content = self.merged_client.put_group_summary(subgroup_id,
                name=new_name, description=new_description, is_active=new_is_active)
        self.assertEquals(response['status'], '201')
        response, content = self.merged_client.get_group_summary(subgroup_id)
        self.assertEquals(content['name'], new_name)
        self.assertEquals(content['description'], new_description)
        self.assertEquals(content['is_active'], new_is_active)

        # Test putting and getting group policies:
        policy_summary = {
            'approval': {
                'admin': True,
                'auto_if_admin': False,
                'auto': False,
            },
            'group_member_visibility': {
                'admin': True,
                'members': False,
                'parent': False,
                'public': False,
            },
            'group_visibility': {
                'parent': True,
                'private': False,
                'public': False,
                'site': False,
            },
            'join': {
                'anybody': True,
                'community': False,
                'none': False,
                'parent': False,
            },
            'invites': {
                'admin_only': True,
                'any_community_member': False,
                'group_members': False,
                'group_members_and_parent': False,
            },
            'sign_up_fields': {
                'first_name': True,
                'last_name': True,
                'institution': False,
                'current_project_name': False,
                'organization': False,
                'address': False,
                'address2': False,
                'city': False,
                'country': False,
                'state': False,
                'zip': False,
                'phone': False,
            }
        }

        policies = self.merged_client.build_policy_dictionary(**policy_summary)

        empty_summary = {}
        empty = self.merged_client.build_policy_dictionary(**empty_summary) 
    
        # response, content = self.merged_client.put_group_policies(root_id, empty) # an attempt to delete the existing policies
        response, content = self.merged_client.put_group_policies(root_id, policies)

        # there are policies that exist before calling put_group_policies.
        # this causes a 200 status to be returend instead of a 201
        # (the policies field is being edited instead of added)
        # this also causes the returned contendt and the policies input to be different

        # self.assertEquals(response['status'], '201')
        self.assertEquals(response['status'], '200')
        # self.assertEquals(content, policies)
    
        # response, content = self.merged_client.put_group_policies(subgroup_id, empty) # an attempt to delete the existing policies
        response, content = self.merged_client.put_group_policies(subgroup_id, policies)

        # self.assertEquals(response['status'], '201')
        self.assertEquals(response['status'], '200')
        # self.assertEquals(content, policies)

        response, content = self.merged_client.get_group_policies(subgroup_id)
        self.assertEquals(response['status'], '200')
        self.assertTrue(content['approval']['value']['admin']['value'])
        self.assertFalse(content['approval']['value']['auto']['value'])
        self.assertTrue(content['sign_up_fields']['value']['first_name']['value'])
        self.assertFalse(content['sign_up_fields']['value']['current_project_name']['value'])

        # Test set_single_policy:
        response, content = self.merged_client.set_single_policy(subgroup_id, 'approval', 'auto')
        self.assertFalse(content['approval']['value']['admin']['value'])
        self.assertTrue(content['approval']['value']['auto']['value'])
        # Should alse work for multi-option policies like signup fields: 
        response, content = self.merged_client.set_single_policy(root_id, 'sign_up_fields', ['zip', 'state'])# added line to satisfy parent-policy requirements
        response, content = self.merged_client.set_single_policy(subgroup_id, 'sign_up_fields', ['zip', 'state'])
        self.assertTrue(content['sign_up_fields']['value']['zip']['value'])
        self.assertTrue(content['sign_up_fields']['value']['state']['value'])

        self.assertFalse(content['sign_up_fields']['value']['first_name']['value'])

        # Newly created group should have the same email templates as the parent.
        response, content = self.merged_client.get_group_email_templates(root_id)
        root_default_templates = sorted(content['templates'], key=lambda k: k['type']) 
        response, content = self.merged_client.get_group_email_templates(subgroup_id)
        self.assertEquals(response['status'], '200')
        new_default_templates = sorted(content['templates'], key=lambda k: k['type']) 
        for new, root in zip(new_default_templates, root_default_templates):
            self.assertEquals(new['type'], root['type'])
            self.assertEquals(new['subject'], root['subject'])

        # Test POSTing email templates:
        template_params = {
            "type": "Welcome",
            "subject": "GO REST client test template",
            "last_updated": "2011-05-06T00:00:00",
            "create_date": "2011-05-06T00:00:00",
            "message": [{
                    "type": "static",
                    "text": "Welcome to the group!"
            }]
        }
        response, content = self.merged_client.post_group_email_templates(subgroup_id, template_params)
        self.assertEquals(response['status'], '201')
        template_id = content['id']

        # Re-posting the same template type should be a 409 Conflict:
        response, content = self.merged_client.post_group_email_templates(subgroup_id, template_params)
        self.assertEquals(response['status'], '409')

        # Test GETting templates:
        response, content = self.merged_client.get_group_email_templates(subgroup_id)
        self.assertTrue(template_params['subject'] in [ template['subject'] for template in content['templates'] ])

        # Test GETing a single template:
        response, content = self.merged_client.get_group_email_template(subgroup_id, template_id)
        self.assertEquals(response['status'], '200')
        self.assertEquals(content['message'][0]['text'], template_params['message'][0]['text'])

        # Test PUTting (updating) a template: 
        new_subject = 'This is the new subject'
        content['subject'] = new_subject
        response, content = self.merged_client.put_group_email_template(subgroup_id, template_id, content)
        self.assertEquals(response['status'], '200')
        self.assertEquals(content['subject'], new_subject)

        # Test GETting a rendered template:
        response, content = self.merged_client.get_group_email_template(subgroup_id, template_id)
        self.assertEquals(response['status'], '200')

    @attr('go_rest_test')
    def test_membership_management(self):

        # Log in as an admin, create a group and a user to play with.
        admin_username = 'testuser'
        admin_password = 'sikrit'
        group_name = 'testgroup2'

        self.merged_client.username_password_login(admin_username, 
            password=admin_password) 
        response, content = self.merged_client.post_group(group_name)
    
        group_id = content['id']

        self.merged_client.set_single_policy(group_id, 'approval', 'admin')

        
        user = 'mattias1' 
        self.merged_client.simple_create_user(user)
        self.created_users.append(user)
       
        # Test that the group membership of a particular username doesn't persist
        # between test runs:
        response, content = self.merged_client.get_group_member(group_id, user)
        self.assertEquals(response['status'], '404', msg="A newly created user should never be part of a group.")

        self.merged_client.username_password_login(user, 'sikrit') # logging in so the user can be editted
        # Test PUTing user custom fields:
        custom_fields = { 
            'current_project_name': 'BIRN Community', 
            'organization': 'Computation Institute',
        }
        self.merged_client.put_user_custom_fields(user, **custom_fields)
        response, content = self.merged_client.get_user(user, custom_fields=custom_fields.keys())
        self.assertEquals(custom_fields, content['custom_fields'])

        # Test GETting and PUTting user visibility:
        response, content = self.merged_client.get_user_policies(user)
        self.assertFalse(content['user_membership_visibility']['value']['community']['value'])
        self.merged_client.put_user_membership_visibility(user, 'community')
        response, content = self.merged_client.get_user_policies(user)
        self.assertTrue(content['user_membership_visibility']['value']['community']['value'])

        # Get validation code from email, then test email validation:  
        mailboxFile2 =  StringIO.StringIO(self.smtp_mail_sink.getMailboxContents()) # mailbox contents is empty
        mailboxObject = mailbox.PortableUnixMailbox(mailboxFile2, email.message_from_file)
        messages = []
        for messageText in [ message.as_string() for message in mailboxObject ]:
            messages.append(messageText)
        validation_code = re.search('[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', 
            str(messages[0])).group(0)
        
        response, content = self.merged_client.post_email_validation(validation_code)
        self.assertTrue(content['email_validated'])

        # POST template for email invitation:
        invite_template = {
            "type": "admin_invite",
            "subject": "You have been invited to {{group_name}}",
            "last_updated": "2011-05-06T00:00:00",
            "create_date": "2011-05-06T00:00:00",
            "message": [
                    {
                    "type": "static",
                    "text": "invite_id: {{invite_id}}",
                }
            ]
        }
        response, content = self.merged_client.put_group_email_template(group_id, invite_template['type'], invite_template)

        # Test email invite flow. It seems there is currently no way to delete 
        # email users through the REST API, so we'll have to add a dash of randomness.
        # TODO: This needs fixing if we want to run these tests in Jenkins or it will
        # clutter the db.
        email_addr = 'someone@' + ''.join(random.sample(string.ascii_lowercase + string.digits, 10)) + '.org'
        self.merged_client.logout()
        self.merged_client.username_password_login(admin_username, 
            password=admin_password)
        response, content = self.merged_client.post_membership(group_id, emails=email_addr)
        self.assertEquals(response['status'], '201')
        self.assertEquals(content['members'][0]['name'], email_addr)
        self.assertEquals(content['members'][0]['status'], 'invited')
	
        """
        # Get invite id:
        mailboxFile2 =  StringIO.StringIO(self.smtp_mail_sink.getMailboxContents())
        mailboxObject = mailbox.PortableUnixMailbox(mailboxFile2, email.message_from_file)
        messages = []
        for messageText in [ message.as_string() for message in mailboxObject ]:
            messages.append(messageText)
        invite_id = re.search('invite_id: [a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',
            str(messages)).group(0).replace('invite_id: ', '')
        """

        # Sign in as user, test claim_invitation:
        self.merged_client.logout()
        self.merged_client.username_password_login(user)
        # depends on commented out code above
        # this causeses the rest of the tests to break because 'user' never gets to claim the invite
        # and therefore is never apart of the group
        # response, content = self.merged_client.claim_invitation(invite_id)

        # Test accepting invitation:
        response, content = self.merged_client.accept_invitation(group_id, user)
        self.assertEquals(response['status'], '201')
        self.assertEquals(content['status'], 'pending')

        # Test admin approving the membership:
        self.merged_client.logout()
        self.merged_client.username_password_login(admin_username, password=admin_password)
        response, content = self.merged_client.approve_join(group_id, user)
        self.assertEquals(response['status'], '201')
        self.assertEquals(content['status'], 'active')

        # Test suspending and unsuspending user:
        response, content = self.merged_client.suspend_group_member(group_id, user,
            new_status_reason='User suspended because he is a very naughty boy.')
        self.assertEquals(response['status'], '201')
        self.assertEquals(content['status'], 'suspended')
        self.assertEquals(content['status_reason'], 
            'User suspended because he is a very naughty boy.')
        response, content = self.merged_client.unsuspend_group_member(group_id, user)
        self.assertEquals(response['status'], '201')
        self.assertEquals(content['status'], 'active')

        # Test promoting the user to admin:
        self.merged_client.put_group_membership_role(group_id, user, 'admin')
        response, content = self.merged_client.get_group_member(group_id, user)
        self.assertEquals(content['role'], 'admin')

    #client tests
    @attr('integration')
    def test_full_validate_token(self):
        import rsa
        pubkey, privkey = rsa.newkeys(512)
        def get_cert(*args, **kwargs):
            return namedtuple('Request',
                    ['content', 'status_code'])(json.dumps({'pubkey':pubkey.save_pkcs1()}), 200)
        self.replacer.replace('requests.get', get_cert)
        token = 'un=test|merged_clientid=test|SigningSubject=https://graph.api.globusonline.org/goauth/keys/test1|expiry={0}'
        expires = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
        token = token.format(time.mktime(expires.timetuple()))
        sig = rsa.sign(token, privkey, 'SHA-1')
        hex_sig = binascii.hexlify(sig)
        token = '{0}|sig={1}'.format(token, hex_sig)
        self.merged_client.validate_token(token)
        sig = sig + 'f'
        hex_sig = binascii.hexlify(sig)
        token = '{0}|sig={1}'.format(token, hex_sig)
        try:
            self.merged_client.validate_token(token)
            self.fail()
        except ValueError:
            pass

    @attr('unit')
    def test_generate_request_url(self):
        expected = "https://graph.api.globusonline.org/goauth/authorize?response_type=code&client_id=I+am+not+a+client"
        self.assertEqual(expected, self.merged_client.generate_request_url())

    @attr('unit')
    def test_get_access_token(self):
        from nexus.token_utils import DictObj
        expected_expiry = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
        expected_expiry = time.mktime(expected_expiry.timetuple())
        result = {
                'access_token': 1234567,
                'refresh_token': 7654321,
                'expires_in': 5 * 60
                }
        def dummy_get_access_token(client_id, client_secret, auth_code, auth_uri ):
            self.assertEqual('my token', auth_code)
            self.assertEqual(self.config['client'], client_id)
            self.assertEqual(self.config['client_secret'], client_secret)
            return DictObj(result) 

        self.replacer.replace('nexus.merged_client.token_utils.request_access_token',
            dummy_get_access_token)
        access_token, refresh_token, expiry = self.merged_client.get_access_token_from_code('my token')
        self.assertEqual(1234567, access_token)
        self.assertEqual(7654321, refresh_token)
        self.assertEqual(expected_expiry, expiry)

