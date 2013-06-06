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
##from pyramid import testing
from nexus.go_rest_client import GlobusOnlineRestClient
from nexus.go_rest_client import UnexpectedRestResponseError
##from webtest import TestApp
from test_utils.smtp_server import SmtpMailsink

class TestGlobusOnlineRestClient(unittest.TestCase):

    def setUp(self):
        # NOTE: shared_secret needs to be filled out to run the tests. Deleted because 
        # it shouldn't be in the commit history of a repo that will later be made public.
        self.shared_secret = ''
        ##self.go_host = 'http://localhost:6543'
	self.go_host = 'graph.api.go.mattiassandbox.globuscs.info'
        #self.go_host = 'https://www.dev.globusonline.org'
        self.go_rest_client = GlobusOnlineRestClient(self.go_host, self.shared_secret)
        # Random numbers added to avoid overwriting some real user since these
        # tests may be run against a real server.
        self.default_username = 'mattias32180973219765321905174'
        self.created_users = []

        self.smtp_mail_sink = SmtpMailsink(port=1025)
        self.smtp_mail_sink.start()

    def tearDown(self):
        for user in self.created_users:
            self.go_rest_client.delete_user(user)
        ##testing.tearDown()
        self.smtp_mail_sink.stop()

    @attr('functional')
    def test_issue_request(self):
        rest_client = GlobusOnlineRestClient('www.google.com', self.shared_secret)
        response, content = rest_client._issue_rest_request('')

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
        ##response, content = self.go_rest_client.username_password_login(username)
        response, content = self.go_rest_client.username_password_login(username, 'sikrit')
	self.assertEquals(response['status'], '200')

    @attr('go_rest_test')
    def test_user_login_methods(self):
        username = 'jbryan'
        password = 'blah12'


	self.go_rest_client.post_user(username, 'Jbryan Jbryanson', 'jbryan@bar.com', 'blah12')##

        # Test username/password login:
        ##response, content = self.go_rest_client.get_user(username)
        response, content = self.go_rest_client.get_user('jbryan')
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
    def test_group_management(self):

        # We need to be logged in as a user that has admin rights to the root-group.
        username = 'jbryan'
        password = 'blah12'
        self.go_rest_client.username_password_login(username, password=password)

        # Get root group:
        ##response, content = self.go_rest_client.get_group_list(depth=1)##no depth argument for get_group_list()
        response, content = self.go_rest_client.get_group_list()##
	self.assertEquals(response['status'], '200')

	print response
	##root_id = content['id']
	root_id = response['x-go-request-id']

        # Create a subroup:
        subgroup_name = "Mattias' sub-group"
        response, content = self.go_rest_client.post_group(subgroup_name, parent=root_id, is_active=False)
        self.assertEquals(response['status'], '201')

        # Get subgroups:
        response, content = self.go_rest_client.get_group_list(root_id=root_id, depth=2)
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
        response, content = self.go_rest_client.put_group_summary(subgroup_id,
            name=new_name, description=new_description, is_active=new_is_active)
        self.assertEquals(response['status'], '201')
        response, content = self.go_rest_client.get_group_summary(subgroup_id)
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

        policies = self.go_rest_client.build_policy_dictionary(**policy_summary)

        response, content = self.go_rest_client.put_group_policies(subgroup_id, policies)
        self.assertEquals(response['status'], '201')
        self.assertEquals(content, policies)

        response, content = self.go_rest_client.get_group_policies(subgroup_id)
        self.assertEquals(response['status'], '200')
        self.assertTrue(content['approval']['value']['admin']['value'])
        self.assertFalse(content['approval']['value']['auto']['value'])
        self.assertTrue(content['sign_up_fields']['value']['first_name']['value'])
        self.assertFalse(content['sign_up_fields']['value']['current_project_name']['value'])

        # Test set_single_policy:
        response, content = self.go_rest_client.set_single_policy(subgroup_id, 'approval', 'auto')
        self.assertFalse(content['approval']['value']['admin']['value'])
        self.assertTrue(content['approval']['value']['auto']['value'])
        # Should alse work for multi-option policies like signup fields:
        response, content = self.go_rest_client.set_single_policy(subgroup_id, 'sign_up_fields', ['zip', 'state'])
        self.assertTrue(content['sign_up_fields']['value']['zip']['value'])
        self.assertTrue(content['sign_up_fields']['value']['state']['value'])
        self.assertFalse(content['sign_up_fields']['value']['first_name']['value'])

        # Newly created group should have the same email templates as the parent.
        response, content = self.go_rest_client.get_group_email_templates(root_id)
        root_default_templates = sorted(content['templates'], key=lambda k: k['type']) 
        response, content = self.go_rest_client.get_group_email_templates(subgroup_id)
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
        response, content = self.go_rest_client.post_group_email_templates(subgroup_id, template_params)
        self.assertEquals(response['status'], '201')
        template_id = content['id']

        # Re-posting the same template type should be a 409 Conflict:
        response, content = self.go_rest_client.post_group_email_templates(subgroup_id, template_params)
        self.assertEquals(response['status'], '409')

        # Test GETting templates:
        response, content = self.go_rest_client.get_group_email_templates(subgroup_id)
        self.assertTrue(template_params['subject'] in [ template['subject'] for template in content['templates'] ])

        # Test GETing a single template:
        response, content = self.go_rest_client.get_group_email_template(subgroup_id, template_id)
        self.assertEquals(response['status'], '200')
        self.assertEquals(content['message'][0]['text'], template_params['message'][0]['text'])

        # Test PUTting (updating) a template: 
        new_subject = 'This is the new subject'
        content['subject'] = new_subject
        response, content = self.go_rest_client.put_group_email_template(subgroup_id, template_id, content)
        self.assertEquals(response['status'], '200')
        self.assertEquals(content['subject'], new_subject)

        # Test GETting a rendered template:
        response, content = self.go_rest_client.get_group_email_template(subgroup_id, template_id)
        self.assertEquals(response['status'], '200')

    @attr('go_rest_test')
    def test_membership_management(self):

        # Log in as an admin, create a group and a user to play with.
        admin_username = 'jbryan'
        admin_password = 'blah12'
        self.go_rest_client.username_password_login(admin_username, 
            password=admin_password) 
        ##response, content = self.go_rest_client.get_group_list(depth=1)##no depth argument for get_group_list()
	response, content = self.go_rest_client.get_group_list()##

	
        ##group_id = content['id']##keyerror no 'id' key
        group_id = response['x-go-request-id']
	##group_id = response['gid']

	self.go_rest_client.set_single_policy(group_id, 'approval', 'admin')

        
        user = 'mattias1' 
        self.go_rest_client.simple_create_user(user)
        self.created_users.append(user)
       
        # Test that the group membership of a particular username doesn't persist
        # between test runs:
        response, content = self.go_rest_client.get_group_member(group_id, user)
        self.assertEquals(response['status'], '404', msg="A newly created user should never be part of a group.")

        # Test PUTing user custom fields:
        custom_fields = { 
            'current_project_name': 'BIRN Community', 
            'organization': 'Computation Institute',
        }
        self.go_rest_client.put_user_custom_fields(user, **custom_fields)
        response, content = self.go_rest_client.get_user(user, custom_fields=custom_fields.keys())
        self.assertEquals(custom_fields, content['custom_fields'])

        # Test GETting and PUTting user visibility:
        response, content = self.go_rest_client.get_user_policies(user)
        self.assertFalse(content['user_membership_visibility']['value']['community']['value'])
        self.go_rest_client.put_user_membership_visibility(user, 'community')
        response, content = self.go_rest_client.get_user_policies(user)
        self.assertTrue(content['user_membership_visibility']['value']['community']['value'])

        # Get validation code from email, then test email validation:
        mailboxFile2 =  StringIO.StringIO(self.smtp_mail_sink.getMailboxContents())
        mailboxObject = mailbox.PortableUnixMailbox(mailboxFile2, email.message_from_file)
        messages = []
        for messageText in [ message.as_string() for message in mailboxObject ]:
            messages.append(messageText)
        validation_code = re.search('[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', 
            str(messages[0])).group(0)
        
        response, content = self.go_rest_client.post_email_validation(validation_code)
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
        response, content = self.go_rest_client.put_group_email_template(group_id, invite_template['type'], invite_template)

        # Test email invite flow. It seems there is currently no way to delete 
        # email users through the REST API, so we'll have to add a dash of randomness.
        # TODO: This needs fixing if we want to run these tests in Jenkins or it will
        # clutter the db.
        email_addr = 'someone@' + ''.join(random.sample(string.ascii_lowercase + string.digits, 10)) + '.org'
        self.go_rest_client.logout()
        self.go_rest_client.username_password_login(admin_username, 
            password=admin_password)
        response, content = self.go_rest_client.post_membership(group_id, emails=email_addr)
        self.assertEquals(response['status'], '201')
        self.assertEquals(content['members'][0]['username'], email_addr)
        self.assertEquals(content['members'][0]['status'], 'invited')
        # Get invite id:
        mailboxFile2 =  StringIO.StringIO(self.smtp_mail_sink.getMailboxContents())
        mailboxObject = mailbox.PortableUnixMailbox(mailboxFile2, email.message_from_file)
        messages = []
        for messageText in [ message.as_string() for message in mailboxObject ]:
            messages.append(messageText)
        invite_id = re.search('invite_id: [a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',
            str(messages)).group(0).replace('invite_id: ', '')

        # Sing in as user, test claim_invitation:
        self.go_rest_client.logout()
        self.go_rest_client.username_password_login(user)
        response, content = self.go_rest_client.claim_invitation(invite_id)

        # Test accepting invitation:
        response, content = self.go_rest_client.accept_invitation(group_id, user)
        self.assertEquals(response['status'], '201')
        self.assertEquals(content['status'], 'pending')

        # Test admin approving the membership:
        self.go_rest_client.logout()
        self.go_rest_client.username_password_login(admin_username, password=admin_password)
        response, content = self.go_rest_client.approve_join(group_id, user)
        self.assertEquals(response['status'], '201')
        self.assertEquals(content['status'], 'active')

        # Test suspending and unsuspending user:
        response, content = self.go_rest_client.suspend_group_member(group_id, user,
            new_status_reason='User suspended because he is a very naughty boy.')
        self.assertEquals(response['status'], '201')
        self.assertEquals(content['status'], 'suspended')
        self.assertEquals(content['status_reason'], 
            'User suspended because he is a very naughty boy.')
        response, content = self.go_rest_client.unsuspend_group_member(group_id, user)
        self.assertEquals(response['status'], '201')
        self.assertEquals(content['status'], 'active')

        # Test promoting the user to admin:
        self.go_rest_client.put_group_membership_role(group_id, user, 'admin')
        response, content = self.go_rest_client.get_group_member(group_id, user)
        self.assertEquals(content['role'], 'admin')
