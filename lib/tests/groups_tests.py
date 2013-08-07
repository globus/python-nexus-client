__author__ = 'Mattias Lidman'

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
from nexus.go_rest_client import GlobusOnlineRestClient
from nexus.go_rest_client import UnexpectedRestResponseError
from test_config_file import config

class ClientGroupTests(unittest.TestCase):

    def setUp(self):
        # NOTE: shared_secret needs to be filled out to run the tests. Deleted because 
        # it shouldn't be in the commit history of a repo that will later be made public.
        
        self.shared_secret = 'test'
        self.config = config

        self.go_rest_client = GlobusOnlineRestClient(config=self.config)
        # Random numbers added to avoid overwriting some real user since these
        # tests may be run against a real server.
        self.default_username = 'mattias32180973219765321905174'
        self.created_users = []
        self.created_groups = []

    def tearDown(self):
        for user in self.created_users:
            self.go_rest_client.delete_user(user)
        
        self.go_rest_client.logout()
        if len(self.created_groups) > 0:
            self.go_rest_client.username_password_login('testuser', 'sikrit')
        
        for group in self.created_groups:
            self.go_rest_client.delete_group(group)
        self.go_rest_client.logout()
        
    @attr('go_rest_test')
    def test_group_management(self):

        # We need to be logged in as a user that has admin rights to the root-group.
        username = 'testuser'
        password = 'sikrit'
        self.go_rest_client.username_password_login(username, password=password)

        # Get root group: 
        response, content = self.go_rest_client.get_group_list() # times out often
        self.assertEquals(response['status'], '200')

        parent_group = 'testgroup'
        response, content = self.go_rest_client.post_group(parent_group)
        root_id = content['id']
        self.created_groups.append(root_id)

        # Create a subroup:
        subgroup_name = "Mattias' sub-group"
        response, content = self.go_rest_client.post_group(subgroup_name, parent=root_id, is_active=False)
        self.assertEquals(response['status'], '201')
        self.created_groups.append(content['id'])

        # Get subgroups:
        response, content = self.go_rest_client.get_group_tree(root_id, 2)
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

        response, content = self.go_rest_client.put_group_policies(root_id, policies)

        # there are policies that exist before calling put_group_policies.
        # this causes a 200 status to be returend instead of a 201
        # (the policies field is being edited instead of added)
        # this also causes the returned content and the policies input to be different

        # self.assertEquals(response['status'], '201')
        self.assertEquals(response['status'], '200')
        # self.assertEquals(content, policies)
    
        response, content = self.go_rest_client.put_group_policies(subgroup_id, policies)

        # self.assertEquals(response['status'], '201')
        self.assertEquals(response['status'], '200')
        # self.assertEquals(content, policies)

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
        response, content = self.go_rest_client.set_single_policy(root_id, 'sign_up_fields', ['zip', 'state'])# to satisfy parent-policy requirements
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
        admin_username = 'testuser'
        admin_password = 'sikrit'
        group_name = 'testgroup2'

        self.go_rest_client.username_password_login(admin_username, 
            password=admin_password) 
        response, content = self.go_rest_client.post_group(group_name)
    
        group_id = content['id']
        self.created_groups.append(group_id)
        self.go_rest_client.set_single_policy(group_id, 'approval', 'admin')

        user = 'mattias1' 
        self.go_rest_client.post_user(user, 'Test User', 'testuseremail100@gmail.com', 'sikrit')
        self.created_users.append(user)
       
        # Test that the group membership of a particular username doesn't persist
        # between test runs:
        response, content = self.go_rest_client.get_group_member(group_id, user)
        self.assertEquals(response['status'], '404', msg="A newly created user should never be part of a group.")

        self.go_rest_client.username_password_login(user, 'sikrit') # logging in so the user can be editted
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

        # About 90% of the rest of this test is broken because the smtp_mail_sink that was used is broken.
        # The smtp_mail_sink that was used only worked reliably with localhost, but the tests no longer 
        # use localhost. 
        # It might be a good idea to leave the code here because the only thing wrong is the
        # smtp_mail_sink and a working one would make the rest of the test work 
        """
        # Get validation code from email, then test email validation:  
        mailboxFile2 =  StringIO.StringIO(self.smtp_mail_sink.getMailboxContents()) # mailbox contents is empty
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
        self.assertEquals(content['members'][0]['name'], email_addr)
        self.assertEquals(content['members'][0]['status'], 'invited')

        # Get invite id:
        mailboxFile2 =  StringIO.StringIO(self.smtp_mail_sink.getMailboxContents())
        mailboxObject = mailbox.PortableUnixMailbox(mailboxFile2, email.message_from_file)
        messages = []
        for messageText in [ message.as_string() for message in mailboxObject ]:
            messages.append(messageText)
        invite_id = re.search('invite_id: [a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',
            str(messages)).group(0).replace('invite_id: ', '')

        # Sign in as user, test claim_invitation:
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
        """

