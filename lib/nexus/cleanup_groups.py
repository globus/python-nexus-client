# A script for cleaning up the groups list

from nexus import go_rest_client

config = {
        "cache": {
            "class": "nexus.token_utils.InMemoryCache",
            "args": []
            },
        "server": "graph.api.go.sandbox.globuscs.info",
        "client": "testuser",
        "client_secret": "sikrit",
        "password": "sikrit"
        }

group_names = ['testgroup', 'testgroup2', "Mattias' sub-group", 'New group name']

gc = go_rest_client.GlobusOnlineRestClient(config=config)

print 'getting group list'
# if this times out then increase the timeout in _issue_rest_request from go_rest_client 
response, content = gc.get_group_list(my_roles=['admin']) 

print 'cleaning up groups'
print 'There are ' + str(len(content)) + ' groups'
i = num_deleted = num_saved = 0
for group in content:
    if group['name'] in group_names:
        gc.delete_group(group['id'])
        num_deleted += 1
    else:
        num_saved += 1
    i += 1 
    print str( (i*100)/len(content) )+'% done\r',

print ''
response, content = gc.get_group_list(my_roles=['admin'])
print content
print "Number of groups deleted : " + str(num_deleted)
print "Number of groups remaining: " + str(num_saved)

