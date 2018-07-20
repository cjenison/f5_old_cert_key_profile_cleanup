#!/usr/bin/python
# f5_old_cert_key_profile_cleanup.py
# Author: Chad Jenison (c.jenison at f5.com)
# Version 1.0
#
# Script that uses F5 BIG-IP iControl REST API to display cert and expiration information on a virtual server basis

import argparse
import sys
import requests
import json
import getpass

#Setup command line arguments using Python argparse
parser = argparse.ArgumentParser(description='A tool to display virtual server certificate information')
parser.add_argument('--bigip', help='IP or hostname of BIG-IP Management or Self IP', required=True)
parser.add_argument('--user', help='username to use for authentication', required=True)

args = parser.parse_args()
contentJsonHeader = {'Content-Type': "application/json"}



def get_auth_token(bigip, username, password):
    authbip = requests.session()
    authbip.verify = False
    payload = {}
    payload['username'] = username
    payload['password'] = password
    payload['loginProviderName'] = 'tmos'
    authurl = 'https://%s/mgmt/shared/authn/login' % (bigip)
    authPost = authbip.post(authurl, headers=contentJsonHeader, data=json.dumps(payload))
    if authPost.status_code == 404:
        print ('attempt to obtain authentication token failed; will fall back to basic authentication; remote LDAP auth will require configuration of local user account')
        token = None
    elif authPost.status_code == 401:
        print ('attempt to obtain authentication token failed due to invalid credentials')
        token = 'Fail'
    elif authPost.json().get('token'):
        token = authPost.json()['token']['token']
        print ('Got Auth Token: %s' % (token))
    else:
        print ('Unexpected error attempting POST to get auth token')
        quit()
    return token

user = args.user
password = getpass.getpass("Password for " + user + ":")
bip = requests.session()
token = get_auth_token(args.bigip, args.user, password)
if token and token != 'Fail':
    bip.headers.update({'X-F5-Auth-Token': token})
else:
    bip.auth = (username, password)
bip.verify = False
requests.packages.urllib3.disable_warnings()
url_base = ('https://%s/mgmt/tm' % (args.bigip))



clientsslprofileset = set()
usedclientsslprofileset = set()
certset = set()
keyset = set()
usedcertset = set()
usedkeyset = set()
clientsslprofiles = bip.get('%s/ltm/profile/client-ssl' % (url_base)).json()
for clientssl in clientsslprofiles['items']:
    #print ('Client SSL Profile: %s - Cert: %s' % (clientssl['name'], clientssl['cert']))
    clientsslprofileset.add(clientssl['name'])


virtuals = bip.get('%s/ltm/virtual' % (url_base)).json()
for virtual in virtuals['items']:
#    print ('Virtual: %s' % (virtual['name']))
    virtualprofiles = bip.get('%s/ltm/virtual/%s/profiles' % (url_base, virtual['name'])).json()
    if virtualprofiles.get('items'):
        for profile in virtualprofiles['items']:
            if profile['name'] in clientsslprofileset:
                usedclientsslprofileset.add(profile['name'])
                clientsslprofile = bip.get('%s/ltm/profile/client-ssl/%s' % (url_base, profile['name'])).json()
                usedcertset.add(clientsslprofile['cert'])
                usedkeyset.add(clientsslprofile['key'])
                certurlfragment = clientsslprofile['cert'].replace("/", "~", 2)
                print('Virtual: %s' % (virtual['name']))
                print('Virtual Destination: %s' % (virtual['destination']))
                if 'description' in virtual:
                    print('Virtual Description: %s' % (virtual['description']))
                certinfo = bip.get('%s/sys/file/ssl-cert/%s' % (url_base, certurlfragment)).json()
                print('SSL Profile: %s' % (profile['name']))
                print('Cert: %s' % (clientsslprofile['cert']))
                print('Cert Expiration: %s' % (certinfo['expirationString']))
                print('Cert Subject: %s' % (certinfo['subject']))
