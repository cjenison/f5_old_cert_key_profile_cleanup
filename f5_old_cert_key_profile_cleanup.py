#!/usr/bin/python
# f5_old_cert_key_profile_cleanup.py
# Author: Chad Jenison (c.jenison at f5.com)
# Version 1.0
#
# Script that uses F5 BIG-IP iControl REST API to identify expired/soon-to-expire certs (and client-ssl profiles) and prune them from the configuration if user wants

import argparse
import sys
import requests
import json
import getpass
from datetime import datetime

requests.packages.urllib3.disable_warnings()

# Taken from http://code.activestate.com/recipes/577058/
def query_yes_no(question, default="no"):
    valid = {"yes": True, "y": True, "ye": True, "no": False, "n": False}
    if default == None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)
    while 1:
        sys.stdout.write(question + prompt)
        choice = raw_input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid.keys():
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' (or 'y' or 'n').\n")

#Setup command line arguments using Python argparse
parser = argparse.ArgumentParser(description='A tool to identify expiring and soon to expire certs and related config detritus and assist user with pruning it from configuration')
parser.add_argument('--bigip', help='IP or hostname of BIG-IP Management or Self IP', required=True)
parser.add_argument('--user', help='username to use for authentication', required=True)
parser.add_argument('--days', help='number of days before expiration to consider cert as expiring soon', default=30)
parser.add_argument('--reportonly', help='produce report only; do not prompt for configuration object deletion', action='store_true')
parser.add_argument('--makeucsonchange', help='produce a UCS on BIG-IP if user chooses to alter (delete) items in the configuration', action='store_true')

args = parser.parse_args()
contentJsonHeader = {'Content-Type': "application/json"}
filename = ''

def convert_bigip_path(path_to_replace):
    return path_to_replace.replace("/", "~")

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
    bip.auth = (args.user, password)
bip.verify = False
requests.packages.urllib3.disable_warnings()
url_base = ('https://%s/mgmt/tm' % (args.bigip))


factoryclientsslprofiles = set(['/Common/clientssl', '/Common/clientssl-insecure-compatible', '/Common/clientssl-secure', '/Common/crypto-server-default-clientssl', '/Common/splitsession-default-clientssl', '/Common/wom-default-clientssl'])
factorycerts = set(['/Common/ca-bundle.crt', '/Common/default.crt', '/Common/f5-ca-bundle.crt', '/Common/f5-irule.crt'])
factorykeys = set(['/Common/default.key', '/Common/f5_api_com.key'])
clientsslprofiles = set()
usedclientsslprofiles = set()
expiredcertclientsslprofiles = set()
soontoexpirecertclientsslprofiles = set()
certs = set()
keys = set()
expiredcerts = set()
soontoexpirecerts = set()
usedcerts = set()
usedkeys = set()
virtualsWithExpiredCerts = set()
virtualsWithSoonToExpireCerts = set()


retrievedcerts = bip.get('%s/sys/file/ssl-cert/' % (url_base)).json()
for cert in retrievedcerts['items']:
    certs.add(cert['fullPath'])
    certinfo = bip.get('%s/sys/file/ssl-cert/%s' % (url_base, convert_bigip_path(cert['fullPath']))).json()
    utcinseconds = (datetime.utcnow() - datetime(1970,1,1)).total_seconds()
    if certinfo['expirationDate'] - utcinseconds < 86400*args.days:
        if certinfo['expirationDate'] < utcinseconds:
            expiredcerts.add(cert['fullPath'])
        else:
            soontoexpirecerts.add(cert['fullPath'])

retreivedkeys = bip.get('%s/sys/file/ssl-key/' % (url_base)).json()
for key in retreivedkeys['items']:
    keys.add(key['fullPath'])

retrievedclientsslprofiles = bip.get('%s/ltm/profile/client-ssl' % (url_base)).json()
for clientssl in retrievedclientsslprofiles['items']:
    clientsslprofiles.add(clientssl['fullPath'])
    clientsslprofile = bip.get('%s/ltm/profile/client-ssl/%s' % (url_base, convert_bigip_path(clientssl['fullPath']))).json()
    if clientsslprofile['cert'] in expiredcerts:
        expiredcertclientsslprofiles.add(clientssl['fullPath'])
    if clientsslprofile['cert'] in soontoexpirecerts:
        soontoexpirecertclientsslprofiles.add(clientssl['fullPath'])

def processClientSslProfileFromVirtual(profileFullPath):
    clientsslprofile = bip.get('%s/ltm/profile/client-ssl/%s' % (url_base, convert_bigip_path(profileFullPath))).json()
    usedclientsslprofiles.add(profileFullPath)
    # insert code for defaultsFrom (parent) handling
    if clientsslprofile.get('defaultsFrom'):
        if clientsslprofile['defaultsFrom'] != '/Common/clientssl' and clientsslprofile['defaultsFrom'] != 'none':
            processClientSslProfileFromVirtual(clientsslprofile['defaultsFrom'])
    if clientsslprofile.get('chain'):
        if clientsslprofile['chain'] != 'none':
            usedcerts.add(clientsslprofile['chain'])
    usedcerts.add(clientsslprofile['cert'])
    usedkeys.add(clientsslprofile['key'])



virtuals = bip.get('%s/ltm/virtual' % (url_base)).json()
for virtual in virtuals['items']:
    #print ('Virtual: %s' % (virtual['fullPath']))
    virtualprofiles = bip.get('%s/ltm/virtual/%s/profiles' % (url_base, convert_bigip_path(virtual['fullPath']))).json()
    if virtualprofiles.get('items'):
        for profile in virtualprofiles['items']:
            if profile['fullPath'] in clientsslprofiles:
                processClientSslProfileFromVirtual(profile['fullPath'])
                if profile['fullPath'] in expiredcertclientsslprofiles:
                    virtualsWithExpiredCerts.add(virtual['fullPath'])
                if profile['fullPath'] in soontoexpirecertclientsslprofiles:
                    virtualsWithSoonToExpireCerts.add(virtual['fullPath'])

unusedclientsslprofiles = clientsslprofiles - usedclientsslprofiles
unusedcerts = certs - usedcerts
unusedkeys = keys - usedkeys

#for clientsslprofile in expiredcertclientsslprofiles:
#    print('Client-ssl profile: %s uses an expired cert' % (clientsslprofile))

def makeBackup():
    global ucsSaved
    global filename
    if not ucsSaved and args.makeucsonchange:
        getDate = bip.get('%s/sys/software/' % (url_base))
        datestring = getDate.headers['Date'].replace(" ", "_", 4).replace(":", "_", 2)
        ucsSavePayload = {}
        ucsSavePayload['command'] = 'save'
        filename = 'sslcleanup_%s.ucs' % (datestring)
        ucsSavePayload['name'] = filename
        print('Attempting UCS Creation - Filename: %s - Please Wait!' % (filename))
        ucsSave = bip.post('%s/sys/ucs/' % (url_base), headers=contentJsonHeader, data=json.dumps(ucsSavePayload))
        if ucsSave.status_code == 200:
            print('UCS File: %s saved to BIG-IP' % (filename))
            ucsSaved = True
        else:
            print('Problem Saving UCS - Message: %s' % (ucsSave.json()['message']))

if not args.reportonly:
    ucsSaved = False
    configChanged = False
    for clientsslprofile in set(expiredcertclientsslprofiles):
        if clientsslprofile in unusedclientsslprofiles:
            if clientsslprofile not in factoryclientsslprofiles:
                profile = bip.get('%s/ltm/profile/client-ssl/%s' % (url_base, convert_bigip_path(clientsslprofile))).json()
                certRetrieved = bip.get('%s/sys/file/ssl-cert/%s' % (url_base, convert_bigip_path(profile['cert']))).json()
                print('Client-SSL Profile: %s' % (clientsslprofile))
                print('Referenced Cert: %s - Expiration: %s' % (profile['cert'], certRetrieved['expirationString']))
                print('Referenced Cert Subject: %s' % (certRetrieved['subject']))
                queryString = 'Client-ssl profile: %s is not used by a virtual server and has an expired cert; Delete profile?' % (clientsslprofile)
                if query_yes_no(queryString, default='no'):
                    configChanged = True
                    makeBackup()
                    deleteprofile = bip.delete('%s/ltm/profile/client-ssl/%s' % (url_base, convert_bigip_path(clientsslprofile)))
                    if deleteprofile.status_code == 200:
                        expiredcertclientsslprofiles.discard(clientsslprofile)
                        print('Successfully deleted client-ssl profile %s' % (clientsslprofile))
                        #print('cert: %s - usedcerts: %s' % (profile['cert'], usedcerts))
                        if profile['cert'] not in usedcerts and profile['cert'] not in factorycerts:
                            queryString = 'Cert: %s from deleted client-ssl profile: %s not used; delete it?' % (profile['cert'], clientsslprofile)
                            if query_yes_no(queryString, default='no'):
                                deletecert = bip.delete('%s/sys/file/ssl-cert/%s' % (url_base, convert_bigip_path(profile['cert'])))
                                if deletecert.status_code == 200:
                                    print('Successfully deleted cert %s' % (profile['cert']))
                                    expiredcerts.discard(profile['cert'])
                                else:
                                    print('Unable to delete cert %s' % (profile['cert']))
                                    print('Message: %s' % (deletecert.json()['message']))
                        if profile['key'] not in usedkeys and profile['key'] not in factorykeys:
                            queryString = 'Key: %s from deleted client-ssl profile: %s not used; delete it?' % (profile['key'], clientsslprofile)
                            if query_yes_no(queryString, default='no'):
                                deletekey = bip.delete('%s/sys/file/ssl-key/%s' % (url_base, convert_bigip_path(profile['key'])))
                                if deletekey.status_code == 200:
                                    print('Successfully deleted key %s' % (profile['key']))
                                else:
                                    print('Unable to delete key %s' % (profile['key']))
                                    print('Message: %s' % (deletekey.json()['message']))
                    else:
                        print('Unable to delete client-ssl profile %s' % (clientsslprofile))
                        print('Message: %s' % (deleteprofile.json()['message']))
                print('-')
    for cert in set(expiredcerts):
        certName = cert.rsplit('.', 1)[0]
        certRetrieved = bip.get('%s/sys/file/ssl-cert/%s.crt' % (url_base, convert_bigip_path(certName)))
        keyRetrieved = bip.get('%s/sys/file/ssl-key/%s.key' % (url_base, convert_bigip_path(certName)))
        print('Cert: %s - Expiration: %s' % (cert, certRetrieved.json()['expirationString']))
        print('Subject: %s' % (certRetrieved.json()['subject']))
        if certRetrieved.status_code == 200 and keyRetrieved.status_code == 200:
            if '%s.key' % (certName) in unusedkeys and cert in unusedcerts:
                queryString = 'Cert %s and Key %s.key expired and unused; delete them?' % (cert, certName)
                if query_yes_no(queryString, default='no'):
                    configChanged = True
                    makeBackup()
                    certDelete = bip.delete('%s/sys/file/ssl-cert/%s' % (url_base, convert_bigip_path(cert)))
                    if certDelete.status_code == 200:
                        expiredcerts.discard(cert)
                    keyDelete = bip.delete('%s/sys/file/ssl-key/%s.key' % (url_base, convert_bigip_path(certName)))
        elif certRetrieved.status_code == 200:
            queryString = 'Cert %s expired and unused (no paired key); delete it?' % (cert)
            if query_yes_no(queryString, default='no'):
                configChanged = True
                makeBackup()
                certDelete = bip.delete('%s/sys/file/ssl-cert/%s' % (url_base, convert_bigip_path(cert)))
                if certDelete.status_code == 200:
                    expiredcerts.discard(cert)
        print('-')


for virtual in virtualsWithExpiredCerts:
    print('Virtual: %s is using a client-ssl profile with an expired cert' % (virtual))
    virtualprofiles = bip.get('%s/ltm/virtual/%s/profiles' % (url_base, convert_bigip_path(virtual))).json()
    for profile in virtualprofiles['items']:
        if profile['fullPath'] in expiredcertclientsslprofiles:
            print ('Client SSL Profile: %s' % (profile['fullPath']))
            profileRetrieved = bip.get('%s/ltm/profile/client-ssl/%s' % (url_base, convert_bigip_path(profile['fullPath']))).json()
            certRetrieved = bip.get('%s/sys/file/ssl-cert/%s' % (url_base, convert_bigip_path(profileRetrieved['cert']))).json()
            print ('Cert: %s - Expiration: %s' % (profileRetrieved['cert'], certRetrieved['expirationString']))
            print ('Subject: %s' % (certRetrieved['subject']))
    print ('-')
for virtual in virtualsWithSoonToExpireCerts:
    print('Virtual: %s is using a client-ssl profile with a soon to expire cert' % (virtual))
    virtualprofiles = bip.get('%s/ltm/virtual/%s/profiles' % (url_base, convert_bigip_path(virtual))).json()
    for profile in virtualprofiles['items']:
        if profile['fullPath'] in soontoexpirecertclientsslprofiles:
            print ('Client SSL Profile: %s' % (profile['fullPath']))
            profileRetrieved = bip.get('%s/ltm/profile/client-ssl/%s' % (url_base, convert_bigip_path(profile['fullPath']))).json()
            certRetrieved = bip.get('%s/sys/file/ssl-cert/%s' % (url_base, convert_bigip_path(profileRetrieved['cert']))).json()
            print ('Cert: %s - Expiration: %s' % (profileRetrieved['cert'], certRetrieved['expirationString']))
            print ('Subject: %s' % (certRetrieved['subject']))
    print ('-')
for clientsslprofile in expiredcertclientsslprofiles:
    print('Client-ssl profile: %s is using an expired cert' % (clientsslprofile))
    profileRetrieved = bip.get('%s/ltm/profile/client-ssl/%s' % (url_base, convert_bigip_path(clientsslprofile))).json()
    certRetrieved = bip.get('%s/sys/file/ssl-cert/%s' % (url_base, convert_bigip_path(profileRetrieved['cert']))).json()
    print ('Cert: %s - Expiration: %s' % (profileRetrieved['cert'], certRetrieved['expirationString']))
    print ('Subject: %s' % (certRetrieved['subject']))
    print ('-')
for clientsslprofile in soontoexpirecertclientsslprofiles:
    print('Client-ssl profile: %s is using a soon to expire cert' % (clientsslprofile))
    profileRetrieved = bip.get('%s/ltm/profile/client-ssl/%s' % (url_base, convert_bigip_path(clientsslprofile))).json()
    certRetrieved = bip.get('%s/sys/file/ssl-cert/%s' % (url_base, convert_bigip_path(profileRetrieved['cert']))).json()
    print ('Cert: %s - Expiration: %s' % (profileRetrieved['cert'], certRetrieved['expirationString']))
    print ('Subject: %s' % (certRetrieved['subject']))
    print ('-')
for cert in expiredcerts:
    print('Cert: %s is expired' % (cert))
    certRetrieved = bip.get('%s/sys/file/ssl-cert/%s' % (url_base, convert_bigip_path(cert))).json()
    print ('Cert: %s - Expiration: %s' % (cert, certRetrieved['expirationString']))
    print ('Subject: %s' % (certRetrieved['subject']))
    print ('-')
for cert in soontoexpirecerts:
    print('Cert: %s is expiring soon' % (cert))
    certRetrieved = bip.get('%s/sys/file/ssl-cert/%s' % (url_base, convert_bigip_path(cert))).json()
    print ('Cert: %s - Expiration: %s' % (cert, certRetrieved['expirationString']))
    print ('Subject: %s' % (certRetrieved['subject']))
    print ('-')

if not args.reportonly and configChanged:
    print('Configuration Changed - Please Verify and if appropriate ConfigSync to Peer system')
    if args.makeucsonchange:
        print('UCS Backup File in place on system: %s - Restore from UCS if mistake was made' % (filename))
