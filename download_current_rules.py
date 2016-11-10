#!/usr/bin/env python2
'''
script to dl current ET OPEN rules, if you are a pro subcriber, simply edit url & oinkcode vars
'''
import urllib2

url = 'https://rules.emergingthreats.net/open/snort-2.9.0-enhanced/rules/emerging-current_events.rules'
#oinkcode = "123456"
#url = 'http://rules.emergingthreatspro.com/' + oinkcode + '/snort-2.9.0-enhanced/rules/emerging-current_events.rules'

try:
    result = urllib2.urlopen(url)
    with open('./current.rules','w') as f:
        f.write(result.read())
    print 'success, now run convert.py on current.rules:'
    print '$ python ./convert.py current.rules'
except urllib2.HTTPError, err:
    print 'error occured: %s %s' % (err.code, err.reason)
