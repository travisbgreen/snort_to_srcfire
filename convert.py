#!/usr/bin/env python2
'''
# convert snort sigs to FireSIGHT format

sample VRT rule:
alert tcp $EXTERNAL_NET any -> $HOME_NET 4000 (msg:"EXPLOIT Alt-N SecurityGateway username buffer overflow attempt"; flow:established, to_server; content:"username="; nocase; isdataat:450,relative; content:!"&"; within:450; content:!"|0A|"; within:450; metadata:policy balanced-ips drop, policy connectivity-ips drop, policy security-ips drop; reference:url,secunia.com/advisories/30497/; classtype:attempted-admin; sid:13916; rev:2;)
alert udp $EXTERNAL_NET 53 -> $HOME_NET any (msg:"DNS large number of NXDOMAIN replies - possible DNS cache poisoning"; byte_test:1,&,2,3; byte_test:1,&,1,3; byte_test:1,&,128,2; threshold:type threshold, track by_src, count 200, seconds 30; metadata:policy balanced-ips alert, policy security-ips alert, service dns; reference:cve,2008-1447; reference:url,www.kb.cert.org/vuls/id/800113; classtype:misc-attack; sid:13948; rev:2;)

references:
http://www.cisco.com/c/en/us/support/docs/security/firesight-management-center/117924-technote-firesight-00.html
https://supportforums.cisco.com/discussion/10478926/converting-snort-signatures-cisco-idsips
https://sourceforge.net/projects/s2c/
'''
import fileinput
import re
import os
import sys
import string

outfile = './converted.rules'
verbose = True
export_sigs = []
# {'conversion_name':[re.object, 'replacement txt']}
conversions = {'remove_http_raw':['http_raw','http'], \
               'thresh_to_detection_filter':['threshold:','detection_filter:'], \
               '3_thresh_to_detection_filter':['type limit,',''], \
               '4_thresh_to_detection_filter':['type threshold,',''], \
               '5_thresh_to_detection_filter':['type both,',''] \
               }

def load_disablesids(disablesid_list = []):
    with open('./sids.disabled','r') as f:
        for line in f.readlines():
            disablesid_list.append(line.strip())
    return disablesid_list

def get_sid(txt):
    m = re.search('sid:(\d+);', txt)
    if m: return m.group(1)
    else: return ''

def main():
    disablesids = load_disablesids()
    for line in fileinput.input():
        if line[0] == '#':
            if verbose: print 'skipping disabled rule: ' + line[0] 
            continue
        elif line[0] == '\n':
            continue
        tmp = line
        if get_sid(tmp) in disablesids: print 'disabled due to disablesids: %s' % (get_sid(tmp))
        for key, value in conversions.iteritems():
            if value[0] in tmp:
                tmp = string.replace(tmp, value[0], value[1])
                if verbose: print 'found conversion %s in %s' % (key, get_sid(tmp))
        export_sigs.append(tmp)

    with open(outfile,'w') as f:
        for sig in export_sigs:
            f.write(sig + '\n')

    print 'Success: %s exported to %s' % (len(export_sigs), outfile)

if __name__ == "__main__":
    main()
