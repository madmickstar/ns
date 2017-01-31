#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import re
import socket
import logging
import _winreg          # import windows registry functionality
import platform         # import for detecting OS
import subprocess       # import handles grabbing output from windows command ifconfig /all
from codecs import open

from nsobjects import QueryServer


#def get_version(path):
#    fullpath = os.path.join(os.path.dirname(sys.argv[0]), path)
#    with open(fullpath, encoding='utf-8') as f:
#        version_file = f.read()
#    regex = r"^__version__ = ['\"]([^'\"]*)['\"]"
#    version_match = re.search(regex, version_file, re.M)
#    if version_match:
#        return version_match.group(1)
#    raise RuntimeError('Unable to find version string in %s.' % version_file)


# Print cli arguments
def print_debug_arguments(args):
    logger = logging.getLogger(__name__)
    counter_domains = 0
    logger.debug('CLI print_failed %s', args)
    for domains in args.domain:
        counter_domains += 1
        logger.debug('CLI Arguments, Domain %s %s', counter_domains, domains)
    if args.server:
        logger.debug('CLI Arguments, DNS Server %s', args.server)
    logger.debug('CLI Arguments, DNS Timeout %s and Liftime %s', args.timeout, args.lifetime)


def print_debug_query(dict_dnsquery):
    logger = logging.getLogger(__name__)
    if dict_dnsquery['Query_Type'] == 'A':
        logger.debug('Standard DNS lookup %s', dict_dnsquery['Domain_Name'])
    elif dict_dnsquery['Query_Type'] == 'PTR':
        logger.debug('Reverse DNS lookup %s', dict_dnsquery['Domain_Name'])
        logger.debug('DNS Reverse IP %s', dict_dnsquery['Query_IP'])
    elif dict_dnsquery['Query_Type'] == 'CNAME':
        logger.debug('Alias DNS lookup %s', dict_dnsquery['Domain_Name'])


# test domain for ipv4 or domain name
def test_ipv4(netloc):
    try:
        socket.inet_aton(netloc)
    except:
        return False
    return True


def validate_cli_dns(dns_server):
    logger = logging.getLogger(__name__)
    # if DNS server is specified check if usable, if not specified get local DNS from OS
    dns_server_list = []         # dns query is expecting list of IPs even if there is only one
    if test_ipv4(dns_server):
        dns_server_list.append(dns_server)
    else:
        logger.error('DNS Server Check, Specified DNS server failed input validation %s', dns_server)
        sys.exit(2)
    return dns_server_list


def test_dns_server(dns_server_list):
    logger = logging.getLogger(__name__)
    final_dns_list = []
    for d in dns_server_list:
        list = [d]
        dict_dnsquery = {'Domain_Name': 'google.com',
                         'Query_Type': 'A',
                         'DNS_Serv': list,
                         'DNS_TO': 2,
                         'DNS_LT': 5}
        a = QueryServer(dict_dnsquery)
        dns_result = a.query_host()
        if len(dns_result) >= 1:
            final_dns_list.append(d)
    return final_dns_list


## get DNS details from windows command output
#def get_local_dns():
#    proc = subprocess.check_output("ipconfig /all" )
#    dns_ip_string = re.compile(r'(?:DNS Servers . . . . . . . . . . . : |[ ]{35,})(\d+\.\d+\.\d+\.\d+)')
#    local_dns_list = dns_ip_string.findall(proc)
#    return local_dns_list


# returns operating system flavour and release
def get_os():
    logger = logging.getLogger(__name__)
    logger.debug('Detecting OS %s %s', platform.system(), platform.release())
    return platform.system(), platform.release()


def dns_suffix_query(args):
    logger = logging.getLogger(__name__)
    os_system, os_release = get_os()                                 # get OS details
    if os_system == 'Windows':
        dns_suffixes = get_windows_suffixes(os_system, os_release, args)
        logger.debug('DNS Suffix Search - Windows suffixes %s %s', os_release, str(dns_suffixes))
    elif os_system == 'Linux':
        try:
            dns_suffixes = get_linux_suffixes()
            logger.debug('DNS Suffix Search - Linux suffixes %s %s', os_release, str(dns_suffixes))
        except Exception, err:
            logger.error('%s', err)
            dns_suffixes = []
    else:
        dns_suffixes = []
        logger.debug('DNS Suffix Search - Unknown OS DNS suffix search')
    return dns_suffixes


# get dns suffixes from windows registry
def get_windows_suffixes(os_system, os_release, args):
    logger = logging.getLogger(__name__)

    dns_suffix_list = []
    # reads registry location which is typically found in AD based PCs
    # read registry key SearchList for 2008ServerR2 or AD based PC
    logger.debug('DNS Suffix Search - Processing suffixes %s %s', os_system, os_release)
    try:
        netKey = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, 'SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient')
        for keyName in ("SearchList",):
            # added try to handle when rego key is not found
            try:
                value, type = _winreg.QueryValueEx(netKey, keyName)
                logger.debug('DNS Suffix Search - Registry key exists, key name %s value %s', keyName, value)
                if value:
                    for item in value.split(','):
                        dns_suffix_list.append(item)
            except:
                logger.debug('DNS Suffix Search - Registry key does not exist, skipping key named %s', keyName)
    except:
        logger.debug('DNS Suffix Search - 1st Registry key does not exist')

    # reads different registry location which is typically found in non AD based PCs
    # read registry key SearchList and DhcpDomain for windows 7 and 10
    try:
        netKey = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, 'SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters')
        for keyName in ("DhcpDomain", "SearchList"):
            # added try to handle when rego key is not found
            try:
                value, type = _winreg.QueryValueEx(netKey, keyName)
                logger.debug('DNS Suffix Search - Registry key exists, key name %s value %s', keyName, value)
                if value:
                    for item in value.split(','):
                        dns_suffix_list.append(item)
            except:
                logger.debug('DNS Suffix Search - Registry key does not exist, skipping key named %s', keyName)
    except:
        logger.debug('DNS Suffix Search - 2nd Registry key does not exist')

    # after finding what it can, return what was found
    return dns_suffix_list


# get suffixes from linux resolv.conf - untested currently
def get_linux_suffixes():
    suffixes = []
    try:
        with open( '/etc/resolv.conf', 'r' ) as resolvconf:
            for line in resolvconf.readlines():
                if 'search' in line:
                    suffixes.append( line.split( ' ' )[ 1 ].strip() )
        return suffixes
    except IOError as error:
        return error.strerror


def cname_lookup(dict_dnsquery, url_type, args):
    logger = logging.getLogger(__name__)
    logger.debug('Domain profile - URL = %s, Name_Type = %s, Q_Type = %s, Q_Name = %s, Q_IP = %s',
                                    url_type,
                                    dict_dnsquery['Hostname_Type'],
                                    dict_dnsquery['Query_Type'],
                                    dict_dnsquery['Domain_Name'],
                                    dict_dnsquery['Query_IP'])
    if args.debug:
        print_debug_query(dict_dnsquery)
    c = QueryServer(dict_dnsquery)
    dns_result = c.query_host()
    if not len(dns_result) == 0:
        print_success(dns_result, dict_dnsquery)
    else:
        logger.debug('Alias DNS lookup unsuccessful')
        

def print_success(dns_result, dict_dnsquery):
    logger = logging.getLogger(__name__)
    for result in dns_result:
        if "PTR" in dict_dnsquery['Query_Type']:
            logger.info('%-30s %s', result, dict_dnsquery['Query_IP'])
        else:
            logger.info('%-30s %s', dict_dnsquery['Domain_Name'], result)


def print_failed(dict_dnsquery):
    logger = logging.getLogger(__name__)
    if "PTR" in dict_dnsquery['Query_Type']:
        logger.info('%-30s ---- timed out ----', dict_dnsquery['Query_IP'])
    else:
        logger.info('%-30s ---- timed out ----', dict_dnsquery['Domain_Name'])