#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import re
import socket
import dns.resolver     # import DNS functionality
from codecs import open


class ProfileHostname:

    def __init__(self, hostname, final_dns_list=[], timeout=2, lifetime=5, ptr_ip=None):
        self._hostname = hostname
        self.server_list = final_dns_list
        self._timeout = timeout
        self._lifetime = lifetime
        self.url_based = self._urlType()
        self._ptr_ip = ptr_ip

        # search and replace unwanted strings in URL like http:// , :80 , /xxxx/xxx
        p = re.compile('^.*//|:.*$|/.*$', re.VERBOSE)
        self._cleaned_domain = p.sub(r'', hostname)

        if self._cleaned_domain[-1] == ".":
            self._cleaned_domain = self._cleaned_domain[:-1] # strip exactly one dot from the right, if present

        allowed = re.compile("(?!-)[A-Za-z0-9-_]{1,63}(?<!-)$", re.IGNORECASE)
        if not all(allowed.match(x) for x in self._cleaned_domain.split(".")):
            raise ValueError("%-30s Invalid characters -" % self._cleaned_domain)
        if len(self._cleaned_domain) > 255:
            raise ValueError("%-30s Invalid length -" % self._cleaned_domain)

        self._hostname_type = self._hostnameType()
        if "IP" in self._hostname_type:
            self._dns_query_type = "PTR"
            self._ptr_domain = '.'.join(reversed(self._cleaned_domain.split("."))) + ".in-addr.arpa"
            self._query_ip=self._cleaned_domain
            self._domain_name = self._ptr_domain
        else:
            self._dns_query_type = "A"
            self._ptr_domain = None
            self._query_ip = None
            self._domain_name = self._cleaned_domain

    def hostname(self):
        return self._hostname

    def cleaned_domain(self):
        return self._cleaned_domain

    def hostname_type(self):
        return self._hostname_type

    def url_type(self):
        return self.url_based

    def dns_query_type(self):
        return self._dns_query_type

    def ptr_domain(self):
        return self._ptr_domain

    def _hostnameType(self):
        try:
            socket.inet_aton(self._cleaned_domain)
            return "IP"
        except:
            pass
        try:
            valid = re.search('^([A-Za-z0-9-_]){1,63}$', self._cleaned_domain, re.M|re.I)
            valid.group(1)
            return "HOSTNAME"
        except:
            pass
        allowed = re.compile("(?!-)[A-Za-z0-9-_]{1,63}(?<!-)$", re.IGNORECASE)
        if all(allowed.match(x) for x in self._cleaned_domain.split(".")):
            return "FQDN"
        return None

    def _urlType(self):
        try:
            valid = re.search(r'^.*//.*$', self._hostname, re.M|re.I)
            valid.group(0)
            return True
        except:
            return False
        
    def query_hostname(self):
        self._dns_profile = self.profile_dns()
        self.query_results = self.query_that_host(self._dns_profile)
        return self.query_results, self._dns_profile

    def query_cname(self):
        self._cname_profile = self.profile_cname()
        self.query_results = self.query_that_host(self._cname_profile)
        return self.query_results, self._cname_profile

    def profile_dns(self):
        dns_profile = {'Domain_Name': self._domain_name,
                         'Query_IP': self._query_ip,
                         'Hostname_Type': self._hostname_type,
                         'Query_Type': self.dns_query_type(),
                         'DNS_Serv': self.server_list,
                         'DNS_TO': self._timeout,
                         'DNS_LT': self._lifetime}
        return dns_profile

    def profile_cname(self):
        if self._ptr_ip is not None:
            self._query_ip=self._ptr_ip
        cname_profile = {'Domain_Name': self._domain_name,
                         'Query_IP': self._query_ip,
                         'Hostname_Type': self._hostname_type,
                         'Query_Type': 'CNAME',
                         'DNS_Serv': self.server_list,
                         'DNS_TO': self._timeout,
                         'DNS_LT': self._lifetime}
        return cname_profile
        
    def query_that_host(self, dict_queryserver):
        self.dict_queryserver = dict_queryserver
        results = []
        try:
            myResolver = dns.resolver.Resolver()
            myResolver.timeout = self.dict_queryserver['DNS_TO']
            myResolver.lifetime = self.dict_queryserver['DNS_LT']
            if not len(self.dict_queryserver['DNS_Serv']) == 0:
                myResolver.nameservers = self.dict_queryserver['DNS_Serv']
            myAnswers = myResolver.query(self.dict_queryserver['Domain_Name'], self.dict_queryserver['Query_Type'])
            #print myAnswers.__dict__
            #print dir(myAnswers[0])
            for rdata in myAnswers:
                results.append(str(rdata))
            return results
        except:
            return results
        
        
class QueryServer():

    def __init__(self, dict_queryserver):
        self.dict_queryserver = dict_queryserver
        self.query_results = self.query_that_host()

    def query_host(self):
        return self.query_results

    def query_that_host(self):
        results = []
        try:
            myResolver = dns.resolver.Resolver()
            myResolver.timeout = self.dict_queryserver['DNS_TO']
            myResolver.lifetime = self.dict_queryserver['DNS_LT']
            if not len(self.dict_queryserver['DNS_Serv']) == 0:
                myResolver.nameservers = self.dict_queryserver['DNS_Serv']
            myAnswers = myResolver.query(self.dict_queryserver['Domain_Name'], self.dict_queryserver['Query_Type'])
            #print myAnswers.__dict__
            #print dir(myAnswers[0])
            for rdata in myAnswers:
                results.append(str(rdata))
            return results
        except:
            return results

            
class Memorise:
    """
    Creates accumlative dns results

    Args:
        host_list: results from most resent query

    Returns:
        mem: accumulative results
    """
    
    mem = []
    
    @classmethod
    def _append_hostname(cls, host_list):
        for h in host_list:
            if h not in cls.mem:
                cls.mem.append(h)
        return Memorise.mem
    
    def __init__(self, host_list=None):
        self.host_list = host_list
        if self.host_list is not None:
            Memorise._append_hostname(self.host_list)
        else:
            Memorise.mem = []
    
    def get_updated_list(self):
        return Memorise.mem  