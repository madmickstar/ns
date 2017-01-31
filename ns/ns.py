#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re               # import regex module
import sys              # import handles errors probably other important stuff
import logging
import argparse         # import cli argument
from argparse import RawTextHelpFormatter # imports rawtesthelpformater for help formatting

import nstools
from nsobjects import QueryServer, ProfileHostname


# processes cli arguments and usage guide
def process_cli(version):

    parser = argparse.ArgumentParser(
        prog='ns',
        description='''DNS resolution tool, supports multiple hostnames simultaneously and url based hostnames.
    DNS resolution tool will automatically strip off excess characters around the host and domain names
    e.g. http://google.com.au will resolve to google.com.au. The DNS server can be specified if you
    wish to query a specific DNS server otherwise the tool will use the operating system default.''',
        epilog='''Command line examples

    Resolve using OS default DNS server :- ns google.com.au
    Resolve using DNS server 8.8.4.4    :- ns http://google.com.au -s 8.8.4.4
    Resolve using DNS server 8.8.8.8    :- ns google.com.au -s''',
        formatter_class=RawTextHelpFormatter)

    parser.add_argument('domain',
                        nargs='+',
                        help='domain name to lookup')
    parser.add_argument('-s', '--server',
                        default=None,
                        nargs='?',
                        const='8.8.8.8',
                        help='define a name server, defaults to 8.8.8.8 if flag used and no ip supplied')
    parser.add_argument('-d', '--debug',
                        action="store_true",
                        help='enable program flow debug')
    parser.add_argument('-t', '--timeout',
                        default='2',
                        type=int,
                        choices=range(1,11),
                        help='Timeout is the number of seconds to wait for a response from a server, value can be between 1-10 - Default=2')
    parser.add_argument('-l', '--lifetime',
                        default='5',
                        type=int,
                        choices=[5, 10, 20, 30, 60],
                        help='Lifetime for request, Default=5')
    parser.add_argument('--version',
                        action='version',
                        version='%(prog)s v'+version)

    # pass args into variable
    args = parser.parse_args()
    return args


# main process
def main():

    from _version import __version__
    version=__version__

    # get cli arguments
    args = process_cli(version)

    # set logging level
    if args.debug:
        logging.basicConfig(stream=sys.stdout,
                            level=logging.DEBUG,
                            format='%(levelname)-8s - %(name)-10s - %(message)s')
        nstools.print_debug_arguments(args)
    else:
        logging.basicConfig(stream=sys.stdout,
                            level=logging.INFO,
                            format='%(message)s')
    logger = logging.getLogger(__name__)
    logger.info('')
    # test and validate cli dns server
    if args.server:
        cli_dns_list = nstools.validate_cli_dns(args.server)
        final_dns_list = nstools.test_dns_server(cli_dns_list)
        if len(final_dns_list) == 0:
            logger.warning('DNS Server CLI - Server failed test %s, falling back to OS DNS', cli_dns_list)
        else:
            logger.debug('DNS Server CLI - Validated and tested DNS servers final list %s', final_dns_list)
    else:
        final_dns_list = []

    # test for dns suffixes and warn user only if a plain hostname is in the list to resolve
    dns_suffixes = nstools.dns_suffix_query(args)
    if len(dns_suffixes) == 0:
        for domains in args.domain:
            try:
                a = ProfileHostname(domains)
            except Exception, err:
                continue
            if 'HOSTNAME' in a.hostname_type():
                logger.warning('**Warning** Plane hostname detected and no DNS suffixes found\n')
                break

    # cycle through domains
    for domains in args.domain:
        logger.debug('-----------------------------------------------------')
        try:
            a = ProfileHostname(domains, final_dns_list, args.timeout, args.lifetime)
        except Exception, err:
            logger.error('%s Skipping', err)
            continue

        url_type = a.url_type()
        hostname_type = a.hostname_type()
        dict_dnsquery = a.profile_dns()

        logger.debug('Domain profile - URL = %s, Name_Type = %s, Q_Type = %s, Q_Name = %s, Q_IP = %s',
                                        url_type,
                                        dict_dnsquery['Hostname_Type'],
                                        dict_dnsquery['Query_Type'],
                                        dict_dnsquery['Domain_Name'],
                                        dict_dnsquery['Query_IP'])

        if hostname_type not in ('IP', 'HOSTNAME', 'FQDN'):
            logger.error('%-30s Supplied domain name is not a recognisable format - Skipping....', domains)
            continue

        if url_type:
            logger.debug('Validation URL - URL cleaned up, before %s after %s', domains, dict_dnsquery['Domain_Name'])

        if args.debug:
            nstools.print_debug_query(dict_dnsquery)

        if 'FQDN' in hostname_type:
            logger.debug('Domain Name Format - Hostname with domain')
            q = QueryServer(dict_dnsquery)
            dns_result = q.query_host()
            if not len(dns_result) == 0:
                nstools.print_success(dns_result, dict_dnsquery)
                dict_dnsquery = a.profile_cname()
                nstools.cname_lookup(dict_dnsquery, url_type, args)
            else:
                nstools.print_failed(dict_dnsquery)
        elif 'IP' in hostname_type:
            logger.debug('Domain Name Format - IP based domain, using reverse DNS lookup')
            q = QueryServer(dict_dnsquery)
            dns_result = q.query_host()
            if not len(dns_result) == 0:
                nstools.print_success(dns_result, dict_dnsquery)
                # query results the same as a FQDN
                for domains in dns_result:
                    b = ProfileHostname(domains, final_dns_list, args.timeout, args.lifetime, a.cleaned_domain())
                    dict_dnsquery = b.profile_cname()
                    nstools.cname_lookup(dict_dnsquery, url_type, args)
            else:
                nstools.print_failed(dict_dnsquery)

        elif 'HOSTNAME' in hostname_type:
            if not len(dns_suffixes) == 0:
                logger.debug('Domain Name Format - Plane hostname with no domain, candidate for suffix search')
                successful_query = False
                for suffix in dns_suffixes:
                    joiner = '.'
                    # join hostname to domain
                    domain_suffix = joiner.join([a.cleaned_domain(), suffix])
                    b = ProfileHostname(domain_suffix, final_dns_list, args.timeout, args.lifetime)
                    dict_dnsquery = b.profile_dns()
                    if args.debug:
                        nstools.print_debug_query(dict_dnsquery)

                    q = QueryServer(dict_dnsquery)
                    dns_result = q.query_host()
                    if not len(dns_result) == 0:
                        successful_query = True
                        nstools.print_success(dns_result, dict_dnsquery)
                        dict_dnsquery = b.profile_cname()
                        nstools.cname_lookup(dict_dnsquery, url_type, args)
                    else:
                        logger.debug('Standard DNS lookup unsuccessful')
                if successful_query == False:
                    dict_dnsquery['Domain_Name'] = a.cleaned_domain()
                    nstools.print_failed(dict_dnsquery)
            else:
                logger.debug('Domain Name Format - Plane hostname with no domain')
                logger.debug('Domain Name Format - No suffixes found to add to hostname')
                q = QueryServer(dict_dnsquery)
                dns_result = q.query_host()
                if not len(dns_result) == 0:
                    nstools.print_success(dns_result, dict_dnsquery)
                    dict_dnsquery = a.profile_cname()
                    nstools.cname_lookup(dict_dnsquery, url_type, args)
                else:
                    nstools.print_failed(dict_dnsquery)
        continue


if __name__ == "__main__":
    main()