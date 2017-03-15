#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys 
import re
import logging
import nstools
from argparse import ArgumentParser, RawTextHelpFormatter
from nsobjects import ProfileHostname, Memorise


# processes cli arguments and usage guide
def process_cli(version):

    parser = ArgumentParser(
        prog='ns',
        description='''DNS resolution tool, supports multiple hostnames simultaneously and url based hostnames.
    DNS resolution tool will automatically strip off excess characters around the host and domain names
    e.g. http://google.com.au will resolve to google.com.au. The DNS server can be specified if you
    wish to query a specific DNS server otherwise the tool will use the operating system default.''',
        epilog='''Command line examples

    Resolve using OS default DNS server :- ns google.com.au
    Resolve using DNS server 8.8.4.4    :- ns http://google.com.au -s 8.8.4.4
    Resolve using DNS server 8.8.8.8    :- ns google.com.au -s''',
        formatter_class = RawTextHelpFormatter)

    parser.add_argument('domain',
                        nargs='+',
                        metavar=('{domain name}'),
                        help='Domain name to lookup')
    parser.add_argument('-s', '--server',
                        default=None,
                        nargs='?',
                        const='8.8.8.8',
                        metavar=('{xx.xx.xx.xx}'),
                        help='Define a name server, defaults to 8.8.8.8 if flag used and no ip supplied')
    parser.add_argument('-t', '--timeout',
                        default='2',
                        type=int,
                        choices=range(1, 11),
                        metavar=('{1..11}'),
                        help='Timeout is the number of seconds to wait for a response from a server, value can be between 1-10 - Default=2')
    parser.add_argument('-l', '--lifetime',
                        default='5',
                        type=int,
                        choices=[5, 10, 20, 30, 60],
                        metavar=('{5, 10, 20, 30, 60}'),
                        help='Lifetime for request, Default=5')
    parser.add_argument('-x', '--exhaustive',
                        default=None,
                        nargs='?',
                        type=int,
                        const='10',
                        choices=[10, 20, 30, 60],
                        metavar=('{10, 20, 30, 60}'),
                        help='Resolve the results exhaustivly, value can be 10, 20, 30, 60 - Default = disabled')
    parser.add_argument('-d', '--debug',
                        action="store_true",
                        help='enable program flow debug')
    parser.add_argument('--version',
                        action='version',
                        version='%(prog)s v'+version)

    # pass args into variable
    args = parser.parse_args()
    return args


def configure_logging(args):
    """
    Creates logging configuration and sets logging level based on cli argument

    Args:
        args: all arguments parsed from cli

    Returns:
        logging: logging configuration
    """
    if args.debug:
        logging.basicConfig(stream=sys.stdout,
                            level=logging.DEBUG,
                            format='%(levelname)-8s - %(name)-10s - %(message)s')
        nstools.print_debug_arguments(args)
    else:
        logging.basicConfig(stream=sys.stdout,
                            level=logging.INFO,
                            format='%(message)s')
    return logging

    
def type_hostname(dns_suffixes, args, a, url_type, final_dns_list): 
    logger = logging.getLogger(__name__)
    if len(dns_suffixes) > 0:
        logger.debug('Domain Name Format - Plane hostname with no domain, candidate for suffix search')
        successful_query = False
        for suffix in dns_suffixes:
            joiner = '.'
            # join hostname to domain
            domain_suffix = joiner.join([a.cleaned_domain(), suffix])
            b = ProfileHostname(domain_suffix, final_dns_list, args.timeout, args.lifetime)
            dns_result, dict_dnsquery = b.query_hostname()
            if args.debug:
                nstools.print_debug_query(dict_dnsquery, url_type)
            if len(dns_result) > 0:
                successful_query = True
                logger.debug('DNS query - A - Success')
                nstools.print_success(dns_result, dict_dnsquery)
                dns_result, dict_dnsquery = b.query_cname()
                if args.debug:
                    nstools.print_debug_query(dict_dnsquery, url_type)
                if len(dns_result) > 0:
                    logger.debug('DNS query - CNAME - Success')
                    nstools.print_success(dns_result, dict_dnsquery)
                else:
                    logger.debug('DNS query - CNAME - No results')
                
        if successful_query == False:
            logger.debug('Standard DNS lookup unsuccessful')
            dict_dnsquery['Domain_Name'] = a.cleaned_domain()
            nstools.print_failed(dict_dnsquery)
    else:
        logger.debug('Domain Name Format - Plane hostname with no domain')
        logger.debug('Domain Name Format - No suffixes found to add to hostname')
        dns_result, dict_dnsquery = a.query_hostname()
        if args.debug:
            nstools.print_debug_query(dict_dnsquery, url_type)
        if len(dns_result) > 0:
            nstools.print_success(dns_result, dict_dnsquery)
            dns_result, dict_dnsquery = a.query_cname()
            if args.debug:
                nstools.print_debug_query(dict_dnsquery, url_type)
            if len(dns_result) > 0:
                logger.debug('DNS query - CNAME - Success')
                nstools.print_success(dns_result, dict_dnsquery)
            else:
                logger.debug('DNS query - CNAME - No results')
        else:
            dict_dnsquery['Domain_Name'] = a.cleaned_domain()
            nstools.print_failed(dict_dnsquery)

            
def type_fwdn_ip(args, a, hostname_type, url_type, final_dns_list, exhaust_freq): 
    logger = logging.getLogger(__name__)
    
    memorised_list = Memorise()
    tracked_results_lol = []
    if args.exhaustive is not None:
        #import time
        i = 0
        while i <= 5:
            i += 1
            dns_result, dict_dnsquery = a.query_hostname()
            Memorise(dns_result)
            dns_result = memorised_list.get_updated_list()
            logger.debug('Exhaustive counter %s %s', i, dns_result)
        Memorise()
    else:
        dns_result, dict_dnsquery = a.query_hostname()

    if args.debug:
        if 'FQDN' in hostname_type:
            logger.debug('Domain Name Format - Hostname with domain')
        else:
            logger.debug('Domain Name Format - IP based domain, using reverse DNS lookup')
        nstools.print_debug_query(dict_dnsquery, url_type)

    if len(dns_result) > 0:
        tracked_results_lol, dns_result = nstools.track_results(dns_result, dict_dnsquery, tracked_results_lol)
        if len(dns_result) > 0:
            logger.debug('DNS query - A - Success')
            nstools.print_success(dns_result, dict_dnsquery)
            Memorise(dns_result)
            dns_result, dict_dnsquery = a.query_cname()
            if args.debug:
                nstools.print_debug_query(dict_dnsquery, url_type)
            if len(dns_result) > 0:
                logger.debug('DNS query - CNAME - Success')
                tracked_results_lol, dns_result = nstools.track_results(dns_result, dict_dnsquery, tracked_results_lol)
                if len(dns_result) > 0:
                    nstools.print_success(dns_result, dict_dnsquery)
                    Memorise(dns_result)
            else:
                logger.debug('DNS query - CNAME - No results')

        if args.exhaustive is not None:
            i = 0
            logger.debug('Entering exhaustive Lookup ----------------------------------------------------------------------------------------------')
            accumlated_result = memorised_list.get_updated_list()
            while i < len(accumlated_result):
                logger.debug('Exhaustive Lookup %s', accumlated_result)
                if 'FQDN' in hostname_type:
                    b = ProfileHostname(accumlated_result[i], final_dns_list, args.timeout, args.lifetime)
                else:
                    b = ProfileHostname(accumlated_result[i], final_dns_list, args.timeout, args.lifetime, a.cleaned_domain())
                dns_result, dict_dnsquery = b.query_hostname()
                if args.debug:
                    nstools.print_debug_query(dict_dnsquery, url_type)
                if len(dns_result) > 0:
                    tracked_results_lol, dns_result = nstools.track_results(dns_result, dict_dnsquery, tracked_results_lol)
                    if len(dns_result) > 0:
                        logger.debug('DNS query - A - Success')
                        nstools.print_success(dns_result, dict_dnsquery)
                        if 'FQDN' in dict_dnsquery['Hostname_Type']:
                            Memorise(dns_result)
                            accumlated_result = memorised_list.get_updated_list()
                            dns_result, dict_dnsquery = b.query_cname()
                            if args.debug:
                                nstools.print_debug_query(dict_dnsquery, url_type)
                            if len(dns_result) > 0:
                                logger.debug('DNS query - CNAME - Success')
                                tracked_results_lol, dns_result = nstools.track_results(dns_result, dict_dnsquery, tracked_results_lol)
                                if len(dns_result) > 0:
                                    nstools.print_success(dns_result, dict_dnsquery)
                                    Memorise(dns_result)
                                    accumlated_result = memorised_list.get_updated_list()
                                else:
                                    logger.debug('DNS query - CNAME - No results')
                            else:
                                logger.debug('DNS query - CNAME - No results')

                i += 1
                logger.debug('Exhaustive counter %s / %s', i, exhaust_freq)
                if i >= exhaust_freq:
                     break
    else:
        logger.debug('Standard DNS lookup unsuccessful')
        dict_dnsquery['Domain_Name'] = a.cleaned_domain()
        nstools.print_failed(dict_dnsquery)
    

# main process
def main():

    from _version import __version__
    version=__version__

    # get cli arguments
    args = process_cli(version)

    # set logging level
    logging = configure_logging(args)
    logger = logging.getLogger(__name__)

    if args.exhaustive is not None:
        exhaust_freq = args.exhaustive
        logger.debug('Exhaustive DNS search enabled, limiting resolution to %s', exhaust_freq)
    else:
        exhaust_freq = 2
        logger.debug('Exhaustive DNS search disabled, limiting resolution to %s', exhaust_freq)

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

    dns_suffixes = nstools.dns_suffix_query()
    # test for dns suffixes and warn user only if a plain hostname is in the list to resolve
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
        except ValueError as err:
            logger.error('%s Skipping', err)
        except Exception, err:
            logger.error('%s Unknown error', err)
            continue
        url_type = a.url_type()
        hostname_type = a.hostname_type()
        #dict_dnsquery['Domain_Name'] = a.cleaned_domain()

        if hostname_type not in ('IP', 'HOSTNAME', 'FQDN'):
            logger.error('%-30s Supplied domain name is not a recognisable format - Skipping....', domains)
            continue
        if url_type:
            logger.debug('Validation URL - URL cleaned up, before %s after %s', domains, a.cleaned_domain())

        if hostname_type in ('FQDN', 'IP'):
            type_fwdn_ip(args, a, hostname_type, url_type, final_dns_list, exhaust_freq)
        elif 'HOSTNAME' in hostname_type:
            type_hostname(dns_suffixes, args, a, url_type, final_dns_list)
        continue


if __name__ == "__main__":
    main()