#!/usr/local/bin/python2.7
# encoding: utf-8

__description__ = '''
fakegw -- arp cache poisonig tool.

This is an packet intercepter which using arp cache poisoning.

@copyright: Copyright (c) 2018 YOJIRO YAMAGUCHI
@license: MIT License
'''

import sys
import os
from argparse import ArgumentParser, RawDescriptionHelpFormatter
import traceback

from fakegw.core import start_fakegw

__version__ = 0.1

DEBUG = 1


def main(argv=None):
    if argv is None:
        argv = sys.argv
    else:
        sys.argv.extend(argv)

    try:
        # Setup argument parser
        parser = ArgumentParser(description=__description__,
                                formatter_class=RawDescriptionHelpFormatter)
        parser.add_argument("-i", "--interface",
                            dest="interface", help="Interface name")
        parser.add_argument("-g", "--gateway",
                            dest="gateway_ip", help="Gateway IP address",
                            required=True)
        parser.add_argument("-t", "--target",
                            dest="target_ip", help="Target IP address",
                            required=True)
        parser.add_argument("-v", "--verbose",
                            dest="verbose",
                            action="store_true",
                            help="Verbose output")

        # Process arguments
        args = parser.parse_args()
        verbose = args.verbose
        interface = args.interface
        gateway_ip = args.gateway_ip
        target_ip = args.target_ip

        if verbose:
            print("Verbose mode on")
        start_fakegw(gateway_ip=gateway_ip,
                     target_ip=target_ip,
                     interface=interface)

        return 0
    except Exception as e:
        print traceback.format_exc()
        return 1


if __name__ == "__main__":
    if DEBUG:
        sys.argv.append("-v")
        sys.argv.append("-g")
        sys.argv.append("192.168.11.1")
        sys.argv.append("-t")
        sys.argv.append("-192.168.11.3")
    sys.exit(main())
