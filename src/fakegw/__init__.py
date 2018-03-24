#!/usr/local/bin/python2.7
# encoding: utf-8

import sys
from argparse import ArgumentParser, RawDescriptionHelpFormatter
import logging
from fakegw.core import start_fakegw
from scapy.utils import PcapWriter


__description__ = '''
fakegw -- arp cache poisonig tool.

This is an packet interceptor which using arp cache poisoning.

@copyright: Copyright (c) 2018 yyojiro
@license: MIT License
'''

logging.basicConfig(format='%(asctime)s:%(levelname)s:%(message)s',
                    level=logging.INFO)

pcap_wirter = None


def debug_callback(packet):
    logging.debug(packet.summary())


def pcap_file_writer(packet):
    pcap_wirter.write(packet)
    if logging.getLogger().isEnabledFor(logging.DEBUG):
        logging.debug(packet.summary())


def main(argv=None):
    if argv is None:
        argv = sys.argv
    else:
        sys.argv.extend(argv)

    try:
        # Setup argument parser
        parser = ArgumentParser(description=__description__,
                                formatter_class=RawDescriptionHelpFormatter)
        parser.add_argument("-v", "--verbose",
                            dest="verbose", help="Verbose output",
                            action = "store_true")
        parser.add_argument("-i", "--interface",
                            dest="interface", help="Interface name")
        parser.add_argument("-g", "--gateway",
                            dest="gateway_ip", help="Gateway IP address",
                            required=True)
        parser.add_argument("-t", "--target",
                            dest="target_ip", help="Target IP address",
                            required=True)
        parser.add_argument("-f", "--file",
                            dest="pcap_file", help="Captured file name")

        # Process arguments
        args = parser.parse_args()
        interface = args.interface
        gateway_ip = args.gateway_ip
        target_ip = args.target_ip
        pcap_file = args.pcap_file

        if args.verbose:
            logging.getLogger().setLevel(logging.DEBUG)
            logging.info("Verbose mode on")

        call_back_func = None
        if pcap_file is not None:
            global pcap_wirter
            pcap_wirter = PcapWriter(pcap_file, append=True, sync=True)
            call_back_func = pcap_file_writer
        else:
            call_back_func = debug_callback

        start_fakegw(gateway_ip=gateway_ip,
                     target_ip=target_ip,
                     interface=interface,
                     callback=call_back_func)

        return 0
    except Exception as e:
        logging.error(e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
