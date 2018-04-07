#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os.path
from argparse import ArgumentParser, RawDescriptionHelpFormatter
import logging, logging.config
import ConfigParser
import imp
from fakegw.core import start_fakegw


__description__ = '''
fakegw -- arp cache poisonig tool.

This is a packet interceptor which using arp cache poisoning.

@copyright: (c) 2018 yyojiro
@license: MIT License
'''

logging.basicConfig(format='[%(asctime)s][%(levelname)s] %(message)s',
                    level=logging.INFO)
logger = logging.getLogger()

default_config = {
    'interface': None,
    'gateway_ip': None,
    'target_ips': None,
    'callback_module': None
}


def debug_callback(packet):
    logging.debug(packet.summary())


def main(argv=None):
    if argv is None:
        argv = sys.argv
    else:
        sys.argv.extend(argv)

    try:
        # setup argument parser
        parser = ArgumentParser(description="arg parser test",
                                formatter_class=RawDescriptionHelpFormatter)
        ex_group = parser.add_mutually_exclusive_group(required=True)
        parser.add_argument("-v", "--verbose",
                            dest="verbose", help="Verbose output",
                            action="store_true")
        parser.add_argument("-i", "--interface",
                            dest="interface", help="Interface name")
        parser.add_argument("-g", "--gateway",
                            dest="gateway_ip", help="Gateway IP address")
        ex_group.add_argument("-t", "--targets",
                              dest="target_ips", help="Target IP address(es).")
        parser.add_argument("-p", "--callback",
                            dest="callback_module", help="Path to callback python module")
        ex_group.add_argument("-c", "--conf",
                              dest="conf_file",
                              help="Configuration file. If you set it, ignore other options")

        # Process arguments
        args = parser.parse_args()
        interface = args.interface
        gateway_ip = args.gateway_ip
        target_ips = args.target_ips
        callback_path = args.callback_module
        call_back_func = None

        global logger
        if args.verbose:
            logger.setLevel(logging.DEBUG)
            logger.info("Verbose mode on")
            call_back_func = debug_callback
        # read config
        if args.conf_file is not None:
            ini = ConfigParser.SafeConfigParser(default_config)
            ini.read(args.conf_file)
            logging.config.fileConfig(args.conf_file)
            logger = logging.getLogger()
            interface = ini.get('subnet', 'interface')
            gateway_ip = ini.get('subnet', 'gateway_ip')
            target_ips = ini.get('subnet', 'target_ips')
            callback_path = ini.get('core', 'callback_module')

        # load callback module
        if callback_path is not None:
            if os.path.exists(callback_path) is False:
                logger.error("%s is not exists." % callback_path)
                return 1
            abspath = os.path.abspath(callback_path)
            module_dir = os.path.dirname(abspath)
            module_name = os.path.basename(abspath).split('.')[0]
            sys.path.append(module_dir)
            (file, path, description) = imp.find_module(module_name, [module_dir])
            module = imp.load_module(module_name, file, path, description)
            logger.info("call back module '%s' is loaded." % module.__name__)
            call_back_func = module.fakegw_callback

        # run main
        start_fakegw(gateway_ip=gateway_ip,
                     target_ips=target_ips,
                     interface=interface,
                     callback=call_back_func)

        return 0
    except AssertionError:
        logger.error("can not find gateway !")
        return 1
    except Exception as e:
        logger.error(e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
