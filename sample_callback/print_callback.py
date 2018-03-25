# -*- coding: utf-8 -*-


def fakegw_callback(packet):
    """
    Sample callback function.
    It print packet summary.
    :param packet: scapy packet instance.
    :return: None
    """
    print packet.summary()
