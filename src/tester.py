'''
Created on 2018/03/21

@author: yojiro
'''

import sys
from fakegw.core import start_fakegw


if __name__ == '__main__':
    start_fakegw(gateway_ip="192.168.11.1",
                 target_ip="192.168.11.3",
                 interface=None)
