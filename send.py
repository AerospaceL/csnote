#!/usr/bin/python
#coding:utf-8
import os
import sys

def macStr(mac, sep=':', capital=False):
    '''
    MAC: 十进制 -> 字符串

    例如: macStr(73588229205) -> '00:11:22:33:44:55'
    '''
    return ((('%02X' if capital else '%02x')+sep)*6)[:-1] % tuple(
        map(lambda x:x%256, (mac>>40, mac>>32, mac>>24, mac>>16, mac>>8, mac)))

def macInt(mac, sep=':'):
    '''
    MAC: 字符串 -> 十进制

    例如: macInt('00:11:22:33:44:55') -> 73588229205
    '''
    mac = list(map(lambda x:int(x,base=16), mac.split(sep)))
    return (mac[0]<<40) + (mac[1]<<32) + (mac[2]<<24) + (mac[3]<<16) + (mac[4]<<8) + mac[5]

def macAdd(mac=None, A=0, B=0, C=0, D=0, E=0, F=0):
    '''
    MAC字符串加上整型数返回新MAC字符串

    参数:
        mac: 原始MAC
        A, B, C, D, E, F: 加数因子
    返回:
        生成MAC字符串
    例如:
        macAdd('00:11:22:33:44:55', F=11) -> '00:11:22:33:44:60'
    '''
    if mac == '' or mac == None:
        return macStr((A<<40) + (B<<32) + (C<<24) + (D<<16) + (E<<8) + F)
    return macStr(macInt(mac) + (A<<40) + (B<<32) + (C<<24) + (D<<16) + (E<<8) + F)

from scapy.all import *

try:
    ip_dst = sys.argv[1]
except:
    ip_dst = "192.168.1.2"

try:
    count = int(sys.argv[2], base=0)
except:
    count=1
    
print "Sending %d IP packet(s) to %s" % (count, ip_dst)
for i in range(0,1):
    smac = macAdd("00:00:00:00:00:00", F=i)
    dmac = macAdd("BC:30:6D:A6:CF:C9", F=i)
    p = (Ether(dst="00:00:00:00:00:01", src="00:00:00:00:00:01")/
	Dot1Q(vlan=i)/ 
	IP(src="0.0.0.0", dst="0.0.0.1")/   
        TCP(sport=7,dport=7)/
        "chenqianxi is a handsome boy,666")
    sendp(p, iface="veth0", count=count) 

