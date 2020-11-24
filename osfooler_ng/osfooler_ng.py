#!/usr/bin/python2
# -*- coding: utf-8 -*-

from random import randint
import hashlib
import logging
import module_p0f
import socket
import fcntl
import struct
import optparse
import sys
import time
import os
import netfilterqueue as nfqueue
import ConfigParser
import ast
l = logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from dpkt import *
from socket import AF_INET, AF_INET6, inet_ntoa
import urllib
import multiprocessing
from multiprocessing import Process

# Some configuration
sys.tracebacklimit = 0
conf.verbose = 0
conf.L3socket = L3RawSocket
sys.path.append('python')
sys.path.append('build/python')
sys.path.append('dpkt-1.6')

# Initialize statistic variables
icmp_packet = 0
IPID = 0

# Started NFQueues
q_num0 = -1
q_num1 = -1

# TCP packet information
# Control flags
TH_FIN = 0x01          # end of data
TH_SYN = 0x02          # synchronize sequence numbers
TH_RST = 0x04          # reset connection
TH_PUSH = 0x08          # push
TH_ACK = 0x10          # acknowledgment number set
TH_URG = 0x20          # urgent pointer set
TH_ECE = 0x40          # ECN echo, RFC 3168
TH_CWR = 0x80          # congestion window reduced
# Options (opt_type) - http://www.iana.org/assignments/tcp-parameters
TCP_OPT_EOL = 0     # end of option list
TCP_OPT_NOP = 1     # no operation
TCP_OPT_MSS = 2     # maximum segment size
TCP_OPT_WSCALE = 3     # window scale factor, RFC 1072
TCP_OPT_SACKOK = 4     # SACK permitted, RFC 2018
TCP_OPT_SACK = 5     # SACK, RFC 2018
TCP_OPT_ECHO = 6     # echo (obsolete), RFC 1072
TCP_OPT_ECHOREPLY = 7     # echo reply (obsolete), RFC 1072
TCP_OPT_TIMESTAMP = 8     # timestamp, RFC 1323
TCP_OPT_POCONN = 9     # partial order conn, RFC 1693
TCP_OPT_POSVC = 10    # partial order service, RFC 1693
TCP_OPT_CC = 11    # connection count, RFC 1644
TCP_OPT_CCNEW = 12    # CC.NEW, RFC 1644
TCP_OPT_CCECHO = 13    # CC.ECHO, RFC 1644
TCP_OPT_ALTSUM = 14    # alt checksum request, RFC 1146
TCP_OPT_ALTSUMDATA = 15    # alt checksum data, RFC 1146
TCP_OPT_SKEETER = 16    # Skeeter
TCP_OPT_BUBBA = 17    # Bubba
TCP_OPT_TRAILSUM = 18    # trailer checksum
TCP_OPT_MD5 = 19    # MD5 signature, RFC 2385
TCP_OPT_SCPS = 20    # SCPS capabilities
TCP_OPT_SNACK = 21    # selective negative acks
TCP_OPT_REC = 22    # record boundaries
TCP_OPT_CORRUPT = 23    # corruption experienced
TCP_OPT_SNAP = 24    # SNAP
TCP_OPT_TCPCOMP = 26    # TCP compression filter
TCP_OPT_MAX = 27

# Some knowledge about nmap packets
# Options
T1_opt1 = "03030a01020405b4080affffffff000000000402"
T1_opt2 = "020405780303000402080affffffff0000000000"
T1_opt3 = "080affffffff0000000001010303050102040280"
T1_opt4 = "0402080affffffff0000000003030a00"
T1_opt5 = "020402180402080affffffff0000000003030a00"
T1_opt6 = "020401090402080affffffff00000000"
T2_T6_opt = "03030a0102040109080affffffff000000000402"
T7_opt = "03030f0102040109080affffffff000000000402"
ECN_opt = "03030a01020405b404020101"
# Window Size
T1_1w = "1"
T1_2w = "63"
T1_3w = "4"
T1_4w = "4"
T1_5w = "16"
T1_6w = "512"
T2w = "128"
T3w = "256"
T4w = "1024"
T5w = "31337"
T6w = "32768"
T7w = "65535"
ECEw = "3"
# Payloads
udp_payload = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"

# Parse fields in nmap-db
def parse_nmap_field(field):
  if (field.find('|') != -1):
    # Choose randomly one value :)
    list = field.split("|")
    # Filter any empty string
    list = filter (None,list)
    result = random.choice(list)
  else:
    result = field
  return result

# Get default interface address without external packages
def get_ip_address(ifname):
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  return socket.inet_ntoa(fcntl.ioctl(
    s.fileno(),
    0x8915,  # SIOCGIFADDR
    struct.pack('256s', ifname[:15])
    )[20:24])

def show_banner():
	print ("""\
		
                 -o:      
                .o+`      
                :o-.-.` ``
          `-::::+o/-:++/o/	          _____             __                                        
        `/+//+/--ss///:-.    ____  ______/ ________   ____ |  |   ___________            ____   ____  
        /o:` .:/:ss         /  _ \/  ___\   __/  _ \ /  _ \|  | _/ __ \_  __ \  ______  /    \ / ___\ 
        oo`.-` .+s+        (  <_> \___ \ |  |(  <_> (  <_> |  |_\  ___/|  | \/ /_____/ |   |  / /_/  >
  .-::::oo--/+/+o/`         \____/____  >|__| \____/ \____/|____/\___  |__|            |___|  \___  / 
 /+/++:-/s+///:-`                     \/                             \/                     \/_____/ 
 `  `-///s:                           
      `-os.                           v1.0b (https://github.com/segofensiva/osfooler-ng)
       /s:                                                                                                                                                   
""")

# Which packet is?
def check_even(number):
  if number % 2 == 0:
    return 1
  else:
    return 0

# Display TCP flags in human format
def tcp_flags(flags):
  ret = ''
  if flags & TH_FIN:
    ret = ret + 'F'
  if flags & TH_SYN:
    ret = ret + 'S'
  if flags & TH_RST:
    ret = ret + 'R'
  if flags & TH_PUSH:
    ret = ret + 'P'
  if flags & TH_ACK:
    ret = ret + 'A'
  if flags & TH_URG:
    ret = ret + 'U'
  if flags & TH_ECE:
    ret = ret + 'E'
  if flags & TH_CWR:
    ret = ret + 'C'
  return ret

# Parse TCP options to human format
def opts_human(options):
  opts = []
  for o, v in options:
    if o == TCP_OPT_WSCALE:
      opts.append("WS%d" % ord(v))
    elif o == TCP_OPT_MSS:
      opts.append("MSS%d" % struct.unpack('>H', v)[0])
    elif o == TCP_OPT_TIMESTAMP:
      opts.append("TS(%d,%d)" % struct.unpack('>II', v))
    elif o == TCP_OPT_NOP:
      opts.append("NOP")
    elif o == TCP_OPT_SACKOK:
      opts.append("SACK")
  return opts

# GET IP ID ICMP
def get_icmp_ipid():
  for x in range(0, len(base["SEQ"])):
    if (base["SEQ"][x][0] == "CI"):
      icmp_ipid = base["SEQ"][x][1]

#
def get_ipid_new(test):
  i = 1
  for x in range(0, len(base["SEQ"])):
    if (base["SEQ"][x][0] == test):
      if base["SEQ"][x][1] == "Z":
        i = 0
      elif base["SEQ"][x][1] == "RD":
        i = 0
        while (i < 20000):
          i = randint(1, 65535)
      elif base["SEQ"][x][1] == "RI":
        i = randint(1, 1500)
        while (i < 1000) or (i % 256 == 0):
          i = randint(1, 1500)
          #print "%s" % i
      elif base["SEQ"][x][1] == "BI":
        i = randint(1, 5120)
        while (i % 256 != 0):
          i = randint(1, 5120)
      elif base["SEQ"][x][1] == "I":
        i = randint(0, 9)
      else:
        IPID = randint(1, 65535)
  return i

# Send ICMP response
def send_icmp_response(pl, probe):
  global icmp_packet
  global icmp_ipid 
  pkt = ip.IP(pl.get_payload())
  # DON'T FRAGMENT ICMP (DFI)
  if (base[probe][0][1] == "N"):
    frag_bit = 0  # None have it activated
  elif (base[probe][0][1] == "S"):
    if (check_even(icmp_packet)):
      frag_bit = 2  # First without DF
    else:
      rag_bit = 0  # Second one with DF
  elif (base[probe][0][1] == "Y"):
    frag_bit = 2  # Both have DF bit active
  else:
    if (check_even(icmp_packet)):
      frag_bit = 0  # First without DF
    else:
      frag_bit = 2  # Second one with DF
  
  TG = int(base[probe][2][1], 16)
  # ICMP response code (CD)
  if (base[probe][3][1] == "Z"):
    code = 0  # Both have 0 value
  elif (base[probe][3][1] == "S"):
    code = pkt.icmp.code  # Same as received in the original packet
  elif (base[probe][3][1] == "00"):  # nn
    code = 1
  else:
    code = 0  # Any other combo
    # TODO
    # any other combo
    icmp_packet = icmp_packet + 1
    inc_ipid = get_ipid_new("II")
    if (inc_ipid):
        icmp_ipid = icmp_ipid + inc_ipid
    else:
        icmp_ipid = icmp_ipid + randint(50, 100)
    if (icmp_ipid > 65535):
        icmp_ipid = icmp_ipid - 65535
    send(IP(id=icmp_ipid, dst=inet_ntoa(pkt.src), src=inet_ntoa(pkt.dst), flags=frag_bit, ttl=TG)
       / ICMP(id=pkt.icmp.data.id, seq=pkt.icmp.data.seq, code=code, type=0), verbose=0)

# Send UDP response
def send_udp_response(pl, probe): 
  pkt = ip.IP(pl.get_payload())
  if (base[probe][0][1] == "Y"):
    frag_bit = 2
  else:
    frag_bit = 0
  TG = int(base[probe][2][1], 16)
  IPL = int(base[probe][3][1], 16)
  FIELD = int(base[probe][4][1])
  send(IP(dst=inet_ntoa(pkt.src), src=inet_ntoa(pkt.dst), ttl=TG, flags=frag_bit) / ICMP(code=3, type=3) /
    IP(dst=inet_ntoa(pkt.dst), src=inet_ntoa(pkt.src), id=pkt.id, ttl=TG - 1) / UDP(dport=pkt.udp.dport, sport=pkt.udp.sport), verbose=0)

# Send probe response
def send_probe_response(pl, probe):
  global IPID 
  pkt = ip.IP(pl.get_payload())
  # IP DON'T FRAGMENT BIT (DF)
  if (base[probe][1][1] == "Y"):
    frag_bit = 2
  else:
    frag_bit = 0
  TG = int(base[probe][3][1], 16)
  # TCP INITICIAL WINDOW SIZE (W)
  W = parse_nmap_field(base[probe][4][1])
  if ( W != "N"):
    W = int(W, 16)
  else :
    W = None
  # TCP SEQUENCE NUMBER (S)
  if base[probe][5][1] == "Z":
    SEQ = 0
  elif base[probe][5][1] == "A":
    SEQ = int(pkt.tcp.ack)
  elif base[probe][5][1] == "A+":
    SEQ = int(pkt.tcp.ack)
    SEQ = SEQ + 1
  else:
    SEQ = randint(1, 65535)
  # TCP ACKNOWLEDGMENT NUMBER (A)
  if base[probe][6][1] == "Z":
    ACK = 0
  elif base[probe][6][1] == "S":
    ACK = int(pkt.tcp.seq)
  elif base[probe][6][1] == "S+":
    ACK = int(pkt.tcp.seq)
    ACK = ACK + 1
  else:
    ACK = randint(1, 65535)
  # TCP FLAGS (F)
  FLAGS = base[probe][7][1]
  # TCP OPTIONS
  opts = []
  opts = options_to_scapy(parse_nmap_field(base[probe][8][1]))
  # TODO
  # TCP RST DATA CHECKSUM
  # TODO
  # TCP MISCELLANEOUS QUIRKS
  # IPID INCREMENTS
  inc_ipid = get_ipid_new("CI")
  if (inc_ipid):
    IPID = IPID + inc_ipid
  else:
    IPID = IPID + randint(50, 100)
  if (IPID > 65535):
    IPID = IPID - 65535
  send(IP(id=IPID, dst=inet_ntoa(pkt.src), src=inet_ntoa(pkt.dst), flags=frag_bit, ttl=TG) /
     TCP(sport=pkt.tcp.dport, dport=pkt.tcp.sport, seq=SEQ, ack=ACK, window=W, options=opts, flags=FLAGS), verbose=0)

# ECN
# Send probe response
def send_ECN_response(pl, probe):
    global IPID 
    pkt = ip.IP(pl.get_payload())
    # IP DON'T FRAGMENT BIT (DF)
    df_parsed = parse_nmap_field(base[probe][1][1])
    if (df_parsed == "Y"):
        frag_bit = 2
    else:
        frag_bit = 0
    # IP INITIAL TIME-TO-LIVE (T)
    ttl_parsed = parse_nmap_field(base[probe][2][1])
    if ttl_parsed.find("-"):
        T = int(ttl_parsed[3:], 16)
    else:
        T = int(ttl_parsed)
    # IP INITIAL TIME-TO-LIVE GUESS (TG)
    TG = int(parse_nmap_field(base[probe][3][1]), 16)
    # TCP INITICIAL WINDOW SIZE (W)
    W = parse_nmap_field(base[probe][4][1])
    if ( W != "N"):
      W = int(W, 16)
    else :
      W = None
    # TCP OPTIONS
    if (base[probe][5][0] == "O"):
      opts = []
      opts = options_to_scapy(parse_nmap_field(base[probe][5][1]))
      if (base[probe][6][1] == "Y"):
        FLAGS = "E"
      elif (base[probe][6][1] == "N"):
        FLAGS = ""
      elif (base[probe][6][1] == "S"):
        FLAGS = "CE"
      else:
        FLAGS = "C"
    elif (base[probe][5][0] == "CC"):
      opts = []
      flags_parsed = parse_nmap_field(base[probe][5][1])
      if (flags_parsed == "Y"):
        FLAGS = "E"
      elif (flags_parsed == "N"):
       FLAGS = ""
      elif (flags_parsed == "S"):
       FLAGS = "CE"
      else:
       FLAGS = "C"
    # TODO
    # TCP RST DATA CHECKSUM (CC)
    # TODO
    # TCP MISCELLANEOUS QUIRKS
    # IPID INCREMENTS
    inc_ipid = get_ipid_new("CI")
    if (inc_ipid):
      IPID = IPID + inc_ipid
    else:
      IPID = IPID + randint(50, 100)
    if (IPID > 65535):
      IPID = IPID - 65535
    send(IP(id=IPID, dst=inet_ntoa(pkt.src), src=inet_ntoa(pkt.dst), flags=frag_bit, ttl=TG) /
      TCP(sport=pkt.tcp.dport, dport=pkt.tcp.sport, window=W, options=opts, flags=FLAGS), verbose=0)

def send_probe_response_T1(pl, probe, packet):
    global IPID 
    pkt = ip.IP(pl.get_payload()) 
    # IP DON'T FRAGMENT BIT (DF)
    df_parsed = parse_nmap_field(base[probe][1][1])
    if (df_parsed == "Y"):
        frag_bit = 2
    else:
        frag_bit = 0
    # IP INITIAL TIME-TO-LIVE GUESS (TG)
    TG = int(parse_nmap_field(base[probe][3][1]), 16)
    # TCP SEQUENCE NUMBER (S)
    seq_parsed = parse_nmap_field(base[probe][4][1])
    if seq_parsed == "Z":
        SEQ = 0
    elif seq_parsed == "A":
        SEQ = int(pkt.tcp.ack)
    elif seq_parsed == "A+":
        SEQ = int(pkt.tcp.ack)
        SEQ = SEQ + 1
    else:
        SEQ = randint(1, 65535)
    # TCP ACKNOWLEDGMENT NUMBER (A)
    if base[probe][5][1] == "Z":
        ACK = 0
    elif base[probe][5][1] == "S":
        ACK = int(pkt.tcp.seq)
    elif base[probe][5][1] == "S+":
        ACK = int(pkt.tcp.seq)
        ACK = ACK + 1
    else:
        ACK = randint(1, 65535)
    # TCP FLAGS (F)
    #   R = RESET
    #     WARNING: RST from XXX.XXX.XXX.XXX port 22 -- is this port really open?
    FLAGS = parse_nmap_field(base[probe][6][1])
    # TCP OPTIONS
    opts = []
    opts = options_to_scapy(parse_nmap_field(base["OPS"][packet - 1][1]))
    # TODO
    # TCP RST DATA CHECKSUM
    # TODO
    # TCP MISCELLANEOUS QUIRKS
    W = parse_nmap_field(base["WIN"][packet - 1][1])
    if ( W != "N"):
      W = int(W, 16)
    else :
      W = None
    send(IP(dst=inet_ntoa(pkt.src), src=inet_ntoa(pkt.dst), flags=frag_bit, ttl=TG) /
         TCP(sport=pkt.tcp.dport, dport=pkt.tcp.sport, seq=SEQ, ack=ACK, flags=FLAGS, window=W, options=opts,), verbose=0)

def get_nmap_os_db_path():
  return os.path.abspath(os.path.dirname(__file__)) + "/dep/nmap-os-db"

# Parse nmap-os-db
def get_base():
    f = get_nmap_os_db_path()
    base = []
    name = None
    dic = {}
    for l in f:
        l = l.strip()
        if not l or l[0] == "#":
            continue
        if l[:12] == "Fingerprint ":
            print " [+] Fingerprint selected: %s" % l[12:]
            name = l[12:].strip()
            sig = {}
            p = base
            continue
        elif l[:6] == "Class":
            continue
        elif l[:4] == "CPE ":
            continue
        else:
            op = l.find("(")
            cl = l.find(")")
            if op < 0 or cl < 0:
                # print "error reading file"
                continue
            cursor = l[:op]
            dic[cursor] = (
                list(map(lambda x: x.split("="), l[op + 1:cl].split("%"))))
    return dic

def get_names(search):
    var = 0
    dic = {}
    f = open(get_nmap_os_db_path())
    for l in f:
        l = l.strip()
        if (not l or l[0] == "#") and (var == 1):
            break
        if l[:12] == "Fingerprint ":
            if (l[12:] == search):
                var = 1
        if (var == 1):
            print "      %s" % l
            if l[:6] == "Class":
                continue
            elif l[:4] == "CPE ":
                continue
            else:
                op = l.find("(")
                cl = l.find(")")
                if op < 0 or cl < 0:
                    # print "error reading file"
                    continue
                cursor = l[:op]
                dic[cursor] = (
                    list(map(lambda x: x.split("="), l[op + 1:cl].split("%"))))
    return dic

def list_os():
    f = open(get_nmap_os_db_path())
    for l in f:
        l = l.strip()
        if l[:12] == "Fingerprint ":
            print "    + \"%s\"" % l[12:]

def get_random_os():
  random = []
  f = open(get_nmap_os_db_path())
  for l in f:
    l = l.strip()
    if l[:12] == "Fingerprint ":
      random.append(l[12:])
  #random = list(dict.fromkeys(random))
  value = randint(0,len(random))
  return random[value]

def search_os(search_string):
    # Search nmap database
    nmap_values = []
    f = open(get_nmap_os_db_path())
    for l in f:
        l = l.strip()
        if l[:12] == "Fingerprint ":
          if re.search(search_string, l[12:], re.IGNORECASE):
            nmap_values.append(l[12:])
    # Remove possible duplicates
    nmap_values = list(dict.fromkeys(nmap_values))
    # Print results
    print " [+] Searching databases for: '%s'" % search_string
    for x in range(len(nmap_values)):
      print "      [nmap] \"%s\"" % nmap_values[x]
    #
    # Search p0f database
    db = module_p0f.p0f_kdb.get_base()
    p0f_values = []
    for i in range(0, 250):
      if (re.search(search_string, db[i][6], re.IGNORECASE) or re.search(search_string, db[i][7], re.IGNORECASE)) :
        p0f_values.append("OS: \"" + db[i][6] + "\" DETAILS: \"" + db[i][7] + "\"")
    # Print results
    for x in range(len(p0f_values)):
      print "      [p0f] %s" % p0f_values[x]
    exit(0)

def options_to_scapy(x):
    options = []
    for indice_opt in range(0, len(x)):
        if x[indice_opt] == "W":
            w_opt = ""
            for index in range(indice_opt + 1, len(x)):
                if ((x[index] != "N") and (x[index] != "W") and (x[index] != "M") and (x[index] != "S") and (x[index] != "T") and (x[index] != "L")):
                    w_opt += x[index]
                else:
                    break
            options.append(('WScale', int(w_opt, 16)))
        if x[indice_opt] == "N":
            options.append(('NOP', None))
        if x[indice_opt] == "M":
            m_opt = ""
            for index in range(indice_opt + 1, len(x)):
                if ((x[index] != "N") and (x[index] != "W") and (x[index] != "M") and (x[index] != "S") and (x[index] != "T") and (x[index] != "L")):
                    m_opt += x[index]
                else:
                    break
            options.append(('MSS', int(m_opt, 16)))
        if x[indice_opt] == "S":
            options.append(('SAckOK', ""))
        if x[indice_opt] == "T":
            if (x[indice_opt + 1] == "0"):
                T_0 = 0
            else:
                T_0 = 1  # Random
            if (x[indice_opt + 2] == "0"):
                T_1 = 0
            else:
                T_1 = 1  # Random
            # PENDING
            options.append(('Timestamp', (T_0, T_1)))
        if x[indice_opt] == "L":
            options.append(('EOL', None))
    return options

def print_tcp_packet(pl, destination): 
    pkt = ip.IP(pl.get_payload())
    option_list = tcp.parse_opts(pkt.tcp.opts)
    
    if opts.verbose:
        print " [+] Modifying '%s' packet in real time (total length %s)" % (destination, pl.get_payload_len())
        print "      [+] IP:  source %s destination %s tos %s id %s" % (inet_ntoa(pkt.src), inet_ntoa(pkt.dst), pkt.tos, pkt.id)
        print "      [+] TCP: sport %s dport %s flags S seq %s ack %s win %s" % (pkt.tcp.sport, pkt.tcp.dport, pkt.tcp.seq, pkt.tcp.ack, pkt.tcp.win)
        print "               options %s" % (opts_human(option_list))

def print_icmp_packet(pl): 
    pkt = ip.IP(pl.get_payload())
    if opts.verbose:
        print " [+] Modifying packet in real time (total length %s)" % pl.get_payload_len()
        print "      [+] IP:   source %s destination %s tos %s id %s" % (inet_ntoa(pkt.src), inet_ntoa(pkt.dst), pkt.tos, pkt.id)
        print "      [+] ICMP: code %s type %s len %s id %s seq %s" % (pkt.icmp.code, pkt.icmp.type, len(pkt.icmp.data.data), pkt.icmp.data.id, pkt.icmp.data.seq)

def print_udp_packet(pl): 
    pkt = ip.IP(pl.get_payload())

    if opts.verbose:
        print " [+] Modifying packet in real time (total length %s)" % pl.get_payload_len()
        print "      [+] IP:   source %s destination %s tos %s id %s" % (inet_ntoa(pkt.src), inet_ntoa(pkt.dst), pkt.tos, pkt.id)
        print "      [+] UDP:  sport %s dport %s len %s" % (pkt.udp.sport, pkt.udp.dport, len(pkt.udp.data))
        print "                data %s" % (pkt.udp.data[0:49])
        print "                     %s" % (pkt.udp.data[50:99])
        print "                     %s" % (pkt.udp.data[100:149])
        print "                     %s" % (pkt.udp.data[150:199])
        print "                     %s" % (pkt.udp.data[200:249])
        print "                     %s" % (pkt.udp.data[250:299])

# Process p0f packets
def cb_p0f( pl ): 

    pkt = ip.IP(pl.get_payload())
    
    if (inet_ntoa(pkt.src) == home_ip) and (pkt.p == ip.IP_PROTO_TCP) and (tcp_flags(pkt.tcp.flags) == "S"):
        options = pkt.tcp.opts.encode('hex_codec')
        op = options.find("080a")
        if (op != -1):
            op = op + 7
            timestamp = options[op:][:5]
            i = int(timestamp, 16)
        if opts.osgenre and opts.details_p0f:
            try:
                pkt_send = module_p0f.p0f_impersonate(IP(dst=inet_ntoa(pkt.dst), src=inet_ntoa(pkt.src), id=pkt.id, tos=pkt.tos) / TCP(
                    sport=pkt.tcp.sport, dport=pkt.tcp.dport, flags='S', seq=pkt.tcp.seq, ack=0), i, osgenre=opts.osgenre, osdetails=opts.details_p0f)
                if opts.verbose:
                    print_tcp_packet(pl, "p0f")
                pl.set_payload(str(pkt_send))
                pl.accept()  
            except Exception, e:
                print " [+] Unable to modify packet with p0f personality..."
                print " [+] Aborting"
                sys.exit()
        elif opts.osgenre and not opts.details_p0f:
            try:
                pkt_send = module_p0f.p0f_impersonate(IP(dst=inet_ntoa(pkt.dst), src=inet_ntoa(pkt.src)) / TCP(
                    sport=pkt.tcp.sport, dport=pkt.tcp.dport, flags='S', seq=pkt.tcp.seq), i, osgenre=opts.osgenre)
                if opts.verbose:
                  print_tcp_packet(pl, "p0f") 
                pl.set_payload(str(pkt_send))
                pl.accept() 
            except Exception, e:
                print " [+] Unable to modify packet with p0f personality..."
                print " [+] Aborting"
                sys.exit()
        else:
            pl.accept()
    else:
		    pl.accept()
      #  return 0

# Process nmap packets
def cb_nmap( pl): 
    pkt = ip.IP(pl.get_payload())   
    if pkt.p == ip.IP_PROTO_TCP:
        # Define vars for conditional loops
        options = pkt.tcp.opts.encode('hex_codec')
        flags = tcp_flags(pkt.tcp.flags)
        if (flags == "S") and (pkt.tcp.win == 1) and (options == T1_opt1):
            # nmap packet detected: Packet1 #1
            print_tcp_packet(pl, "nmap")
            pl.drop() 
            if (base["T1"][0][1] == "Y"):
                send_probe_response_T1(pl, "T1", 1)
        elif (flags == "S") and (pkt.tcp.win == 63) and (options == T1_opt2):
            # nmap packet detected: Packet1 #2
            print_tcp_packet(pl, "nmap")
            pl.drop() 
            if (base["T1"][0][1] == "Y"):
                send_probe_response_T1(pl, "T1", 2)
        elif (flags == "S") and (pkt.tcp.win == 4) and (options == T1_opt3):
            # nmap packet detected: Packet1 #3
            print_tcp_packet(pl, "nmap")
            pl.drop() 
            if (base["T1"][0][1] == "Y"):
                send_probe_response_T1(pl, "T1", 3)
        elif (flags == "S") and (pkt.tcp.win == 4) and (options == T1_opt4):
            # nmap packet detected: Packet1 #4
            print_tcp_packet(pl, "nmap")
            pl.drop() 
            if (base["T1"][0][1] == "Y"):
                send_probe_response_T1(pl, "T1", 4)
        elif (flags == "S") and (pkt.tcp.win == 16) and (options == T1_opt5):
            # nmap packet detected: Packet1 #5
            print_tcp_packet(pl, "nmap")
            pl.drop() 
            if (base["T1"][0][1] == "Y"):
                send_probe_response_T1(pl, "T1", 5)
        elif (flags == "S") and (pkt.tcp.win == 512) and (options == T1_opt6):
            # nmap packet detected: Packet1 #6
            print_tcp_packet(pl, "nmap")
            pl.drop() 
            if (base["T1"][0][1] == "Y"):
                send_probe_response_T1(pl, "T1", 6)
        elif (flags == "") and (pkt.tcp.win == 128) and (options == T2_T6_opt):
            # nmap packet detected: Packet2
            print_tcp_packet(pl, "nmap")
            pl.drop() 
            if (base["T2"][0][1] == "Y"):
                send_probe_response(pl, "T2")
        elif (flags == "FSPU") and (pkt.tcp.win == 256) and (options == T2_T6_opt):
            # nmap packet detected: Packet3
            print_tcp_packet(pl, "nmap")
            pl.drop() 
            if (base["T3"][0][1] == "Y"):
                send_probe_response(pl, "T3")
        elif (flags == "A") and (pkt.tcp.win == 1024) and (options == T2_T6_opt):
            # nmap packet detected: Packet4
            print_tcp_packet(pl, "nmap")
            pl.drop() 
            if (base["T4"][0][1] == "Y"):
                send_probe_response(pl, "T4")
        elif (flags == "S") and (pkt.tcp.win == 31337) and (options == T2_T6_opt):
            # nmap packet detected: Packet5
            print_tcp_packet(pl, "nmap")
            if (base["T5"][0][1] == "Y"):
                send_probe_response(pl, "T5")
        elif (flags == "A") and (pkt.tcp.win == 32768) and (options == T2_T6_opt):
            # nmap packet detected: Packet6
            print_tcp_packet(pl, "nmap")
            pl.drop() 
            if (base["T6"][0][1] == "Y"):
                send_probe_response(pl, "T6")
        elif (flags == "FPU") and (pkt.tcp.win == 65535) and (options == T7_opt):
            # nmap packet detected: Packet7
            print_tcp_packet(pl, "nmap")
            pl.drop() 
            if (base["T7"][0][1] == "Y"):
                send_probe_response(pl, "T7")
        elif (flags == "SEC") and (pkt.tcp.win == 3) and (options == ECN_opt):
            # nmap packet detected: Packet ECE
            print_tcp_packet(pl, "nmap")
            pl.drop() 
            if (base["ECN"][0][1] == "Y"):
                send_ECN_response(pl, "ECN")
        else:
            pl.accept()
    elif pkt.p == ip.IP_PROTO_UDP:
        if (pkt.udp.data == udp_payload):
            # nmap packet detected: Packet UDP
            print_udp_packet(pl)
            pl.drop() 
            # TODO
            if ( base["U1"][0][0] != "R" ):
                send_udp_response(pl, "U1")
        else:
          pl.accept()
    elif pkt.p == ip.IP_PROTO_ICMP:
        if (pkt.icmp.code == 9) and (pkt.icmp.type == 8) and (len(pkt.icmp.data.data) == 120):
            # nmap packet detected: Packet ICMP #1
            print_icmp_packet(pl)
            pl.drop() 
            if (base["IE"][0][0] != "R"):
                send_icmp_response(pl, "IE")
        elif (pkt.icmp.code == 0) and (pkt.icmp.type == 8) and (len(pkt.icmp.data.data) == 150):
            # nmap packet detected: Packet ICMP #2
            print_icmp_packet(pl)
            pl.drop() 
            if (base["IE"][0][0] != "R"):
                send_icmp_response(pl, "IE")
        else: 
            pl.accept() 
    else:
        pl.accept() 
        return 0


def init(queue):
  q = nfqueue.NetfilterQueue()
  if (queue % 2 ==  0):
    q.bind(queue, cb_nmap)
    print "      [->] %s: nmap packet processor" % multiprocessing.current_process().name
  if (queue % 2 ==  1 and (opts.osgenre or (opts.details_p0f and opts.osgenre))):
    q.bind(queue, cb_p0f)
    print "      [->] %s: p0f packet processor" % multiprocessing.current_process().name
  try: 
    q.run()
  except KeyboardInterrupt,err:
    pass

# Upload database
def update_nmap_db():
  sys.stdout.write(' [+] Checking nmap database... ')
  sys.stdout.flush()
  url = 'https://svn.nmap.org/nmap/nmap-os-db'
  response = urllib.urlopen(url)
  data = response.read()
  m = hashlib.md5()
  m.update(data)
  new_db=m.hexdigest()
  old_db=md5(get_nmap_os_db_path())
  if (new_db != old_db):
		f = open(get_nmap_os_db_path(), "w")
		f.write(data)
		f.close()
		print "updated!"
  else:
	  print "latest!"

def md5(fname):
  hash_md5 = hashlib.md5()
  with open(fname, "rb") as f:
    for chunk in iter(lambda: f.read(4096), b""):
      hash_md5.update(chunk)
  return hash_md5.hexdigest()

def user_is_root():
  if not os.geteuid() == 0:
      sys.exit(' [+] OSfooler must be run as root')
  else:
      return

def main():
  # Main program begins here
  show_banner()
  parser = optparse.OptionParser()
  parser.add_option('-n', '--nmap', action='store_true',
                    dest='nmap', help="list available nmap signatures")
  parser.add_option('-m', '--os_nmap', action='store',
                    dest='os', help="use nmap Operating System")
  parser.add_option('-p', '--p0f', action='store_true',
                    dest='p0f', help="list available p0f v2 signatures")
  parser.add_option('-o', '--os_p0f', action='store',
                    dest='osgenre', help="use p0f v2 OS Genre")
  parser.add_option('-d', '--details_p0f',
                    action='store', dest='details_p0f', help="choose p0f v2 Details")
  parser.add_option('-i', '--interface', action='store',
                    dest='interface', help="choose network interface (eth0)")
  parser.add_option('-s', '--search', action='store',
                    dest='search', help="search OS in nmap/p0f v2 db")
  parser.add_option('-u', '--updatedb', action='store_true',
                    dest='updatedb', help="update nmap database")
  parser.add_option('-v', '--verbose', action='store_true',
                    dest='verbose', help="be verbose")
  parser.add_option('-V', '--version', action='store_true',
                    dest='version', help="display the version of OSfooler and exit")
  global opts
  (opts, args) = parser.parse_args()

  if opts.search:
    search_os(opts.search)
    exit(0)

  if opts.version:
    exit(0)

  if opts.updatedb:
    user_is_root()
    update_nmap_db()
    exit(0)

  if opts.nmap:
    print(" [+] Please, select nmap OS to emulate")
    list_os()
    exit(0)

  if opts.p0f:
    print("Please, select p0f OS Genre and Details")
    db = module_p0f.p0f_kdb.get_base()
    for i in range(0, 250):
      print "\tOS Genre=\"%s\" Details=\"%s\"" % (db[i][6], db[i][7])
    exit(0)

  if not opts.os and (not (opts.details_p0f and not opts.osgenre)) and (not opts.osgenre):
    print " [ERROR] Please, choose a nmap or p0f OS system to emulate"
    print " [+] Use %s -h to get more information" % sys.argv[0]
    print
    sys.exit(' [+] Aborting...')

  if (opts.details_p0f and not opts.osgenre):
    print " [ERROR] Please, choose p0f OS system to emulate, not only OS details"
    print " [+] Use %s -p to list possible candidates" % sys.argv[0]
    print
    sys.exit(' [+] Aborting...')

  # Check if user is root before continue
  user_is_root()

  if opts.interface:
    interface = opts.interface 
    try:
      q_num0 = os.listdir("/sys/class/net/").index(opts.interface) * 2
      q_num1 = os.listdir("/sys/class/net/").index(opts.interface) * 2 + 1
    except ValueError, err:
      q_num0 = -1
      q_num1 = -1
  else:
    interface = "eth0" # you may paste here your main interface found by '$~: ip a', for instance  
    try:
      q_num0 = os.listdir("/sys/class/net/").index(opts.interface) * 2
      q_num1 = os.listdir("/sys/class/net/").index(opts.interface) * 2 + 1
    except ValueError, err:
      q_num0 = -1
      q_num1 = -1

  # Global -> get values from cb_nmap() and cb_p0f
  global base

  if opts.os:
    print " [+] Mutating to nmap:"
    base = {}
    if (opts.os == "random"):
      base = get_names(get_random_os())
    else:
      base = get_names(opts.os)
    if (not base):
      print "      [->] \"%s\" could not be found in nmap database..." % opts.os
      sys.exit(' [+] Aborting...')

  if (opts.osgenre):
    print " [+] Mutating to p0f:"
    db = module_p0f.p0f_kdb.get_base()
    exists = 0
    if (opts.osgenre == "random"):
      rand_os = randint(0,250)
      opts.osgenre = db[rand_os][6]
    if (not opts.details_p0f):
      for i in range(0, 250):
        if (db[i][6] == opts.osgenre):
          print "      WWW:%s|TTL:%s|D:%s|SS:%s|OOO:%s|QQ:%s|OS:%s|DETAILS:%s" % (db[i][0],db[i][1],db[i][2],db[i][3],db[i][4],db[i][5],db[i][6],db[i][7])
          exists = 1
    if (opts.details_p0f):
      for i in range(0, 250):
        if (db[i][6] == opts.osgenre and db[i][7] == opts.details_p0f):
          print "      WWW:%s|TTL:%s|D:%s|SS:%s|OOO:%s|QQ:%s|OS:%s|DETAILS:%s" % (db[i][0],db[i][1],db[i][2],db[i][3],db[i][4],db[i][5],db[i][6],db[i][7])
          exists = 1
          break
    if (not exists):
      print "      [->] Could not found that combination in p0f database..."
      sys.exit(' [+] Aborting...')

  if (not opts.details_p0f and opts.osgenre):
      print " [i] You've only selected p0f OS genre. Details will be chosen randomly every packet from the list bellow"
  
  # Start activity
  print " [+] Activating queues"
  procs = []
  # nmap mode
  if opts.os:  
    os.system("iptables -A INPUT -j NFQUEUE --queue-num %s" % q_num0) 
    proc = Process(target=init,args=(q_num0,))
    procs.append(proc)
    proc.start() 
  # p0f mode
  if (opts.osgenre):
    global home_ip
    home_ip = get_ip_address(interface)  
    os.system("iptables -A OUTPUT -p TCP --syn -j NFQUEUE --queue-num %s" % q_num1) 
    proc = Process(target=init,args=(q_num1,))
    procs.append(proc)
    proc.start() 
  # Detect mode

  try:
      for proc in procs:
        proc.join()
      print
      # Flush all iptabels rules
      if (q_num0 >= 0):
        os.system("iptables -D INPUT -j NFQUEUE --queue-num %s" % q_num0) 
      if (q_num1 >= 1):
        os.system("iptables -D OUTPUT -p TCP --syn -j NFQUEUE --queue-num %s" % q_num1) 
      print " [+] Active queues removed"
      print " [+] Exiting OSfooler..." 
  except KeyboardInterrupt:
      print
      # Flush all iptabels rules
      if (q_num0 >= 0):
        os.system("iptables -D INPUT -j NFQUEUE --queue-num %s" % q_num0) 
      if (q_num1 >= 1):
        os.system("iptables -D OUTPUT -p TCP --syn -j NFQUEUE --queue-num %s" % q_num1) 
      print " [+] Active queues removed"
      print " [+] Exiting OSfooler..."
      #for p in multiprocessing.active_children():
      #  p.terminate()

if __name__ == "__main__":
  main()
