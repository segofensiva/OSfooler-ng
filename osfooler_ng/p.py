
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
    elif pkt.p == ip.IP_PROTO_UDP:
        if (pkt.udp.data == udp_payload):
            # nmap packet detected: Packet UDP
            print_udp_packet(pl)
            pl.drop() 
            # TODO
            # if ( base["U1"][0][0] != "R" ):
                # send_udp_response(payload, "U1")
    elif pkt.p == ip.IP_PROTO_ICMP:
        if (pkt.icmp.code == 9) and (pkt.icmp.type == 8) and (len(pkt.icmp.data.data) == 120):
            # nmap packet detected: Packet ICMP #1
            print_icmp_packet(pl)
            pl.drop() 
            if (base["IE"][0][0] != "R"):
                send_icmp_response(payload, "IE")
        if (pkt.icmp.code == 0) and (pkt.icmp.type == 8) and (len(pkt.icmp.data.data) == 150):
            # nmap packet detected: Packet ICMP #2
            print_icmp_packet(pl)
            pl.drop() 
            if (base["IE"][0][0] != "R"):
                send_icmp_response(pl, "IE")
    else:
        pl.accept() 
        return 0
