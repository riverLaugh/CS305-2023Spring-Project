from ryu.lib import addrconv
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu.lib.packet import dhcp


class Config():
    controller_macAddr = '7e:49:b3:f0:f9:99'  # don't modify, a dummy mac address for fill the mac enrty
    dns = '8.8.8.8'  # don't modify, just for the dns entry
    start_ip = '192.168.1.2'  # can be modified
    end_ip = '192.168.1.255'  # can be modified
    netmask = '255.255.255.0'  # can be modified

    # You may use above attributes to configure your DHCP server.
    # You can also add more attributes like "lease_time" to support bouns function.


class DHCPServer():
    ip_xid_map = {}
    current_ip = {}
    hardware_addr = Config.controller_macAddr
    start_ip = Config.start_ip
    end_ip = Config.end_ip
    netmask = Config.netmask
    dns = Config.dns
    start = start_ip.split('.')
    end = end_ip.split('.')
    startnum = int(start[3])
    endnum = int(end[3])
    ip_pool = []
    for i in range(2, 255):
        ip_pool.append('192.168.1.' + str(i))

    @classmethod
    def assemble_ack(cls, datapath, port, pkt):
        # TODO: Generate DHCP ACK packet here
        # dhcp_pkt = dhcp.dhcp(
        #     op=dhcp.DHCP_BOOT_REPLY,  # DHCP operation code (reply)
        #     chaddr=pkt.get_protocol(ethernet.ethernet).src,  # Client MAC address
        #     xid=pkt.get_protocol(dhcp.dhcp).xid,  # Transaction ID
        #     yiaddr=cls.ip_xid_map[pkt.get_protocol(dhcp.dhcp).xid],  # Offered IP address
        #     options=dhcp.options(option_list=[
        #         dhcp.option(tag=53, value=b'\x05'),
        #         dhcp.option(tag=1, value=b'255.255.255.0'),
        #         dhcp.option(tag=3, value=b'192.128.1.1'),
        #         dhcp.option(tag=6, value=addrconv.ipv4.text_to_bin(cls.dns)),
        #         dhcp.option(tag=51, value=b'\x00\x00\x00\x0a'),
        #         dhcp.option(tag=54, value=addrconv.ipv4.text_to_bin('192.168.2.1'))
        #     ]
        #     )
        # )
        dhcp_pkt = pkt.get_protocol(dhcp.dhcp)
        wnt = 0
        for opt in pkt.get_protocol(dhcp.dhcp).options.option_list:
            if opt.tag == 50:
                wnt = addrconv.ipv4.bin_to_text(opt.value)

        dhcp_pkt.options.option_list.remove(
            next(opt for opt in dhcp_pkt.options.option_list if opt.tag == 53))
        dhcp_pkt.options.option_list.insert(
            0, dhcp.option(tag=1, value=b'255.255.255.0'))
        dhcp_pkt.options.option_list.insert(
            0, dhcp.option(tag=3, value=b'192.128.1.1'))
        dhcp_pkt.options.option_list.insert(
            0, dhcp.option(tag=6, value=addrconv.ipv4.text_to_bin(cls.dns)))
        dhcp_pkt.options.option_list.insert(
            0, dhcp.option(tag=12, value='fuck'))
        dhcp_pkt.options.option_list.insert(
            0, dhcp.option(tag=53, value=b'\x05'))
        dhcp_pkt.options.option_list.insert(
            0, dhcp.option(tag=54, value=addrconv.ipv4.text_to_bin('192.168.2.1')))
        dhcp_pkt.options.option_list.insert(
            0, dhcp.option(tag=51, value=b'\x00\x00\x00\x0a'))

        dhcp_pkt = dhcp.dhcp(
            op=dhcp.DHCP_BOOT_REPLY,  # DHCP operation code (reply)
            chaddr=pkt.get_protocol(ethernet.ethernet).src,  # Client MAC address
            xid=pkt.get_protocol(dhcp.dhcp).xid,  # Transaction ID
            yiaddr=wnt  # Offered IP address
        )

        # Create UDP packet
        udp_pkt = udp.udp(
            src_port=67,  # Source port (server)
            dst_port=68  # Destination port (client)
        )
        # Create IPv4 packet
        ipv4_pkt = ipv4.ipv4(
            src='192.168.1.1',  # Source IP address (server)
            dst='255.255.255.255',  # Destination IP address (broadcast)
            proto=17  # Protocol (UDP)
        )
        # Create Ethernet packet
        eth_pkt = ethernet.ethernet(
            src='2c:8d:b1:6d:e6:0b',  # Source MAC address (server)
            dst=pkt.get_protocol(ethernet.ethernet).dst,  # Destination MAC address (client)
            ethertype=pkt.get_protocol(ethernet.ethernet).ethertype  # EtherType (IPv4)
        )
        # Assemble the packets
        packet2 = packet.Packet()
        packet2.add_protocol(eth_pkt)
        packet2.add_protocol(ipv4_pkt)
        packet2.add_protocol(udp_pkt)
        packet2.add_protocol(dhcp_pkt)
        print('ACK:')
        print(cls.ip_xid_map[pkt.get_protocol(dhcp.dhcp).xid])
        return packet2

    @classmethod
    def assemble_offer(cls, pkt, datapath):
        # TODO: Generate DHCP OFFER packet here
        # print('++++++++++')
        dhcp_pkt = pkt.get_protocol(dhcp.dhcp)
        dhcp_pkt.options.option_list.remove(
            next(opt for opt in dhcp_pkt.options.option_list if opt.tag == 53))
        dhcp_pkt.options.option_list.insert(
            0, dhcp.option(tag=1, value=b'255.255.255.0'))
        dhcp_pkt.options.option_list.insert(
            0, dhcp.option(tag=3, value=b'192.128.1.1'))
        dhcp_pkt.options.option_list.insert(
            0, dhcp.option(tag=6, value=addrconv.ipv4.text_to_bin(cls.dns)))
        dhcp_pkt.options.option_list.insert(
            0, dhcp.option(tag=12, value='fuck'))
        dhcp_pkt.options.option_list.insert(
            0, dhcp.option(tag=53, value=b'\x02'))
        dhcp_pkt.options.option_list.insert(
            0, dhcp.option(tag=54, value=addrconv.ipv4.text_to_bin('192.168.2.1')))
        dhcp_pkt.options.option_list.insert(
            0, dhcp.option(tag=51, value=b'\x00\x00\x00\x0a'))

        dhcp_pkt = dhcp.dhcp(
            op=dhcp.DHCP_BOOT_REPLY,  # DHCP operation code (reply)
            chaddr=pkt.get_protocol(ethernet.ethernet).src,  # Client MAC address
            xid=pkt.get_protocol(dhcp.dhcp).xid,  # Transaction ID
            yiaddr=cls.ip_pool[0],  # Offered IP address
            hlen=6,
            siaddr='192.168.1.0'
        )

        cls.ip_xid_map[pkt.get_protocol(dhcp.dhcp).xid] = cls.ip_pool[0]
        print('offer:')
        print(cls.ip_pool[0])
        # print('_______________________')
        del cls.ip_pool[0]
        # Create UDP packet
        udp_pkt = udp.udp(
            src_port=67,  # Source port (server)
            dst_port=68  # Destination port (client)
        )
        # Create IPv4 packet
        ipv4_pkt = ipv4.ipv4(
            src='192.168.1.1',  # Source IP address (server)
            dst='255.255.255.255',  # Destination IP address (broadcast)
            proto=17  # Protocol (UDP)
        )
        # Create Ethernet packet
        eth_pkt = ethernet.ethernet(
            src='2c:8d:b1:6d:e6:0b',  # Source MAC address (server)
            dst=pkt.get_protocol(ethernet.ethernet).dst,  # Destination MAC address (client)
            ethertype=pkt.get_protocol(ethernet.ethernet).ethertype  # EtherType (IPv4)
        )
        # print('???????????????????????')
        # Assemble the packets
        packet1 = packet.Packet()
        packet1.add_protocol(eth_pkt)
        packet1.add_protocol(ipv4_pkt)
        packet1.add_protocol(udp_pkt)
        packet1.add_protocol(dhcp_pkt)
        # print(packet1)
        return packet1

    @classmethod
    def handle_dhcp(cls, datapath, port, pkt):
        # print(pkt.get_protocol(dhcp.dhcp))
        pkt_dhcp = pkt.get_protocol(dhcp.dhcp)
        if pkt_dhcp.options.option_list[0].value == b'\x01':
            print('dhcp_pktover')
            # DHCP dhcp_pktOVER packet received
            # You may choose an available IP from the IP pool and generate DHCP OFFER packet
            # Then send the generated packet to the host
            offer_pkt = cls.assemble_offer(pkt, datapath)
            cls._send_packet(datapath, port, offer_pkt)

        elif pkt_dhcp.options.option_list[0].value == b'\x03':
            print('request')
            # DHCP REQUEST packet received
            # You should send ACK packet and set the yiaddr field to the chosen IP address
            ack_pkt = cls.assemble_ack(datapath, port, pkt)
            cls._send_packet(datapath, port, ack_pkt)

        else:
            # Unsupported DHCP message type
            return

    @classmethod
    def _send_packet(cls, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if isinstance(pkt, str):
            pkt = pkt.encode()
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)
