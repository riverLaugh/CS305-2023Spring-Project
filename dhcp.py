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
    end_ip = '192.168.1.100'  # can be modified
    netmask = '255.255.255.0'  # can be modified

    # You may use above attributes to configure your DHCP server.
    # You can also add more attributes like "lease_time" to support bouns function.


class DHCPServer():
    hardware_addr = Config.controller_macAddr
    start_ip = Config.start_ip
    end_ip = Config.end_ip
    netmask = Config.netmask
    dns = Config.dns

    @classmethod
    def assemble_ack(cls, pkt, datapath, port):
        # TODO: Generate DHCP ACK packet here
        dhcp_pkt = dhcp.dhcp(
            op=dhcp.DHCP_BOOT_REPLY,  # DHCP operation code (reply)
            chaddr='12:34:56:78:90:ab',  # Client MAC address
            xid=123456789,  # Transaction ID
            yiaddr='192.168.0.100',  # Offered IP address
            options=[
                (dhcp.DHCP_ACK, b'\x02'),  # DHCP Message Type: ack
                (dhcp.DHCP_SERVER_IDENTIFIER_OPT, '192.168.0.1'),  # DHCP Server Identifier
                (dhcp.DHCP_GATEWAY_ADDR_OPT, '192.168.0.1'),  # Router (gateway) IP address
                (dhcp.DHCP_SUBNET_MASK_OPT, '255.255.255.0'),  # Subnet mask
                (dhcp.DHCP_IP_ADDR_LEASE_TIME_OPT, b'\x00\x00\x1c\x20'),  # Lease time: 7200 seconds
                (dhcp.DHCP_END_OPT, b'')  # End option
            ]
        )
        # Create UDP packet
        udp_pkt = udp.udp(
            src_port=67,  # Source port (server)
            dst_port=68  # Destination port (client)
        )
        udp_pkt = pkt.encode()
        udp_pkt.serialize()

        # Create IPv4 packet
        ipv4_pkt = ipv4.ipv4(
            src='192.168.0.1',  # Source IP address (server)
            dst='255.255.255.255',  # Destination IP address (broadcast)
            proto=17  # Protocol (UDP)
        )
        ipv4_pkt = ipv4_pkt.encode()
        ipv4_pkt.serialize()

        # Create Ethernet packet
        eth_pkt = ethernet.ethernet(
            src='11:22:33:44:55:66',  # Source MAC address (server)
            dst='12:34:56:78:90:ab',  # Destination MAC address (client)
            ethertype=ethernet.ether.ETH_TYPE_IP  # EtherType (IPv4)
        )
        eth_pkt.serialize()
        # Assemble the packets
        eth_pkt.set_payload(ipv4_pkt)
        ipv4_pkt.set_payload(udp_pkt)
        udp_pkt.set_payload(dhcp_pkt)
        packet_data = eth_pkt.serialize()
        return packet_data
        return pkt

    @classmethod
    def assemble_offer(cls, pkt, datapath):
        # TODO: Generate DHCP OFFER packet here
        dhcp_pkt = dhcp.dhcp(
            op=dhcp.DHCP_BOOT_REPLY,  # DHCP operation code (reply)
            chaddr='12:34:56:78:90:ab',  # Client MAC address
            xid=123456789,  # Transaction ID
            yiaddr='192.168.0.100',  # Offered IP address
            options=[
                (dhcp.DHCP_OFFER, b'\x02'),  # DHCP Message Type: Offer
                (dhcp.DHCP_SERVER_IDENTIFIER_OPT, '192.168.0.1'),  # DHCP Server Identifier
                (dhcp.DHCP_GATEWAY_ADDR_OPT, '192.168.0.1'),  # Router (gateway) IP address
                (dhcp.DHCP_SUBNET_MASK_OPT, '255.255.255.0'),  # Subnet mask
                (dhcp.DHCP_IP_ADDR_LEASE_TIME_OPT, b'\x00\x00\x1c\x20'),  # Lease time: 7200 seconds
                (dhcp.DHCP_END_OPT, b'')  # End option
            ]
        )
        # Create UDP packet
        udp_pkt = udp.udp(
            src_port=67,  # Source port (server)
            dst_port=68  # Destination port (client)
        )
        udp_pkt = pkt.encode()
        udp_pkt.serialize()

        # Create IPv4 packet
        ipv4_pkt = ipv4.ipv4(
            src='192.168.0.1',  # Source IP address (server)
            dst='255.255.255.255',  # Destination IP address (broadcast)
            proto=17  # Protocol (UDP)
        )
        ipv4_pkt = ipv4_pkt.encode()
        ipv4_pkt.serialize()

        # Create Ethernet packet
        eth_pkt = ethernet.ethernet(
            src='11:22:33:44:55:66',  # Source MAC address (server)
            dst='12:34:56:78:90:ab',  # Destination MAC address (client)
            ethertype=ethernet.ether.ETH_TYPE_IP  # EtherType (IPv4)
        )
        eth_pkt.serialize()
        # Assemble the packets
        eth_pkt.set_payload(ipv4_pkt)
        ipv4_pkt.set_payload(udp_pkt)
        udp_pkt.set_payload(dhcp_pkt)
        packet_data = eth_pkt.serialize()
        return packet_data

    @classmethod
    def handle_dhcp(cls, datapath, port, pkt):
        dhcp_pkt = pkt.get_protocol(dhcp.dhcp)
        if dhcp_pkt.option_dhcp_message_type == dhcp.DHCP_DISCOVER:
            # DHCP DISCOVER packet received
            # You may choose an available IP from the IP pool and generate DHCP OFFER packet
            # Then send the generated packet to the host
            offer_pkt = cls.assemble_offer(dhcp_pkt,datapath)
            cls._send_packet(datapath, port, offer_pkt)
        elif dhcp_pkt.option_dhcp_message_type == dhcp.DHCP_REQUEST:
            # DHCP REQUEST packet received
            # You should send ACK packet and set the yiaddr field to the chosen IP address
            ack_pkt = cls.assemble_ack(datapath, port, dhcp_pkt)
            cls._send_packet(datapath, port, ack_pkt)
        else:
            # Unsupported DHCP message type
            return

    '''
    datapath：表示一个连接到 OVS 网桥的交换机。
    port：表示这个数据包要从交换机上的哪个虚拟端口出去。
    pkt：待发送出去的数据包。一个 PacketIn 事件数据包
    '''
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


if __name__ == "__main__":
    pass