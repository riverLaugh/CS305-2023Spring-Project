from ryu.lib import addrconv
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu.lib.packet import dhcp


class Config():
    controller_macAddr = '7e:49:b3:f0:f9:99' # don't modify, a dummy mac address for fill the mac enrty
    dns = '8.8.8.8' # don't modify, just for the dns entry
    start_ip = '192.168.1.2' # can be modified
    end_ip = '192.168.1.250' # can be modified
    netmask = '255.255.255.0' # can be modified

    # You may use above attributes to configure your DHCP server.
    # You can also add more attributes like "lease_time" to support bouns function.


class DHCPServer():
    hardware_addr = Config.controller_macAddr
    start_ip = Config.start_ip
    end_ip = Config.end_ip
    netmask = Config.netmask
    dns = Config.dns
    available_ip=range(int(start_ip[-1]),int(end_ip[-1])+1)

    @classmethod
    def assemble_ack(cls, pkt, datapath, port):
        # TODO: Generate DHCP ACK packet here
        eth=pkt.get_protocol(ethernet.ethernet)
        dhcp_pk = pkt.get_protocol(dhcp.dhcp)
        ip_pk = pkt.get_protocol(ipv4.ipv4)
        desired_ip=dhcp_pk.options.get(dhcp.DHCP_REQUESTED_IP_ADDR_OPT)
        dhcp_pkt = dhcp.dhcp(
            op=2,  # DHCP operation code (reply)
            chaddr=eth.src,  # Client MAC address
            xid=123456789,  # Transaction ID
            yiaddr=desired_ip,  # Offered IP address
            options=[
                (dhcp.DHCP_ACK, b'\x02'),  # DHCP Message Type: Offer
                # (dhcp.DHCP_SERVER_IDENTIFIER_OPT, ),  # DHCP Server Identifier
                # (dhcp.DHCP_GATEWAY_ADDR_OPT, '192.168.0.1'),  # Router (gateway) IP address
                (dhcp.DHCP_SUBNET_MASK_OPT, '255.255.255.0'),  # Subnet mask
                # (dhcp.DHCP_IP_ADDR_LEASE_TIME_OPT, b'\x00\x00\x1c\x20'),  # Lease time: 7200 seconds
                (dhcp.DHCP_END_OPT, b'')  # End option
            ]
        )
        udp_pkt = udp.udp(
            src_port=67,  # Source port (server)
            dst_port=68  # Destination port (client)
        )
        ip_pkt = ipv4.ipv4(
            src='192.168.1.1',
            dst='255.255.255.255',
            ttl=64,
            proto=17)
        eth_pkt = ethernet.ethernet(
            src=eth.dst,  # Source MAC address (server)
            dst=eth.src,  # Destination MAC address (client)
            ethertype=eth.ethertype  # EtherType (IPv4)
        )
        packeta = packet.Packet()
        packeta.add_protocol(eth_pkt)
        packeta.add_protocol(ip_pkt)
        packeta.add_protocol(udp_pkt)
        packeta.add_protocol(dhcp_pkt)
        packeta.serialize()


        return packeta

    @classmethod
    def assemble_offer(cls, pkt, datapath):
        # TODO: Generate DHCP OFFER packet here
        ip = cls.available_ip[0]
        cls.available_ip = cls.available_ip[1:]
        res = '192.168.1.' + str(ip)

        eth = pkt.get_protocol(ethernet.ethernet)
        ip_pk = pkt.get_protocol(ipv4.ipv4)
        dhcp_pkt = dhcp.dhcp(
            op=2,  # DHCP operation code (reply)
            chaddr=eth.src,  # Client MAC address
            xid=123456789,  # Transaction ID
            yiaddr=res,  # Offered IP address
            options=[
                (dhcp.DHCP_OFFER, b'\x02'),  # DHCP Message Type: Offer
                # (dhcp.DHCP_SERVER_IDENTIFIER_OPT, res),  # DHCP Server Identifier
                # (dhcp.DHCP_GATEWAY_ADDR_OPT, '192.168.0.1'),  # Router (gateway) IP address
                (dhcp.DHCP_SUBNET_MASK_OPT, '255.255.255.0'),  # Subnet mask
                # (dhcp.DHCP_IP_ADDR_LEASE_TIME_OPT, b'\x00\x00\x1c\x20'),  # Lease time: 7200 seconds
                (dhcp.DHCP_END_OPT, b'')  # End option
            ]
        )
        udp_pkt = udp.udp(
            src_port=67,  # Source port (server)
            dst_port=68  # Destination port (client)
        )
        ip_pkt = ipv4.ipv4(
            src='192.168.1.1',
            # src=ip_pk.dst,
            dst='255.255.255.255',
            ttl=64,
            proto=17)
        eth_pkt = ethernet.ethernet(
            src=eth.dst,  # Source MAC address (server)
            dst=eth.src,  # Destination MAC address (client)
            ethertype=eth.ethertype  # EtherType (IPv4)
        )
        packeta = packet.Packet()
        packeta.add_protocol(eth_pkt)
        packeta.add_protocol(ip_pkt)
        packeta.add_protocol(udp_pkt)
        packeta.add_protocol(dhcp_pkt)
        packeta.serialize()
        return packeta

    @classmethod
    def handle_dhcp(cls, datapath, port, pkt):
        # TODO: Specify the type of received DHCP packet




        pass
        # You may choose a valid IP from IP pool and genereate DHCP OFFER packet
        # Or generate a DHCP ACK packet
        # Finally send the generated packet to the host by using _send_packet method

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

