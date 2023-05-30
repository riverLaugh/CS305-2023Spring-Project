from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link, get_host, get_all_host, get_all_link, get_all_switch
from ryu.ofproto import ofproto_v1_0
from ryu.lib.packet import packet, ethernet, ether_types, arp
from ryu.lib.packet import dhcp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import packet
from ryu.lib.packet import udp
from dhcp import DHCPServer
from ofctl_utilis import OfCtl, VLANID_NONE
from server import Graph, Switch, Host
from ofctl_utilis import OfCtl


class ControllerApp(app_manager.RyuApp):
    Graph = Graph()
    arpTable = {}
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ControllerApp, self).__init__(*args, **kwargs)

    @set_ev_cls(event.EventSwitchEnter)
    def handle_switch_add(self, ev):
        switch = Switch(ev.switch)
        switch.isswitch = True
        self.Graph.add_switch(switch)
        print('add switch')
        """
        Event handler indicating a switch has come online.
        """

    @set_ev_cls(event.EventSwitchLeave)
    def handle_switch_delete(self, ev):
        print("handle_switch_delete")
        for node in self.Graph.nodes:
            if node.datapath == ev.switch.dp:
                self.Graph.delete_switch(sw=node)
                break

        """
        Event handler indicating a switch has been removed
        """

    @set_ev_cls(event.EventHostAdd)
    def handle_host_add(self, ev):
        print("host_add")
        host = Host(mac=ev.host.mac, ipv4=ev.host.ipv4[0], dpid=ev.host.dpid)
        host.isswitch = False
        # ev.host.port.dpid
        for nde in self.Graph.nodes:
            if nde.isswitch is True:
                if nde.dpid == ev.host.port.dpid:
                    self.Graph.add_host(switch=nde, host=host, port1=ev.host.port)
                    break
        # self.Graph.update_flow_table()

        """
        Event handler indiciating a host has joined the network
        This handler is automatically triggered when a host sends an ARP response.
        """

        # TODO:  Update network topology and flow rules

    # @set_ev_cls(event.EventHostAdd)
    # def handle_host_add(self, ev):
    #     print('host_add')
    #     """
    #     Event handler indiciating a host has joined the network
    #     This handler is automatically triggered when a host sends an ARP response.
    #     """
    #     # TODO:  Update network topology and flow rules

    @set_ev_cls(event.EventLinkAdd)
    def handle_link_add(self, ev):
        print('handle_link_add')
        global nodeA, nodeB
        for nde in self.Graph.nodes:
            if nde.dpid == ev.link.src.dpid:
                nodeA = nde
                break
        for nde in self.Graph.nodes:
            if nde.dpid == ev.link.dst.dpid:
                nodeB = nde
                break
        self.Graph.add_link(nodeA, nodeB, ev.link.src, ev.link.dst)
        self.Graph.update_flow_table()
        print(self.Graph.graph)
        """
        Event handler indicating a link between two switches has been added
        """
        # TODO:  Update network topology and flow rules

    @set_ev_cls(event.EventLinkDelete)
    def handle_link_delete(self, ev):
        print("link delete")
        global nodeA, nodeB
        for nde in self.Graph.nodes:
            if nde.dpid == ev.link.src.dpid:
                nodeA = nde
                break
        for nde in self.Graph.nodes:
            if nde.dpid == ev.link.dst.dpid:
                nodeB = nde
                break
        self.Graph.delete_link(nodeA, nodeB, ev.link.src, ev.link.dst)
        self.Graph.update_flow_table()
        """
        Event handler indicating when a link between two switches has been deleted
        """
        # TODO:  Update network topology and flow rules

    @set_ev_cls(event.EventPortModify)
    def handle_port_modify(self, ev):
        print('modify port')
        # print(ev.msg)
        global switch
        for nde in self.Graph.nodes:
            if nde.dpid == ev.port.dpid:
                switch = nde
                break
        self.Graph.modify_port(port=ev.port, state=ev.port._state)
        self.Graph.update_flow_table()
        """
        Event handler for when any switch port changes state.
        This includes links for hosts as well as links between switches.
        """
        # TODO:  Update network topology and flow rules

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        try:
            msg = ev.msg
            datapath = msg.datapath
            pkt = packet.Packet(data=msg.data)
            pkt_dhcp = pkt.get_protocols(dhcp.dhcp)
            inPort = msg.in_port
            if not pkt_dhcp:
                arp_pkt = pkt.get_protocols(arp.arp)
                oftcl = OfCtl(datapath, logger=None)
                if arp_pkt:
                    print(arp_pkt)
                    tag_ip = arp_pkt.dst_ip
                    global mac
                    for nde in self.Graph.nodes:
                        if nde.isswitch is False and nde.ip == tag_ip:
                            mac = nde.mac
                    oftcl.send_arp(vlan_id=VLANID_NONE, arp_opcode=arp.ARP_REPLY, dst_mac=arp_pkt.src_mac,
                                   sender_mac=mac, sender_ip=arp_pkt.dst_ip,
                                   target_mac=arp_pkt.src_mac, target_ip=arp_pkt.src_ip,
                                   src_port=datapath.ofproto.OFPP_CONTROLLER,
                                   output_port=inPort
                                   )
                    ip = arp_pkt.src_ip.spilt('.')  # 192.168.2.2
                    # num = int(ip[3])
                    # host_mac = arp_pkt.src_mac
                    # host_ip = arp_pkt.src_ip
                    # flag = False
                    # for node in self.Graph.nodes:
                    #     if host_mac == node.mac:
                    #         flag = True
                    #         break
                    # if not flag:
                    #     sw = self.Graph.nodes[num]
                    #     host = Host(host_mac, host_ip, sw.dpid)
                    #     self.Graph.add_host(sw, host, None)

            else:
                DHCPServer.handle_dhcp(datapath, inPort, pkt)
            return
        except Exception as e:
            self.logger.error(e)

    # def cal_shortest_path(self,ev):
