import sys
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


class Graph:
    def __init__(self):
        self.graph = {}  # graph = {node:{neibourhood: port}}
        self.nodes = []

    def update_flow_table(self):
        for node in self.nodes:
            self.find_shortest_path(node)

    def find_shortest_path(self, start_node):
        distance, res = self.dijkstra(start_node)
        for host in self.graph:
            if host.isswitch is False and host != start_node:
                mac = host.mac
                cur = host
                while cur != start_node:
                    cur = res[start_node][0]
                    port = res[start_node][1]
                    if cur.isswitch is True:
                        self.add_forwarding_rule(cur.datapath, mac, port.port_no)

    def dijkstra(self, start):
        res = {}
        visited = set()
        distance = {node: sys.maxsize for node in self.nodes}
        distance[start] = 0
        # print('graph:'+ str(len(self.graph)))
        # print('nodes:'+ str(len(self.nodes)))
        while len(visited) != len(self.nodes):
            # print(len(visited))
            tempnode = min(self.graph.keys() - visited, key=lambda k: distance[k])
            visited.add(tempnode)
            for neighbour, port in self.graph[tempnode].items():
                if port._state != 1:
                    if distance[tempnode] + 1 < distance[neighbour]:
                        distance[neighbour] = distance[tempnode] + 1
                        res[neighbour] = (tempnode, port)  # 记录最短路上 , 最近的主机和 node的port
        return distance, res

    def add_link(self, sw1, sw2, port1, port2):
        self.link(sw1, sw2, port1)
        self.link(sw2, sw1, port2)

    def delete_switch(self, sw):
        if sw in self.nodes:
            self.nodes.remove(sw)
            for key in list(self.graph.keys()):
                if sw in self.graph[key]:
                    del self.graph[key][sw]
            del self.graph[sw]
        else:
            raise ValueError("Node not in graph")

    def delete_link(self, fa1, fa2, port1, port2):
        del self.graph[fa1][fa2]
        del self.graph[fa2][fa1]

    def modify_port(self, port, state):
        for node in self.graph:
            neibourhood_dict = self.graph[node]  # 获取 node 的邻居字典
            for neibour in neibourhood_dict:
                if neibour.dpid == port.dpid and neibourhood_dict[neibour].port_no == port.port_no:
                    neibourhood_dict[neibour]._state = state  # 获取该邻居节点对应的端口

    def add_switch(self, swNode):
        self.graph[swNode] = {}
        self.nodes.append(swNode)
        pass

    def add_host(self, switch, host, port1):
        self.graph[host] = {}
        self.nodes.append(host)
        self.link(switch, host, port1)
        self.link(host, switch, None)  # 不知道host的端口
        pass

    def link(self, fa1, fa2, port):
        if fa1 in self.graph:
            self.graph[fa1][fa2] = port
        else:
            self.graph[fa1] = {}
            self.graph[fa1][fa2] = port

    def add_forwarding_rule(self, datapath, dl_dst, port):
        ofctl = OfCtl.factory(datapath, self.logger)
        actions = [datapath.ofproto_parser.OFPActionOutput(port)]
        ofctl.set_flow(cookie=0, priority=0,
                       dl_type=ether_types.ETH_TYPE_IP,
                       dl_vlan=VLANID_NONE,
                       dl_dst=dl_dst,
                       actions=actions)


class Switch:
    def __init__(self, sw):
        self.isswitch = True
        self.isvisited = False
        self.datapath = sw.dp
        self.dpid = self.datapath.id


class Host:
    def __init__(self, mac, ipv4, dpid, port):
        self.isswitch = False
        self.isvisited = False
        self.mac = mac
        self.ip = ipv4[0]
        self.dpid = dpid
        self.port = port
