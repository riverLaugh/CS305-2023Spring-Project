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
        self.logger = None
        self.graph = {}  # graph = {node:{neibourhood: port}}
        self.nodes = []
        self.switches = []
        self.hosts = []
        self.count = 0

    def update_flow_table(self):
        for node in self.nodes:
            if isinstance(node, Host):
                self.find_shortest_path(node)
        print(self.count)

    def find_shortest_path(self, host):
        mydir = self.graph[host]
        for key in mydir.keys():
            start_sw = key  # 得到host相连的交换机
            host_port = mydir[key]
        # self.add_forwarding_rule(datapath=start_sw.datapath,dl_dst=host.mac,port=host_port)
        distance, res = self.dijkstra(start_sw)
        # try:
        # print(f"start_sw={start_sw}")
        # print(res)
        for node in self.graph:
            if node.isswitch is False and node != start_sw:  # 遍历每一个host
                mac = node.mac  # 从start_sw 到
                # print(self.graph[node])
                mydir = self.graph[node]
                # print(mydir)
                for key in mydir.keys():
                    cur = key
                    neigh_port1 = mydir[key]  # port1是该host与交换机相连的端口
                # self.add_forwarding_rule(datapath=cur.datapath,dl_dst=node.mac,port=neigh_port1)
                if cur.isswitch == False:
                    print("shotest path: is not switch")
                while cur != start_sw:
                    # print(f"start_sw :{start_sw}")
                    # print(f"cur:{cur}")
                    if cur.isswitch is True:
                        port = res[cur][1]
                        last_cur = res[cur][0]
                        print(f"dst:{cur}")
                        self.count += 1
                        print(self.count)
                        self.add_forwarding_rule(datapath=last_cur.datapath, dl_dst=mac, port=port.port_no)
                        print(f"{last_cur}:{port.port_no}:{cur}:{node.mac}")
                        cur = last_cur
        print("-----------------------------------")

        # except KeyError:
        #     print("keyError")

    def dijkstra(self, start_sw):  # 传进来的得是个switch
        try:
            print(start_sw)
            res = {}
            visited = set()
            # print(visited)
            # print("[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]")
            # print(self.nodes)
            # print("[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]")
            # print(self.graph)
            # print("[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]")
            for host in self.hosts:
                visited.add(host)
            distance = {node: sys.maxsize for node in self.nodes}
            distance[start_sw] = 0
            while len(visited) != len(self.nodes):
                # print("ccccccccccccccccc")
                tempnode = min(self.graph.keys() - visited, key=lambda k: distance[k])
                visited.add(tempnode)
                for neighbour, port in self.graph[tempnode].items():
                    if isinstance(neighbour, Switch) and port._state != 1:  # neibour得是switch
                        # print("bbbbbbbbbbb")
                        if distance[tempnode] + 1 < distance[neighbour]:
                            # print("aaaaaaaaaaaaaaa")
                            distance[neighbour] = distance[tempnode] + 1
                            res[neighbour] = (tempnode, port)  # 记录最短路上 , 最近的主机和 node的port
            print(res)
            print("------------------------------------------------")
            return distance, res
        except KeyError:
            print()

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
        self.switches.append(swNode)
        pass

    def add_host(self, switch, host, port):
        self.graph[host] = {}
        self.nodes.append(host)
        self.hosts.append(host)
        self.link(switch, host, port)
        self.link(host, switch, port)  # 不知道host的端口
        self.add_forwarding_rule(datapath=switch.datapath, dl_dst=host.mac, port=port.port_no)
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
        self.datapath = sw.dp
        self.dpid = self.datapath.id

    def __repr__(self):
        return f"Switch({self.dpid})"


class Host:
    def __init__(self, host):
        self.isswitch = False
        self.mac = host.mac
        self.ip = host.ipv4[0]
        self.port = host.port
        # self.dpid = host.dpid

    def __repr__(self):
        return f"Host({self.ip})"

    def __str__(self):
        return f"Host({self.ip} ,{self.mac})"
