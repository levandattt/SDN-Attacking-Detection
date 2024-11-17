#!/usr/bin/python
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.log import setLogLevel, info
from mininet.cli import CLI

import ipaddress


class RouterInfo:
    def __init__(self, name, ip, if_size=10):
        self.name = name
        self.ip = ip
        self.interfaces = []
        self.links = {}
        self.host = None
        self.top_if = 0
        for i in range(if_size):
            self.interfaces.append(f'{name}-eth{i}')

    def get_default_route(self):
        # Convert the IP with CIDR to an IPv4Network object
        network = ipaddress.ip_network(self.ip, strict=False)
        # Return the network address in CIDR notation
        return str(network)

    def used_if(self):
        self.top_if += 1

    def get_if(self):
        return self.interfaces[self.top_if]


class LinuxRouter(Node):
    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        self.cmd('sysctl net.ipv4.ip_forward=1')

    def terminate(self):
        self.cmd('sysctl net.ipv4.ip_forward=0')
        super(LinuxRouter, self).terminate()


class NetworkTopo(Topo):
    def link_switch_router(self, router_info, switch):
        self.addLink(switch,
                     router_info.name,
                     intfName2=router_info.get_if(),
                     params2={'ip': router_info.ip})
        router_info.used_if()

    def add_router(self, router_info):
        router = self.addHost(router_info.name, cls=LinuxRouter, ip=router_info.ip)
        router_info.host = router
        return router

    def add_route_router(self, router_1_info, router_2_info, via1, via2):
        self.routes.append((router_1_info.name,
                            f'ip route add {router_2_info.get_default_route()} via {via1[1]} dev {via1[0]}'))
        self.routes.append((router_2_info.name,
                            f'ip route add {router_1_info.get_default_route()} via {via2[1]} dev {via2[0]}'))

    def add_route(self, host, route_string):
        self.routes.append((host, route_string))

    def apply_routes(self, net):
        for host, route_cmd in self.routes:
            net[host].cmd(route_cmd)

    def link_routers(self, router_info_1, router_info_2, p2p_subnet):
        # Add router-router links within AS1
        self.addLink(router_info_1.host,
                     router_info_2.host,
                     intfName1=router_info_1.get_if(),
                     intfName2=router_info_2.get_if(),
                     params1={'ip': p2p_subnet[0]},
                     params2={'ip': p2p_subnet[1]})

        self.routes.append((router_info_1.name,
                            f'ip route add {router_info_2.get_default_route()} via {p2p_subnet[1][:-3]} dev {router_info_1.get_if()}'))
        self.routes.append((router_info_2.name,
                            f'ip route add {router_info_1.get_default_route()} via {p2p_subnet[0][:-3]} dev {router_info_2.get_if()}'))
        router_info_1.links[router_info_2.name] = (router_info_1.get_if(), p2p_subnet[1][:-3])
        router_info_2.links[router_info_1.name] = (router_info_2.get_if(), p2p_subnet[0][:-3])

        router_info_1.used_if()
        router_info_2.used_if()

    def add_host(self, name, ip, router_info):
        return self.addHost(name=name, ip=ip, defaultRoute=f'via {router_info.ip[:-3]}')

    def add_attackers(self, attacker_prefix, num, three_prefixes, router_info, switch):
        attackers = []
        for i in range(num):
            attacker = self.add_host(name=f'{attacker_prefix}{i}', ip=f'{three_prefixes}.{i + 3}/24', router_info=router_info)
            # link to switch
            self.addLink(attacker, switch)
            attackers.append(attacker)
        return attackers

    def build(self, p2p_subnets):
        # Create AS1 (Viettel)
        self.routes = []

        as1_r1_router = RouterInfo('as1_r1', '113.22.0.1/24')
        as1_r2_router = RouterInfo('as1_r2', '42.112.3.1/24')
        as1_r3_router = RouterInfo('as1_r3', '118.69.132.1/24')

        self.add_router(as1_r1_router)
        self.add_router(as1_r2_router)
        self.add_router(as1_r3_router)

        as1_r1_s1 = self.addSwitch('as1_r1-s1')
        as1_r2_s1 = self.addSwitch('as1_r2-s1')
        as1_r3_s1 = self.addSwitch('as1_r3-s1')

        self.link_switch_router(
            as1_r1_router,
            as1_r1_s1)

        self.link_switch_router(
            as1_r2_router,
            as1_r2_s1)

        self.link_switch_router(
            as1_r3_router,
            as1_r3_s1)

        # Add router-router links within AS1
        self.link_routers(as1_r1_router, as1_r2_router, p2p_subnets['as1_r1-as1_r2'])
        self.link_routers(as1_r2_router, as1_r3_router, p2p_subnets['as1_r2-as1_r3'])
        self.add_route_router(as1_r1_router,
                              as1_r3_router,
                              as1_r1_router.links['as1_r2'],
                              as1_r3_router.links['as1_r2'])

        d1 = self.add_host(name='d1', ip='113.22.0.2/24', router_info=as1_r1_router)
        d2 = self.add_host(name='d2', ip='42.112.3.2/24', router_info=as1_r2_router)
        d3 = self.add_host(name='d3', ip='118.69.132.2/24', router_info=as1_r3_router)

        # link to switch
        self.addLink(d1, as1_r1_s1)
        self.addLink(d2, as1_r2_s1)
        self.addLink(d3, as1_r3_s1)

        # Create AS2 (Google)
        as2_r1_router = RouterInfo('as2_r1', '74.125.119.1/24')
        as2_r2_router = RouterInfo('as2_r2', '209.85.244.1/24')

        self.add_router(as2_r1_router)
        self.add_router(as2_r2_router)

        as2_r1_s1 = self.addSwitch('as2_r1-s1')
        as2_r2_s1 = self.addSwitch('as2_r2-s1')

        self.link_switch_router(as2_r1_router, as2_r1_s1)
        self.link_switch_router(as2_r2_router, as2_r2_s1)

        # Link AS1 and AS2 routers
        self.link_routers(as1_r3_router, as2_r1_router, p2p_subnets['as1_r3-as2_r1'])
        self.link_routers(as2_r1_router, as2_r2_router, p2p_subnets['as2_r1-as2_r2'])
        self.add_route_router(as1_r1_router, as2_r1_router, as1_r1_router.links['as1_r2'],
                              as2_r1_router.links['as1_r3'])
        self.add_route_router(as1_r1_router, as2_r2_router, as1_r1_router.links['as1_r2'],
                              as2_r2_router.links['as2_r1'])
        self.add_route_router(as1_r2_router, as2_r2_router, as1_r2_router.links['as1_r3'],
                              as2_r2_router.links['as2_r1'])
        self.add_route_router(as1_r2_router, as2_r1_router, as1_r2_router.links['as1_r3'],
                              as2_r1_router.links['as1_r3'])

        self.add_route_router(as1_r3_router, as2_r2_router, as1_r3_router.links['as2_r1'],
                              as2_r2_router.links['as2_r1'])

        google_server_1 = self.add_host('google_1', ip='74.125.119.2/24', router_info=as2_r1_router)
        google_server_2 = self.add_host('google_2', ip='209.85.244.2/24', router_info=as2_r2_router)
        self.addLink(google_server_1, as2_r1_s1)
        self.addLink(google_server_2, as2_r2_s1)

        self.attackers = self.add_attackers("atk_r1",50, '113.22.0', as1_r1_router, as1_r1_s1)
        # self.attackers.extend(self.add_attackers("atk_r2",2, '113.22.0', as1_r2_router, as1_r2_s1))

        self.victims = [google_server_1, google_server_2]

    def attack(self, net, target, attack_cmd):
        for attacker in self.attackers:
            attacker_name = str(attacker)
            print(f'Debug: Attacker: {attacker_name}, Command: {attack_cmd} {target}')
            output = net[attacker_name].cmd(f'{attack_cmd} {target} &> /dev/null &')
            print(f'Debug: Command Output: {output}')

def run():
    p2p_subnets = {
        'as1_r1-as1_r2': ['113.22.100.1/30', '113.22.100.2/30'],
        'as1_r2-as1_r3': ['42.112.100.1/30', '42.112.100.2/30'],
        'as1_r3-as2_r1': ['118.69.100.1/30', '118.69.100.2/30'],
        'as2_r1-as2_r2': ['74.125.100.1/30', '74.125.100.2/30'],
        # 'as2_r1-as2_r2': ('10.0.4.1/30', '10.0.4.2/30'),
        # 'as2_r2-google': ('10.0.5.1/30', '10.0.5.2/30')
    }

    topo = NetworkTopo(p2p_subnets=p2p_subnets)
    net = Mininet(topo=topo)
    net.start()
    topo.apply_routes(net)
    topo.attack(net, '209.85.244.2', 'ping -f')

    # Test connectivity in CLI
    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run()
