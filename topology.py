#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel

def create_topology():
    # Tạo network
    net = Mininet(controller=RemoteController, link=TCLink)

    # Thêm Controller từ xa (RYU Controller)
    controller = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)

    # Thêm các switch
    s1 = net.addSwitch('s1')
    s2 = net.addSwitch('s2')
    s3 = net.addSwitch('s3')

    # Thêm các host
    h1 = net.addHost('h1')
    h2 = net.addHost('h2')
    h3 = net.addHost('h3')
    h4 = net.addHost('h4')

    # Thêm các server
    server1 = net.addHost('server1')
    server2 = net.addHost('server2')

    # Thêm SNORT IDS (giả sử là một host riêng)
    snortIDS = net.addHost('snortIDS')

    # Kết nối các host với switch s2
    net.addLink(h1, s2)
    net.addLink(h2, s2)
    net.addLink(h3, s2)
    net.addLink(h4, s2)

    # Kết nối server1 và server2 với switch s3
    net.addLink(server1, s3)
    net.addLink(server2, s3)

    # Kết nối s1 với SNORT IDS và Ryu controller
    net.addLink(s1, snortIDS)
    net.addLink(s1, controller)

    # Kết nối các switch với nhau
    net.addLink(s1, s2)
    net.addLink(s1, s3)

    # Bắt đầu network
    net.start()

    # Thêm các luồng OpenFlow cho mỗi switch
    s2.cmd('ovs-ofctl add-flow s2 priority=1,actions=normal')
    s1.cmd('ovs-ofctl add-flow s1 priority=1,actions=normal')
    s3.cmd('ovs-ofctl add-flow s3 priority=1,actions=normal')

    # Mở CLI để tương tác
    CLI(net)

    # Dừng network khi kết thúc
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_topology()
