- Add rules:
sudo nano /etc/snort/rules/local.rules
- Run snort
sudo snort -i s1-eth4 -c /etc/snort/snort.conf
- Run ryu
sudo  ryu-manager --ofp-tcp-listen-port 6653 snort_ddos_app.py

- Add mininet link
sh ovs-ofctl add-flow s2 priority=1,actions=normal
sh ovs-ofctl add-flow s1 priority=1,actions=normal
sh ovs-ofctl add-flow s3 priority=1,actions=normal

- Attack with:

+ h1 ping -f server1
+ h1 hping3 -1 --flood server1
+ h2 hping3 -i u5000 -S -p 80 server2
