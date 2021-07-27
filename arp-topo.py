#!/usr/bin/python
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.link import TCLink
import time
import datetime
import subprocess
import os,signal
import sys
#           1.0      
#    h1----s1----h2
  
nonbottlebw1=20
bottleneckbw=6
nonbottlebw2=100  
buffer_size =bottleneckbw*1000*30/(1500*8) 
net = Mininet( cleanup=True )
h1 = net.addHost('h1',ip='10.0.1.1')
h2 = net.addHost('h2',ip='10.0.1.2')

s1 = net.addSwitch( 's1' )
c0 = net.addController('c0')
net.addLink(h1,s1,intfName1='h1-eth0',intfName2='s1-eth0',cls=TCLink , bw=nonbottlebw1, delay='10ms', max_queue_size=10*buffer_size)
net.addLink(s1,h2,intfName1='s1-eth1',intfName2='h2-eth0',cls=TCLink , bw=nonbottlebw1, delay='10ms', max_queue_size=10*buffer_size) 

net.build()
h1.cmd("ifconfig h1-eth0 10.0.1.1/24")
#h1.cmd("route add default gw 10.0.1.2 dev h1-eth0")
h1.cmd('sysctl net.ipv4.ip_forward=1')


h2.cmd("ifconfig h2-eth0 10.0.1.2/24")
h2.cmd('sysctl net.ipv4.ip_forward=1')

net.start()
time.sleep(1)
CLI(net)
net.stop()
