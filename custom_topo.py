from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.link import TCLink

class TwoSwitchTopo(Topo):
    def build(self):
        # Buat switch
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')

        # Buat host
        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')

        # Hubungkan host ke switch masing-masing
        self.addLink(h1, s1)
        self.addLink(h2, s2)

        # Hubungkan switch satu sama lain
        self.addLink(s1, s2)

topos = {'twoswitch': (lambda: TwoSwitchTopo())}
