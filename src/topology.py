from mininet.net import Mininet
from mininet.node import Controller, OVSKernelSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel

def car_network():
    net = Mininet(controller=Controller, switch=OVSKernelSwitch, waitConnected=True)

    print("***SDN Controller") #basic controller
    net.addController('c0', controller=RemoteController)

    print("***Central Switch") # virtual switch
    s1 = net.addSwitch('s1')

    print("***ECUs")
    infotainment = net.addHost('attacker', ip='10.0.0.1') #virtual host
    brakes = net.addHost('victim', ip='10.0.0.2') # virtual machine as the victim

    print("***Car")
    net.addLink(infotainment, s1) #infotainment to central switch
    net.addLink(brakes, s1) # brake nodes to central switch

    print("***Starting the vehicle network") #boot network
    net.start()

    print("*** Testing connectivity")
    net.pingAll()

    print("***Type 'pingall' to test.") #network is live
    CLI(net)

    print("***Shutting down") #shut down after
    net.stop()

if __name__ == '__main__': #boilerplate
    setLogLevel('info')
    car_network()
