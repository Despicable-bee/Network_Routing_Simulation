# Standard libs
import ipaddress
from typing import Generator
from typing import Optional

# Local libs
from RUSHBHelper import __DEBUG_MODE_ENABLED__
from RUSHBHelper import DebugPrinter

from RUSHBMultithreading import ThreadQueueMessage
from RUSHBMultithreading import ThreadType
from RUSHBHelper import RUSHBSwitchType
from RUSHBHelper import RUSHBSwitchServiceSides
from RUSHBHelper import RUSHBPacketModes

from RUSHBPackets import RUSHBBroadcastPacket
from RUSHBPackets import RUSHBDataPacket
from RUSHBPackets import RUSHBGreetingPacket
from RUSHBPackets import RUSHBLocationPacket
from RUSHBPackets import RUSHBQueryPacket
from RUSHBPackets import RUSHBReadyPacket
from RUSHBRoutingTable import RUSHBConnectionsTable, RUSHBRoutingTable

# * DEBUG ----------------------------------------------------------------------

__filename__ = 'RUSHBSwitchPacketHelper.py'

class TackOnsList(object):
    def __init__(self):
        self.__assignedLocalIp = None
        self.__assignedGlobalIp = None
        self.__ipAddrExhausted = False
        self.__hostIpAddr = None
        self.__ourLat = None
        self.__ourLng = None

        self.__tcpConnectionsTable = None
        self.__udpConnectionsTable = None
    
        self.__routingTable = None

    def get_assigned_local_ip(self):
        return self.__assignedLocalIp

    def set_assigned_local_ip(self, 
            newAssignedLocalIp: ipaddress.IPv4Address):
        self.__assignedLocalIp = newAssignedLocalIp

    def get_assigned_global_ip(self):
        return self.__assignedGlobalIp

    def set_assigned_global_ip(self, 
            newAssignedGlobalIp: ipaddress.IPv4Address):
        self.__assignedGlobalIp = newAssignedGlobalIp

    def get_ip_addr_exhausted(self):
        return self.__ipAddrExhausted

    def set_ip_addr_exhausted(self, newIpAddrExhausted: bool):
        self.__ipAddrExhausted = newIpAddrExhausted

    def get_host_ip_addr(self):
        return self.__hostIpAddr

    def set_host_ip_addr(self, newHostIpAddr: ipaddress.IPv4Address):
        self.__hostIpAddr = newHostIpAddr

    def get_our_lat(self):
        return self.__ourLat

    def set_our_lat(self, newOurLat: int):
        self.__ourLat = newOurLat

    def get_our_lng(self):
        return self.__ourLng

    def set_our_lng(self, newOurLng: int):
        self.__ourLng = newOurLng

    def get_tcp_connections_table(self):
        return self.__tcpConnectionsTable

    def set_tcp_connections_table(self, 
            newTcpConnectionsTable: RUSHBConnectionsTable):
        self.__tcpConnectionsTable = newTcpConnectionsTable

    def get_udp_connections_table(self):
        return self.__udpConnectionsTable

    def set_udp_connections_table(self, 
            newUdpConnectionsTable: RUSHBConnectionsTable):
        self.__udpConnectionsTable = newUdpConnectionsTable

    def get_routing_table(self):
        return self.__routingTable

    def set_routing_table(self, newRoutingTable: RUSHBRoutingTable):
        self.__routingTable = newRoutingTable

# * HELPER CLASS ---------------------------------------------------------------

class RUSHBSwitchPacketHelper(object):
    def __init__(self):
        self.__classname__ = 'RUSHBSwitchPacketHelper'
    
    def determine_tack_ons(self, message: ThreadQueueMessage, 
            switchServiceSide: RUSHBSwitchServiceSides,
            switchHostIp: ipaddress.IPv4Address,
            availableGlobalIps: Optional[Generator],
            availableLocalIps: Optional[Generator],
            threadName: str,
            ourLat: int,
            ourLng: int,
            tcpConnectionsTable: RUSHBConnectionsTable,
            udpConnectionsTable: RUSHBConnectionsTable,
            routingTable: RUSHBRoutingTable):
        """ Determine what additional data needs to be handed to the worker. """
        
        msgData = message.get_message_data()

        tackOns = TackOnsList()

        if msgData == None:
            raise Exception("Message data == None")

        msgMode = msgData.get_mode()

        if msgMode == None:
            raise Exception("Message mode == None")

        # Check for ip tack ons (i.e. we receive a DISCOVERY packet, add the 
        #   data necessary to build a OFFER packet)
        if msgMode == RUSHBPacketModes.DISCOVERY: 
            try:
                if switchServiceSide == RUSHBSwitchServiceSides.GLOBAL_SIDE:
                    if availableGlobalIps == None:
                        raise Exception("Global tack-ons requires generator")
                    newIpAddr = next(availableGlobalIps)
                    tackOns.set_assigned_global_ip(newIpAddr)
                else:
                    if availableLocalIps == None:
                        raise Exception("Local tack-ons requires generator")
                    newIpAddr = next(availableLocalIps)
                    tackOns.set_assigned_local_ip(newIpAddr)
                
            except StopIteration as e:
                if __DEBUG_MODE_ENABLED__:
                    DebugPrinter.print_generic_header(
                            threadName=threadName,
                            filename=__filename__,
                            classname=self.__classname__,
                            methodname='determine_tack_ons')
                    print("Available ip addresses exhausted")
                tackOns.set_ip_addr_exhausted(True)
                return tackOns

            # Tell switch they need to include the host address
            tackOns.set_host_ip_addr(switchHostIp)

        # Check for latitude and longitude tack ons
        if msgMode == RUSHBPacketModes.ACKNOWLEDGE or\
                msgMode == RUSHBPacketModes.LOCATION: 
            tackOns.set_our_lat(ourLat)
            tackOns.set_our_lng(ourLng)

        # Check for connections table tack ons
        if msgMode == RUSHBPacketModes.LOCATION or \
                msgMode == RUSHBPacketModes.BROADCAST or \
                msgMode == RUSHBPacketModes.DATA or \
                msgMode == RUSHBPacketModes.FRAGMENT_A or \
                msgMode == RUSHBPacketModes.FRAGMENT_B:
            tackOns.set_tcp_connections_table(tcpConnectionsTable)
            tackOns.set_udp_connections_table(udpConnectionsTable)

        # Check for routing data tack ons
        if msgMode == RUSHBPacketModes.BROADCAST or \
                msgMode == RUSHBPacketModes.LOCATION or \
                msgMode == RUSHBPacketModes.DATA or \
                msgMode == RUSHBPacketModes.FRAGMENT_A or \
                msgMode == RUSHBPacketModes.FRAGMENT_B:
            tackOns.set_routing_table(routingTable)

        return tackOns
    

    pass