# Standard libs
from re import M
import threading
import queue as threadingQueue

from typing import Optional
from typing import Union

import socket

from multiprocessing import Queue

import ipaddress

# Local libs
from RUSHBHelper import MainThreadQueueMessageType
from RUSHBHelper import ChildThreadQueueMessageType
from RUSHBHelper import ThreadType
from RUSHBHelper import RUSHBSwitchType
from RUSHBHelper import RUSHBSwitchServiceSides

from RUSHBPackets import RUSHBGreetingPacket
from RUSHBPackets import RUSHBDataPacket
from RUSHBPackets import RUSHBReadyPacket
from RUSHBPackets import RUSHBQueryPacket
from RUSHBPackets import RUSHBBroadcastPacket
from RUSHBPackets import RUSHBLocationPacket
from RUSHBRoutingTable import RUSHBConnectionsTable, RUSHBRoutingTable

# * DEBUG ----------------------------------------------------------------------

__filename__ = 'RUSHBSwitchMultithreading.py'

# * AUXILIARY CLASSES ----------------------------------------------------------

class ThreadQueueContainer:
    def __init__(self,
            threadName: str,
            threadLock: threading.Lock,
            fromParentQueue: Optional[threadingQueue.Queue]=None,
            toParentQueue: Optional[threadingQueue.Queue]=None,
            # General purpose socket (use as you wish)
            socket: Optional[socket.socket]=None,
            # General purpose port numb (use as you wish)
            portNum: Optional[int]=None,
            # Context params for worker thread
            parentSwitchType: Optional[RUSHBSwitchType]=None,
            switchServiceSide: Optional[RUSHBSwitchServiceSides]=None,
            parentSourceIp: Optional[ipaddress.IPv4Address]=None):

        self.__fromParentQueue = fromParentQueue
        self.__toParentQueue = toParentQueue
        self.__threadName = threadName
        self.__sock = socket
        self.__portNum = portNum
        self.__parentSwitchType = parentSwitchType
        self.__switchServiceSide = switchServiceSide
        self.__threadLock = threadLock
        self.__parentSourceIp = parentSourceIp
    
    def get_from_parent_queue(self):
        return self.__fromParentQueue

    def get_to_parent_queue(self):
        return self.__toParentQueue
    
    def get_thread_name(self):
        return self.__threadName

    def get_socket(self):
        return self.__sock

    def set_socket(self, newSocket: socket.socket):
        self.__sock = newSocket

    def get_port_num(self):
        return self.__portNum

    def set_port_num(self, newPortNum: int):
        self.__portNum = newPortNum
        
    def get_parent_switch_type(self):
        return self.__parentSwitchType

    def set_parent_switch_type(self, newParentSwitchType: RUSHBSwitchType):
        self.__parentSwitchType = newParentSwitchType

    def get_switch_service_side(self):
        return self.__switchServiceSide

    def set_switch_service_side(self, newServiceSide: RUSHBSwitchServiceSides):
        self.__switchServiceSide = newServiceSide

    def get_thread_lock(self):
        return self.__threadLock

    def get_parent_source_ip(self):
        return self.__parentSourceIp

    def set_parent_source_ip(self, 
            newParentSourceIp: Optional[ipaddress.IPv4Address]=None):
        self.__parentSourceIp = newParentSourceIp
    

class ThreadQueueMessage:
    def __init__(self,
            msgType: Union[MainThreadQueueMessageType, 
                    ChildThreadQueueMessageType],
            msgFrom: str,
            msgData: Optional[Union[RUSHBGreetingPacket,
                    RUSHBDataPacket,
                    RUSHBReadyPacket,
                    RUSHBQueryPacket,
                    RUSHBBroadcastPacket,
                    RUSHBLocationPacket]]=None,  
            portNum: Optional[int]=None,
            # socket for connection requests (TCP greeter)
            newSocket: Optional[socket.socket]=None,
            # Ip address of the main switch
            ourSourceIp: Optional[ipaddress.IPv4Address]=None,
            # Optional ip address, used during greeting process
            assignedIp: Optional[ipaddress.IPv4Address]=None,
            # Optional ip address, used during the greeting process
            theirSourceIp: Optional[ipaddress.IPv4Address]=None,
            # Optional latitude value, used when sending location packets
            ourLat: Optional[int]=None,
            # Optional lontiude value, used when sending location packets
            ourLng: Optional[int]=None,
            # Optional connections table, used when determining where to send
            #   broadcast messages
            tcpConnTable: Optional[RUSHBConnectionsTable]=None,
            # Optional connections table, used when determining where to send
            #   broadcast messages (Hybrid only, we don't broadcast to adapters)
            udpConnTable: Optional[RUSHBConnectionsTable]=None,
            # Optional distance value, used for updating the routing table
            distance: Optional[int]=None,
            # Optional routing table, used for broadcast, and routing tasks
            routingTable: Optional[RUSHBRoutingTable]=None,
            
            # Keeps track of which port number the switch originally received 
            #   the message from
            receivedFromPortNum: Optional[int]=None):

        """
        
        ARGS:
        - msgType: The `instruction` for the recipient
        - msgFrom: The thread id of the sender
        - msgData: Optional object representation of a packet.
        - portNum: Optional integer holding a port number (use at your
                disgression)
        """
        self.__msgType = msgType
        self.__msgFrom = msgFrom
        self.__portNum = portNum
        self.__msgData = msgData

        self.__ourSourceIp = ourSourceIp
        self.__assignedIp = assignedIp
        self.__theirSourceIp = theirSourceIp

        self.__newSocket = newSocket
        
        self.__ourLat = ourLat
        self.__ourLng = ourLng

        self.__tcpConnTable = tcpConnTable
        self.__udpConnTable = udpConnTable

        self.__distance = distance

        self.__routingTable = routingTable

        self.__receivedFromPortNum = receivedFromPortNum

    def get_message_type(self):
        return self.__msgType

    def get_message_from(self):
        """ The name of the thread this message was from. """
        return self.__msgFrom

    def get_port_number(self):
        return self.__portNum

    def get_message_data(self):
        return self.__msgData

    def get_our_source_ip(self):
        return self.__ourSourceIp

    def set_our_source_ip(self, newSourceIp: ipaddress.IPv4Address):
        self.__ourSourceIp = newSourceIp

    def get_assigned_ip(self):
        return self.__assignedIp

    def set_assigned_ip(self, newAssignedIp: ipaddress.IPv4Address):
        self.__assignedIp = newAssignedIp

    def get_their_source_ip(self):
        return self.__theirSourceIp

    def get_new_socket(self):
        return self.__newSocket

    def get_our_lat(self):
        return self.__ourLat

    def set_our_lat(self, newOurLat: int):
        self.__ourLat = newOurLat

    def get_our_lng(self):
        return self.__ourLng

    def set_our_lng(self, newOurLng: int):
        self.__ourLng = newOurLng

    def get_tcp_conn_table(self):
        return self.__tcpConnTable

    def set_tcp_conn_table(self, newTcpConnTable: RUSHBConnectionsTable):
        self.__tcpConnTable = newTcpConnTable

    def get_udp_conn_table(self):
        return self.__udpConnTable

    def set_udp_conn_table(self, newUdpConnTable: RUSHBConnectionsTable):
        self.__udpConnTable = newUdpConnTable

    def get_distance(self):
        return self.__distance
    
    def set_distance(self, newDistance: int):
        self.__distance = newDistance

    def get_routing_table(self):
        return self.__routingTable

    def set_routing_table(self, newRoutingTable: RUSHBRoutingTable):
        self.__routingTable = newRoutingTable

    def get_received_from_port_num(self):
        return self.__receivedFromPortNum

# * TRACKERS -------------------------------------------------------------------

class ChildThreadTracker(object):
    def __init__(self, threadType: ThreadType,
            thread: threading.Thread,
            toThreadQueue: Optional[threadingQueue.Queue]=None,
            fromThreadQueue: Optional[threadingQueue.Queue]=None,
            portNumber: Optional[int]=None):

        self.__threadType = threadType
        self.__thread = thread
        self.__toThreadQueue = toThreadQueue
        self.__fromThreadQueue = fromThreadQueue
        self.__portNum = portNumber

    def get_thread_type(self):
        return self.__threadType

    def get_thread(self):
        return self.__thread

    def get_to_thread_queue(self):
        return self.__toThreadQueue

    def set_to_thread_queue(self, newToThreadQueue: threadingQueue.Queue):
        self.__toThreadQueue = newToThreadQueue

    def get_from_thread_queue(self):
        return self.__fromThreadQueue

    def get_port_number(self):
        return self.__portNum

class PortThreadContainer(object):
    def __init__(self,
            workerThreadTracker: Optional[ChildThreadTracker]=None, 
            senderThreadTracker: Optional[ChildThreadTracker]=None, 
            recvrThreadTracker: Optional[ChildThreadTracker]=None):
        """ Container for the various processes associated with a port number. 
        """
        self.__workerThread = workerThreadTracker
        self.__senderThread = senderThreadTracker
        self.__recvrThread = recvrThreadTracker

    def get_worker_thread_tracker(self):
        return self.__workerThread

    def set_worker_thread_tracker(self, 
            newWorkerThreadTracker: ChildThreadTracker):
        self.__workerThread = newWorkerThreadTracker
    
    def get_sender_thread_tracker(self):
        return self.__senderThread

    def set_sender_thread_tracker(self, 
            newSenderThreadTracker: ChildThreadTracker):
        self.__senderThread = newSenderThreadTracker

    def get_recvr_thread_tracker(self):
        return self.__recvrThread

    def set_recvr_thread_tracker(self, 
            newReceiverThreadTracker: ChildThreadTracker):
        self.__recvrThread = newReceiverThreadTracker

# * THREAD CLASSES -------------------------------------------------------------

class Terminal_Thread(object):
    def __init__(self, threadQueueContainer: ThreadQueueContainer):
        self.__toParentQueue = threadQueueContainer.get_to_parent_queue()
        self.__threadName = threadQueueContainer.get_thread_name()

    def main_loop(self):
        assert isinstance(self.__toParentQueue, threadingQueue.Queue), \
                "toParentQueue must be a valid threading queue"
        while True:
            try:
                userInput = input("> ")
            except EOFError as e:
                self.__toParentQueue.put(ThreadQueueMessage(
                    msgType=MainThreadQueueMessageType.THREAD_TERMINATING,
                    msgFrom=self.__threadName))
                break
            # Attempt to split the input by the space
            splitInput = userInput.split(" ")

            if len(splitInput) != 2:
                continue

            if splitInput[0] != 'connect' or not splitInput[1].isdigit():
                continue
            
            print("We got some data: {}".format(userInput))
            print("Sending to main thread")

            self.__toParentQueue.put(ThreadQueueMessage(
                    msgType=MainThreadQueueMessageType.CONNECT_REQUEST,
                    msgFrom=self.__threadName,
                    portNum=int(splitInput[1])))