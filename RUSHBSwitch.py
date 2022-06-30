# Standard libs
from pprint import PrettyPrinter
import sys

import threading
from threading import Lock

import queue as threadQueue

from enum import Enum
from enum import auto

from typing import List
from typing import Generator
from typing import Dict
from typing import Optional

import ipaddress

import socket

import time

# Local libs

from RUSHBHelper import DebugPrinter
from RUSHBHelper import MainThreadQueueMessageType
from RUSHBHelper import ChildThreadQueueMessageType
from RUSHBHelper import GenericErrorHandler
from RUSHBHelper import __DEBUG_MODE_ENABLED__
from RUSHBHelper import GeneralHelperMethods
from RUSHBHelper import RUSHBSwitchType
from RUSHBHelper import RUSHBSwitchServiceSides
from RUSHBHelper import RUSHBPacketModes

from RUSHBMultithreading import ChildThreadTracker, ThreadQueueContainer
from RUSHBMultithreading import PortThreadContainer
from RUSHBMultithreading import ThreadType
from RUSHBMultithreading import ThreadQueueMessage

from RUSHBRoutingTable import RUSHBRoutingTable
from RUSHBRoutingTable import RUSHBConnectionsTable

from RUSHBThreadStarters import tcp_greeter_thread_starter
from RUSHBThreadStarters import tcp_receiver_thread_starter
from RUSHBThreadStarters import tcp_sender_thread_starter
from RUSHBThreadStarters import udp_receiver_thread_starter
from RUSHBThreadStarters import udp_sender_thread_starter
from RUSHBThreadStarters import terminal_thread_starter
from RUSHBThreadStarters import global_worker_thread_starter
from RUSHBThreadStarters import local_worker_thread_starter

from RUSHBPackets import RUSHBBroadcastPacket
from RUSHBPackets import RUSHBDataPacket
from RUSHBPackets import RUSHBGreetingPacket
from RUSHBPackets import RUSHBLocationPacket
from RUSHBPackets import RUSHBQueryPacket
from RUSHBPackets import RUSHBReadyPacket

from RUSHBSwitchPacketHelper import RUSHBSwitchPacketHelper
from RUSHBSwitchPacketHelper import TackOnsList

# * DEBUG ----------------------------------------------------------------------

__filename__ = 'RUSHBSwitch.py'

# * MAIN -----------------------------------------------------------------------

class RUSHBSwitch:
    def __init__(self, cmdLineArgs: List[str]):
        self.__classname__ = 'RUSHBSwitch'
        
        self.__mtid = 'MAIN'

        self.__threadLock = Lock()
        self.__printLock = Lock()

        # These will be overwritten but the command line args init method
        self.__hostAddrGlobal: Optional[ipaddress.IPv4Address] = None
        self.__hostAddrLocal: Optional[ipaddress.IPv4Address] = None

        # Initialise the switch based on the command line args.
        try:
            # Don't include the 'RUSHBSwitch.py command line arg
            self.__init_command_line_args(cmdLineArgs=cmdLineArgs[1:])
        except Exception as e:
            if __DEBUG_MODE_ENABLED__:
                self.__printLock.acquire()
                DebugPrinter.print_generic_header(
                        threadName=self.__mtid,
                        filename=__filename__,
                        methodname='__init__',
                        classname='RUSHBSwitch')
                exc_type, exc_obj, exc_tb = sys.exc_info()
                geh = GenericErrorHandler()
                geh.debug_print_error(filename=__filename__,
                        className=self.__classname__,
                        methodName="__init__",
                        lineNum=exc_tb.tb_lineno,   # type: ignore
                        exception=e)
                sys.stdout.flush()
                self.__printLock.release()
            
            # Print out the usage statement
            print("Usage: python RUSHBSwitch.py [local|global] {ip} " + \
                    "{optional_ip} {x} {y}")
            return None

        sys.stdout.flush()

        # Initialise the supporting elements for the switch
        self.__fromChildToParentThreadQueue: threadQueue.Queue = \
                threadQueue.Queue()

        # UDP Thread trackers
        self.__localChildThreadsDict: Dict[int, ChildThreadTracker] = {}
        self.__udpSenderThreadTracker: ChildThreadTracker
        self.__udpReceiverThreadTracker: ChildThreadTracker

        # Terminal thread tracker
        self.__terminalThreadTracker: ChildThreadTracker

        # TCP Thread trackers
        self.__globalChildThreadsDict: Dict[int, PortThreadContainer] = {}
        self.__tcpGreeterThreadTracker: ChildThreadTracker

        # Routing table
        self.__routingTable: RUSHBRoutingTable = RUSHBRoutingTable()

        # Connections tables
        self.__tcpConnectionsTable = RUSHBConnectionsTable()
        self.__udpConnectionsTable = RUSHBConnectionsTable()

        # Iniitalise the supporting elements
        self.__init_support_elements()
    
    # ? PUBLIC METHODS ---------------------------------------------------------

    def main_loop(self):
        # Seek the generators to the host address
        if self.__switchType == RUSHBSwitchType.GLOBAL or \
                self.__switchType == RUSHBSwitchType.HYBRID:
            while True:
                nextIp = next(self.__availableGlobalIps)
                if nextIp == self.__hostAddrGlobal:
                    break
            
        if self.__switchType == RUSHBSwitchType.LOCAL or \
                self.__switchType == RUSHBSwitchType.HYBRID:
            while True:
                nextIp = next(self.__availableLocalIps)
                if nextIp == self.__hostAddrLocal:
                    break

        while True:
            # Wait for input from any of the other thread processes
            message = self.__fromChildToParentThreadQueue.get(block=True)

            self.__threadLock.acquire()

            if not isinstance(message, ThreadQueueMessage):
                # Ignore invalid messages
                print("Invalid message")
                self.__fromChildToParentThreadQueue.task_done()
                self.__threadLock.release()
                continue

            if __DEBUG_MODE_ENABLED__:
                DebugPrinter.print_generic_header(threadName=self.__mtid,
                        filename=__filename__,
                        classname=self.__classname__,
                        methodname='main_loop')
                print('Main loop received message from {}'.format(
                        message.get_message_from()))
                print("Message Type: {}".format(
                        message.get_message_type()))
                # TODO - Message data
                sys.stdout.flush()
            
            # Handle the message
            msgType = message.get_message_type()

            if not isinstance(msgType, MainThreadQueueMessageType):
                raise Exception(
                        "Should only receive main thread queue message types")

            if msgType == MainThreadQueueMessageType.CONNECT_REQUEST:
                self.__handle_connect_request(message)
                
            elif msgType == MainThreadQueueMessageType.HANDLE_GREETER_SOCKET:
                self.__handle_greeter_socket(message)

            elif msgType == MainThreadQueueMessageType.TCP_FORWARD_MSG_TO_SENDER:
                self.__handle_tcp_forward_msg_to_sender(message)

            elif msgType == MainThreadQueueMessageType.TCP_FORWARD_MSG_TO_WORKER:
                self.__handle_tcp_forward_msg_to_worker(message)

            elif msgType == MainThreadQueueMessageType.UDP_FORWARD_MSG_TO_SENDER:
                self.__handle_udp_forward_msg_to_sender(message)

            elif msgType == MainThreadQueueMessageType.UDP_FORWARD_MSG_TO_WORKER:
                self.__handle_udp_forward_msg_to_worker(message)

            elif msgType == MainThreadQueueMessageType.UPDATE_ROUTING_TABLE:
                self.__handle_update_routing_table(message)

            elif msgType == MainThreadQueueMessageType\
                    .ADD_TO_TCP_CONNECTIONS_TABLE:
                self.__handle_add_to_tcp_connections_table(message)

            elif msgType == MainThreadQueueMessageType\
                    .ADD_TO_UDP_CONNECTIONS_TABLE:
                self.__handle_add_to_udp_connections_table(message)

            elif msgType == MainThreadQueueMessageType.THREAD_TERMINATING:
                # The terminal thread has finished, join
                self.__terminalThreadTracker.get_thread().join()

            else:
                raise Exception("Unknown message type: {}".format(msgType))
            
            self.__fromChildToParentThreadQueue.task_done()
            self.__threadLock.release()

    # ? PRIVATE METHODS --------------------------------------------------------

    def __handle_greeter_socket(self, message: ThreadQueueMessage):
        """ Creates a bunch of handler threads to accomodate the greeter. 
        """

        newSock = message.get_new_socket()

        if not isinstance(newSock, socket.socket):
            raise Exception("Socket not provided for tcp connection request.")

        destination = message.get_port_number()

        if destination == None:
            raise Exception("Greeter did not provide new port" + \
                    " num for tcp connection request.")

        if __DEBUG_MODE_ENABLED__:
            DebugPrinter.print_generic_header(
                    threadName=self.__mtid,
                    filename=__filename__,
                    classname=self.__classname__,
                    methodname='__handle_greeter_socket')
            print("Initialising tcp handler threads for PORT: {}".format(
                    destination)) 
            sys.stdout.flush()

        self.__init_thread(threadType=ThreadType.TCP_RECEIVER_THREAD,
                newPortNum=destination,
                newSocket=newSock,
                threadName='GLOBAL RECVER-{}'.format(destination))
        
        self.__init_thread(threadType=ThreadType.TCP_SENDER_THREAD,
                newPortNum=destination,
                newSocket=newSock,
                threadName='GLOBAL SENDER-{}'.format(destination))
        
        self.__init_thread(threadType=ThreadType.GLOBAL_WORKER_THREAD,
                newPortNum=destination,
                newSocket=newSock,
                threadName='GLOBAL WORKER-{}'.format(destination))

    def __handle_tcp_forward_msg_to_sender(self, message: ThreadQueueMessage):
        """ Handles the forwarding of the tcp message to the correct TCP sender.
        
        The worker process will have already determine exactly where the packet
            needs to go, hence all we have to do is get the correct sender out
            and `.put()` it in the right queue :D
        """
        portNum = message.get_port_number()

        if portNum == None:
            raise Exception("Message does not include port num")
        
        senderThread = self.__globalChildThreadsDict[portNum]\
                .get_sender_thread_tracker()
        
        if not isinstance(senderThread, ChildThreadTracker):
            raise Exception("Error trying to get sender for port: {}"\
                    .format(portNum))

        senderThread.get_to_thread_queue().put(message) # type: ignore

    def __handle_tcp_forward_msg_to_worker(self, message: ThreadQueueMessage):
        destination = message.get_port_number()

        if not isinstance(destination, int):
            raise Exception("Port number not specified: {}".format(
                    destination))
        
        if __DEBUG_MODE_ENABLED__:
            DebugPrinter.print_generic_header(threadName=self.__mtid,
                    filename=__filename__,
                    classname=self.__classname__,
                    methodname='__handle_tcp_forward_msg_to_worker')
            print("Packet contents:")
            message.get_message_data()\
                    .debug_print_packet_contents() # type: ignore

        # Determine if we need to attach additional information
        rbsph = RUSHBSwitchPacketHelper()
        
        if self.__switchType == RUSHBSwitchType.GLOBAL or \
                self.__switchType == RUSHBSwitchType.HYBRID:
            if self.__hostAddrGlobal == None:
                raise Exception("Switch should have global host ip addr (bug?)")
            switchHostIp = self.__hostAddrGlobal
            availableGlobalIps = self.__availableGlobalIps
        else:
            switchHostIp = ipaddress.IPv4Address('0.0.0.0')
            availableGlobalIps = None

        tackons = rbsph.determine_tack_ons(message=message,
                switchHostIp=switchHostIp,
                availableGlobalIps=availableGlobalIps,
                availableLocalIps=None,
                switchServiceSide=RUSHBSwitchServiceSides.GLOBAL_SIDE,
                threadName=self.__mtid,
                ourLat=self.__lat,
                ourLng=self.__lng,
                tcpConnectionsTable=self.__tcpConnectionsTable,
                udpConnectionsTable=self.__udpConnectionsTable,
                routingTable=self.__routingTable)

        msgData = message.get_message_data()

        # Check if this is a location packet, if so, then tell the terminal that
        #   we have a complete connection
        if isinstance(msgData, RUSHBLocationPacket):
            self.__terminalThreadTracker.get_to_thread_queue().put( # type: ignore
                    ThreadQueueMessage(
                        msgFrom=self.__mtid,
                        msgType=MainThreadQueueMessageType.CONNECTION_COMPLETE
            ))

        newMessage = ThreadQueueMessage(
                msgType=ChildThreadQueueMessageType.PROCESS_TCP_MESSAGE,
                msgData=msgData,
                msgFrom=self.__mtid,
                receivedFromPortNum=message.get_received_from_port_num())

        if tackons.get_ip_addr_exhausted():
            # ip_addr_exhausted flag set to True indicates that we were handed
            #   a DISCOVERY packet, but we were out of ip addresses.
            # ignore this connection request
            return

        # ? START CHECKS     
        checkGlobalIp = tackons.get_assigned_global_ip()
        checkLocalIp = tackons.get_assigned_local_ip()
        if checkGlobalIp != None:
            newMessage.set_assigned_ip(checkGlobalIp)
        elif checkLocalIp != None:
            newMessage.set_assigned_ip(checkLocalIp)

        checkHostAddr = tackons.get_host_ip_addr()
        if checkHostAddr != None:
            newMessage.set_our_source_ip(checkHostAddr)
        
        checkOurLat = tackons.get_our_lat()
        checkOurLng = tackons.get_our_lng()
        if checkOurLat != None and checkOurLng != None:
            newMessage.set_our_lat(checkOurLat)
            newMessage.set_our_lng(checkOurLng)

        checkTcpConnTable = tackons.get_tcp_connections_table()
        checkUdpConnTable = tackons.get_udp_connections_table()
        if checkTcpConnTable != None and checkUdpConnTable != None:
            newMessage.set_tcp_conn_table(self.__tcpConnectionsTable)
            newMessage.set_udp_conn_table(self.__udpConnectionsTable)

        checkRoutingTable = tackons.get_routing_table()
        if checkRoutingTable != None:
            newMessage.set_routing_table(self.__routingTable)
        # ? END CHECKS

        # Send the packet to the appropriate worker
        workerThread = self.__globalChildThreadsDict[destination]\
                .get_worker_thread_tracker()

        if not isinstance(workerThread, ChildThreadTracker):
            raise Exception("TCP Child worker process missing")

        workerThread.get_to_thread_queue().put(newMessage) # type: ignore

    def __handle_udp_forward_msg_to_sender(self, message: ThreadQueueMessage):
        """ Handles the forwarding of the udp message to the correct UDP sender. 
        
        The worker process will have already determined exactly where the packet
            needs to go, hence all we have to do is push to the thing :D
        """
        portNum = message.get_port_number()

        if portNum == None:
            raise Exception("Message does not include port num")

        senderThread = self.__udpSenderThreadTracker

        if not isinstance(senderThread, ChildThreadTracker):
            raise Exception("Error trying to get sender for port: {}"\
                    .format(portNum))

        senderThread.get_to_thread_queue().put(message) # type: ignore

    def __handle_udp_forward_msg_to_worker(self, message: ThreadQueueMessage):
        """ Handles forwarding a udp message to a udp worker :v """
        destination = message.get_port_number()
        msgData = message.get_message_data()

        if not isinstance(destination, int):
            raise Exception("Port number not specified: {}".format(
                    destination))

        if msgData == None:
            raise Exception(
                    "UDP forward msg to worker must contain a valid packet")

        if __DEBUG_MODE_ENABLED__:
            DebugPrinter.print_generic_header(threadName=self.__mtid,
                    filename=__filename__,
                    classname=self.__classname__,
                    methodname='__handle_tcp_forward_msg_to_worker')
            print("Packet contents:")
            msgData.debug_print_packet_contents()
        
        # Determine if we need to attach additional information
        rbsph = RUSHBSwitchPacketHelper()
        
        if self.__hostAddrLocal == None:
            raise Exception("Switch should have local ip addr (bug?)")

        tackons = rbsph.determine_tack_ons(message=message,
                switchHostIp=self.__hostAddrLocal,
                availableGlobalIps=None,
                availableLocalIps=self.__availableLocalIps,
                switchServiceSide=RUSHBSwitchServiceSides.LOCAL_SIDE,
                threadName=self.__mtid,
                ourLat=self.__lat,
                ourLng=self.__lng,
                tcpConnectionsTable=self.__tcpConnectionsTable,
                udpConnectionsTable=self.__udpConnectionsTable,
                routingTable=self.__routingTable)

        newMessage = ThreadQueueMessage(
                msgType=ChildThreadQueueMessageType.PROCESS_UDP_MESSAGE,
                msgData=msgData,
                msgFrom=self.__mtid,
                receivedFromPortNum=message.get_received_from_port_num())

        # Check if this is a discovery packet (i.e. a connection request)
        if msgData.get_mode() == RUSHBPacketModes.DISCOVERY:
            # Generate a new worker process to handle this
            if __DEBUG_MODE_ENABLED__:
                DebugPrinter.print_generic_header(
                        threadName=self.__mtid,
                        filename=__filename__,
                        classname=self.__classname__,
                        methodname='__handle_udp_forward_msg_to_worker')
                print("Generating new worker process on port: {}"\
                        .format(destination)) 
                sys.stdout.flush()
            
            self.__init_thread(threadType=ThreadType.LOCAL_WORKER_THREAD,
                    newPortNum=destination,
                    threadName='LOCAL WORKER-{}'.format(destination))

        if tackons.get_ip_addr_exhausted():
            # ip_addr_exhausted flag set to True indicates that we were handed
            #   a DISCOVERY packet, but we were out of ip addresses.
            # ignore this connection request
            return

        # ? START CHECKS     
        checkGlobalIp = tackons.get_assigned_global_ip()
        checkLocalIp = tackons.get_assigned_local_ip()
        if checkGlobalIp != None:
            newMessage.set_assigned_ip(checkGlobalIp)
        elif checkLocalIp != None:
            newMessage.set_assigned_ip(checkLocalIp)

        checkHostAddr = tackons.get_host_ip_addr()
        if checkHostAddr != None:
            newMessage.set_our_source_ip(checkHostAddr)
        
        checkOurLat = tackons.get_our_lat()
        checkOurLng = tackons.get_our_lng()
        if checkOurLat != None and checkOurLng != None:
            newMessage.set_our_lat(checkOurLat)
            newMessage.set_our_lng(checkOurLng)

        checkTcpConnTable = tackons.get_tcp_connections_table()
        checkUdpConnTable = tackons.get_udp_connections_table()
        if checkTcpConnTable != None and checkUdpConnTable != None:
            newMessage.set_tcp_conn_table(self.__tcpConnectionsTable)
            newMessage.set_udp_conn_table(self.__udpConnectionsTable)

        checkRoutingTable = tackons.get_routing_table()
        if checkRoutingTable != None:
            newMessage.set_routing_table(self.__routingTable)
        # ? END CHECKS

        # Send the packet to the appropriate worker
        workerThread = self.__localChildThreadsDict[destination]

        if not isinstance(workerThread, ChildThreadTracker):
            raise Exception("UDP Child worker process missing")

        workerThread.get_to_thread_queue().put(newMessage) # type: ignore
    
    def __handle_update_routing_table(self, message: ThreadQueueMessage):
        """ Handles the updating of the routing table. """
        
        ipaddr = message.get_their_source_ip()
        portNum = message.get_port_number()
        distance = message.get_distance()

        if __DEBUG_MODE_ENABLED__:
            DebugPrinter.print_generic_header(
                    threadName=self.__mtid,
                    filename=__filename__,
                    classname=self.__classname__,
                    methodname='__handle_update_routing_table')
            print("Updating routing table with the following:")
            print("target ip: {}".format(ipaddr))
            print("Via port: {}".format(portNum))
            print("Distance: {}".format(distance))

        if ipaddr == None or portNum == None or distance == None:
            raise Exception("Update routing table requires correct params")

        result = self.__routingTable.add_entry_2(ipAddr=ipaddr.exploded, 
                viaPort=portNum, distance=distance)

        if result == None:
            raise Exception("Error trying to add result to routing table")

        if __DEBUG_MODE_ENABLED__:
            DebugPrinter.print_generic_header(
                    threadName=self.__mtid,
                    filename=__filename__,
                    classname=self.__classname__,
                    methodname='__handle_update_routing_table')
            print("Routing table contents:")
            self.__routingTable.debug_print_contents()

    def __handle_add_to_tcp_connections_table(self, 
            message: ThreadQueueMessage):
        """ Handles adding a new tcp connection to the tcp connections table. 
        """
        portNum = message.get_port_number()
        ourSourceIp = message.get_our_source_ip()
        theirSourceIp = message.get_their_source_ip()
        assignedIp = message.get_assigned_ip()

        if portNum == None or assignedIp == None:
            raise Exception("Worker did not provide port number " + \
                    "or an assigned ip address")

        if isinstance(ourSourceIp, ipaddress.IPv4Address):
            # Must have received directive from worker who received a REQUEST
            #   packet
            self.__tcpConnectionsTable.add_table_entry(
                    viaPort=portNum, 
                    ourSourceIp=ourSourceIp,
                    theirSourceIp=assignedIp)
        elif isinstance(theirSourceIp, ipaddress.IPv4Address):
            # Must have received directive from worker who received a 
            #   ACKNOWLEDGE packet
            self.__tcpConnectionsTable.add_table_entry(
                    viaPort=portNum, 
                    ourSourceIp=assignedIp,
                    theirSourceIp=theirSourceIp)
        else:
            raise Exception("Worker did not provide ourSourceIp or " + \
                    "theirSourceIp")
        
        if __DEBUG_MODE_ENABLED__:
            DebugPrinter.print_generic_header(
                    threadName=self.__mtid,
                    filename=__filename__,
                    classname=self.__classname__,
                    methodname='__handle_add_to_tcp_connections_table')
            print("Updated tcp connections table")
            self.__tcpConnectionsTable.debug_printout()
            sys.stdout.flush()

    def __handle_add_to_udp_connections_table(self, 
            message: ThreadQueueMessage):
        portNum = message.get_port_number()
        ourSourceIp = message.get_our_source_ip()
        theirSourceIp = message.get_their_source_ip()
        assignedIp = message.get_assigned_ip()

        if portNum == None or assignedIp == None:
            raise Exception("Worker did not provide port number " + \
                    "or an assigned ip address")
        
        if isinstance(ourSourceIp, ipaddress.IPv4Address):
            # Must have received directive from worker who received a REQUEST
            #   packet
            self.__udpConnectionsTable.add_table_entry(
                    viaPort=portNum, 
                    ourSourceIp=ourSourceIp,
                    theirSourceIp=assignedIp)
        elif isinstance(theirSourceIp, ipaddress.IPv4Address):
            # Must have received directive from worker who received a 
            #   ACKNOWLEDGE packet
            self.__udpConnectionsTable.add_table_entry(
                    viaPort=portNum, 
                    ourSourceIp=assignedIp,
                    theirSourceIp=theirSourceIp)
        else:
            raise Exception("Worker did not provide ourSourceIp or " + \
                    "theirSourceIp")

        if __DEBUG_MODE_ENABLED__:
            DebugPrinter.print_generic_header(
                    threadName=self.__mtid,
                    filename=__filename__,
                    classname=self.__classname__,
                    methodname='__handle_add_to_udp_connections_table')
            print("Updated udp connections table")
            self.__udpConnectionsTable.debug_printout()
            sys.stdout.flush()

    def __handle_connect_request(self, message: ThreadQueueMessage):
        """ Handles a request to connect from the terminal. 
        
        ARGS:
        - message: The thread message that contains the connect request info.
        """

        if self.__switchType == RUSHBSwitchType.HYBRID:
            # Connect command shouldn't do anything for a hybrid switch
            return 

        if __DEBUG_MODE_ENABLED__:
            DebugPrinter.print_generic_header(threadName=self.__mtid,
                    filename=__filename__,
                    classname=self.__classname__,
                    methodname='__handle_connect_request')
            print("Received a connection request")
            print("Port number: {}".format(message.get_port_number()))
            sys.stdout.flush()
        
        destination = message.get_port_number()

        # Check that a port number was included
        if not isinstance(destination, int):
            raise Exception("Port number not specified: {}".format(
                    destination))

        # Create a TCP client socket connection
        # (i.e. you can only connect to other switches, hence all switches 
        #   will communicate with you via TCP)
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        counter = 0
        while True:
            try:
                clientSocket.connect(('127.0.0.1', destination))
                break
            except ConnectionRefusedError as e:
                counter += 1
                if counter == 5:
                    raise Exception("Error trying to establish connection")
                else:
                    time.sleep(0.1)

        if __DEBUG_MODE_ENABLED__:
            DebugPrinter.print_generic_header(threadName=self.__mtid,
                    filename=__filename__,
                    classname=self.__classname__,
                    methodname='__handle_connect_request')
            print("Connected to new socket with PORT: {}".format(
                    clientSocket.getsockname()[1]))

        destination = clientSocket.getsockname()[1]

        # Create the required TCP sender, receiver and worker threads to
        #   accomodate the connection.
        self.__init_thread(threadType=ThreadType.TCP_SENDER_THREAD,
                threadName="SENDER-" + str(destination),
                newPortNum=destination,
                newSocket=clientSocket)
        
        self.__init_thread(threadType=ThreadType.TCP_RECEIVER_THREAD,
                threadName="RECVER-" + str(destination),
                newPortNum=destination,
                newSocket=clientSocket)

        self.__init_thread(threadType=ThreadType.GLOBAL_WORKER_THREAD,
                threadName= "WORKER-" + str(destination),
                newPortNum=destination,
                newSocket=clientSocket)

        # Tell the worker process to expect an offer packet soon
        workerProcess = self.__globalChildThreadsDict[destination]\
                .get_worker_thread_tracker()

        if not isinstance(workerProcess, ChildThreadTracker):
            raise Exception("Error trying to initialise worker process")

        workerProcess.get_to_thread_queue().put(    # type: ignore
            ThreadQueueMessage(
                msgFrom=self.__mtid,
                msgType=ChildThreadQueueMessageType.EXPECT_OFFER_PACKET))

        # Generate a discovery packet and push it to the sender process
        discoveryPacket = RUSHBGreetingPacket(inputDict={
            'source_ip_addr': '0.0.0.0',
            'destination_ip_addr': '0.0.0.0',
            'reserved_bytes': b'\x00\x00\x00',
            'mode': RUSHBPacketModes.DISCOVERY.value,
            'assigned_ip_addr': '0.0.0.0'
        })

        if __DEBUG_MODE_ENABLED__:
            DebugPrinter.print_generic_header(
                    threadName=self.__mtid,
                    filename=__filename__,
                    classname=self.__classname__,
                    methodname='__handle_connect_request')
            print("Discovery Packet bytes: {}".format(
                    discoveryPacket.to_bytes()))
            sys.stdout.flush()

        # Send the discovery packet via TCP to the specified port
        senderTracker = self.__globalChildThreadsDict[destination]\
                .get_sender_thread_tracker()

        if not isinstance(senderTracker, ChildThreadTracker):
            raise Exception("Error sender tracker not initialised.")

        senderTracker.get_to_thread_queue().put( # type: ignore
                ThreadQueueMessage(
                        msgData=discoveryPacket,
                        msgFrom=self.__mtid,
                        msgType=ChildThreadQueueMessageType\
                                .PROCESS_TCP_MESSAGE))

    def __generate_available_ip_addresses(self, cidrIpAddress: str):
        """ Generates a list of all the available ip addresses from cidr. 
        
        ARGS:
        - cidrIpAddress: A valid cidr ip address range (e.g. 192.168.0.1/24)

        RETURNS:
        - On success, the method will return a tuple containing (in order),
            the starting ip address, and a list of available ip addresses.
        """
        # Split the cidr address
        splitAddr = cidrIpAddress.split('/')

        startingIp = splitAddr[0]
        cidrPrefix = splitAddr[1]

        # Retrieve the cidr prefix as a subnet mask
        cidrPrefixAsInt = int(cidrPrefix)

        cidrSubnetMask = GeneralHelperMethods.cidr_to_netmask(
                cidrPrefixAsInt)
        
        cidrSubnetMask = ipaddress.IPv4Address(cidrSubnetMask)
        
        startingIp = ipaddress.IPv4Address(startingIp)

        # Convert the subnet mask and starting ip to integers
        cidrSubnetMaskAsInt = GeneralHelperMethods.int_from_bytes(
                cidrSubnetMask.packed)
        startingIpAsInt = GeneralHelperMethods.int_from_bytes(
                startingIp.packed)

        # Bitwise AND the starting ip with the 
        culledHostBits = startingIpAsInt & cidrSubnetMaskAsInt

        # Generate the culled host bits address
        culledHostBitsAddress = ipaddress.IPv4Address(culledHostBits).exploded \
                + '/' + cidrPrefix
        
        # Generate a list of all the available addressess
        ips = ipaddress.ip_network(culledHostBitsAddress)

        if __DEBUG_MODE_ENABLED__:
            DebugPrinter.print_generic_header(threadName=self.__mtid,
                    filename=__filename__,
                    methodname='__generate_available_ip_addresses',
                    classname='RUSHBSwitch')
            print("Total ips generated: {}".format(ips.num_addresses))
            sys.stdout.flush()

        return (startingIp, ips)

    # ? INIT METHODS -----------------------------------------------------------

    def __init_support_elements(self):
        """ Initialises all the supporting elements of the switch. """
        switchInitialised = False

        if self.__switchType == RUSHBSwitchType.LOCAL or \
                self.__switchType == RUSHBSwitchType.HYBRID:
            # Init UDP listening socket
            self.__enable_switch_local_mode()
            
            # Create UDP Sender thread (shared)
            self.__init_thread(threadType=ThreadType.UDP_SENDER_THREAD, 
                    threadName='UDP_SENDER',
                    newPortNum=self.__localSocket.getsockname()[1])

            # Create UDP Receiver thread (shared)
            self.__init_thread(threadType=ThreadType.UDP_RECEIVER_THREAD, 
                    threadName='UDP_RECEIVER',
                    newPortNum=self.__localSocket.getsockname()[1])
            
            switchInitialised = True

        if self.__switchType == RUSHBSwitchType.GLOBAL or \
                 self.__switchType == RUSHBSwitchType.HYBRID:
            # Init TCP listening socket
            self.__enable_switch_global_mode()

            # Create TCP Greeter thread (unique)
            self.__init_thread(threadType=ThreadType.TCP_GREETER_THREAD,
                    threadName='TCP_GREETER',
                    newPortNum=self.__globalSocket.getsockname()[1])
            
            switchInitialised = True
        
        if not switchInitialised:
            raise Exception("Unknown switch type: {}".format(
                    self.__switchType))

        # Initialise terminal thread
        self.__init_thread(threadType=ThreadType.TERMINAL_THREAD,
                threadName='TERMINAL',
                newPortNum=0)

    def __enable_switch_local_mode(self):
        # Create a local socket
        self.__localSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Bind the local socket to localhost (and have the kernel come up with 
        #   a port number).
        self.__localSocket.bind(('', 0))

    def __enable_switch_global_mode(self):
        # Create a global socket
        self.__globalSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Bind the global socket to localhost (and have the kernel come up with
        #   a port number).
        self.__globalSocket.bind(('', 0))

        # Begin listening for incomming connections.
        self.__globalSocket.listen(1)

    def __init_thread(self, threadType: ThreadType, threadName: str, 
            newPortNum: int,
            newSocket: Optional[socket.socket]=None):

        fromParentToChildQueue = threadQueue.Queue()
        
        newChildQueueContainer = ThreadQueueContainer(
            threadName=threadName,
            toParentQueue=self.__fromChildToParentThreadQueue,
            fromParentQueue=fromParentToChildQueue,
            threadLock=self.__threadLock)

        # ? Terminal thread
        if threadType == ThreadType.TERMINAL_THREAD:
            # Set the to terminal queue
            t = threading.Thread(target=terminal_thread_starter, 
                    args=(newChildQueueContainer,))

        # ? TCP Threads
        elif threadType == ThreadType.TCP_GREETER_THREAD:
            print(self.__globalSocket.getsockname()[1])
            sys.stdout.flush()
            # Set the global listening socket
            newChildQueueContainer.set_socket(self.__globalSocket)

            t = threading.Thread(target=tcp_greeter_thread_starter, 
                    args=(newChildQueueContainer,))
            
        elif threadType == ThreadType.TCP_RECEIVER_THREAD:
            # Check if we included a new socket
            if newSocket == None:
                raise Exception("Did not provide socket for tcp recver")
            newChildQueueContainer.set_socket(newSocket=newSocket)
            newChildQueueContainer.set_port_num(newPortNum)

            t = threading.Thread(target=tcp_receiver_thread_starter, 
                    args=(newChildQueueContainer,))
            
        elif threadType == ThreadType.TCP_SENDER_THREAD:
            # Check if we included a new socket
            if newSocket == None:
                raise Exception("Did not provide socket for tcp sender")

            newChildQueueContainer.set_socket(newSocket=newSocket)
            newChildQueueContainer.set_port_num(newPortNum)
            
            t = threading.Thread(target=tcp_sender_thread_starter, 
                    args=(newChildQueueContainer,))

        # ? Worker Threads
        elif threadType == ThreadType.GLOBAL_WORKER_THREAD:
            # Check if we included a new socket
            if newSocket == None:
                raise Exception("Did not provide socket for global worker")
            newChildQueueContainer.set_socket(newSocket)
            newChildQueueContainer.set_parent_switch_type(self.__switchType)
            newChildQueueContainer.set_switch_service_side(
                    RUSHBSwitchServiceSides.GLOBAL_SIDE)
            newChildQueueContainer.set_port_num(newPortNum)
            newChildQueueContainer.set_parent_source_ip(self.__hostAddrGlobal)
            
            t = threading.Thread(target=global_worker_thread_starter, 
                    args=(newChildQueueContainer,))

        elif threadType == ThreadType.LOCAL_WORKER_THREAD:
            # Check if we included a new port number
            newChildQueueContainer.set_port_num(newPortNum=newPortNum)
            newChildQueueContainer.set_parent_switch_type(self.__switchType)
            newChildQueueContainer.set_switch_service_side(
                    RUSHBSwitchServiceSides.LOCAL_SIDE)
            newChildQueueContainer.set_parent_source_ip(self.__hostAddrLocal)

            t = threading.Thread(target=local_worker_thread_starter, 
                    args=(newChildQueueContainer,))

        # ? UDP Threads
        elif threadType == ThreadType.UDP_RECEIVER_THREAD:
            # Print out the local socket port number so we can connect
            print(str(self.__localSocket.getsockname()[1]), flush=True)

            newChildQueueContainer.set_socket(self.__localSocket)

            t = threading.Thread(target=udp_receiver_thread_starter, 
                    args=(newChildQueueContainer,))
            pass
        elif threadType == ThreadType.UDP_SENDER_THREAD:
            newChildQueueContainer.set_socket(self.__localSocket)

            t = threading.Thread(target=udp_sender_thread_starter, 
                    args=(newChildQueueContainer,))
        else:
            raise Exception("Unknown thread type: {}".format(threadType))

        # Start the thread
        t.start()

        # Save the thread to a tracker object
        temp = ChildThreadTracker(
                threadType=threadType,
                thread=t,
                toThreadQueue=fromParentToChildQueue,
                portNumber=newPortNum)

        # if not t.is_alive():
        #     raise Exception("Error starting thread: {}".format(threadType))
        
        # ? Global comms threads + Worker
        if threadType == ThreadType.GLOBAL_WORKER_THREAD or \
                threadType == ThreadType.TCP_RECEIVER_THREAD or \
                threadType == ThreadType.TCP_SENDER_THREAD:
            if newPortNum not in self.__globalChildThreadsDict:
                # Create a new port thread container and save stuff to it
                newPortThreadContainer = PortThreadContainer()
                if threadType == ThreadType.GLOBAL_WORKER_THREAD:
                    newPortThreadContainer.set_worker_thread_tracker(temp)

                elif threadType == ThreadType.TCP_RECEIVER_THREAD:
                    newPortThreadContainer.set_recvr_thread_tracker(temp)

                else:   # TCP Sender thread
                    newPortThreadContainer.set_sender_thread_tracker(temp)
                self.__globalChildThreadsDict[newPortNum] = \
                        newPortThreadContainer
            else:
                # We need to add whatever process to the appropriate place
                if threadType == ThreadType.GLOBAL_WORKER_THREAD:
                    assert self.__globalChildThreadsDict[newPortNum]\
                            .get_worker_thread_tracker() == None, \
                            "Global worker trying to overwrite existing tracker"

                    self.__globalChildThreadsDict[newPortNum]\
                            .set_worker_thread_tracker(temp)

                elif threadType == ThreadType.TCP_RECEIVER_THREAD:
                    assert self.__globalChildThreadsDict[newPortNum]\
                            .get_recvr_thread_tracker() == None, \
                            "TCP recver trying to overwrite existing tracker"

                    self.__globalChildThreadsDict[newPortNum]\
                            .set_recvr_thread_tracker(temp)

                else:   # TCP Sender thread
                    assert self.__globalChildThreadsDict[newPortNum]\
                            .get_sender_thread_tracker() == None, \
                            "TCP sender trying to overwrite existing tracker"

                    self.__globalChildThreadsDict[newPortNum]\
                            .set_sender_thread_tracker(temp)
        
        # ? Greeter thread
        elif threadType == ThreadType.TCP_GREETER_THREAD:
            self.__tcpGreeterThreadTracker = temp

        # ? Local worker thread
        elif threadType == ThreadType.LOCAL_WORKER_THREAD:
            if newPortNum not in self.__localChildThreadsDict:
                self.__localChildThreadsDict[newPortNum] = temp
            else:
                raise Exception(
                        "Local worker tracker overwriting existing tracker")

        # ? Local comms threads
        elif threadType == ThreadType.UDP_SENDER_THREAD:
            self.__udpSenderThreadTracker = temp
            
        elif threadType == ThreadType.UDP_RECEIVER_THREAD:
            self.__udpReceiverThreadTracker = temp

        elif threadType == ThreadType.TERMINAL_THREAD:
            self.__terminalThreadTracker = temp

        else:
            raise Exception("Unknown worker thread type: {}".format(threadType))

    def __init_command_line_args(self, cmdLineArgs: List[str]):
        """ Handles the initialisation of the command line arguements. """
        if __DEBUG_MODE_ENABLED__:
            DebugPrinter.print_generic_header(threadName=self.__mtid,
                        filename=__filename__,
                        classname=self.__classname__,
                        methodname='main_loop')
            print('Command line args')
            for arg in cmdLineArgs:
                print(arg)
            sys.stdout.flush()

        # Preconditions
        if len(cmdLineArgs) == 4:
            if __DEBUG_MODE_ENABLED__:
                DebugPrinter.print_generic_header(threadName=self.__mtid,
                        filename=__filename__,
                        classname=self.__classname__,
                        methodname='main_loop')
                print("Received 4 command line args")
                sys.stdout.flush()

            # Remember cmdLineArgs[0] == 'RUSHBSwitch.py'
            self.__type_precondition(cmdLineArgs[0])
            self.__ip_network_precondition(cmdLineArgs[1])
            self.__lat_lng_precondition(latitude=cmdLineArgs[2], 
                    longitude=cmdLineArgs[3])
            
        elif len(cmdLineArgs) == 5:
            if __DEBUG_MODE_ENABLED__:
                DebugPrinter.print_generic_header(threadName=self.__mtid,
                        filename=__filename__,
                        classname=self.__classname__,
                        methodname='main_loop')
                print("Received 5 command line args")
                sys.stdout.flush()
            
            self.__type_precondition(cmdLineArgs[0])
            
            # Check the switch mode is not global
            assert cmdLineArgs[0] != 'global', \
                    "Global mode cannot have two ip addresses"
            
            self.__ip_network_precondition(cmdLineArgs[1])
            self.__ip_network_precondition(cmdLineArgs[2])
            self.__lat_lng_precondition(latitude=cmdLineArgs[3], 
                    longitude=cmdLineArgs[4])
        

        # Assignment
        if cmdLineArgs[0] == 'local' and len(cmdLineArgs) == 4:
            # Only contains a local connector (UDP only)
            self.__switchType = RUSHBSwitchType.LOCAL
        elif cmdLineArgs[0] == 'local' and len(cmdLineArgs) == 5:
            # Contains BOTH a local and global connector (UDP & TCP)
            self.__switchType = RUSHBSwitchType.HYBRID
        else:
            # Only contains a global connector (TCP only)
            self.__switchType = RUSHBSwitchType.GLOBAL 
        
        # Generate a list of all available ip addresses
        temp = self.__generate_available_ip_addresses(
                cmdLineArgs[1])

        # Local mode with two ip ranges
        if len(cmdLineArgs) == 5:
            
            self.__hostAddrLocal = temp[0]
            self.__availableLocalIps: Generator = temp[1].hosts()

            temp2 = self.__generate_available_ip_addresses(
                    cmdLineArgs[2])

            self.__hostAddrGlobal = temp2[0]
            self.__availableGlobalIps: Generator = temp2[1].hosts()

            self.__lat = int(cmdLineArgs[3])
            self.__lng = int(cmdLineArgs[4])

        # Could be either local or global mode
        else:
            # Check for `local` or `global` mode
            if self.__switchType == RUSHBSwitchType.LOCAL:
                self.__hostAddrLocal = temp[0]
                self.__availableLocalIps = temp[1].hosts()
            else:
                self.__hostAddrGlobal = temp[0]
                self.__availableGlobalIps = temp[1].hosts()

            self.__lat = int(cmdLineArgs[2])
            self.__lng = int(cmdLineArgs[3])

        if __DEBUG_MODE_ENABLED__:
            DebugPrinter.print_generic_header(threadName=self.__mtid,
                        filename=__filename__,
                        classname=self.__classname__,
                        methodname='main_loop')
            print('Precondition checks passed')
            sys.stdout.flush()

    # ? PRECONDITIONS ----------------------------------------------------------

    @staticmethod
    def __type_precondition(switchType: str):
        assert switchType == 'local' or switchType == 'global', \
                "must be a valid switch type"

    @staticmethod
    def __ip_addr_precondition(ipAddrCidr: str):
        try:
            ipAddr = ipaddress.IPv4Address(ipAddrCidr)
        except Exception as e:
            raise Exception("Must be a valid ipv4 address")
    
    @staticmethod
    def __ip_network_precondition(ipAddrCidr: str):
        # Split the cidr address
        splitAddr = ipAddrCidr.split('/')
        assert len(splitAddr) == 2, "Must be valid CIDR ip address range"

        startingIp = splitAddr[0]
        cidrPrefix = splitAddr[1]

        assert cidrPrefix.isdigit(), "CIDR prefix must be a valid digit"
        
        try:
            cidrPrefixAsInt = int(cidrPrefix)
        except Exception as e:
            raise Exception("CIDR prefix must be a valid integer")
            
        assert cidrPrefixAsInt >= 0 and cidrPrefixAsInt <= 32, \
                "CIDR prefix must be between 0 and 32"
        
        try:
            startingIp = ipaddress.IPv4Address(startingIp)
        except Exception as e:
            raise Exception("Ip address must be valid")

    @staticmethod
    def __lat_lng_precondition(latitude: str, longitude: str):
        # Check that both latitude and longitude are digits
        assert latitude.isdigit() and longitude.isdigit(), \
                "Latitude and longitude must be valid digits"
        
        try:
            lat = int(latitude)
            lng = int(longitude)
        except ValueError:
            raise Exception(\
                    "Latitude and longitude must both be valid integers")

        assert lat >= 0 and lng >= 0 and lat <= 1000 and lng <= 1000, \
                "Latitude and longitude must both be valid positive integers"

if __name__ == '__main__':
    switch = RUSHBSwitch(cmdLineArgs=sys.argv)

    switch.main_loop()