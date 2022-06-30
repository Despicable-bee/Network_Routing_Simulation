# Standard libs
import queue as threadQueue

from typing import Optional
from typing import List
from typing import Dict

import time

import ipaddress

import math

# Local libs
from RUSHBMultithreading import ThreadQueueContainer
from RUSHBMultithreading import ThreadQueueMessage

from RUSHBHelper import ChildThreadQueueMessageType, GeneralHelperMethods, LocationPacketState
from RUSHBHelper import DebugPrinter
from RUSHBHelper import MainThreadQueueMessageType
from RUSHBHelper import RUSHBSwitchServiceSides
from RUSHBHelper import RUSHBSwitchType
from RUSHBHelper import RUSHBPacketModes
from RUSHBHelper import GreetingProtocolStates
from RUSHBHelper import ReadyToReceiveStates
from RUSHBHelper import __DEBUG_MODE_ENABLED__

from RUSHBPackets import RUSHBBroadcastPacket, RUSHBMaxPacketSize
from RUSHBPackets import RUSHBDataPacket
from RUSHBPackets import RUSHBGreetingPacket
from RUSHBPackets import RUSHBLocationPacket
from RUSHBPackets import RUSHBQueryPacket
from RUSHBPackets import RUSHBReadyPacket
from RUSHBRoutingTable import RUSHBConnectionsTable, RUSHBConnectionsTableEntry, RUSHBRoutingTable, RUSHBRoutingTableEntry

# * DEBUG ----------------------------------------------------------------------

__filename__ = 'RUSHBWorkerThread.py'

# * WORKER THREAD --------------------------------------------------------------

class Worker_Thread(object):
    def __init__(self, queueContainer: ThreadQueueContainer):
        self.__classname__ = 'Worker_Thread'

        # Queues for communication
        self.__fromParentQueue = queueContainer.get_from_parent_queue()
        self.__toParentQueue = queueContainer.get_to_parent_queue()

        self.__queue_precondition(self.__fromParentQueue)
        self.__queue_precondition(self.__toParentQueue)

        # Thread name (identification)
        self.__threadName = queueContainer.get_thread_name()

        # Parent switch type (context)
        self.__parentSwitchType = queueContainer.get_parent_switch_type()
        
        # Switch service side (does this worker service global or local?)
        #   (context)
        self.__switchServiceSide = queueContainer\
                .get_switch_service_side()

        self.__portNum = queueContainer.get_port_num()

        # Other variables
        self.__parentSourceIpAddr = queueContainer.get_parent_source_ip()

        # Buffer of packets to be sent out upon receiving a READY_TO_RECEIVE 
        #   signal
        self.__packetSenderBuffer: List[ThreadQueueMessage] = []
        self.__packetReceiverBuffer: List[RUSHBDataPacket] = []
        # TODO - Fix for multiple incoming packets?

        # Time of last check (ready to receive)
        self.__oldtime: float = 0.0

        self.__greetingPreviousState: GreetingProtocolStates = \
                GreetingProtocolStates.DEFAULT

        self.__r2rPreviousState: ReadyToReceiveStates = \
                ReadyToReceiveStates.DEFAULT

        self.__locationPacketState: LocationPacketState = \
                LocationPacketState.DEFAULT

        self.__threadLock = queueContainer.get_thread_lock()

    def main_loop(self):
        while True:
            
            # Wait on the queue for a message
            message: ThreadQueueMessage = \
                    self.__fromParentQueue.get(block=True) # type: ignore
            
            self.__threadLock.acquire()

            msgType = message.get_message_type()
            msgData = message.get_message_data()

            if __DEBUG_MODE_ENABLED__:
                DebugPrinter.print_generic_header(
                        threadName=self.__threadName,
                        filename=__filename__,
                        classname=self.__classname__,
                        methodname='main_loop')
                print("Received message:")
                print("Message type: {}".format(msgType))
                print("Message data: {}".format(msgData))
            
            if not isinstance(msgType, ChildThreadQueueMessageType):
                if __DEBUG_MODE_ENABLED__:
                    DebugPrinter.print_generic_header(
                            threadName=self.__threadName,
                            filename=__filename__,
                            classname=self.__classname__,
                            methodname='main_loop')
                    print("Incorrect message type received")
                # Skip any message that is not intended for the child
                self.__fromParentQueue.task_done()  # type: ignore
                self.__threadLock.release()
                continue

            if msgType == ChildThreadQueueMessageType.EXPECT_OFFER_PACKET:
                self.__greetingPreviousState = GreetingProtocolStates\
                        .SENT_DISCOVERY_EXPECTING_OFFER
                if __DEBUG_MODE_ENABLED__:
                    DebugPrinter.print_generic_header(
                            threadName=self.__threadName,
                            filename=__filename__,
                            classname=self.__classname__,
                            methodname='main_loop')
                    print("Setting worker to EXPECT_OFFER_PACKET")
                    self.__fromParentQueue.task_done()  # type: ignore
                    self.__threadLock.release()
                    continue
            
            # Take a look at the message data and determine what we need to do
            if msgData == None:
                if __DEBUG_MODE_ENABLED__:
                    DebugPrinter.print_generic_header(
                            threadName=self.__threadName,
                            filename=__filename__,
                            classname=self.__classname__,
                            methodname='main_loop')
                    print("Received no msgData, continuing")
                # Invalid packet, ignore
                self.__fromParentQueue.task_done()  # type: ignore
                self.__threadLock.release()
                continue

            if isinstance(msgData, RUSHBGreetingPacket):
                self.__greeting_protocol_routine(message=message)

            elif isinstance(msgData, RUSHBDataPacket):
                self.__data_packet_routine(message=message)
                pass

            elif isinstance(msgData ,RUSHBQueryPacket):
                self.__query_packet_routine(message=message)
                pass

            elif isinstance(msgData, RUSHBReadyPacket):
                self.__ready_to_receive_packet_routine(message=message)
                pass

            elif isinstance(msgData, RUSHBLocationPacket):
                self.__location_packet_routine(message=message)

            elif isinstance(msgData, RUSHBBroadcastPacket):
                self.__broadcast_packet_routine(message=message)
                pass

            else:
                raise Exception("Unknown packet type: {}".format(
                        type(msgData)))

            self.__fromParentQueue.task_done()  # type: ignore
            self.__threadLock.release()
    # ? PRIVATE METHODS --------------------------------------------------------
    
    def __data_packet_routine(self, message: ThreadQueueMessage):
        """ Handler for the various Data packet routines (0x05, 0x0a, 0x0b) """
        
        msgData = message.get_message_data()

        if not isinstance(msgData, RUSHBDataPacket):
            raise Exception("Data worker expects a data packet")

        # Get the destination ip address of the packet
        destIp = msgData.get_destination_ip_addr()
        sourceIp = msgData.get_source_ip_addr()

        # Get our source address in relation to this port number
        tcpConnTable = message.get_tcp_conn_table()
        udpConnTable = message.get_udp_conn_table()

        if not isinstance(tcpConnTable, RUSHBConnectionsTable):
            raise Exception("Data worker expects a tcp connection table")

        if not isinstance(udpConnTable, RUSHBConnectionsTable):
            raise Exception("Data worker expects a udp connection table")

        if self.__portNum == None:
            raise Exception("Data worker expects the port number to be " + \
                    "specified")

        if self.__switchServiceSide == RUSHBSwitchServiceSides.GLOBAL_SIDE:
            ourConn = tcpConnTable.get_connections_table()[self.__portNum]
        else:
            ourConn = udpConnTable.get_connections_table()[self.__portNum]

        routingTable = message.get_routing_table()

        if not isinstance(routingTable, RUSHBRoutingTable):
            raise Exception("Data worker expects a routing table")

        receivedFromPort = message.get_received_from_port_num()

        if receivedFromPort == None:
            raise Exception("Received from port num should be a valid int")

        # Determine if we have to fragment the packet
        if len(msgData.to_bytes()) > RUSHBMaxPacketSize:
            if __DEBUG_MODE_ENABLED__:
                DebugPrinter.print_generic_header(
                        threadName=self.__threadName,
                        filename=__filename__,
                        classname=self.__classname__,
                        methodname='__data_packet_routine')
                print("Fragmenting packet")
            # Fragment the packet
            msgDataBytes = msgData.get_data()
            offset = 0
            packetsList: List[RUSHBDataPacket] = []
            while len(msgDataBytes) > RUSHBMaxPacketSize - 12:
                dataExtract = msgDataBytes[:RUSHBMaxPacketSize - 12]
                # Create new data fragment packet
                newFragA = RUSHBDataPacket(inputDict={
                    'source_ip_addr': msgData.get_source_ip_addr(),
                    'destination_ip_addr': msgData.get_destination_ip_addr(),
                    'mode': RUSHBPacketModes.FRAGMENT_A.value,
                    'reserved_bytes': GeneralHelperMethods\
                            .int_to_bytes(offset).rjust(3, b'\x00'),
                    'data': dataExtract
                })
                packetsList.append(newFragA)
                
                # Update the offset
                offset += (RUSHBMaxPacketSize - 12)

                # Update the msgDataBytes
                msgDataBytes = msgDataBytes[RUSHBMaxPacketSize - 12:]
            
            # Add in the last packet
            newFragB = RUSHBDataPacket(inputDict={
                'source_ip_addr': msgData.get_source_ip_addr(),
                'destination_ip_addr': msgData.get_destination_ip_addr(),
                'mode': RUSHBPacketModes.FRAGMENT_B.value,
                'reserved_bytes': GeneralHelperMethods\
                        .int_to_bytes(offset).rjust(3, b'\x00'),
                'data': msgDataBytes
            })

            packetsList.append(newFragB)

            if __DEBUG_MODE_ENABLED__:
                DebugPrinter.print_generic_header(
                        threadName=self.__threadName,
                        filename=__filename__,
                        classname=self.__classname__,
                        methodname='__data_packet_routine')
                print("Total Fragment packets: {}".format(len(packetsList)))

        else:
            if __DEBUG_MODE_ENABLED__:
                DebugPrinter.print_generic_header(
                        threadName=self.__threadName,
                        filename=__filename__,
                        classname=self.__classname__,
                        methodname='__data_packet_routine')
                print("Packet does NOT need to be fragmented")
            # Don't fragment the packet
            packetsList = [msgData]
        
        for packet in packetsList:
            # Check if the packet is for this switch
            if self.__routing_worker_check_packet_is_for_me(
                    sourceIp=sourceIp,
                    destinationIp=destIp, 
                    ourConnTableEntry=ourConn,
                    msgData=packet):
                # print("Packet was for me :D")
                pass
            # Check if the packet is for one of our local connections
            elif (self.__parentSwitchType == RUSHBSwitchType.LOCAL or \
                    self.__parentSwitchType == RUSHBSwitchType.HYBRID) and \
                    self.__routing_worker_check_packet_is_for_local_connection(
                            destinationIp=destIp,
                            msgData=packet,
                            udpConnTable=udpConnTable,
                            receivedFromPortNumber=receivedFromPort):
                # print("Packet is for local connection")
                pass
            # Failed last two checks, must be destined for another switch
            elif self.__routing_worker_check_packet_is_for_other_switch(
                    destinationIp=destIp,
                    msgData=packet,
                    ourConn=ourConn,
                    routingTable=routingTable,
                    tcpConnTable=tcpConnTable,
                    udpConnTable=udpConnTable,
                    receivedFromPort=receivedFromPort):
                # print("Packet is for another switch")
                pass
            elif self.__routing_worker_best_effort_forward(
                    destinationIp=destIp,
                    msgData=packet,
                    tcpConnTable=tcpConnTable,
                    receivedFromPort=receivedFromPort):
                # print("Routing best effort")
                pass
            else:
                raise Exception("Routing worker unhandled case")

    def __query_packet_routine(self, message: ThreadQueueMessage):
        """ Handler for the Query packet routine (0x06) """
        data = message.get_message_data()

        if data == None:
            raise Exception("Invalid queue message")

        # We received a query packet, send back a ready to receive packet
        readyToReceivePacket = RUSHBReadyPacket(inputDict={
            'source_ip_addr': data.get_destination_ip_addr(),
            'destination_ip_addr': data.get_source_ip_addr(),
            'mode': RUSHBPacketModes.READY_TO_RECEIVE.value,
            'reserved_bytes': b'\x00\x00\x00'
        })

        if self.__switchServiceSide == RUSHBSwitchServiceSides.GLOBAL_SIDE:
            msgType = MainThreadQueueMessageType.TCP_FORWARD_MSG_TO_SENDER
        else:
            msgType = MainThreadQueueMessageType.UDP_FORWARD_MSG_TO_SENDER

        newMessage = ThreadQueueMessage(msgType=msgType,
                msgData=readyToReceivePacket,
                msgFrom=self.__threadName,
                portNum=self.__portNum)
        
        self.__toParentQueue.put( # type: ignore
                newMessage)

    def __ready_to_receive_packet_routine(self, message: ThreadQueueMessage):
        """ Handler for the Ready to Receive packet routine (0x07) """
        # Update the old time
        self.__oldtime = time.time()

        if self.__portNum == None:
            raise Exception("Port num shouldn't be none for r2r")

        # Send off the packet buffer
        for message in self.__packetSenderBuffer:
            self.__toParentQueue.put(   # type: ignore
                    message)
        
        # Clear the sender buffer
        self.__packetSenderBuffer = []

    def __broadcast_packet_routine(self, message: ThreadQueueMessage):
        """Handler from the broadcast packet routine (0x09). """
        data = message.get_message_data()

        if not isinstance(data, RUSHBBroadcastPacket):
            raise Exception("Invalid queue message, expecting broadcast packet")

        if __DEBUG_MODE_ENABLED__:
            DebugPrinter.print_generic_header(
                            threadName=self.__threadName,
                            filename=__filename__,
                            classname=self.__classname__,
                            methodname='__broadcast_packet_routine')
            print("Data mode: {}".format(data.get_mode()))
            print("Data type: {}".format(type(data)))
        
        # distance
        distance = data.get_distance()

        tcpConnTable = message.get_tcp_conn_table()

        if tcpConnTable == None:
            raise Exception("Broadcast worker requires tcp " + \
                    "connections table")

        # Distance of connection we got broadcast packet from.
        routingTable = message.get_routing_table()

        if routingTable == None:
            raise Exception("Broadcast worker requires routing table")

        if self.__portNum == None:
            raise Exception("Broadcast worker requires a valid port number")

        targetIp = data.get_target_ip()

        if targetIp == None:
            raise Exception("Packet should contain target ip")

        # ? BROADCAST RACE BREAKER CONDITION
        if self.__broadcast_breaker_condition_check(data, 
                routingTable, 
                tcpConnTable):
            # Break condition
            return

        # Check race breaker condition
        # if routingTable.check_entry_exists(targetIp.exploded):
        #     entry = routingTable.get_entry(targetIp.exploded) 
        #     if entry[0].get_distance() < distance: # type: ignore
        #         # Don't broadcast a packet with a distance that is larger
        #         #   than the distance currently in the routing table
        #         return
        
        # conns = tcpConnTable.get_connections_table()

        # # Why would we want to loop back to ourselves?
        # for conn in conns:
        #     currentConn = conns[conn]
        #     if currentConn.get_our_source_ip() == targetIp:
        #         return

        # Tell main to attempt to add this to the routing table.
        newMessage = ThreadQueueMessage(
                msgType=MainThreadQueueMessageType.UPDATE_ROUTING_TABLE,
                msgFrom=self.__threadName,
                theirSourceIp=ipaddress.IPv4Address(
                        data.get_target_ip()),
                portNum=self.__portNum,
                distance=distance)

        self.__toParentQueue.put(   # type: ignore
                newMessage)

        # Broadcast to all your neighbour except the one you got it from
        conns = tcpConnTable.get_connections_table()
        for conn in conns:
            if conn == self.__portNum:
                # Don't broadcast back to where we received this message from
                continue 

            currentConn = conns[conn]

            sourceIp = currentConn.get_our_source_ip().exploded
            destIp = currentConn.get_their_source_ip().exploded

            # Determine the link distance of the broadcast destination
            routingEntry = routingTable.get_entry(destIp)

            if routingEntry == None:
                raise Exception("Location routing entry should be valid")

            # It's the same distance anyways
            linkDistance = routingEntry[0].get_distance()

            # Create new broadcast packet
            broadcastPacket = RUSHBBroadcastPacket(inputDict={
                'source_ip_addr': sourceIp,
                'destination_ip_addr': destIp,
                'mode': RUSHBPacketModes.BROADCAST.value,
                'reserved_bytes': b'\x00\x00\x00',
                'target_ip_addr': data.get_target_ip().exploded,
                'distance': linkDistance + distance})

            # Send the broadcast packet off
            newMessage = ThreadQueueMessage(
                msgType=MainThreadQueueMessageType.TCP_FORWARD_MSG_TO_SENDER,
                msgFrom=self.__threadName,
                msgData=broadcastPacket,
                portNum=conn)

            self.__toParentQueue.put( # type: ignore
                    newMessage)

    def __location_packet_routine(self, message: ThreadQueueMessage):
        """ Handler for the location packet routine (0x08). """
        data = message.get_message_data()

        if not isinstance(data, RUSHBLocationPacket):
            raise Exception("Invalid queue message, expecting location packet")

        if __DEBUG_MODE_ENABLED__:
            DebugPrinter.print_generic_header(
                            threadName=self.__threadName,
                            filename=__filename__,
                            classname=self.__classname__,
                            methodname='__location_packet_routine')
            print("Data mode: {}".format(data.get_mode()))
            print("Data type: {}".format(type(data)))
        
        ourLat = message.get_our_lat()
        ourLng = message.get_our_lng()

        if ourLat == None or ourLng == None:
            raise Exception("Location packet routine requires lat and lng info")

        # Determine if we need to send a location packet back or not
        if self.__locationPacketState == LocationPacketState.DEFAULT:
            # We need to send a location packet back.
            locationPacket = RUSHBLocationPacket(inputDict={
                'source_ip_addr': data.get_destination_ip_addr(),
                'destination_ip_addr': data.get_source_ip_addr(),
                'mode': RUSHBPacketModes.LOCATION.value,
                'reserved_bytes': b'\x00\x00\x00',
                'lat': ourLat,
                'lng': ourLng
            })

            self.__toParentQueue.put(   # type: ignore
                    ThreadQueueMessage(
                            msgType=MainThreadQueueMessageType\
                                    .TCP_FORWARD_MSG_TO_SENDER,
                            portNum=self.__portNum,
                            msgData=locationPacket,
                            msgFrom=self.__threadName))
        else:
            # We DON'T need to send a location packet back.
            self.__locationPacketState = LocationPacketState.DEFAULT
        
        # Determine the distance of the switch to us
        theirLat = data.get_lat()
        theirLng = data.get_lng()

        distance = round(
                math.sqrt((ourLat - theirLat)**2 + (ourLng - theirLng)**2))

        # Tell main to attempt to add this to the routing table.
        newMessage = ThreadQueueMessage(
                msgType=MainThreadQueueMessageType.UPDATE_ROUTING_TABLE,
                msgFrom=self.__threadName,
                theirSourceIp=ipaddress.IPv4Address(
                        data.get_source_ip_addr()),
                portNum=self.__portNum,
                distance=distance)

        self.__toParentQueue.put(   # type: ignore
                newMessage)

        # Determine who we need to broadcast this message to (TCP side).
        tcpConnTable = message.get_tcp_conn_table()

        if tcpConnTable == None:
            raise Exception("Worker location packet routine" + \
                    " requires tcp connections table")

        conns = tcpConnTable.get_connections_table()

        routingTable = message.get_routing_table()

        if routingTable == None:
            raise Exception("Location worker requires routing table")

        for conn in conns:
            if conn == self.__portNum:
                # We don't broadcast our distance to the place we got the 
                #   location packet from.
                continue
            
            sourceIp = conns[conn].get_our_source_ip().exploded
            destIp = conns[conn].get_their_source_ip().exploded

            # Determine the link distance of the broadcast destination
            routingEntry = routingTable.get_entry(destIp)

            if routingEntry == None:
                raise Exception("Location routing entry should be valid")

            # It's the same distance anyways
            linkDistance = routingEntry[0].get_distance()

            # Create a broadcast packet
            broadcastPacket = RUSHBBroadcastPacket(inputDict={
                'source_ip_addr': sourceIp,
                'destination_ip_addr': destIp,
                'mode': RUSHBPacketModes.BROADCAST.value,
                'reserved_bytes': b'\x00\x00\x00',
                'target_ip_addr': data.get_source_ip_addr(),
                'distance': distance + linkDistance
            })

            if __DEBUG_MODE_ENABLED__:
                DebugPrinter.print_generic_header(
                        threadName=self.__threadName,
                        filename=__filename__,
                        classname=self.__classname__,
                        methodname='__location_packet_routine')
                print("Sending off broadcast message")
                broadcastPacket.debug_print_packet_contents()
                print("\nPacket as bytes:")
                print(broadcastPacket.to_bytes())
            
            # Send it to the appropriate port
            newMessage = ThreadQueueMessage(
                    msgType=MainThreadQueueMessageType\
                            .TCP_FORWARD_MSG_TO_SENDER,
                    msgFrom=self.__threadName,
                    portNum=conn,
                    msgData=broadcastPacket)

            self.__toParentQueue.put(   # type: ignore
                    newMessage)

        # Check hybrid switch condition
        if self.__parentSwitchType == RUSHBSwitchType.HYBRID:
            # Broadcast the distance of the entire UDP side
            udpConnTable = message.get_udp_conn_table()

            if udpConnTable == None:
                raise Exception("(hybrid) Worker location packet routine" + \
                        " requires udp connections table")

            if __DEBUG_MODE_ENABLED__:
                DebugPrinter.print_generic_header(
                        threadName=self.__threadName,
                        filename=__filename__,
                        classname=self.__classname__,
                        methodname='__location_packet_routine')
                print("Hyrbid switch, broadcasting UDP side to TCP side")
                udpConnTable.debug_printout()

            udpConns = udpConnTable.get_connections_table()
            
            for conn in udpConns:
                targetIp = udpConns[conn].get_our_source_ip().exploded
                
                # Create a broadcast packet
                broadcastPacket = RUSHBBroadcastPacket(inputDict={
                    'source_ip_addr': data.get_destination_ip_addr(),
                    'destination_ip_addr': data.get_source_ip_addr(),
                    'mode': RUSHBPacketModes.BROADCAST.value,
                    'reserved_bytes': b'\x00\x00\x00',
                    'target_ip_addr': targetIp,
                    'distance': distance
                })

                # Send it to where we got it from
                newMessage = ThreadQueueMessage(
                        msgType=MainThreadQueueMessageType\
                                .TCP_FORWARD_MSG_TO_SENDER,
                        msgFrom=self.__threadName,
                        portNum=self.__portNum,
                        msgData=broadcastPacket)

                self.__toParentQueue.put(   # type: ignore
                        newMessage)


    def __greeting_protocol_routine(self, 
            message: ThreadQueueMessage):
        """ Handler for the various greeting routine steps. (0x01 - 0x04). 
        
        ARGS:
        - message: Queue message from the parent, contains context info as
                well as the packet.
        """

        data = message.get_message_data()

        if data == None:
            raise Exception("Invalid queue message")

        if __DEBUG_MODE_ENABLED__:
            DebugPrinter.print_generic_header(
                            threadName=self.__threadName,
                            filename=__filename__,
                            classname=self.__classname__,
                            methodname='__greeting_protocol_routine')
            print("Worker greeter routine, current state:")
            print("Data mode: {}".format(data.get_mode()))
            print("Previous state: {}".format(self.__greetingPreviousState))
            print("Data type: {}".format(type(data)))

        if message.get_message_type() == ChildThreadQueueMessageType\
                    .PROCESS_UDP_MESSAGE:
            # We were asked to process a UDP message, hence tell main to send
            #   the packet we generate to the UDP sender
            returnMessageType = MainThreadQueueMessageType\
                    .UDP_FORWARD_MSG_TO_SENDER
        else:
            # We were asked to process a TCP message, hence tell main to send
            #   the packet we generate to the corresponding TCP sender
            returnMessageType = MainThreadQueueMessageType\
                    .TCP_FORWARD_MSG_TO_SENDER

        # ? DISCOVERY
        if data.get_mode() == RUSHBPacketModes.DISCOVERY and \
                self.__greetingPreviousState == GreetingProtocolStates.DEFAULT:

            # Get the host address and next assigned ip address
            hostAddr = message.get_our_source_ip()
            assignedIp = message.get_assigned_ip()

            if hostAddr == None or assignedIp == None:
                raise Exception(
                        "Unable to retrieve host ip or assigned ip data")

            # Received discovery packet, create offer packet
            offerPacket = RUSHBGreetingPacket(inputDict={
                'source_ip_addr': hostAddr,
                'destination_ip_addr': '0.0.0.0',
                'mode': RUSHBPacketModes.OFFER.value,
                'reserved_bytes': b'\x00\x00\x00',
                'assigned_ip_addr': assignedIp
            })

            # Send the offer packet to the parent for final processing and
            #   sendoff.
            self.__toParentQueue.put(   # type: ignore
                    ThreadQueueMessage(
                            msgType=returnMessageType,
                            portNum=self.__portNum,
                            msgData=offerPacket,
                            msgFrom=self.__threadName))

            # Set the previous state (so we can advance to the next part)
            self.__greetingPreviousState = GreetingProtocolStates.\
                    SENT_OFFER_EXPECTING_REQUEST
        
        # ? OFFER
        elif data.get_mode() == RUSHBPacketModes.OFFER and \
                self.__greetingPreviousState == GreetingProtocolStates.\
                        SENT_DISCOVERY_EXPECTING_OFFER and \
                        isinstance(data, RUSHBGreetingPacket):

            # Received OFFER packet, create REQUEST packet
            requestPacket = RUSHBGreetingPacket(inputDict={
                'source_ip_addr': '0.0.0.0',
                'destination_ip_addr': data.get_source_ip_addr(),
                'mode': RUSHBPacketModes.REQUEST.value,
                'reserved_bytes': b'\x00\x00\x00',
                'assigned_ip_addr': data.get_assigned_ip_addr()
            })
            
            # Send the REQUEST packet to the parent for final processing and
            #   sendoff.
            self.__toParentQueue.put(   # type: ignore
                    ThreadQueueMessage(
                        msgType=returnMessageType,
                        portNum=self.__portNum,
                        msgData=requestPacket,
                        msgFrom=self.__threadName))

            # Set the previous state (so we can advance to the next part)
            self.__greetingPreviousState = GreetingProtocolStates.\
                    SENT_REQUEST_EXPECTING_ACK
        
        # ? REQUEST
        elif data.get_mode() == RUSHBPacketModes.REQUEST and \
                self.__greetingPreviousState == GreetingProtocolStates.\
                        SENT_OFFER_EXPECTING_REQUEST and \
                isinstance(data, RUSHBGreetingPacket):

            # Received REQUEST packet, create ACKNOWLEDGE packet
            acknowledgePacket = RUSHBGreetingPacket(inputDict={
                'source_ip_addr': data.get_destination_ip_addr(),
                'destination_ip_addr': data.get_assigned_ip_addr(),
                'mode': RUSHBPacketModes.ACKNOWLEDGE.value,
                'reserved_bytes': b'\x00\x00\x00',
                'assigned_ip_addr': data.get_assigned_ip_addr()
            })

            # Tell the parent to add the ip address to the connections table.
            if self.__switchServiceSide == RUSHBSwitchServiceSides.GLOBAL_SIDE:
                newMessage = ThreadQueueMessage(
                    msgType=MainThreadQueueMessageType\
                            .ADD_TO_TCP_CONNECTIONS_TABLE,
                    portNum=self.__portNum,
                    msgFrom=self.__threadName,
                    assignedIp=ipaddress.IPv4Address(
                            data.get_assigned_ip_addr()),
                    ourSourceIp=ipaddress.IPv4Address(
                            data.get_destination_ip_addr()))
            else:
                newMessage = ThreadQueueMessage(
                    msgType=MainThreadQueueMessageType\
                            .ADD_TO_UDP_CONNECTIONS_TABLE,
                    portNum=self.__portNum,
                    msgFrom=self.__threadName,
                    assignedIp=ipaddress.IPv4Address(
                            data.get_assigned_ip_addr()),
                    ourSourceIp=ipaddress.IPv4Address(
                            data.get_destination_ip_addr()))

            # Send off the request to add the TCP connection to the connections
            #   table (because we're going to send an acknowledgement packet
            #   after this)
            self.__toParentQueue.put( # type: ignore
                    newMessage)

            # Send the ACKNOWLEDGE packet to the parent for final processing and
            #   sendoff.
            newMessage2 = ThreadQueueMessage(
                msgType=returnMessageType,
                portNum=self.__portNum,
                msgData=acknowledgePacket,
                msgFrom=self.__threadName)

            self.__toParentQueue.put(newMessage2)    # type: ignore
            

            # Set the previous state (we should not be expecting any more 
            #   packets)
            self.__greetingPreviousState = GreetingProtocolStates.DEFAULT

        # ? ACKNOWLEDGE
        elif data.get_mode() == RUSHBPacketModes.ACKNOWLEDGE and \
                self.__greetingPreviousState == GreetingProtocolStates.\
                        SENT_REQUEST_EXPECTING_ACK and \
                isinstance(data, RUSHBGreetingPacket):
            # Received ACKNOWLEDGE packet, tell the parent of this and have
            #   them make note of this in the appropriate tables.

            if self.__switchServiceSide == RUSHBSwitchServiceSides.GLOBAL_SIDE:
                newMessage = ThreadQueueMessage(
                    msgType=MainThreadQueueMessageType\
                            .ADD_TO_TCP_CONNECTIONS_TABLE,
                    portNum=self.__portNum,
                    msgFrom=self.__threadName,
                    assignedIp=ipaddress.IPv4Address(
                            data.get_assigned_ip_addr()),
                    theirSourceIp=ipaddress.IPv4Address(
                            data.get_source_ip_addr()))
            else:
                newMessage = ThreadQueueMessage(
                    msgType=MainThreadQueueMessageType\
                            .ADD_TO_UDP_CONNECTIONS_TABLE,
                    portNum=self.__portNum,
                    msgFrom=self.__threadName,
                    assignedIp=ipaddress.IPv4Address(
                            data.get_assigned_ip_addr()),
                    theirSourceIp=ipaddress.IPv4Address(
                            data.get_source_ip_addr()))

            self.__toParentQueue.put( # type: ignore
                    newMessage)

            ourLat = message.get_our_lat()
            ourLng = message.get_our_lng()
            if ourLat == None or ourLng == None:
                raise Exception("Worker did not receive latitude" + \
                        " and longitude values")

            # Send off a location packet
            locationPacket = RUSHBLocationPacket(inputDict={
                'source_ip_addr': data.get_assigned_ip_addr(),
                'destination_ip_addr': data.get_source_ip_addr(),
                'mode': RUSHBPacketModes.LOCATION.value,
                'reserved_bytes': b'\x00\x00\x00',
                'lat': ourLat,
                'lng': ourLng
            })

            newMessage = ThreadQueueMessage(
                msgType=returnMessageType,
                portNum=self.__portNum,
                msgFrom=self.__threadName,
                msgData=locationPacket)

            self.__toParentQueue.put( # type: ignore
                    newMessage)

            # When we receive a response location packet, don't send one back.
            self.__locationPacketState = LocationPacketState\
                    .EXPECTING_RETURN_LOCATION_PACKET

            # Set the previous state (we should not be expecting any more 
            #   packets)
            self.__greetingPreviousState = GreetingProtocolStates.\
                    DEFAULT
        
        else:
            raise Exception("Error, unknown protocol state: {}".format(
                    data.get_mode()))

    # ? PRIVATE METHODS --------------------------------------------------------

    def __routing_worker_best_effort_forward(self, 
            tcpConnTable: RUSHBConnectionsTable,
            destinationIp: str,
            msgData: RUSHBDataPacket,
            receivedFromPort: int):
        """ Forwards to a global switch with the longest prefix length. 
        
        NOTE: All previous checks have failed, thus we default to this
        """
        # Get a list of all the routing table entries that contain port numbers
        conns = tcpConnTable.get_connections_table()

        longestPrefixToBeat = 0 
        portNum = 0
        for conn in conns:
            if conn == receivedFromPort:
                continue

            if portNum == 0:
                portNum = conn

            currentConn = conns[conn].get_their_source_ip()



            # Compare the next switches source ip to the destination
            temp = GeneralHelperMethods\
                    .determine_max_matching_prefix_len(currentConn,
                        ipaddress.IPv4Address(destinationIp))

            # If our prefix is longer, set that as the new 
            #   target to beat, and save our via port
            if temp > longestPrefixToBeat:
                longestPrefixToBeat = temp
                portNum = conn

        if portNum == 0:
            raise Exception("Should be another connection available")

        if portNum == self.__portNum:
            
            # longest prefix connection is us!
            newMessage = ThreadQueueMessage(
                    msgType=MainThreadQueueMessageType\
                            .TCP_FORWARD_MSG_TO_SENDER,
                    msgData=msgData,
                    msgFrom=self.__threadName,
                    portNum=portNum,
                    receivedFromPortNum=receivedFromPort)

            self.__check_send_query_packet(
                    packetMessage=newMessage,
                    portNum=portNum,
                    returnMsgType=MainThreadQueueMessageType\
                            .TCP_FORWARD_MSG_TO_SENDER,
                    ourConn=conns[portNum])
            return True
        else:
            # Longest prefix connection is someone else
            newMessage = ThreadQueueMessage(
                msgType=MainThreadQueueMessageType.TCP_FORWARD_MSG_TO_WORKER,
                msgData=msgData,
                msgFrom=self.__threadName,
                portNum=portNum,
                receivedFromPortNum=receivedFromPort)

            self.__toParentQueue.put(   # type: ignore
                    newMessage)
            return True


    def __routing_worker_check_packet_is_for_other_switch(self, 
            destinationIp: str,
            routingTable: RUSHBRoutingTable,
            msgData: RUSHBDataPacket,
            tcpConnTable: RUSHBConnectionsTable,
            udpConnTable: RUSHBConnectionsTable,
            ourConn: RUSHBConnectionsTableEntry,
            receivedFromPort: int):
        """ Checks if the packet is intended for one of the connections in our 
            routing table. """
            # Attempt to get an entry out of the routing table
        entry = routingTable.get_entry(destinationIp)

        if entry != None:
            # We have a match! send it there
            
            # Get the routes with the minimum distance
            distanceToBeat = 1000
            temp = []
            for ent in entry:
                if ent.get_distance() < distanceToBeat:
                    temp = [ent]
                    distanceToBeat = ent.get_distance()
                elif ent.get_distance() == distanceToBeat:
                    temp.append(ent)
            
            # Overwrite temp with the narrowed down entries
            entry = temp

            # Check if routing table has more than one path (of equal length)
            #   to path
            longestPrefixToBeat = 0
            portNum = entry[0].get_via_port()
            if len(entry) > 1:
                for ent in entry:
                    if ent.get_via_port() in tcpConnTable\
                            .get_connections_table():
                        connEntry = tcpConnTable.get_connections_table()\
                                [ent.get_via_port()]
                        
                        theirIp = connEntry.get_their_source_ip()
                        
                    else:
                        connEntry = udpConnTable.get_connections_table()\
                                [ent.get_via_port()]

                        theirIp = connEntry.get_their_source_ip()

                    # Compare our source ip to the destination ip
                    temp = GeneralHelperMethods\
                            .determine_max_matching_prefix_len(theirIp,
                                ipaddress.IPv4Address(destinationIp))

                    # If our prefix is longer, set that as the new 
                    #   target to beat, and save our via port
                    if temp > longestPrefixToBeat:
                        longestPrefixToBeat = temp
                        portNum = ent.get_via_port()
            else:
                # Only one entry, go for that one
                entry = entry[0]
                portNum = entry.get_via_port()

            if portNum in tcpConnTable.get_connections_table():
                returnMsgType = MainThreadQueueMessageType\
                        .TCP_FORWARD_MSG_TO_SENDER
                forwardMsgType = MainThreadQueueMessageType\
                        .TCP_FORWARD_MSG_TO_WORKER
            elif portNum in udpConnTable.get_connections_table():
                returnMsgType = MainThreadQueueMessageType\
                        .UDP_FORWARD_MSG_TO_WORKER
                forwardMsgType = MainThreadQueueMessageType\
                        .UDP_FORWARD_MSG_TO_WORKER
            else:
                raise Exception("Port num {} not present in connections tables"\
                        .format(portNum))

            # Check if this is the port that is connected to the next 
            #   forwarding destination
            if self.__portNum == portNum:
                newMessage = ThreadQueueMessage(
                        msgType=returnMsgType,
                        msgFrom=self.__threadName,
                        msgData=msgData,
                        portNum=portNum,
                        receivedFromPortNum=receivedFromPort)

                # Check if we need to send a query packet or not
                self.__check_send_query_packet(
                        packetMessage=newMessage,
                        portNum=portNum,
                        returnMsgType=returnMsgType,
                        ourConn=ourConn)
            else:
                # Forward the port number to the correct spot
                newMessage = ThreadQueueMessage(
                    msgType=forwardMsgType,
                    msgFrom=self.__threadName,
                    msgData=msgData,
                    portNum=portNum,
                    receivedFromPortNum=receivedFromPort)
                
                self.__toParentQueue.put(   # type: ignore
                        newMessage)

            return True

        else:
            # routing table does not contain entry
            return False

    def __check_send_query_packet(self, 
            packetMessage: ThreadQueueMessage,
            portNum: int,
            ourConn: RUSHBConnectionsTableEntry,
            returnMsgType: MainThreadQueueMessageType):
        """ Checks if we need to send a query packet or not """

        currentTime = time.time()
        if(currentTime - self.__oldtime) > 5:
            # We need to send another query packet, buffer the fragement / data
            #   packet for now.

            self.__packetSenderBuffer.append(packetMessage)

            if self.__r2rPreviousState == ReadyToReceiveStates.DEFAULT:
                # Create query packet
                queryPacket = RUSHBQueryPacket(inputDict={
                    'source_ip_addr': ourConn.get_our_source_ip()\
                            .exploded,
                    'destination_ip_addr': ourConn\
                            .get_their_source_ip().exploded,
                    'mode': RUSHBPacketModes.QUERY.value,
                    'reserved_bytes': b'\x00\x00\x00'
                })

                newMessage = ThreadQueueMessage(
                    msgType=returnMsgType,
                    msgFrom=self.__threadName,
                    msgData=queryPacket,
                    portNum=portNum)

                self.__toParentQueue.put(   # type: ignore
                        newMessage)
            else:
                # Continue to wait for the r2r signal
                pass
        else:
            # Less that 5 seconds has passed since the last check, forward the 
            #   packet.
            self.__toParentQueue.put( # type: ignore
                    packetMessage)
        pass

    def __routing_worker_check_packet_is_for_local_connection(self,
            udpConnTable: RUSHBConnectionsTable,
            destinationIp: str,
            msgData: RUSHBDataPacket,
            receivedFromPortNumber: int):
        """ Checks if the packet is intended for one of the local connections. 
        
        NOTE: If we get here, then that means the check for "this is for me"
            didn't work.
        """
        conns = udpConnTable.get_connections_table()
        for conn in conns:
            localConnIp = conns[conn].get_their_source_ip()
            if localConnIp == ipaddress.IPv4Address(destinationIp):
                if self.__portNum == conn:
                    # Forward this to the sender
                    newMsgType = MainThreadQueueMessageType\
                            .UDP_FORWARD_MSG_TO_SENDER
                else:
                    # Forward this message to the correct local handler
                    newMsgType = MainThreadQueueMessageType\
                            .UDP_FORWARD_MSG_TO_WORKER
                
                newMessage = ThreadQueueMessage(
                        msgType=newMsgType,
                        msgFrom=self.__threadName,
                        msgData=msgData,
                        portNum=conn,
                        receivedFromPortNum=receivedFromPortNumber)
                
                if self.__portNum == conn:
                    # Check if we need to send a query packet or not
                    self.__check_send_query_packet(
                            packetMessage=newMessage,
                            portNum=conn,
                            returnMsgType=newMsgType,
                            ourConn=conns[conn])
                else:
                    # Forward to the correct worker
                    self.__toParentQueue.put( # type: ignore
                            newMessage)
                
                if __DEBUG_MODE_ENABLED__:
                    DebugPrinter.print_generic_header(
                            threadName=self.__threadName,
                            filename=__filename__,
                            classname=self.__classname__,
                            methodname='__routing_worker_check_' + \
                                    'packet_is_for_local_connection')
                    print("Packet belongs to a local connection!")
                    print("Forwarding to port: {}".format(conn))
                    print("Their connection ip: {}".format(localConnIp))

                return True

        if __DEBUG_MODE_ENABLED__:
            DebugPrinter.print_generic_header(
                    threadName=self.__threadName,
                    filename=__filename__,
                    classname=self.__classname__,
                    methodname='__routing_worker_check_' + \
                            'packet_is_for_local_connection')
            print("Packet belongs to another router")

        return False

    def __routing_worker_check_packet_is_for_me(self, 
            destinationIp: str,
            sourceIp: str, 
            ourConnTableEntry: RUSHBConnectionsTableEntry,
            msgData: RUSHBDataPacket):
        """ Checks if the packet is intended for this switch. """
        if __DEBUG_MODE_ENABLED__:
            DebugPrinter.print_generic_header(
                    threadName=self.__threadName,
                    filename=__filename__,
                    classname=self.__classname__,
                    methodname='__routing_worker_check_packet_is_for_me')
            print("Our connection entry")
            print(ourConnTableEntry.to_dict())

        destIpObj = ipaddress.IPv4Address(destinationIp)
        if destIpObj == ourConnTableEntry.get_our_source_ip() or \
                destIpObj == self.__parentSourceIpAddr:
            # This packet is for me :D
            if __DEBUG_MODE_ENABLED__:
                DebugPrinter.print_generic_header(
                        threadName=self.__threadName,
                        filename=__filename__,
                        classname=self.__classname__,
                        methodname='__routing_worker_check_packet_is_for_me')
                print("Received packet for me :D")

            # Check if this packet is a fragment
            if msgData.get_mode() == RUSHBPacketModes.DATA:
                print("Received from {}: {}".format(sourceIp, 
                        msgData.get_data()))

            elif msgData.get_mode() == RUSHBPacketModes.FRAGMENT_A:
                # Buffer the packets, print everything out when we get 
                #   FRAGMENT_B
                if __DEBUG_MODE_ENABLED__:
                    DebugPrinter.print_generic_header(
                            threadName=self.__threadName,
                            filename=__filename__,
                            classname=self.__classname__,
                            methodname='__routing_worker_check_packet_is_for_me')
                    print("Adding fragment A to buffer")
                self.__packetReceiverBuffer.append(msgData)

            elif msgData.get_mode() == RUSHBPacketModes.FRAGMENT_B:
                # Add to the packet buffer, and then print everything out
                if __DEBUG_MODE_ENABLED__:
                    DebugPrinter.print_generic_header(
                            threadName=self.__threadName,
                            filename=__filename__,
                            classname=self.__classname__,
                            methodname='__routing_worker_check_packet_is_for_me')
                    print("Adding fragment B to buffer")
                self.__packetReceiverBuffer.append(msgData)
                
                totalData = ''
                for packet in self.__packetReceiverBuffer:
                    totalData += packet.get_data()

                print("Received from {}: {}".format(sourceIp, 
                        totalData))

                # Clear receiver buffer
                self.__packetReceiverBuffer = []
            
            else:
                raise Exception("Unknown data packet mode: {}".format(
                        msgData.get_mode()))
            return True
        else:
            # This packet is not for me :c
            if __DEBUG_MODE_ENABLED__:
                DebugPrinter.print_generic_header(
                        threadName=self.__threadName,
                        filename=__filename__,
                        classname=self.__classname__,
                        methodname='__routing_worker_check_packet_is_for_me')
                print("Packet is not for me :c")
            return False 

    def __broadcast_breaker_condition_check(self, 
            ingressPacket: RUSHBBroadcastPacket,
            routingTable: RUSHBRoutingTable,
            tcpConnsTable: RUSHBConnectionsTable):
        """ Check for the broadcast break condition.
        
        If the switch receives the same broadcast packet
        (i.e. same source_ip_addr, same destination_ip_addr, 
            and same target_ip_addr), but the distance is larger, it should
            ignore that packet (and not send to neighbours)

        
        """
        targetIp = ingressPacket.get_target_ip()

        rtEntry = routingTable.get_entry(targetIp.exploded)

        if ingressPacket.get_distance() >= 1000:
            # Distance is over 1000, leave
            return False

        if rtEntry == None:
            # Target ip not present, add to routing table
            return False
        
        for ent in rtEntry:
            # Check if the source and destination ip match,
            # and if they match, check if the distance in the routing table is
            # less than the distance in the ingress packet
            viaPort = ent.get_via_port()
            conn = tcpConnsTable.get_connections_table()[viaPort]
            if conn.get_our_source_ip() == \
                    ingressPacket.get_destination_ip_addr() and \
                    conn.get_their_source_ip() == \
                    ingressPacket.get_source_ip_addr() and \
                    ent.get_distance() < ingressPacket.get_distance():
                # BREAK CONDITION, we received a packet with the same source,
                #   destination, and target ip, but the distance was larger
                return True

        # Couldn't find a match, add to the routing table.
        return False

    # ? PRECONDITIONS ----------------------------------------------------------

    def __queue_precondition(self, queue: Optional[threadQueue.Queue]):
        assert isinstance(queue, threadQueue.Queue), \
                "Worker must be given a valid queue"

    