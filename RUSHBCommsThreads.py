# Standard libs
import socket
import os
import sys

import queue as threadingQueue

# Local libs
from RUSHBMultithreading import ThreadQueueContainer
from RUSHBMultithreading import ThreadQueueMessage

from RUSHBPackets import RUSHBPacketBuilder
from RUSHBPackets import RUSHBMaxPacketSize

from RUSHBHelper import DebugPrinter, MainThreadQueueMessageType
from RUSHBHelper import __DEBUG_MODE_ENABLED__

import time
import threading

# * DEBUG ----------------------------------------------------------------------

__filename__ = 'RUSHBCommsThreads.py'

# * TERMINAL THREAD ------------------------------------------------------------

class Terminal_Thread(object):
    def __init__(self, queueContainer: ThreadQueueContainer):
        self.__toParentQueue = queueContainer.get_to_parent_queue()
        self.__fromParentQueue = queueContainer.get_from_parent_queue()
        self.__threadName = queueContainer.get_thread_name()
        self.__classname__ = 'Terminal_Thread'
        self.__threadLock = queueContainer.get_thread_lock()

    def main_loop(self):
        self.__threadLock.acquire()
        assert isinstance(self.__toParentQueue, threadingQueue.Queue), \
                "toParentQueue must be a valid threading queue"
        assert isinstance(self.__fromParentQueue, threadingQueue.Queue), \
                "fromParentQueue must be a valid threading queue"
        self.__threadLock.release()
        while True:
            try:
                userInput = input("> ")
            except EOFError as e:
                self.__toParentQueue.put(ThreadQueueMessage(
                    msgType=MainThreadQueueMessageType\
                            .THREAD_TERMINATING,
                    msgFrom=self.__threadName))
                break
       
            self.__threadLock.acquire()
        
            # Attempt to split the input by the space
            splitInput = userInput.split(" ")

            if len(splitInput) != 2:
                self.__threadLock.release()
                continue

            if splitInput[0] != 'connect' or not splitInput[1].isdigit():
                self.__threadLock.release()
                continue
            
            if __DEBUG_MODE_ENABLED__:
                DebugPrinter.print_generic_header(
                        threadName=self.__threadName,
                        filename=__filename__,
                        classname=self.__classname__,
                        methodname='main_loop')
                print("We got some data: {}".format(userInput))
                print("Sending to main thread")
                sys.stdout.flush()

            self.__toParentQueue.put(ThreadQueueMessage(
                    msgType=MainThreadQueueMessageType.CONNECT_REQUEST,
                    msgFrom=self.__threadName,
                    portNum=int(splitInput[1])))

            self.__threadLock.release()
            
            # Wait for confirmation from parent that TCP connection has 
            #   completed
            message = self.__fromParentQueue.get(block=True)

            if not isinstance(message, ThreadQueueMessage):
                raise Exception("Terminal expecting confirmation message")

            if message.get_message_type() != MainThreadQueueMessageType\
                    .CONNECTION_COMPLETE:
                raise Exception("Terminal expecting CONNECTION_COMPLETE")

# * TCP THREADS ----------------------------------------------------------------

class TCPPacketGreeter_Thread(object):
    def __init__(self, queueContainer: ThreadQueueContainer):
        # Queues
        self.__toParentQueue = queueContainer.get_to_parent_queue()

        if self.__toParentQueue == None:
            raise Exception("TCP receiver should receive a valid queue")

        self.__sock = queueContainer.get_socket()

        if not isinstance(self.__sock, socket.socket): 
            raise Exception("TCP sender must container a valid socket")

        # Process id of the current child process
        self.__threadName = queueContainer.get_thread_name()

        self.__serverPort = self.__sock.getsockname()[1]

        self.__classname__ = 'TCPPacketGreeter_Thread'

        self.__threadLock = queueContainer.get_thread_lock()

    def main_loop(self):
        self.__threadLock.acquire()
        assert isinstance(self.__sock, socket.socket), \
                "TCPPacketGreeter must have a valid socket"
        self.__threadLock.release()
        while True:
            connectionSocket, addr = self.__sock.accept()

            self.__threadLock.acquire()

            if __DEBUG_MODE_ENABLED__:
                DebugPrinter.print_generic_header(
                        threadName=self.__threadName,
                        filename=__filename__,
                        classname=self.__classname__,
                        methodname='main_loop')
                print("\nTCP Greeter new port: {}".format(addr[1]))
                print("Received new connection request") 
                sys.stdout.flush()

            # We got a new connection, 
            self.__toParentQueue.put( # type: ignore
                    ThreadQueueMessage(
                            msgType=MainThreadQueueMessageType\
                                    .HANDLE_GREETER_SOCKET,
                            portNum=addr[1],
                            newSocket=connectionSocket,
                            msgFrom=self.__threadName))
            
            self.__threadLock.release()

class TCPPacketReceiver_Thread(object):
    def __init__(self, queueContainer: ThreadQueueContainer):
        # Queues
        self.__toParentQueue = queueContainer.get_to_parent_queue()

        self.__sock = queueContainer.get_socket()

        if self.__toParentQueue == None:
            raise Exception("TCP receiver should receive a valid queue")

        if not isinstance(self.__sock, socket.socket): 
            raise Exception("TCP receiver must container a valid socket")

        # Process id of the current child process
        self.__threadName = queueContainer.get_thread_name()

        self.__serverPort = queueContainer.get_port_num()

        self.__classname__ = 'TCPPacketReceiver_Thread'

        self.__threadLock = queueContainer.get_thread_lock()

    def main_loop(self):
        self.__threadLock.acquire()
        assert isinstance(self.__sock, socket.socket), \
                "TCPPacketReciever must have a valid socket"
        rbpb = RUSHBPacketBuilder()
        
        if __DEBUG_MODE_ENABLED__:
            DebugPrinter.print_generic_header(
                        threadName=self.__threadName,
                        filename=__filename__,
                        classname=self.__classname__,
                        methodname='main_loop')
            print("TCP RECEIVER READY !")
            sys.stdout.flush()
        self.__threadLock.release()
        while True:
            # Wait for a packet to arrive.
            try:
                recvedData = self.__sock.recv(RUSHBMaxPacketSize)
            except Exception as e:
                print(e)
                print("Couldn't receive from socket {}".format(
                        self.__serverPort))
                continue    


            self.__threadLock.acquire()

            # Determine what kind of packet this is
            try:
                packet = rbpb.bytes_to_packet(recvedData)
            except Exception as e:
                # Likely a malformed packet, ignore it
                self.__threadLock.release()
                continue

            if packet == None:
                if __DEBUG_MODE_ENABLED__:
                    DebugPrinter.print_generic_header(
                        threadName=self.__threadName,
                        filename=__filename__,
                        classname=self.__classname__,
                        methodname='main_loop')
                    print("\nTCP Recver port: {}".format(self.__serverPort))
                    print("Unknown packet type: {}".format(recvedData))
                    sys.stdout.flush()
                self.__threadLock.release()
                continue
            
            if __DEBUG_MODE_ENABLED__:
                DebugPrinter.print_generic_header(
                        threadName=self.__threadName,
                        filename=__filename__,
                        classname=self.__classname__,
                        methodname='main_loop')
                print("\nReceived data on TCP port: {}".format(
                        self.__serverPort))
                sys.stdout.flush()

            # Send the packet to the parent queue
            self.__toParentQueue.put( # type: ignore
                    ThreadQueueMessage(
                            msgType=MainThreadQueueMessageType\
                                    .TCP_FORWARD_MSG_TO_WORKER,
                            msgData=packet,
                            msgFrom=self.__threadName,
                            portNum=self.__serverPort,
                            receivedFromPortNum=self.__serverPort))
            
            self.__threadLock.release()

class TCPPacketSender_Thread(object):
    def __init__(self, queueContainer: ThreadQueueContainer):
        # Queues
        self.__fromParentQueue = queueContainer.get_from_parent_queue()

        if self.__fromParentQueue == None:
            raise Exception("TCP Sender should receive a valid queue")

        self.__sock = queueContainer.get_socket()

        if not isinstance(self.__sock, socket.socket): 
            raise Exception("TCP sender must container a valid socket")

        # Process id of the current child process
        self.__threadName = queueContainer.get_thread_name()

        self.__serverPort = queueContainer.get_port_num()

        self.__classname__ = 'TCPPacketSender_Thread'

        self.__threadLock = queueContainer.get_thread_lock()

    def main_loop(self):
        self.__threadLock.acquire()
        assert isinstance(self.__sock, socket.socket), \
                "TCP sender main loop must have a valid socket"
        
        if __DEBUG_MODE_ENABLED__:
            DebugPrinter.print_generic_header(
                        threadName=self.__threadName,
                        filename=__filename__,
                        classname=self.__classname__,
                        methodname='main_loop')
            print("TCP SENDER READY !")
            sys.stdout.flush()
        self.__threadLock.release()

        while True:
            # Get a message from the parent
            response: ThreadQueueMessage = self.__fromParentQueue\
                    .get( # type: ignore
                    block=True)

            self.__threadLock.acquire()

            # Extract the message to send
            msgData = response.get_message_data()
            
            if not RUSHBPacketBuilder.check_is_rushb_packet(msgData):
                # Ignore any malformed data packets
                if __DEBUG_MODE_ENABLED__:
                    DebugPrinter.print_generic_header(
                        threadName=self.__threadName,
                        filename=__filename__,
                        classname=self.__classname__,
                        methodname='main_loop')
                    print("\nTCP Sender port: {}".format(self.__serverPort))
                    print("Malformed message packet, msgData type: {}".format(
                            type(msgData)))
                    sys.stdout.flush()
                
                self.__fromParentQueue.task_done()  # type: ignore
                self.__threadLock.release()
                continue

            msgToSend = msgData.to_bytes()  # type: ignore
            
            if not isinstance(msgToSend, bytes):
                if __DEBUG_MODE_ENABLED__:
                    DebugPrinter.print_generic_header(
                        threadName=self.__threadName,
                        filename=__filename__,
                        classname=self.__classname__,
                        methodname='main_loop')
                    print("\nTCP Sender port: {}".format(self.__serverPort))
                    print("Malformed message to send, msgToSend type: {}"\
                            .format(type(msgToSend)))
                    sys.stdout.flush()

                self.__fromParentQueue.task_done()  # type: ignore
                self.__threadLock.release()
                continue
            try:
                self.__sock.send(msgToSend)
                # Small delay because the tutors code sucks ass
                time.sleep(0.1)
            except Exception as e:
                print("Couldn't send to TCP socket!")

            if __DEBUG_MODE_ENABLED__:
                DebugPrinter.print_generic_header(
                        threadName=self.__threadName,
                        filename=__filename__,
                        classname=self.__classname__,
                        methodname='main_loop')
                print("TCP Sender port: {}".format(self.__serverPort))
                print("Packet away!")
                sys.stdout.flush()

            self.__fromParentQueue.task_done()  # type: ignore

            self.__threadLock.release()

# * UDP THREADS ----------------------------------------------------------------

class UDPPacketSender_Thread(object):
    def __init__(self, queueContainer: ThreadQueueContainer):
        # Queues
        self.__toParentQueue = queueContainer.get_to_parent_queue()
        self.__fromParentQueue = queueContainer.get_from_parent_queue()

        if self.__toParentQueue == None or self.__fromParentQueue == None:
            raise Exception("UDPPacketSender must receive valid queues")

        self.__sock = queueContainer.get_socket()

        assert isinstance(self.__sock, socket.socket), "Must be a valid socket"

        self.__threadName = queueContainer.get_thread_name()

        self.__classname__ = 'UDPPacketSender_Thread'

        self.__threadLock = queueContainer.get_thread_lock()

    # ? PUBLIC METHODS ---------------------------------------------------------

    def main_loop(self):
        while True:
            # Get a packet from the parent (wait until we get one)
            response: ThreadQueueMessage = self.__fromParentQueue\
                    .get( # type: ignore
                    block=True)

            self.__threadLock.acquire()

            portNum = response.get_port_number()
            data = response.get_message_data()
            if portNum == None or data == None:
                raise Exception("Error, client address or data is None")
            
            self.__sock.sendto(     # type: ignore
                    data.to_bytes(), 
                    ("127.0.0.1", portNum))

            if __DEBUG_MODE_ENABLED__:
                DebugPrinter.print_generic_header(
                        threadName=self.__threadName,
                        filename=__filename__,
                        classname=self.__classname__,
                        methodname='main_loop')
                print("UDP Sender:")
                print("Packet away!")
                sys.stdout.flush()

            self.__fromParentQueue.task_done()  # type: ignore
            
            self.__threadLock.release()

    def get_from_parent_queue(self):
        return self.__fromParentQueue

    def get_to_parent_queue(self):
        return self.__toParentQueue

class UDPPacketReceiver_Thread(object):
    def __init__(self, queueContainer: ThreadQueueContainer):
        # Queues
        self.__toParentQueue = queueContainer.get_to_parent_queue()
        self.__fromParentQueue = queueContainer.get_from_parent_queue()

        self.__sock = queueContainer.get_socket()

        if not isinstance(self.__sock, socket.socket): 
            raise Exception("Must be a valid socket")

        # Process id of the current child process
        self.__threadName = queueContainer.get_thread_name()

        self.__serverPort = self.__sock.getsockname()[1]

        self.__classname__ = 'UDPPacketReceiver_Thread'

        self.__threadLock = queueContainer.get_thread_lock()
    
    # ? PUBLIC METHODS ---------------------------------------------------------

    def main_loop(self):
        """ Loops forever (I can't be bothered to write a termination sequence)

        NOTE: Because the spec doesn't specify the maximum size packet the 
            adapter will send, we will arbitrarily set the buffer size to 10x
            that of the max packet size. 
        """
        rbpb = RUSHBPacketBuilder()
        while True:
            # Tell the server to wait
            message, clientAddress = self.__sock.recvfrom(  # type: ignore
                    RUSHBMaxPacketSize*10)
            
            self.__threadLock.acquire()

            # Attempt to convert message to a packet
            try:
                packet = rbpb.bytes_to_packet(bytesRaw=message)
            except Exception as e:
                # Likely a malformed packet, ignore it
                self.__threadLock.release()
                continue

            if packet == None:
                # Invalid packet recieved, therefore ignore
                self.__threadLock.release()
                continue

            if __DEBUG_MODE_ENABLED__:
                DebugPrinter.print_generic_header(
                        threadName=self.__threadName,
                        filename=__filename__,
                        classname=self.__classname__,
                        methodname='main_loop')
                print("UDP Received message:")
                print("Client address: {}".format(clientAddress))
                sys.stdout.flush()

            # Send this packet to the main process for further processing
            self.__toParentQueue.put(   # type: ignore
                    ThreadQueueMessage(
                            msgType=MainThreadQueueMessageType\
                                    .UDP_FORWARD_MSG_TO_WORKER,
                            msgFrom=self.__threadName,
                            msgData=packet,
                            portNum=clientAddress[1],
                            receivedFromPortNum=clientAddress[1]))

            self.__threadLock.release()

    def get_from_parent_queue(self):
        return self.__fromParentQueue

    def get_to_parent_queue(self):
        return self.__toParentQueue