# Standard libs

# Local libs
from RUSHBMultithreading import ThreadQueueContainer

from RUSHBCommsThreads import TCPPacketGreeter_Thread
from RUSHBCommsThreads import TCPPacketReceiver_Thread
from RUSHBCommsThreads import TCPPacketSender_Thread

from RUSHBCommsThreads import UDPPacketReceiver_Thread
from RUSHBCommsThreads import UDPPacketSender_Thread

from RUSHBCommsThreads import Terminal_Thread

from RUSHBWorkerThread import Worker_Thread

# * DEBUG ----------------------------------------------------------------------

# * THREAD STARTERS ------------------------------------------------------------

# ? UDP STARTERS ---------------------------------------------------------------

def udp_sender_thread_starter(queueContainer: ThreadQueueContainer):
    udpSenderThread = UDPPacketSender_Thread(queueContainer=queueContainer)
    
    udpSenderThread.main_loop()

def udp_receiver_thread_starter(queueContainer: ThreadQueueContainer):
    udpReceiverThread = UDPPacketReceiver_Thread(queueContainer=queueContainer)

    udpReceiverThread.main_loop()

# ? TCP STARTERS ---------------------------------------------------------------

def tcp_greeter_thread_starter(queueContainer: ThreadQueueContainer):
    tcpGreeterThread = TCPPacketGreeter_Thread(queueContainer=queueContainer)

    tcpGreeterThread.main_loop()

def tcp_sender_thread_starter(queueContainer: ThreadQueueContainer):
    tcpSenderThread = TCPPacketSender_Thread(queueContainer=queueContainer)
    
    tcpSenderThread.main_loop()

def tcp_receiver_thread_starter(queueContainer: ThreadQueueContainer):
    tcpReceiverThread = TCPPacketReceiver_Thread(queueContainer=queueContainer)

    tcpReceiverThread.main_loop()

# ? TERMINAL STARTER -----------------------------------------------------------

def terminal_thread_starter(queueContainer: ThreadQueueContainer):
    terminalThread = Terminal_Thread(queueContainer=queueContainer)

    terminalThread.main_loop()

# ? WORKER STARTERS ------------------------------------------------------------

def global_worker_thread_starter(queueContainer: ThreadQueueContainer):
    globalWorkerThread = Worker_Thread(queueContainer=queueContainer)

    globalWorkerThread.main_loop()

def local_worker_thread_starter(queueContainer: ThreadQueueContainer):
    localWorkerThread = Worker_Thread(queueContainer=queueContainer)

    localWorkerThread.main_loop()
