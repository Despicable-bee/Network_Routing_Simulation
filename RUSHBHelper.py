# Standard libs
from enum import Enum
from enum import auto
import ipaddress

# * GLOBAL LOCK FOR THREADS ----------------------------------------------------

# * DEBUG VARIABLES ------------------------------------------------------------

__filename__ = 'RUSHBHelper.py'
__DEBUG_MODE_ENABLED__ = False

# * ENUMS ----------------------------------------------------------------------

class RUSHBSwitchType(Enum):
    LOCAL = auto()
    GLOBAL = auto()
    HYBRID = auto()

class RUSHBSwitchServiceSides(Enum):
    LOCAL_SIDE = auto()
    GLOBAL_SIDE = auto()

class RUSHBPacketModes(Enum):
    # Modes 0x01 - 0x04 are intended for the greeting protocol
    DISCOVERY = 0x01
    OFFER = 0x02
    REQUEST = 0x03
    ACKNOWLEDGE = 0x04
    # 0x05 - Data packet (forward it somewhere)
    DATA = 0x05
    # 0x06 - Ask if adapter ready to receive packets
    QUERY = 0x06
    # 0x07 - Adapter ready to receive packets
    READY_TO_RECEIVE = 0x07
    # 0x08 - Location packet (switches only?)
    LOCATION = 0x08
    # 0x09 - Broadcast mode (switches only)
    BROADCAST = 0x09
    # 0x0a - More fragment packets coming
    FRAGMENT_A = 0x0a
    # 0x0b - Last fragment packets
    FRAGMENT_B = 0x0b

class MainThreadQueueMessageType(Enum):
    # Child -> Parent (I've got a valid request to connect)
    CONNECT_REQUEST = auto()

    # Parent -> Child (Connection protocol finished, you can read the next one 
    #   in now)
    CONNECTION_COMPLETE = auto()

    # Child -> Parent (I've got a greeting socket that needs to be turned into
    #   handler processes)
    HANDLE_GREETER_SOCKET = auto()

    # Child -> Parent (I'm done here, please call join on my thread handle)
    THREAD_TERMINATING = auto()

    # Forward message to a TCP worker (denoted by port number)
    TCP_FORWARD_MSG_TO_WORKER = auto()

    # Forward message to a TCP sender (denoted by port number) 
    TCP_FORWARD_MSG_TO_SENDER = auto()

    # Forward message to a UDP worker (denoted by port number)
    UDP_FORWARD_MSG_TO_WORKER = auto()

    # Forward message to the UDP sender (include port number)
    UDP_FORWARD_MSG_TO_SENDER = auto()

    # Attempt to update the routing table with a new entry
    UPDATE_ROUTING_TABLE = auto()

    # Add an entry to the TCP connections table
    ADD_TO_TCP_CONNECTIONS_TABLE = auto()

    # Add an entry to the UDP connections table
    ADD_TO_UDP_CONNECTIONS_TABLE = auto()

class ChildThreadQueueMessageType(Enum):
    # Expect to receive an offer packet next.
    EXPECT_OFFER_PACKET = auto()

    # Process this UDP message for me please
    PROCESS_UDP_MESSAGE = auto()

    # Process this TCP message for me please
    PROCESS_TCP_MESSAGE = auto()
    
class GreetingProtocolStates(Enum):
    DEFAULT = auto()

    SENT_DISCOVERY_EXPECTING_OFFER = auto()

    SENT_OFFER_EXPECTING_REQUEST = auto()

    SENT_REQUEST_EXPECTING_ACK = auto()

class ReadyToReceiveStates(Enum):
    DEFAULT = auto()

    SENT_QUERY_EXPECTING_READY = auto()

class LocationPacketState(Enum):
    # Has not sent out any location packets, hence upon receiving one, worker
    #   will send one back.
    DEFAULT = auto()

    # Has already sent a location packet to a connection, hence upon receiving
    #   one, worker will NOT send one back.
    EXPECTING_RETURN_LOCATION_PACKET = auto()

class ThreadType(Enum):
    # Terminal thread
    TERMINAL_THREAD = auto()

    # Local comms threads
    UDP_SENDER_THREAD = auto()
    UDP_RECEIVER_THREAD = auto()

    # Global comms threads
    TCP_GREETER_THREAD = auto()
    TCP_SENDER_THREAD = auto()
    TCP_RECEIVER_THREAD = auto()

    # Global worker thread
    GLOBAL_WORKER_THREAD = auto()

    # Local worker thread
    LOCAL_WORKER_THREAD = auto()

# * HELPERS --------------------------------------------------------------------

class GenericErrorHandler(object):
    def __init__(self):
        pass

    def debug_print_error(self, filename: str, className: str, methodName: str, 
            exception: Exception, lineNum: int):
        """ General purpose debug error printer. 
        
        ARGS:
        - filename: The name of the file this error originates from
        - className: The name of the class the error is from
        - methodName: The name of the method this error is from
        - exception: The exception raised during runtime
        - lineNum: The line number the error occurred on (within the scope
                of the try catch)
        """
        print("ERROR:\n\t\
                File -> [ {} ]\n\t\
                Class -> [ {} ]\n\t\
                Method -> [ {} ]\n\t\
                Line Num -> [ {} ]".format(filename, className, 
                        methodName, lineNum))
        
        print("EXCEPTION: {}".format(exception))

class DebugPrinter(object):
    def __init__(self):
        pass
    
    @staticmethod
    def print_generic_header(threadName: str, 
            filename: str, 
            classname: str, 
            methodname: str):
        DebugPrinter.print_debug_row(threadName=threadName)
        DebugPrinter.print_debug_filename(filename=filename)
        DebugPrinter.print_classname(classname=classname)
        DebugPrinter.print_debug_method(methodName=methodname)

    @staticmethod
    def print_colour(r: int, g: int, b: int, text: str):
        return "\033[38;2;{};{};{}m{} \033[38;2;255;255;255m".format(r, g, b, 
                text)

    @staticmethod
    def print_classname(classname: str):
        message = "CLASS:"
        # Colour the message
        cMessage = DebugPrinter.print_colour(255,87,34, message)
        print("{} {}".format(cMessage, classname))

    @staticmethod
    def print_debug_row(threadName: str):
        message = "\nDEBUG MESSAGE - {} THREAD: ".format(threadName)
        # Colour the message
        cMessage = DebugPrinter.print_colour(255,235,59, message)
        print("{}".format(cMessage) + "-"*(80 - len(message)))
    
    @staticmethod
    def print_debug_filename(filename: str):
        message = "FILE:"
        # Colour the message
        cMessage = DebugPrinter.print_colour(255,193,7, message)
        print("{} {}".format(cMessage, filename))

    @staticmethod
    def print_debug_method(methodName: str):
        message = "METHOD:"
        # Colour the message
        cMessage = DebugPrinter.print_colour(255,152,0, message)
        print("{} {}".format(cMessage, methodName))

class GeneralHelperMethods(object):
    def __init__(self):
        pass

    # ? STATIC METHODS ---------------------------------------------------------
    
    @staticmethod
    def debug_header_print(message):
        cMessage = DebugPrinter.print_colour(76,175,80, message)
        print("\n{} ".format(cMessage) + '-'*(80-len(message)-1))

    @staticmethod
    def int_to_bytes(x: int) -> bytes:
        return x.to_bytes((x.bit_length() + 7) // 8, 'big')

    @staticmethod    
    def int_from_bytes(xbytes: bytes) -> int:
        return int.from_bytes(xbytes, 'big')

    @staticmethod
    def cidr_to_netmask(cidr: int):
        """ Converts a given cidr index to its corresponding subnet mask. """
        cidr = int(cidr)
        mask = (0xffffffff >> (32 - cidr)) << (32 - cidr)
        return (str( (0xff000000 & mask) >> 24)   + '.' +
                str( (0x00ff0000 & mask) >> 16)   + '.' +
                str( (0x0000ff00 & mask) >> 8)    + '.' +
                str( (0x000000ff & mask)))

    @staticmethod
    def determine_max_matching_prefix_len(ipaddr1: ipaddress.IPv4Address, 
            ipaddr2: ipaddress.IPv4Address):
        ipaddrBytes1 = ipaddr1.packed
        ipaddrBytes2 = ipaddr2.packed
        
        counter = 0
        for i in range(0,len(ipaddrBytes1)):
            bin1 = bin(ipaddrBytes1[i]).replace('0b',"").rjust(8, '0')
            bin2 = bin(ipaddrBytes2[i]).replace('0b',"").rjust(8, '0')
            # print("Compare:")
            # print(bin1)
            # print(bin2)
            for j in range(0,len(bin1)):
                if bin1[j] != bin2[j]:
                    return counter
                else:
                    counter += 1
        
        return counter
        pass