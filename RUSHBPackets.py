# Standard libs
from enum import Enum
from enum import auto

import sys

from typing import Optional
from typing import Union

import ipaddress

# Local libs
from RUSHBHelper import DebugPrinter, RUSHBPacketModes, __DEBUG_MODE_ENABLED__
from RUSHBHelper import GeneralHelperMethods, GenericErrorHandler

# * DEBUG ----------------------------------------------------------------------

__filename__ = 'RUSHBPackets.py'

# * ENUMS ----------------------------------------------------------------------

# * CONSTANTS ------------------------------------------------------------------

RUSHBMaxPacketSize = 1500

# * CLASSES --------------------------------------------------------------------

class RUSHBPacketCommonHeader(object):
    def __init__(self, bytesRaw: Optional[bytes]=None,
            inputDict: Optional[dict]=None):
        if bytesRaw != None:
            # Preconditions

            # - source address
            self.ip_address_precondition(input=bytesRaw[:4])

            # - destination address
            self.ip_address_precondition(input=bytesRaw[4:8])

            # - Reserved (all 0s)
            self.__reserved_bytes_precondition(bytesRaw=bytesRaw[8:11])

            # - Mode
            self.__mode_precondition(modeAsInt=bytesRaw[11])

            # Assignment
            self.__sourceIpAddr = ipaddress.IPv4Address(bytesRaw[:4])
            self.__destIpAddr = ipaddress.IPv4Address(bytesRaw[4:8])
            self.__reservedBytes = bytesRaw[8:11]
            self.__mode = RUSHBPacketModes(bytesRaw[11])
        elif inputDict != None:
            # Preconditions
            
             # - source address
            self.ip_address_precondition(input=inputDict['source_ip_addr'])

            # - destination address
            self.ip_address_precondition(
                    input=inputDict['destination_ip_addr'])
            
            # Don't need to check reserved since that is assumed to be zero

            # - Mode
            self.__mode_precondition(modeAsInt=inputDict['mode'])

            # Assignment
            self.__sourceIpAddr = ipaddress.IPv4Address(
                    inputDict['source_ip_addr'])
            self.__destIpAddr = ipaddress.IPv4Address(
                    inputDict['destination_ip_addr'])
            self.__reservedBytes = inputDict['reserved_bytes']
            self.__mode = RUSHBPacketModes(inputDict['mode'])
        else:
            raise Exception("No input provided")

    # ? PUBLIC METHODS ---------------------------------------------------------

    def get_source_ip_addr(self):
        """ Returns the source ip addr in dot decimal format. 
        
        e.g. 192.168.0.1
        """
        return self.__sourceIpAddr.exploded

    def get_destination_ip_addr(self):
        """ Returns the destination ip addr in dot decimal format. 
        
        e.g. 127.0.0.1
        """
        return self.__destIpAddr.exploded

    def get_mode(self):
        return self.__mode

    def get_reserved_bytes(self):
        return self.__reservedBytes

    def to_bytes(self):
        """ Returns the contents of the packet as a `bytes` object."""
        # print("Source: {} -> {}".format(self.__sourceIpAddr.exploded, 
        #         self.__sourceIpAddr.packed))
        # print("Dest: {} -> {}".format(self.__destIpAddr.exploded, 
        #         self.__destIpAddr.packed))
        # print("Reserved: {}".format(self.__reservedBytes.rjust(3,b'\x00')))
        # print("Mode: {} -> {}".format(self.__mode, 
        #         GeneralHelperMethods.int_to_bytes(self.__mode.value)))
        binPacket = self.__sourceIpAddr.packed + \
                self.__destIpAddr.packed + \
                self.__reservedBytes.rjust(3,b'\x00') + \
                GeneralHelperMethods.int_to_bytes(self.__mode.value)
        
        return binPacket

    def debug_print_packet_contents(self):
        print("Source IP Address: {}".format(self.__sourceIpAddr.exploded))
        print("Destination IP Address: {}".format(self.__destIpAddr.exploded))
        print("Reserved bytes: {}".format(self.__reservedBytes))
        print("Mode: {}".format(self.__mode.name))

    # ? PRECONDITIONS ----------------------------------------------------------

    @staticmethod
    def ip_address_precondition(input: Union[bytes, str]):
        try:
            ipaddress.IPv4Address(input)
        except Exception as e:
            raise Exception("Must be valid ipv4 address")
    
    @staticmethod
    def __reserved_bytes_precondition(bytesRaw: bytes):
        assert GeneralHelperMethods.int_from_bytes(bytesRaw) >= 0, \
                "Reserved bytes must be a valid offset"

    @staticmethod
    def __mode_precondition(modeAsInt: int):
        assert isinstance(modeAsInt, int), "Mode must be a valid integer"
        assert modeAsInt <= 0x0b and modeAsInt >= 0x01, \
                "Mode must be within the range appropriate for greeting packet"

class RUSHBGreetingPacket(RUSHBPacketCommonHeader):
    def __init__(self, bytesRaw: Optional[bytes]=None,
            inputDict: Optional[dict]=None):
        self.__classname__ = 'RUSHBGreetingPacket'
        
        if bytesRaw != None:
            # Preconditions
            RUSHBPacketCommonHeader.__init__(self, bytesRaw=bytesRaw)

            # - Assigned ip address
            RUSHBPacketCommonHeader.ip_address_precondition(
                    input=bytesRaw[12:16])

            # Assignment
            self.__assignedIp = ipaddress.IPv4Address(bytesRaw[12:16])

        elif inputDict != None:
            # Preconditions
            
             # - source address
            RUSHBPacketCommonHeader.__init__(self, inputDict=inputDict)

            # - Assigned ip address
            RUSHBPacketCommonHeader.ip_address_precondition(
                    input=inputDict['assigned_ip_addr'])

            # Assignment
            self.__assignedIp = ipaddress.IPv4Address(
                    inputDict['assigned_ip_addr'])
        
        else:
            raise Exception("No input was provided.")

        # Check source and ip addresses under mode
        mode = RUSHBPacketCommonHeader.get_mode(self)
        srcAddr = RUSHBPacketCommonHeader.get_source_ip_addr(self)
        destAddr = RUSHBPacketCommonHeader.get_destination_ip_addr(self)

        if mode == RUSHBPacketModes.DISCOVERY:
            
            if srcAddr != '0.0.0.0' or \
                    destAddr != '0.0.0.0' or \
                    self.__assignedIp.exploded != '0.0.0.0':
                raise Exception("Incorrectly formatted Discovery packet")
        elif mode == RUSHBPacketModes.OFFER:
            if destAddr != '0.0.0.0':
                raise Exception("Incorrectly formatted Offer packet")
        elif mode == RUSHBPacketModes.REQUEST:
            if srcAddr != '0.0.0.0':
                raise Exception("Incorrectly formatted Request packet")

        # Check reserved bytes
        rBytes = RUSHBPacketCommonHeader.get_reserved_bytes(self)

        if rBytes != b'\x00\x00\x00':
            raise Exception("Bytes should all be zero")
        

    # ? PUBLIC METHODS ---------------------------------------------------------

    def get_assigned_ip_addr(self):
        """ Returns the assigned ip addr in dot decimal format. 
        
        e.g. 0.0.0.0
        """
        return self.__assignedIp.exploded

    def to_bytes(self):
        """ Returns the contents of the packet as a `bytes` object."""
        binPacket = RUSHBPacketCommonHeader.to_bytes(self) + \
                self.__assignedIp.packed
        
        return binPacket

    def debug_print_packet_contents(self):
        GeneralHelperMethods.debug_header_print('GREETING PACKET CONTENTS')
        RUSHBPacketCommonHeader.debug_print_packet_contents(self)
        print("Assigned IP Address: {}".format(self.__assignedIp.exploded))

    

class RUSHBDataPacket(RUSHBPacketCommonHeader):
    def __init__(self, bytesRaw: Optional[bytes]=None,
            inputDict: Optional[dict]=None):
        self.__classname__ = 'RUSHBDataPacket'
        if bytesRaw != None:
            # Preconditions
            RUSHBPacketCommonHeader.__init__(self, bytesRaw=bytesRaw)

            # Assignment
            self.__data = (bytesRaw[12:]).decode()

        elif inputDict != None:
            # Preconditions
            RUSHBPacketCommonHeader.__init__(self, inputDict=inputDict)

            # Assignment
            self.__data = inputDict['data']
        else:
            raise Exception("No input was provided")

    # ? PUBLIC METHODS ---------------------------------------------------------

    def get_data(self):
        return self.__data

    def to_bytes(self):
        """ Returns the contents of the packet as a `bytes` object. """
        binPacket = RUSHBPacketCommonHeader.to_bytes(self) + \
                self.__data.encode()
        return binPacket

    def debug_print_packet_contents(self):
        GeneralHelperMethods.debug_header_print('DATA PACKET CONTENTS')
        RUSHBPacketCommonHeader.debug_print_packet_contents(self)
        print("Data: {}".format(self.__data))

class RUSHBQueryPacket(RUSHBPacketCommonHeader):
    def __init__(self, bytesRaw: Optional[bytes]=None,
            inputDict: Optional[dict]=None):
        self.__classname__ = 'RUSHBQueryPacket'

        RUSHBPacketCommonHeader.__init__(self, 
                bytesRaw=bytesRaw, 
                inputDict=inputDict)

    # ? PUBLIC METHODS ---------------------------------------------------------

    def to_bytes(self):
        return RUSHBPacketCommonHeader.to_bytes(self)

    def debug_print_packet_contents(self):
        GeneralHelperMethods.debug_header_print('QUERY PACKET CONTENTS')
        RUSHBPacketCommonHeader.debug_print_packet_contents(self)

class RUSHBReadyPacket(RUSHBPacketCommonHeader):
    def __init__(self, bytesRaw: Optional[bytes]=None,
            inputDict: Optional[dict]=None):
        self.__classname__ = 'RUSHBReadyPacket'

        RUSHBPacketCommonHeader.__init__(self, 
                bytesRaw=bytesRaw, 
                inputDict=inputDict)

    # ? PUBLIC METHODS ---------------------------------------------------------

    def to_bytes(self):
        return RUSHBPacketCommonHeader.to_bytes(self)

    def debug_print_packet_contents(self):
        GeneralHelperMethods.debug_header_print('READY PACKET CONTENTS')
        RUSHBPacketCommonHeader.debug_print_packet_contents(self)

class RUSHBLocationPacket(RUSHBPacketCommonHeader):
    def __init__(self, bytesRaw: Optional[bytes]=None,
            inputDict: Optional[dict]=None):
        self.__classname__ = 'RUSHBLocationPacket'
        
        if bytesRaw != None:
            # Preconditions
            RUSHBPacketCommonHeader.__init__(self, bytesRaw=bytesRaw)

            # - Latitude
            self.__lat_lng_precondition(bytesRaw[12:14])

            # - Longitude
            self.__lat_lng_precondition(bytesRaw[14:16])

            # Assignment
            self.__lat = GeneralHelperMethods.int_from_bytes(bytesRaw[12:14])
            self.__lng = GeneralHelperMethods.int_from_bytes(bytesRaw[14:16])

        elif inputDict != None:
            # Preconditions
            RUSHBPacketCommonHeader.__init__(self, inputDict=inputDict)

            # - Latitude
            self.__lat_lng_precondition(inputDict['lat'])
            
            # - Longitude
            self.__lat_lng_precondition(inputDict['lng'])

            # Assignment
            self.__lat = inputDict['lat']
            self.__lng = inputDict['lng']
        else:
            raise Exception("No input was provided.")

    # ? PUBLIC METHODS ---------------------------------------------------------

    def get_lat(self):
        return self.__lat

    def get_lng(self):
        return self.__lng

    def to_bytes(self):
        """ Returns the contents of the packet as a `bytes` object. """
        binPacket = RUSHBPacketCommonHeader.to_bytes(self) + \
            GeneralHelperMethods.int_to_bytes(self.__lat).rjust(2,b'\x00') + \
            GeneralHelperMethods.int_to_bytes(self.__lng).rjust(2,b'\x00')

        return binPacket

    def debug_print_packet_contents(self):
        GeneralHelperMethods.debug_header_print('LOCATION PACKET CONTENTS')
        RUSHBPacketCommonHeader.debug_print_packet_contents(self)
        print("Lat: {}, Lng: {}".format(self.__lat, self.__lng))

    # ? PRECONDITIONS ----------------------------------------------------------

    def __lat_lng_precondition(self, input: Union[bytes, int]):
        if isinstance(input, bytes):
            # Convert the bytes to an integer
            inputAsInt = GeneralHelperMethods.int_from_bytes(input)
            assert inputAsInt >= 0, "Lat or Lng must be greater than zero"
        elif isinstance(input, int):
            assert input >= 0, "Lat or Lng must be greater than zero"
        else:
            assert False, "Input must either be bytes or an int"

class RUSHBBroadcastPacket(RUSHBPacketCommonHeader):
    def __init__(self, bytesRaw: Optional[bytes]=None,
            inputDict: Optional[dict]=None):
        self.__classname__ = 'RUSHBBroadcastPacket'
        
        if bytesRaw != None:
            # Preconditions
            RUSHBPacketCommonHeader.__init__(self, bytesRaw=bytesRaw)

            # - Target Ip Address
            RUSHBPacketCommonHeader.ip_address_precondition(bytesRaw[12:16])

            # - Distance
            self.__distance_precondition(bytesRaw[16:20])

            # Assignment
            self.__targetIp = ipaddress.IPv4Address(bytesRaw[12:16])
            self.__distance = GeneralHelperMethods.int_from_bytes(
                    bytesRaw[16:20])
            
        elif inputDict != None:
            # Preconditions
            RUSHBPacketCommonHeader.__init__(self, inputDict=inputDict)
            
            # - Target Ip Address
            RUSHBPacketCommonHeader.ip_address_precondition(
                    inputDict['target_ip_addr'])

            # - Distance
            self.__distance_precondition(inputDict['distance'])

            # Assignment
            self.__targetIp = ipaddress.IPv4Address(inputDict['target_ip_addr'])
            self.__distance = inputDict['distance']
        else:
            raise Exception("No input was provided.")

    # ? PUBLIC METHODS ---------------------------------------------------------
    
    def get_target_ip(self):
        return self.__targetIp

    def get_distance(self):
        return self.__distance

    def debug_print_packet_contents(self):
        """  """
        GeneralHelperMethods.debug_header_print('BROADCAST PACKET CONTENTS')
        RUSHBPacketCommonHeader.debug_print_packet_contents(self)
        print("Target IP Address: {}".format(self.__targetIp.exploded))
        print("Distance: {}".format(self.__distance))

    def to_bytes(self):
        binPacket = RUSHBPacketCommonHeader.to_bytes(self) + \
                self.__targetIp.packed + \
                GeneralHelperMethods.int_to_bytes(self.__distance)\
                        .rjust(4, b'\x00')
        
        return binPacket



    # ? PRECONDITIONS ----------------------------------------------------------

    @staticmethod
    def __distance_precondition(distance: Union[bytes,int]):
        if isinstance(distance, bytes):
            distanceAsInt = GeneralHelperMethods.int_from_bytes(distance)
            assert distanceAsInt > 0, "Distance must be > 0"
            
        elif isinstance(distance, int):
            assert distance > 0, "Distance must be > 0"
        else:
            assert False, "Distance must be valid bytes or an integer"

# * AUXILIARY CLASSES ----------------------------------------------------------

class RUSHBPacketBuilder(object):
    def __init__(self):
        """ Class for building packets from raw input. """
        
        self.__classname__ = 'RUSHBPacketBuilder'

    def bytes_to_packet(self, bytesRaw: bytes):
        """ Attempts to build a new packet from a given series of bytes. """
        
        try:
            # Extract the mode
            mode = RUSHBPacketModes(bytesRaw[11])
            
            if mode == RUSHBPacketModes.DISCOVERY or \
                    mode == RUSHBPacketModes.OFFER or \
                    mode == RUSHBPacketModes.REQUEST or \
                    mode == RUSHBPacketModes.ACKNOWLEDGE:
                # Attempt to create a greeting packet
                return RUSHBGreetingPacket(bytesRaw=bytesRaw)
            
            elif mode == RUSHBPacketModes.DATA:
                # Attempt to create a data packet
                return RUSHBDataPacket(bytesRaw=bytesRaw)

            elif mode == RUSHBPacketModes.QUERY:
                # Attempt to create a query packet
                return RUSHBQueryPacket(bytesRaw=bytesRaw)

            elif mode == RUSHBPacketModes.READY_TO_RECEIVE:
                # Attempt to create a ready packet
                return RUSHBReadyPacket(bytesRaw=bytesRaw)

            elif mode == RUSHBPacketModes.LOCATION:
                # Attempt to create a location packet
                return RUSHBLocationPacket(bytesRaw=bytesRaw)

            elif mode == RUSHBPacketModes.BROADCAST:
                # Attempt to create a broadcast packet
                return RUSHBBroadcastPacket(bytesRaw=bytesRaw)

            elif mode == RUSHBPacketModes.FRAGMENT_A or \
                    mode == RUSHBPacketModes.FRAGMENT_B:
                # Attempt to create a fragment packet
                return RUSHBDataPacket(bytesRaw=bytesRaw)
            
            else:
                raise Exception("Unknown packet mode: {}".format(mode))

        except Exception as e:
            if __DEBUG_MODE_ENABLED__:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                geh = GenericErrorHandler()
                geh.debug_print_error(filename=__filename__,
                        className=self.__classname__,
                        methodName="bytes_to_packet",
                        lineNum=exc_tb.tb_lineno,   # type: ignore
                        exception=e)
                sys.stdout.flush()
            raise Exception("Error trying to build packet")
    
    # ? STATIC METHODS ---------------------------------------------------------

    @staticmethod
    def check_is_rushb_packet(packet: Optional[Union[
            RUSHBGreetingPacket, 
            RUSHBDataPacket, 
            RUSHBQueryPacket, 
            RUSHBReadyPacket, 
            RUSHBLocationPacket, 
            RUSHBBroadcastPacket]]):
        """ Checks if the packet is any of the specified types. """
        if isinstance(packet, RUSHBGreetingPacket) or \
                isinstance(packet, RUSHBDataPacket) or \
                isinstance(packet, RUSHBQueryPacket) or \
                isinstance(packet, RUSHBReadyPacket) or \
                isinstance(packet, RUSHBLocationPacket) or \
                isinstance(packet, RUSHBBroadcastPacket):
            return True
        
        return False

if __name__ == '__main__':
    discoveryPacket = RUSHBGreetingPacket(inputDict={
        'source_ip_addr': '0.0.0.0',
        'destination_ip_addr': '255.255.255.255',
        'reserved_bytes': b'\x00\x00\x00',
        'mode': RUSHBPacketModes.DISCOVERY.value,
        'assigned_ip_addr': '0.0.0.0'
    })

    print(discoveryPacket.to_bytes())
    pass