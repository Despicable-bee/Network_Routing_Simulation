# Standard libs
import ipaddress
from typing import Dict
from typing import List
from typing import Optional
from pprint import PrettyPrinter

# Local Libs
from RUSHBHelper import __DEBUG_MODE_ENABLED__

# * DEBUG ----------------------------------------------------------------------

__filename__ = 'RUSHBRoutingTable.py'

# * AUXILIARY CLASSES ----------------------------------------------------------

class RUSHBConnectionsTableEntry(object):
    def __init__(self, ourSourceIp: ipaddress.IPv4Address, 
            theirSourceIp: ipaddress.IPv4Address):
        
        self.__ourSourceIp = ourSourceIp
        self.__theirSourceIp = theirSourceIp

    def get_our_source_ip(self):
        return self.__ourSourceIp

    def get_their_source_ip(self):
        return self.__theirSourceIp

    def set_our_source_ip(self, newOurSourceIp: ipaddress.IPv4Address):
        self.__ourSourceIp = newOurSourceIp

    def set_their_source_ip(self, newTheirSourceIp: ipaddress.IPv4Address):
        self.__theirSourceIp = newTheirSourceIp

    def to_dict(self):
        return {
            'our_source_ip': self.__ourSourceIp.exploded,
            'their_source_ip': self.__theirSourceIp.exploded
        }

class RUSHBConnectionsTable(object):
    def __init__(self):
        self.__connectionsDict: Dict[int, RUSHBConnectionsTableEntry] = {}
        pass

    def add_table_entry(self, viaPort: int, ourSourceIp: ipaddress.IPv4Address, 
            theirSourceIp: ipaddress.IPv4Address):
        """ Adds an entry to the dictionary """
        # Check if the via port already exists
        if viaPort in self.__connectionsDict:
            raise Exception("Cannot overwrite existing connection")
        
        self.__connectionsDict[viaPort] = RUSHBConnectionsTableEntry(
                ourSourceIp=ourSourceIp,
                theirSourceIp=theirSourceIp)

    def get_connections_table(self):
        return self.__connectionsDict
        
    def debug_printout(self):
        print("Connections table contents:")
        printoutDict = {}
        for port in self.__connectionsDict:
            printoutDict[port] = self.__connectionsDict[port].to_dict()
        
        pp = PrettyPrinter()
        pp.pprint(printoutDict)

class RUSHBRoutingTableEntry(object):
    def __init__(self, viaPort: int, distance: int):
        # Preconditions
        self.__via_port_precondition(viaPort=viaPort)
        self.__distance_precondition(distance=distance)

        # Assignment
        self.__viaPort = viaPort
        self.__distance = distance
        
    # ? PUBLIC METHODS ---------------------------------------------------------

    def to_dict(self):
        return {
            'via_port': self.__viaPort,
            'distance': self.__distance
        }

    def get_via_port(self):
        return self.__viaPort

    def set_via_port(self, newViaPort: int):
        self.__via_port_precondition(viaPort=newViaPort)
        self.__viaPort = newViaPort

    def get_distance(self):
        return self.__distance

    def set_distance(self, newDistance: int):
        self.__distance_precondition(distance=newDistance)
        self.__distance = newDistance


    # ? PRECONDITIONS ----------------------------------------------------------

    @staticmethod
    def __via_port_precondition(viaPort: int):
        assert viaPort > 0, "viaPort must be a valid port number"

    @staticmethod
    def __distance_precondition(distance: int):
        assert distance >= 0, "Distance must be a valid positive integer"

# * CLASS ----------------------------------------------------------------------

class RUSHBRoutingTable(object):
    def __init__(self):
        self.__routingTable: Dict[str, List[RUSHBRoutingTableEntry]] = {}

    # ? PUBLIC METHODS ---------------------------------------------------------

    def get_routing_table(self):
        return self.__routingTable

    def debug_print_contents(self):
        """ Prints out the contents of the entire routing table. """
        printoutDict: Dict[str, list] = {}
        for ip in self.__routingTable:
            printoutList: List[dict] = []
            for item in self.__routingTable[ip]:
                printoutList.append(item.to_dict())
            printoutDict[ip] = printoutList
        
        pp = PrettyPrinter()
        pp.pprint(printoutDict)

    def get_entry(self, ipAddr: str):
        """ Attempts to retrieve an entry from the routing table. 
        
        ARGS:
        - ipAddr: The destination ip address that we want the port number for.

        RETURNS:
        - If available, the method will return the corresponding 
            `RoutingTableEntry`. Otherwise will return `None`.
        """
        if self.check_entry_exists(ipAddr=ipAddr):
            return self.__routingTable[ipAddr]
        return None

    def check_entry_exists(self, ipAddr: str):
        """ Checks if a specified ip address already exists. """
        return ipAddr in self.__routingTable

    def add_entry(self, ipAddr: str, viaPort: int, distance: int):
        """ Attempts to add an entry into the routing table. 
        
        ARGS:
        - ipAddr: The ip address that will correspond to the viaPort and distance
        - viaPort: The port number that this ipAddr will correspond to.
        - distance: The computed distance of the target.

        RETURNS:
        - If `ipAddr` does NOT exist in the routing table, then the method will
            create a new entry and add it to the table, and then return `True`.
        - If an entry DOES exist however, then the method will check if said 
            entry is of the same length. If so, then it will append it to the
            list and return `True`. If not, then it will NOT append the new 
            entry to the list and return `False`.
        - If for any reason the method fails (i.e. bad input), the method will
            return `None`.
        """
        try:
            temp = RUSHBRoutingTableEntry(viaPort=viaPort, distance=distance)

            if not self.check_entry_exists(ipAddr=ipAddr):
                # Attempt to create a routing table entry.
                
                self.__routingTable[ipAddr] = [temp]
                
            else:
                if self.__routingTable[ipAddr][0].get_distance() != distance:
                    return False
                self.__routingTable[ipAddr].append(temp)
            return True
        except Exception as e:
            return False

    def add_entry_2(self, ipAddr: str, viaPort: int, distance: int):
        """ Attempts to add an entry into the routing table """
        try:
            temp = RUSHBRoutingTableEntry(viaPort=viaPort, distance=distance)

            if not self.check_entry_exists(ipAddr=ipAddr):
                # Attempt to create a routing table entry
                self.__routingTable[ipAddr] = [temp]
                return True
            else:
                # 
                for ent in self.__routingTable[ipAddr]:
                    if ent.get_via_port() == temp.get_via_port():
                        if ent.get_distance() <= temp.get_distance():
                            # Existing distance is less than new distance, 
                            #   ignore
                            return False
                        else:
                            # Existing distance is MORE than new distance, 
                            #   replace
                            ent.set_distance(temp.get_distance())
                            return True
                # No matching entries were found, hence, add a new entry to the
                #   routing table
                self.__routingTable[ipAddr].append(temp)
                return True
        except Exception as e:
            return None

    def update_entry(self, ipAddr: str, viaPort: int, distance: int):
        """ Attempts to update an existing entry in the list. 
        
        ARGS:
        - ipAddr: The ip address whose entry we wish to update
        - viaPort: The port that we need to forward the packet to in order to
            reach the destination.
        - distance: The distance to the target.

        RETURNS:
        - If a matching entry exists in the routing table, then one of two 
            things can happen. If the distance specified is GREATER THAN or 
            EQUAL TO the distance of the existing entry, then the method will
            make no changes and return `False`.
            If the distance is LESS THAN the distance of the existing entry, 
            then the method will overwrite the exsiting entry and return `True`.
        
        - If a matching entry CANNOT BE FOUND, then the method will return 
            `None`.
        """
        # Check if the entry already exists
        if self.check_entry_exists(ipAddr=ipAddr):
            # Check if the distance specified is less than the existing distnace
            entry = self.__routingTable[ipAddr][0]
            if entry.get_distance() > distance:
                # Overwrite the old list with a new one.
                entry.set_distance(newDistance=distance)
                entry.set_via_port(newViaPort=viaPort)
                self.__routingTable[ipAddr] = [entry]
                if __DEBUG_MODE_ENABLED__:
                    print("Entry updated")
                return True

            else:
                if __DEBUG_MODE_ENABLED__:
                    print("Did not update entry")
                return False
                
        else:
            if __DEBUG_MODE_ENABLED__:
                print("Did not update entry")
            return None