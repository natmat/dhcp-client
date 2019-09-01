'''
Created on Mar 27, 2011

@author: nmattick
'''
import socket
import struct
import sys

import utils

from dhcpPacket import DHCPPacket


def get_transaction_ID_as_string(transaction_ID):
    trans_id_as_int = hex(int.from_bytes(transaction_ID, byteorder='big'))
    return str(trans_id_as_int)


class DHCPDiscover:
    transaction_ID = None

    def __init__(self):
        self.transaction_ID = utils.new_transaction_ID(self.transaction_ID)

    def build_packet(self):
        mac_bytes = utils.get_MAC_in_bytes()
        packet = b''
        packet += b'\x01'  # Message type: Boot Request (1)
        packet += b'\x01'  # Hardware type: Ethernet
        packet += b'\x06'  # Hardware address length: 61
        packet += b'\x00'  # Hops: 0
        packet += self.transaction_ID  # Transaction ID
        packet += b'\x00\x00'  # Seconds elapsed: 0
        packet += b'\x80\x00'  # Bootp flags: 0x8000 (Broadcast) + reserved flags
        packet += b'\x00\x00\x00\x00'  # Client IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Your (client) IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Next server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Relay agent IP address: 0.0.0.0
        # packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
        packet += mac_bytes
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # Client hardware address padding: 00000000000000000000
        packet += b'\x00' * 67  # Server host name not given
        packet += b'\x00' * 125  # Boot file name not given
        packet += b'\x63\x82\x53\x63'  # Magic cookie: DHCP
        packet += b'\x35\x01\x01'  # Option: (t=53,l=1) DHCP Message Type = DHCP Discover
        # packet += b'\x3d\x06\x00\x26\x9e\x04\x1e\x9b'   #Option: (t=61,l=6) Client identifier
        packet += b'\x3d\x06' + mac_bytes
        packet += b'\x37\x03\x03\x01\x06'  # Option: (t=55,l=3) Parameter Request List
        packet += b'\xff'  # End Option
        return packet


class DHCPOffer:
    def __init__(self, data, trans_ID):
        self.data = data
        self.trans_ID = trans_ID
        self.offer_IP = ''
        self.next_server_IP = ''
        self.DHCP_server_identifier = ''
        self.lease_time = ''
        self.router = ''
        self.subnet_mask = ''
        self.DNS = []
        self.unpack()

    def unpack(self):
        if self.data[4:8] == self.trans_ID:
            data = self.data
            self.offer_IP = '.'.join(map(lambda x: str(x), data[16:20]))
            self.next_server_IP = '.'.join(map(lambda x: str(x), data[20:24]))
            self.DHCP_server_identifier = '.'.join(map(lambda x: str(x), data[245:249]))
            self.lease_time = str(struct.unpack('!L', data[251:255])[0])
            self.router = '.'.join(map(lambda x: str(x), data[257:261]))
            self.subnet_mask = '.'.join(map(lambda x: str(x), data[263:267]))
            dnsNB = int(data[268] / 4)
            for i in range(0, 4 * dnsNB, 4):
                self.DNS.append('.'.join(map(lambda x: str(x), data[269 + i:269 + i + 4])))

    def print_offer(self):
        key = ['transactionID', 'DHCP Server', 'Offered IP address', 'subnet mask', 'lease time (s)', 'default gateway']
        # Convert transId from bytes to string
        trans_id_as_string = get_transaction_ID_as_string(self.trans_ID)
        val = [trans_id_as_string, self.DHCP_server_identifier, self.offer_IP, self.subnet_mask, self.lease_time,
               self.router]
        for i in range(len(key)):
            print('{0:20s} : {1:15s}'.format(key[i], val[i]))

        print('{0:20s}'.format('DNS Servers') + ' : ', end='')
        if self.DNS:
            print('{0:15s}'.format(self.DNS[0]))
        if len(self.DNS) > 1:
            for i in range(1, len(self.DNS)):
                print('{0:22s} {1:15s}'.format(' ', self.DNS[i]))


def recv_DHCP_offer(dhcp_socket, discover_packet):
    # receiving DHCPOffer packet
    dhcp_socket.settimeout(3)
    try:
        while True:
            data = dhcp_socket.recv(1024)
            offer = DHCPOffer(data, discover_packet.transaction_ID)
            if offer.offer_IP:
                offer.print_offer()
                break
    except socket.timeout as e:
        print(e)


class DHCPRequest:
    transaction_ID = None

    def __init__(self):
        self.transaction_ID = utils.new_transaction_ID(self.transaction_ID)

    def buildPacket(self):
        macb = utils.get_MAC_in_bytes()
        packet = b''
        packet += b'\x01'  # Message type: Boot Request (1)
        packet += b'\x01'  # Hardware type: Ethernet
        packet += b'\x06'  # Hardware address length: 6
        packet += b'\x00'  # Hops: 0
        packet += self.transaction_ID  # Transaction ID
        packet += b'\x00\x00'  # Seconds elapsed: 0
        packet += b'\x80\x00'  # Bootp flags: 0x8000 (Broadcast) + reserved flags
        packet += b'\x00\x00\x00\x00'  # Client IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Your (client) IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Next server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Relay agent IP address: 0.0.0.0
        # packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
        packet += macb
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # Client hardware address padding: 00000000000000000000
        packet += b'\x00' * 67  # Server host name not given
        packet += b'\x00' * 125  # Boot file name not given
        packet += b'\x63\x82\x53\x63'  # Magic cookie: DHCP
        packet += b'\x35\x01\x03'  # Option: (t=53,l=1) DHCP Message Type = DHCP Request
        # packet += b'\x3d\x06\x00\x26\x9e\x04\x1e\x9b'   #Option: (t=61,l=6) Client identifier
        packet += b'\x3d\x06' + macb
        packet += b'\x37\x03\x03\x01\x06'  # Option: (t=55,l=3) Parameter Request List
        packet += b'\xff'  # End Option
        return packet


class DHCPAck:
    def __init__(self, data, transID):
        self.data = data
        self.transID = transID
        self.offerIP = ''
        self.nextServerIP = ''
        self.DHCPServerIdentifier = ''
        self.leaseTime = ''
        self.router = ''
        self.subnetMask = ''
        self.DNS = []
        self.unpack()

    def unpack(self):
        if self.data[4:8] == self.transID:
            data = self.data
            self.offerIP = '.'.join(map(lambda x: str(x), data[16:20]))
            self.nextServerIP = '.'.join(map(lambda x: str(x), data[20:24]))
            self.DHCPServerIdentifier = '.'.join(map(lambda x: str(x), data[245:249]))
            self.leaseTime = str(struct.unpack('!L', data[251:255])[0])
            self.router = '.'.join(map(lambda x: str(x), data[257:261]))
            self.subnetMask = '.'.join(map(lambda x: str(x), data[263:267]))
            dnsNB = int(data[268] / 4)
            for i in range(0, 4 * dnsNB, 4):
                self.DNS.append('.'.join(map(lambda x: str(x), data[269 + i:269 + i + 4])))

    def printAck(self):
        key = ['transactionID', 'DHCP Server', 'Offered IP address', 'subnet mask', 'lease time (s)', 'default gateway']
        val = [get_transaction_ID_as_string(self.transID), self.DHCPServerIdentifier, self.offerIP, self.subnetMask,
               self.leaseTime, self.router]
        for i in range(5):
            print('{0:20s} : {1:15s}'.format(key[i], val[i]))

        print('{0:20s}'.format('DNS Servers') + ' : ', end='')
        if self.DNS:
            print('{0:15s}'.format(self.DNS[0]))
        if len(self.DNS) > 1:
            for i in range(1, len(self.DNS)):
                print('{0:22s} {1:15s}'.format(' ', self.DNS[i]))


def recv_DHCPACK(dhcpSocket, requestPacket):
    # receiving DHCPOffer packet
    dhcpSocket.settimeout(3)
    try:
        while True:
            data = dhcpSocket.recv(1024)
            ack = DHCPAck(data, requestPacket.transaction_ID)
            if ack.offerIP:
                ack.printAck()
                break
    except socket.timeout as e:
        print(e)
    except:
        print("Unexpected error: {}", format(sys.exc_info()[0]))
        raise


def incrementTransID(transaction_ID):
    bytesAsInt = int.from_bytes(transaction_ID, byteorder='big')
    bytesAsInt += 1
    transaction_ID = bytesAsInt.to_bytes(4, byteorder='big')


if __name__ == '__main__':
    # defining the socket
    dhcpSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # internet, UDP
    dhcpSocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)  # broadcast

    tmpDHCPPacket = DHCPPacket()

    try:
        dhcpSocket.bind(('', 68))  # we want to send from port 68
    except Exception as e:
        print('port 68 in use...')
        dhcpSocket.close()
        input('press any key to quit...')
        exit()

    option = None
    while option is None or option != 'q':
        option = input('Enter option:\n1: DHCP Discover\n2: DHCP Request\n?: ')
        if option == '1':
            # buiding and sending the DHCPDiscover packet
            discoverPacket = DHCPDiscover()
            dhcpSocket.sendto(discoverPacket.build_packet(), ('<broadcast>', 67))
            print('DHCP Discover sent waiting for reply {}...\n'.format(discoverPacket.transaction_ID))
            recv_DHCP_offer(dhcpSocket, discoverPacket)

        elif option == '2':
            # buiding and sending the DHCPDiscover packet
            requestPacket = DHCPRequest()
            dhcpSocket.sendto(requestPacket.buildPacket(), ('<broadcast>', 67))
            print('DHCP Request sent waiting for reply {}...\n'.format(requestPacket.transaction_ID))
            recv_DHCPACK(dhcpSocket, requestPacket)

        else:
            break

    print('The END')
    dhcpSocket.close()  # we close the socket
    exit()
