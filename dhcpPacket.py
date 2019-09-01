import utils


class DHCPPacket:
    transactionID = None

    def __init__(self):
        self.transactionID = utils.new_transaction_ID(self.transactionID)

    def buildPacket(self):
        macb = utils.get_MAC_in_bytes()
        packet = b''
        packet += b'\x01'  # Message type: Boot Request (1)
        packet += b'\x01'  # Hardware type: Ethernet
        packet += b'\x06'  # Hardware address length: 6
        packet += b'\x00'  # Hops: 0
        packet += self.transactionID  # Transaction ID
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
        packet += b'\x35\x01\x01'  # Option: (t=53,l=1) DHCP Message Type = DHCP Discover
        # packet += b'\x3d\x06\x00\x26\x9e\x04\x1e\x9b'   #Option: (t=61,l=6) Client identifier
        packet += b'\x3d\x06' + macb
        packet += b'\x37\x03\x03\x01\x06'  # Option: (t=55,l=3) Parameter Request List
        packet += b'\xff'  # End Option

        p = bytearray()
        p.append(0x01)  # Message type: Boot Request (1)
        p.append(0x01)  # Hardware type: Ethernet
        p.append(0x06)  # Hardware address length: 6
        p.append(0x00)  # Hops: 0
        p.append(self.transactionID)  # Transaction ID
        p.append(0x00,0x00)  # Seconds elapsed: 0
        p.append(0x80,0x00)  # Bootp flags: 0x8000 (Broadcast) + reserved flags
        p.append(0x00,0x00,0x00,0x00)  # Client IP address: 0.0.0.0
        p.append(0x00,0x00,0x00,0x0)  # Your (client) IP address: 0.0.0.0
        p.append(0x00,0x00,0x00,0x00)  # Next server IP address: 0.0.0.0
        p.append(0x00,0x00,0x00,0x00)  # Relay agent IP address: 0.0.0.0
        p.append(0x00,0x26,0x9e,0x04,0x1e,0x9b)   #Client MAC address: 00:26:9e:04:1e:9b
        p.append(macb)
        p.append(0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)  # Client hardware address padding: 00000000000000000000

        # packet += b'\x00' * 67  # Server host name not given
        # packet += b'\x00' * 125  # Boot file name not given
        p.append(0x63,0x82,0x53,0x63)  # Magic cookie: DHCP
        p.append(0x35,0x01,0x01)  # Option: (t=53,l=1) DHCP Message Type = DHCP Discover
        # packet += b'\x3d\x06\x00\x26\x9e\x04\x1e\x9b'   #Option: (t=61,l=6) Client identifier
        p.append(0x3d,0x06)
        p.append(macb)
        p.append(0x37,0x03,0x03,0x01,0x06)  # Option: (t=55,l=3) Parameter Request List
        p.append(0xff)  # End Option

        return packet
