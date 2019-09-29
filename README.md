# Net Loom

Net Loom is a re-write of the Lightweight IP Stack in C++ 17.

## Programming Guidelines

* Functions should return a tuple consisting of the output and a status code.

## Design

### Low-Level I/O

* send/receive bytes
* talk directly to OS interfaces

* Low-Level I/O Context
  * Receive Q: Bytes / Frames
  * Transmit Q: Bytes / Frames
  * Handle / Pointer / Socket / Object reference
  * Low-Level I/O type
  * State information

#### Low-Level I/O Types

* Libpcap/NPcap
* Socket
* NDIS or its replacement
* AF_PACKET / PF_PACKET / zero-copy
* Redis
* ZMQ
* File
* NULL

### Network Interfaces

* Virtual network interfaces: protocols emulated by the network stack

#### Virtual Network Interface Types

* PPP
* SLIP
* AX.25
* ATM, <https://en.wikipedia.org/wiki/Asynchronous_transfer_mode>
* DTN?
* Frame Relay
* Generic Stream Encapsulation (GSE)
* Cubesat Space Protocol, <https://en.wikipedia.org/wiki/Cubesat_Space_Protocol> <http://www.libcsp.org/> 
* Infiniband, <https://en.wikipedia.org/wiki/InfiniBand>
* CANbus, <https://en.wikipedia.org/wiki/CAN_bus>
  * UAVCAN, <https://github.com/UAVCAN>
  * SocketCAN, <https://en.wikipedia.org/wiki/SocketCAN>
* MIL-STD 1553, <https://en.wikipedia.org/wiki/MIL-STD-1553>
* Uni-Directional Lightweight Encapsulation (ULE), <https://en.wikipedia.org/wiki/Unidirectional_Lightweight_Encapsulation>
* Multi-Protocol Encapsulation, <https://en.wikipedia.org/wiki/Multiprotocol_Encapsulation>
* MODbus
* ARINC 818, <https://en.wikipedia.org/wiki/ARINC_818>
* Ethernet over USB, <https://en.wikipedia.org/wiki/Ethernet_over_USB>
* IPMI, Serial over LAN, RMCP+, <https://en.wikipedia.org/wiki/Intelligent_Platform_Management_Interface>
* SpaceWire, <https://en.wikipedia.org/wiki/SpaceWire>
* AFDX Bus, <https://en.wikipedia.org/wiki/Avionics_Full-Duplex_Switched_Ethernet>
* Fiber Channel, <https://en.wikipedia.org/wiki/Fibre_Channel>

### Protocols

#### Protocol Types

* DTN?
* Ethernet
* IPv4
* IPv6
* ICMP
* IGMP
* ECN?
* TCP
* UDP
* DCCP
* SCTP?
* RSVP?
* Tsunami UDP Protocol? <https://en.wikipedia.org/wiki/SourceForge>
* UDP-Lite? <https://en.wikipedia.org/wiki/UDP-based_Data_Transfer_Protocol>
* Licklider Transmission Protocol (LTP), <https://en.wikipedia.org/wiki/Licklider_Transmission_Protocol>
* Multi-Purpose Transmission Procotol (MTP), <https://en.wikipedia.org/wiki/Multipurpose_Transaction_Protocol>
* L2TP
* PPTP
* Secure Socket Tunneling Protocol (SSTP), <https://en.wikipedia.org/wiki/Secure_Socket_Tunneling_Protocol>
* QUIC
* Scalable TCP? <https://en.wikipedia.org/wiki/Scalable_TCP>
* Stream Control Transmission Protocol (SCTP)? <https://en.wikipedia.org/wiki/Stream_Control_Transmission_Protocol>
* OpnLLDP, <https://en.wikipedia.org/wiki/OpenLLDP>

### External Libs

* GridFTP
* RTP
* RTSP
* MPEG

## TODO items

* Use rocksdb for key/value 'global' storage
* Separate protocols into static libraries
* Create C API interfaces for calling with external programs that are not C++
* Re-implement all code using C++ 17 spec.
* Document using google style
* Implement VXLAN protocol
* Replace LinkedLists with arrays or vectors
& Redfish protocol: <https://en.wikipedia.org/wiki/Redfish_(specification)>

## References

* RocksDB: [<https://rocksdb.org/docs/getting-started.html]>
