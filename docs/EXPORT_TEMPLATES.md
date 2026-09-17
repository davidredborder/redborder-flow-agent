# redborder-flow-agent Export Protocols Specification

This document details the binary flow templates and wire formats implemented in `redborder-flow-agent` for **IPFIX (NetFlow v10)**, **NetFlow v9**, **NetFlow v5**, and **sFlow v5**.

---

## 1. IPFIX (NetFlow v10) Specification

The IPFIX exporter implements **RFC 7011** (IPFIX Protocol Specification) and uses standard IANA Information Elements along with Cisco NBAR (RFC 6759) and RedBorder enterprise elements.

### 1.1 Header Format (16 octets)

| Field | Type | Size (bytes) | Description |
| :--- | :--- | :--- | :--- |
| **Version** | `uint16` | 2 | Constant `10` (`0x000a`) |
| **Length** | `uint16` | 2 | Total IPFIX message length (Header + Sets) |
| **Export Time** | `uint32` | 4 | Current Unix epoch timestamp in seconds |
| **Sequence Number** | `uint32` | 4 | Incremental sequence number of exported records |
| **Domain ID** | `uint32` | 4 | Observation Domain ID (`cfg.SourceID`, default `1001`) |

### 1.2 Template Set (Template ID: `260`, Set ID: `2`)

Sent periodically every `template_interval_sec` (default 30s) or upon exporter startup. Total Field Count: **24 fields** (Total Data Record Size: **210 bytes**).

| # | Element ID | IANA / Standard Name | Length (bytes) | Type | RedBorder Field / Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | **8** | `sourceIPv4Address` | 4 | `ipv4Address` | `lan_ip` (or client IP) |
| 2 | **12** | `destinationIPv4Address` | 4 | `ipv4Address` | `wan_ip` (or server IP) |
| 3 | **56** | `sourceMacAddress` | 6 | `macAddress` | Client MAC address |
| 4 | **80** | `destinationMacAddress` | 6 | `macAddress` | Next-hop / Server MAC address |
| 5 | **58** | `vlanId` | 2 | `unsigned16` | 802.1Q VLAN Tag |
| 6 | **7** | `sourceTransportPort` | 2 | `unsigned16` | `lan_l4_port` |
| 7 | **11** | `destinationTransportPort` | 2 | `unsigned16` | `wan_l4_port` |
| 8 | **4** | `protocolIdentifier` | 1 | `unsigned8` | Layer 4 Protocol (TCP=6, UDP=17, ICMP=1) |
| 9 | **6** | `tcpControlBits` | 1 | `unsigned8` | Bitwise TCP control flags (`SYN`, `ACK`, `FIN`, `RST`, `PSH`) |
| 10 | **1** | `octetDeltaCount` | 8 | `unsigned64` | `bytes` / `total_bytes` |
| 11 | **2** | `packetDeltaCount` | 8 | `unsigned64` | `pkts` / `total_packets` |
| 12 | **61** | `flowDirection` | 1 | `unsigned8` | `0` = Ingress / Downstream, `1` = Egress / Upstream |
| 13 | **150** | `flowStartSeconds` | 4 | `dateTimeSeconds` | Start epoch timestamp |
| 14 | **151** | `flowEndSeconds` | 4 | `dateTimeSeconds` | End epoch timestamp |
| 15 | **95** | `applicationId` | 4 | `unsigned32` | Cisco NBAR Engine ID + App ID `(engineID << 24) \| appID` |
| 16 | **96** | `applicationName` | 16 | `string` | Protocol/App name (e.g. `tls`, `http`, `dns`, `ssh`, `ntp`) |
| 17 | **87** | `httpHostName` | 32 | `string` | Hostname / SNI domain / Website URL / DNS cache resolved |
| 18 | **301** | `isOpenPort` *(Enterprise)* | 1 | `unsigned8` | Port state indicator (`1` = open / established handshake, `0` = closed) |
| 19 | **302** | `tcpRoundTripTime` *(Enterprise)*| 4 | `unsigned32` | TCP RTT Latency in milliseconds |
| 20 | **305** | `sensorName` *(Enterprise)* | 16 | `string` | Matched Sensor identifier (e.g. `flow1`, `rb-flow-agent`) |
| 21 | **306** | `tagName` *(Enterprise)* | 16 | `string` | Primary classification `tag` |
| 22 | **307** | `tag2Name` *(Enterprise)* | 16 | `string` | Secondary classification `tag2` |
| 23 | **308** | `ja4Fingerprint` *(Enterprise)* | 36 | `string` | Full 36-char JA4 TLS client fingerprint string |
| 24 | **309** | `osName` *(Enterprise)* | 16 | `string` | Passively detected Client OS (e.g. `Linux`, `Windows`, `macOS`) |

---

## 2. NetFlow v9 Specification

The NetFlow v9 exporter implements **RFC 3954** (Cisco Systems NetFlow Services Export Version 9).

### 2.1 Header Format (20 octets)

| Field | Type | Size (bytes) | Description |
| :--- | :--- | :--- | :--- |
| **Version** | `uint16` | 2 | Constant `9` (`0x0009`) |
| **Count** | `uint16` | 2 | Total number of FlowSet records (Template or Data) |
| **SysUptime** | `uint32` | 4 | Probe uptime in milliseconds since process start |
| **Unix Secs** | `uint32` | 4 | Current Unix epoch timestamp in seconds |
| **Flow Sequence** | `uint32` | 4 | Sequence counter of total flow records sent |
| **Source ID** | `uint32` | 4 | Engine / Exporter Source ID (`cfg.SourceID`, default `1001`) |

### 2.2 Template FlowSet (Template ID: `260`, FlowSet ID: `0`)

Total Field Count: **24 fields** (Total Data Record Size: **200 bytes**).

| # | Field Type ID | Cisco NetFlow v9 Name | Length (bytes) | Description |
| :--- | :--- | :--- | :--- | :--- |
| 1 | **8** | `IPV4_SRC_ADDR` | 4 | `lan_ip` / Client IP |
| 2 | **12** | `IPV4_DST_ADDR` | 4 | `wan_ip` / Server IP |
| 3 | **56** | `IN_SRC_MAC` | 6 | Source MAC address |
| 4 | **80** | `OUT_DST_MAC` | 6 | Destination MAC address |
| 5 | **58** | `SRC_VLAN` | 2 | 802.1Q VLAN Tag |
| 6 | **7** | `L4_SRC_PORT` | 2 | Source Port |
| 7 | **11** | `L4_DST_PORT` | 2 | Destination Port |
| 8 | **4** | `PROTOCOL` | 1 | IP Protocol (TCP=6, UDP=17, ICMP=1) |
| 9 | **6** | `TCP_FLAGS` | 1 | TCP Control Flags |
| 10 | **1** | `IN_BYTES` | 4 | 32-bit Octet delta count |
| 11 | **2** | `IN_PKTS` | 4 | 32-bit Packet delta count |
| 12 | **61** | `DIRECTION` | 1 | `0` = Ingress / Downstream, `1` = Egress / Upstream |
| 13 | **22** | `FIRST_SWITCHED` | 4 | Start epoch timestamp |
| 14 | **21** | `LAST_SWITCHED` | 4 | End epoch timestamp |
| 15 | **95** | `APPLICATION_ID` | 4 | NBAR 4-byte Application ID |
| 16 | **96** | `APPLICATION_NAME` | 16 | Application protocol string |
| 17 | **87** | `HTTP_HOST` | 32 | Hostname / SNI / Domain |
| 18 | **301** | `IS_OPEN_PORT` | 1 | `1` = Open port, `0` = Closed |
| 19 | **302** | `TCP_RTT_MS` | 4 | TCP RTT Latency in milliseconds |
| 20 | **305** | `SENSOR_NAME` | 16 | Sensor rule name |
| 21 | **306** | `TAG_NAME` | 16 | Classification Tag |
| 22 | **307** | `TAG2_NAME` | 16 | Classification Tag 2 |
| 23 | **308** | `JA4_FINGERPRINT` | 36 | JA4 TLS client fingerprint |
| 24 | **309** | `OS_NAME` | 16 | Inferred OS name |

---

## 3. NetFlow v5 Specification

The NetFlow v5 exporter implements the fixed-size Cisco NetFlow v5 packet structure without runtime templates.

### 3.1 Header Format (24 octets)

| Field | Type | Size (bytes) | Description |
| :--- | :--- | :--- | :--- |
| **Version** | `uint16` | 2 | Constant `5` (`0x0005`) |
| **Count** | `uint16` | 2 | Number of records in packet (1 to 30) |
| **SysUptime** | `uint32` | 4 | Milliseconds since probe boot |
| **Unix Secs** | `uint32` | 4 | Current Unix epoch seconds |
| **Unix Nanos** | `uint32` | 4 | Residual nanoseconds |
| **Flow Sequence** | `uint32` | 4 | Total flows exported counter |
| **Engine Type** | `uint8` | 1 | `cfg.EngineID` or `0` |
| **Engine ID** | `uint8` | 1 | `cfg.EngineID` or `0` |
| **Sampling Interval** | `uint16` | 2 | Sampling mode / rate (`0` = 1:1 unsampled) |

### 3.2 Record Format (48 octets per record)

| Field | Type | Size (bytes) | Description |
| :--- | :--- | :--- | :--- |
| **`SrcAddr`** | `[4]byte` | 4 | Source IPv4 Address |
| **`DstAddr`** | `[4]byte` | 4 | Destination IPv4 Address |
| **`NextHop`** | `[4]byte` | 4 | Next hop router IP (default `0.0.0.0`) |
| **`Input`** | `uint16` | 2 | Input SNMP ifIndex |
| **`Output`** | `uint16` | 2 | Output SNMP ifIndex |
| **`DPkts`** | `uint32` | 4 | Packets in flow |
| **`DOctets`** | `uint32` | 4 | Layer 3 octets in flow |
| **`First`** | `uint32` | 4 | SysUptime at start of flow |
| **`Last`** | `uint32` | 4 | SysUptime at end of flow |
| **`SrcPort`** | `uint16` | 2 | TCP/UDP source port |
| **`DstPort`** | `uint16` | 2 | TCP/UDP destination port |
| **`Pad1`** | `uint8` | 1 | Zero padding byte |
| **`TCPFlags`** | `uint8` | 1 | Cumulative TCP flags |
| **`Prot`** | `uint8` | 1 | IP protocol (TCP=6, UDP=17, etc.) |
| **`Tos`** | `uint8` | 1 | IP Type of Service (ToS / DSCP) |
| **`SrcAs`** | `uint16` | 2 | Source AS number (`0`) |
| **`DstAs`** | `uint16` | 2 | Destination AS number (`0`) |
| **`SrcMask`** | `uint8` | 1 | Source subnet mask bits |
| **`DstMask`** | `uint8` | 1 | Destination subnet mask bits |
| **`Pad2`** | `uint16` | 2 | Zero padding bytes |

---

## 4. sFlow v5 Specification

The sFlow exporter implements **RFC 3176 / sFlow v5** using `Raw Packet Header` and `Extended Switch Data` sample records.

### 4.1 Sample Record Structure

- **Datagram Header**: Version 5, Agent IPv4, Datagram Sequence, Uptime ms.
- **Sample Type**: `1` (Flow Sample).
- **Enterprise / Format**:
  - `Header Format 1`: Raw Packet Flow Sample (L2/L3/L4 protocol headers, stripped packet payload up to 128 bytes).
  - `Extended Data Format 1` (`Extended Switch Data`):
    - `Src VLAN`: Ingress 802.1Q tag
    - `Src Priority`: VLAN priority
    - `Dst VLAN`: Egress 802.1Q tag
    - `Dst Priority`: VLAN priority

---

## 5. Kafka JSON Flow Record Specification (`rb_flow` topic)

The Kafka exporter streams unified JSON documents formatted for RedBorder's analytics and storage pipeline.

### 5.1 JSON Field Reference

| Field Name | Type | Presence | Description |
| :--- | :--- | :--- | :--- |
| `type` | `string` | Always | Protocol identifier, e.g. `"netflowv10"` |
| `conversation` | `string` | Always | Canonical bidirectional conversation key: `<src_ip>:<src_port>-<dst_ip>:<dst_port>-<proto>` |
| `direction` | `string` | Always | `"upstream"` (client to server) or `"downstream"` (server to client) |
| `biflow_direction` | `string` | Optional | `"initiator"` or `"reverse initiator"` |
| `flow_state` | `string` | Optional | `"SYN_SENT"`, `"ESTABLISHED"`, `"CLOSED_FIN"`, `"CLOSED_RST"`, `"UDP_ACTIVE"`, etc. |
| `flow_end_reason` | `string` | Optional | `"idle timeout"`, `"active timeout"`, `"fin"`, `"rst"` |
| `ip_protocol_version` | `integer` | Always | `4` (IPv4) or `6` (IPv6) |
| `protocol` | `integer` | Always | Layer 4 protocol number (`6` = TCP, `17` = UDP, `1` = ICMP) |
| `proto_name` | `string` | Always | Protocol name: `"TCP"`, `"UDP"`, `"ICMP"` |
| `l4_proto` | `integer` | Always | Layer 4 protocol number |
| `bytes` / `total_bytes` | `integer` | Always | Byte volume transferred in this directional record |
| `pkts` / `total_packets` | `integer` | Always | Number of packets transferred in this directional record |
| `lan_ip` | `string` | Always | Local / Internal endpoint IPv4/IPv6 address |
| `wan_ip` | `string` | Always | Remote / External endpoint IPv4/IPv6 address |
| `lan_l4_port` | `integer` | Always | Local / LAN L4 port number |
| `wan_l4_port` | `integer` | Always | Remote / WAN L4 port number |
| `src_mac` | `string` | Always | Ethernet source MAC address |
| `dst_mac` | `string` | Always | Ethernet destination MAC address |
| `client_mac` | `string` | Optional | True client endpoint MAC address |
| `lan_vlan` | `string` | Optional | 802.1Q VLAN Tag of LAN endpoint (e.g. `"70"`, `"150"`) |
| `wan_vlan` | `string` | Optional | 802.1Q VLAN Tag of WAN endpoint (only present for inter-VLAN internal traffic) |
| `interface` | `string` | Always | Captured network interface (e.g. `"eth2"`) |
| `ifindex` | `integer` | Always | Interface SNMP index |
| `lan_interface` / `wan_interface` | `integer` | Optional | Interface index |
| `lan_interface_name` / `wan_interface_name` | `string` | Optional | Interface name |
| `lan_interface_description` / `wan_interface_description` | `string` | Optional | Interface description |
| `start_time` | `integer` | Always | Flow start unix epoch timestamp (seconds) |
| `end_time` | `integer` | Always | Flow last seen unix epoch timestamp (seconds) |
| `duration` | `integer` | Always | Flow duration in milliseconds |
| `timestamp` | `integer` | Always | Export event unix epoch timestamp (seconds) |
| `tos` | `integer` | Always | IP Type of Service / DSCP value |
| `src_ttl` / `dst_ttl` | `integer` | Optional | Observed TTL from source and destination endpoints |
| `tcp_flags` | `string` | Optional | Pipe-delimited TCP flags, e.g. `"SYN\|ACK\|PSH"` |
| `tcp_window` | `integer` | Optional | TCP advertised window size |
| `tcp_rtt` | `integer` | Optional | TCP 3-way handshake round-trip latency in milliseconds |
| `is_open_port` | `boolean` | Always | `true` if port had an active/established connection |
| `app_protocol` | `string` | Optional | Detected L7 protocol: `"TLS"`, `"HTTP"`, `"DNS"`, `"SSH"`, etc. |
| `application_id_name` | `string` | Optional | Application identifier name, e.g. `"tls"`, `"dns"`, `"13:453"` |
| `engine_id_name` | `string` | Optional | NBAR Engine ID, e.g. `"13"` |
| `host` | `string` | Optional | TLS SNI hostname, HTTP `Host` header, or DNS domain |
| `website` | `string` | Optional | Resolved website or domain name |
| `tls_version` | `string` | Optional | Detected TLS version: `"TLS 1.3"`, `"TLS 1.2"` |
| `ja4` | `string` | Optional | 36-char JA4 TLS client fingerprint string (e.g. `"t13d1716h2_..."`) |
| `ja4_r` | `string` | Optional | Raw / unhashed JA4 client fingerprint representation |
| `client_type` | `string` | Optional | Inferred client type: `"browser"`, `"bot"`, `"scanner"`, etc. |
| `client_app` | `string` | Optional | Detected client software name from JA4 database |
| `is_bot` | `boolean` | Optional | `true` if identified as an automated bot/script/CLI tool |
| `is_threat` | `boolean` | Optional | `true` if JA4 matches malware/C2 signatures |
| `os` | `string` | Optional | Passively fingerprinted OS: `"Linux"`, `"Windows"`, `"macOS"` |
| `os_fingerprint` | `string` | Optional | SYN OS fingerprint string: `"ttl64:win64240:mss,sack,ts,nop,ws"` |
| `http_method` | `string` | Optional | HTTP request method (`"GET"`, `"POST"`, etc.) |
| `http_uri` | `string` | Optional | HTTP URI path requested |
| `http_status_code` | `integer` | Optional | HTTP response status code (`200`, `404`, etc.) |
| `http_user_agent` | `string` | Optional | HTTP User-Agent header string |
| `sensor` / `sensor_name` | `string` | Optional | Matched sensor probe name |
| `sensor_ip` | `string` | Optional | Probe IP address |
| `tag` / `tag2` | `string` | Optional | Primary and secondary classification tags |
| `<custom_enrichments>` | `string` | Optional | Flattened custom key-value pairs (e.g. `sensor_uuid`, `proxy_uuid`) |

### 5.2 Example Kafka JSON Event

```json
{
  "type": "netflowv10",
  "app_protocol": "TLS",
  "application_id_name": "tls",
  "biflow_direction": "reverse initiator",
  "bytes": 6584,
  "client_app": "Script / CLI Tool (No ALPN)",
  "client_mac": "00:0c:29:4d:af:3b",
  "client_type": "bot",
  "conversation": "10.0.209.59:54440-10.1.33.90:443-6",
  "direction": "downstream",
  "dst_mac": "ec:ce:13:ae:35:b3",
  "dst_ttl": 63,
  "duration": 167,
  "end_time": 1789572136,
  "engine_id_name": "13",
  "flow_end_reason": "rst",
  "flow_state": "CLOSED_RST",
  "host": "erchef.service.redborder.cluster",
  "ifindex": 4,
  "input_vrf": 0,
  "interface": "eth2",
  "ip_protocol_version": 4,
  "is_bot": true,
  "is_open_port": true,
  "is_threat": false,
  "ja4": "t13d311200_e8f1e7e78f70_136ffa00a224",
  "l4_proto": 6,
  "lan_interface": 4,
  "lan_interface_description": "eth2",
  "lan_interface_name": "eth2",
  "lan_ip": "10.0.209.59",
  "lan_l4_port": 54440,
  "lan_vlan": "33",
  "os": "Linux",
  "os_fingerprint": "ttl61:win64240:mss,sack,ts,nop,ws",
  "output_vrf": 0,
  "pkts": 14,
  "proto_name": "TCP",
  "protocol": 6,
  "sensor": "flow1",
  "sensor_ip": "10.10.10.2",
  "sensor_name": "flow1",
  "sensor_uuid": "d7b95a1b-10c7-47c5-8987-e9bc21971ced",
  "src_mac": "00:0c:29:4d:af:3b",
  "src_ttl": 60,
  "start_time": 1789572135,
  "tcp_flags": "SYN|ACK|FIN|RST|PSH",
  "tcp_window": 587,
  "timestamp": 1789572137,
  "tls_version": "TLS 1.3",
  "tos": 0,
  "total_bytes": 6584,
  "total_packets": 14,
  "wan_interface": 4,
  "wan_interface_description": "eth2",
  "wan_interface_name": "eth2",
  "wan_ip": "10.1.33.90",
  "wan_l4_port": 443,
  "wan_vlan": "20",
  "website": "erchef.service.redborder.cluster"
}
```

