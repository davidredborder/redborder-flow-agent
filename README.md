# redborder-flow-agent

A high-performance, multi-core network probe and flow exporter written in Go. Captures live traffic across multiple network interfaces using Linux raw `AF_PACKET` sockets, performs stateful L4/L7 protocol analysis (open port tracking, TLS SNI/version, HTTP Host/URI/status/user-agent, DNS domain mapping, optional nDPI deep packet inspection), and exports enriched flows as **NetFlow v5**, **NetFlow v9**, **IPFIX (RFC 7011)**, **sFlow v5**, or directly as **JSON streams to Apache Kafka and stdout**.

---

## Key Features

- **Multi-Interface & Multi-Core**: Ingests traffic simultaneously across multiple network interfaces using Linux raw `AF_PACKET` sockets with per-interface worker pools.
- **Redborder Directional Flow Model (Model A)**:
  - Preserves **fixed Client (`src_ip`/`src_port`)** and **Server (`dst_ip`/`dst_port`)** across both directions.
  - Emits two independent records per session tagged with `direction: "upstream"` and `direction: "downstream"`.
  - Both records share the exact same `conversation` key for easy aggregation and joining.
- **TCP Connection & Open Port Tracking**:
  - Analyzes TCP 3-way handshakes (`SYN` -> `SYN/ACK` -> `ACK`) to determine confirmed listening ports and responsive services.
  - Measures **TCP RTT latency (`tcp_rtt` in ms)** from passive handshake timing ($\Delta t(\text{SYN-ACK} - \text{SYN})$).
  - Detects responsive bidirectional UDP services.
  - Exports explicit `is_open_port` boolean indicator across IPFIX (IE `301`), NetFlow v9 (Field `301`), and Kafka/stdout JSON.
- **Website & Domain Extraction**:
  - **TLS SNI & Version**: Server Name Indication and negotiated TLS version (`TLS 1.3`, `TLS 1.2`) from ClientHello.
  - **HTTP Inspection**: Full URL reconstruction (`Host` + `URI`), request method, status codes, and `User-Agent`.
  - **DNS Snooping**: Real-time IP-to-Domain mapping cache from DNS query/response traffic.
- **nDPI Deep Packet Inspection (Optional CGO Mode)**:
  - Deep packet classification recognizing 350+ application protocols (Netflix, YouTube, BitTorrent, Zoom, WireGuard, SSH, Telegram, etc.) while preserving exact domain extraction (`website`).
- **Export Protocols**:
  - **Apache Kafka & stdout**: Direct streaming of structured JSON flow records with compression (`snappy`, `lz4`, `gzip`, `zstd`).
  - **IPFIX (RFC 7011)**: Template exporter supporting MACs, VLANs, standard IEs, `isOpenPort` (IE `301`), `tcpRoundTripTime` (IE `302`), `httpHostName` (IE `456`), and `applicationName` (IE `95`).
  - **NetFlow v9**: Dynamic template announcing MACs, VLANs, ports, IPs, flags, `isOpenPort` (Field `301`), `TCP_RTT_MS` (Field `302`), `WEBSITE_URL` (Field `303`), and `APP_PROTOCOL` (Field `304`).
  - **NetFlow v5**: Standards-compliant 5-tuple metrics.
  - **sFlow v5**: Sampled headers and flow records.

---

## Protocol Template Mappings

### 1. IPFIX (RFC 7011) Template

| Field | Information Element (IE) | Size | Description |
| :--- | :--- | :--- | :--- |
| **`sourceIPv4Address`** | `8` | 4 bytes | Client IP |
| **`destinationIPv4Address`** | `12` | 4 bytes | Server IP |
| **`sourceMacAddress`** | `56` | 6 bytes | Client MAC |
| **`destinationMacAddress`** | `80` | 6 bytes | Server MAC |
| **`vlanId`** | `58` | 2 bytes | 802.1Q VLAN ID |
| **`sourceTransportPort`** | `7` | 2 bytes | Client Port |
| **`destinationTransportPort`** | `11` | 2 bytes | Server Port |
| **`protocolIdentifier`** | `4` | 1 byte | Protocol (TCP=6, UDP=17, ICMP=1) |
| **`tcpControlBits`** | `6` | 1 byte | Cumulative TCP Flags (`SYN`, `ACK`, etc.) |
| **`octetDeltaCount`** | `1` | 8 bytes | Volume in Bytes (64-bit) |
| **`packetDeltaCount`** | `2` | 8 bytes | Volume in Packets (64-bit) |
| **`flowStartSeconds`** | `150` | 4 bytes | Start Unix timestamp |
| **`flowEndSeconds`** | `151` | 4 bytes | End Unix timestamp |
| **`isOpenPort`** | `301` | 1 byte | Open Port indicator (`1` = open, `0` = closed) |
| **`tcpRoundTripTime`** | `302` | 4 bytes | Handshake RTT Latency in milliseconds |
| **`httpHostName`** | `456` | 32 bytes | Website URL / Domain / SNI |
| **`applicationName`** | `95` | 16 bytes | App Protocol (e.g. `Netflix`, `YouTube`, `TLS`, `HTTP`) |
| **`sensorName`** | `305` | 16 bytes | Assigned Sensor Identifier |
| **`tagName`** | `306` | 16 bytes | Primary Classification Tag |
| **`tag2Name`** | `307` | 16 bytes | Secondary Classification Tag |
| **`ja4Fingerprint`** | `308` | 36 bytes | JA4 TLS Client Fingerprint |
| **`osName`** | `309` | 16 bytes | Inferred Client Operating System (e.g. `Linux`, `Windows`) |

---

### 2. NetFlow v9 Template (Template ID 257)

| Field | Field ID | Length | Description |
| :--- | :--- | :--- | :--- |
| **`IPV4_SRC_ADDR`** | `8` | 4 bytes | Client IP |
| **`IPV4_DST_ADDR`** | `12` | 4 bytes | Server IP |
| **`IN_SRC_MAC`** | `56` | 6 bytes | Client MAC |
| **`OUT_DST_MAC`** | `80` | 6 bytes | Server MAC |
| **`SRC_VLAN`** | `58` | 2 bytes | VLAN ID |
| **`L4_SRC_PORT`** | `7` | 2 bytes | Client Port |
| **`L4_DST_PORT`** | `11` | 2 bytes | Server Port |
| **`PROTOCOL`** | `4` | 1 byte | Protocol |
| **`TCP_FLAGS`** | `6` | 1 byte | TCP Flags |
| **`IN_BYTES`** | `1` | 4 bytes | Bytes |
| **`IN_PKTS`** | `2` | 4 bytes | Packets |
| **`FIRST_SWITCHED`** | `22` | 4 bytes | Start uptime (ms) |
| **`LAST_SWITCHED`** | `21` | 4 bytes | End uptime (ms) |
| **`IS_OPEN_PORT`** | `301` | 1 byte | Open Port boolean |
| **`TCP_RTT_MS`** | `302` | 4 bytes | Handshake latency (ms) |
| **`WEBSITE_URL`** | `303` | 32 bytes | Website URL / Domain / SNI |
| **`APP_PROTOCOL`** | `304` | 16 bytes | App Protocol Name |
| **`SENSOR_NAME`** | `305` | 16 bytes | Sensor Name |
| **`TAG_NAME`** | `306` | 16 bytes | Primary Metadata Tag |
| **`TAG2_NAME`** | `307` | 16 bytes | Secondary Metadata Tag |
| **`JA4_FINGERPRINT`** | `308` | 36 bytes | JA4 TLS Client Fingerprint |
| **`OS_NAME`** | `309` | 16 bytes | Inferred Client Operating System |

---

### 3. Kafka & stdout JSON Flow Record (pmacct, f2k & sfacctd Compatibility)

When streaming directly to Apache Kafka or stdout, `redborder-flow-agent` emits structured, enriched JSON records aligned with standard **pmacct**, **f2k**, **sfacctd**, and **Logstash** pipelines:

```json
{
  "type": "netflowv10",
  "ip_protocol_version": 4,
  "l4_proto": 6,
  "direction": "downstream",
  "biflow_direction": "reverse initiator",
  "application_id_name": "13:453",
  "engine_id_name": "13",
  "host": "google.com",
  "lan_ip": "10.1.33.138",
  "wan_ip": "216.58.205.37",
  "lan_l4_port": 53282,
  "wan_l4_port": 443,
  "src_mac": "00:50:56:bf:01:23",
  "dst_mac": "b4:2e:99:6f:dc:19",
  "client_mac": "00:50:56:bf:01:23",
  "vlan": 100,
  "lan_vlan": 100,
  "wan_vlan": 100,
  "interface": "eth0",
  "ifindex": 14,
  "lan_interface": 14,
  "wan_interface": 14,
  "lan_interface_name": "eth0",
  "wan_interface_name": "eth0",
  "lan_interface_description": "eth0",
  "wan_interface_description": "eth0",
  "input_vrf": 0,
  "output_vrf": 0,
  "flow_end_reason": "idle timeout",
  "sensor_name": "sensor_core_01",
  "sensor_ip": "10.1.50.20",
  "bytes": 52,
  "pkts": 1,
  "timestamp": 1789469658,
  "start_time": 1789469653,
  "end_time": 1789469658,
  "duration": 5000,
  "conversation": "10.1.33.138:53282-216.58.205.37:443-6",
  "protocol": 6,
  "proto_name": "TCP",
  "total_bytes": 52,
  "total_packets": 1,
  "tcp_flags": "ACK|PSH",
  "tcp_rtt": 18,
  "tcp_window": 64240,
  "is_open_port": true,
  "flow_state": "ESTABLISHED",
  "tls_version": "TLS 1.3",
  "ja4": "t13d1516h2_8daaf6152771_e562703ab85f",
  "client_type": "browser",
  "client_app": "Chrome / Chromium",
  "os": "Linux",
  "os_fingerprint": "ttl64:win64240:mss,sack,ts,nop,ws"
}
```

| Field Name | Description | Compatibility Target |
| :--- | :--- | :--- |
| **`lan_ip`** / **`wan_ip`** | Local / Home Network IP (`home_nets`) and Remote IP | redBorder WebUI / Druid / pmacct |
| **`lan_l4_port`** / **`wan_l4_port`** | Local and Remote Layer 4 transport ports | redBorder WebUI / Druid / pmacct |
| **`client_mac`** | Client / Local host MAC address | pmacct / redBorder WebUI |
| **`vlan`** / **`lan_vlan`** / **`wan_vlan`** | 802.1Q VLAN IDs | pmacct / redBorder WebUI |
| **`lan_interface_name`** / **`wan_interface_name`** | Capture interface name | pmacct / redBorder WebUI |
| **`bytes`** / **`pkts`** | Total volume in bytes and packet count | pmacct / Druid / redBorder WebUI |
| **`l4_proto`** | Numeric Layer 4 protocol (e.g. `6` for TCP, `17` for UDP) | pmacct / redBorder WebUI |
| **`ip_protocol_version`** | IP version (`4` or `6`) | pmacct / redBorder WebUI |
| **`direction`** | `"upstream"` (LAN $\to$ WAN) or `"downstream"` (WAN $\to$ LAN) | redBorder WebUI / Direction Filter |
| **`biflow_direction`** | `"initiator"` (upstream) or `"reverse initiator"` (downstream) | pmacct / Druid / WebUI |
| **`application_id_name`** | Application identifier in `"<engine_id>:<app_id>"` format (e.g. `"13:453"`, `"13:91"`) | nDPI / pmacct / f2k / WebUI |
| **`engine_id_name`** | Classification engine ID (e.g. `"13"` for nDPI/NBAR) | pmacct / redBorder WebUI |
| **`host`** | TLS SNI, HTTP Host, or DNS domain | redBorder WebUI (`host`) |
| **`conversation`** | Canonical bidirectional session key | Druid / Session Aggregation |
| **`is_open_port`** | Confirmed listening service / responsive open port | Security Telemetry |
| **`tcp_rtt`** | Handshake latency in milliseconds | TCP Performance Metrics |
| **`ja4`** / **`ja4_r`** | JA4 TLS client fingerprint | Threat & Bot Intelligence |

## Sensor Assignment & Metadata Enrichment Options

`redborder-flow-agent` supports two flexible ways to assign sensor identities and metadata enrichments:

### Option A: Global Single Sensor Assignment
Assign all observed network traffic to a single sensor probe with static metadata enrichments:
```yaml
sensor_name: "sensor_core_01"   # Sensor name
sensor_ip: "192.168.1.10"       # Sensor IP address
tag: "production"               # Primary classification tag
tag2: "datacenter-1"            # Secondary classification tag
enrichments:
  environment: "production"
  cluster: "dc1-prod"
```

### Option B: Dynamic Subnet-Based Sensor Splitting
Split traffic across virtual sensors by matching source or destination IP subnets:
1. **Source Subnet Matching**: When a new flow is observed, `src_ip` is checked against defined sensor subnets. If matched, the flow is assigned that sensor's `sensor_name`, `sensor_ip`, `tag`, `tag2`, and custom `enrichments`.
2. **Destination Subnet Fallback**: If `src_ip` does not match, `dst_ip` is evaluated against the sensor subnet ranges.
3. **Global Default Fallback**: If neither `src_ip` nor `dst_ip` match, the flow inherits the global `sensor_name`, `sensor_ip`, `tag`, `tag2`, and global `enrichments`.

### Hierarchical Inheritance & Overrides

When traffic matches a subnet in `sensors`:
- **`sensor_name` & `sensor_ip`**: The matched sensor's name and IP **overwrite** the global settings. If `sensor_ip` is omitted in the rule, it inherits the global `sensor_ip`.
### Option C: Explicit Home Networks Declaration (`home_nets`)
In addition to standard RFC 1918 private address ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, CGNAT `100.64.0.0/10`, IPv6 ULA `fc00::/7`), you can explicitly declare custom organizational subnets or public ranges owned by your organization as home/local networks:
```yaml
home_nets:
  - "10.0.0.0/8"
  - "172.16.0.0/12"
  - "192.168.0.0/16"
  - "198.18.0.0/15"
  - "200.1.0.0/16"   # Corporate public IP range treated strictly as local LAN
```

> **Note**: If `home_nets` is not specified, `redborder-flow-agent` automatically falls back to RFC 1918 private address space, CGNAT, IPv6 ULA, and any subnets defined under `sensors[].subnets`.

---

## Redborder Directional Flow Model & Locality Standard

In `redborder-flow-agent`, network sessions are tracked statefully in memory and exported according to the **Redborder Locality Standard**:

1. **Fixed Local Source IP (`src_ip`)**:
   - `src_ip` / `src_port` is **strictly the Local / Internal network** (e.g. `10.x.x.x`, `172.16.x.x`, `192.168.x.x`, or configured in `home_nets` / `sensors[].subnets`).
   - `dst_ip` / `dst_port` is **strictly the Remote / External network** (e.g. public internet IP or foreign subnet).
   - This mapping is fixed across both upstream and downstream flow records. Even for **inbound sessions** (e.g. external clients connecting to an internal reverse proxy), the reverse proxy (`10.1.150.2`) is always `src_ip` and the external client (`81.45.89.232`) is always `dst_ip`.
2. **Direction Identification**:
   - `direction: "upstream"` (`biflow_direction: "initiator"`) $\to$ Egress traffic flowing from Local (`src_ip`) to Remote (`dst_ip`).
   - `direction: "downstream"` (`biflow_direction: "reverse initiator"`) $\to$ Ingress traffic flowing from Remote (`dst_ip`) to Local (`src_ip`).
3. **Logstash Normalization**:
   - Because `src_ip` is guaranteed to be the local network IP, Logstash pipelines can directly rename `src_ip` $\to$ `lan_ip` and `dst_ip` $\to$ `wan_ip` for redBorder WebUI and Druid indexing without conditional logic.
4. **Conversation Tagging**:
   - Both upstream and downstream records share the identical `conversation` key (e.g. `10.1.150.2:443-81.45.89.232:54321-6`) allowing analytics engines (Druid, ClickHouse, Elasticsearch) to aggregate total session volume (`SUM(bytes) GROUP BY conversation`).

### Endpoint & Locality Classification Hierarchy

`redborder-flow-agent` applies the following decision hierarchy to ensure deterministic `src_ip` (Local) vs `dst_ip` (Remote) mapping:

```
                                [ Incoming Flow / Packet ]
                                             │
                          ┌──────────────────┴──────────────────┐
                          │   1. Strict Locality Rule           │
                          │   - Configured home_nets            │
                          │   - sensors[].subnets in config.yaml│
                          │   - RFC 1918 / CGNAT / IPv6 ULA     │
                          │   => Local IP is ALWAYS src_ip      │
                          │   => Remote IP is ALWAYS dst_ip     │
                          └──────────────────┬──────────────────┘
                                             │ (If BOTH endpoints are Local or BOTH are External)
                          ┌──────────────────┴──────────────────┐
                          │   2. TCP Handshake Flags            │
                          │   - SYN (Client): Client -> Server  │
                          │   - SYN-ACK (Server): Server -> Client
                          └──────────────────┬──────────────────┘
                                             │ (If mid-stream / UDP / ICMP)
                          ┌──────────────────┴──────────────────┐
                          │   3. Server vs Ephemeral Ports      │
                          │   - Well-known ports (< 1024, 443,  │
                          │     80, 53, 22, 161, 6343, 9092...) │
                          │   => Ephemeral port is src_ip       │
                          │   => Listening port is dst_ip       │
                          └─────────────────────────────────────┘
```

1. **Locality Standard (Top Priority)**:
   - If one IP is Local and the other is External, the **Local IP is ALWAYS `src_ip`** and the **External IP is ALWAYS `dst_ip`**.
   - Traffic originating from the external IP arriving at the local IP is tagged with `direction: "downstream"`.
2. **TCP Handshake (`SYN` vs `SYN-ACK`)**:
   - Used when both endpoints have the same locality (e.g. internal LAN to LAN, or router-to-router public traffic).
   - `SYN` without ACK confirms the initiator. `SYN-ACK` from the listener inverts the endpoints so the initiator is `src_ip`.
3. **Well-Known Server vs Ephemeral Ports**:
   - Fallback heuristic when handshake flags are unavailable: well-known listening ports identify the `dst_ip` (server) endpoint.

---

## Building

### Mode 1: Pure Go Build (Default, Zero C Dependencies)
```bash
make build
```

### Mode 2: nDPI Dynamic Build
```bash
# Requires libndpi-devel installed on build host & target host
make build-ndpi
```

### Mode 3: nDPI Fully Static Standalone Binary (Zero Runtime Dependencies)
```bash
# Embeds libndpi.a statically into the binary so it runs on ANY Linux machine without libndpi installed
make build-ndpi-static
```

### RPM Package Build
```bash
# 1. Build pure-Go RPM inside isolated Mock chroot
make rpm

# 2. Build RPM dynamically linked to system libndpi
make rpm WITH_NDPI=1

# 3. Build RPM statically embedding nDPI (downloads upstream nDPI git release & compiles libndpi.a into binary)
make rpm WITH_NDPI_STATIC=1

# You can specify any nDPI version/tag to download and embed (defaults to 4.14):
make rpm WITH_NDPI_STATIC=1 NDPI_VERSION=4.14
make rpm WITH_NDPI_STATIC=1 NDPI_VERSION=6.0

# 4. Or build RPM locally on host with rpmbuild
make rpm-local WITH_NDPI=1
# or local static build:
make rpm-local WITH_NDPI_STATIC=1 NDPI_VERSION=4.14
```

## Configuration (`configs/config.yaml`)

```yaml
system:
  cores: 0                     # CPU cores to utilize (GOMAXPROCS); 0 = all available host cores
  cpu_affinity: "0-3"          # Pin process threads to specific core IDs (e.g. "0-3" or "0,2,4,6")

stats:
  enabled: true
  socket_path: "/var/run/redborder-flow-agent.sock" # Unix domain socket for live metrics (like redborder-monitor)
  http_addr: ""                                    # Optional HTTP metrics endpoint (e.g. "127.0.0.1:9100")

capture:
  interfaces:
    - "eth0"
  promiscuous: true
  snaplen: 1518
  workers_per_interface: 2
  buffer_size_mb: 16

analysis:
  track_open_ports: true
  track_tcp_metrics: true      # Handshake latency (tcp_rtt), window size
  extract_tls_sni: true
  extract_tls_version: true    # TLS 1.3, TLS 1.2
  extract_http_host: true
  extract_http_details: true   # HTTP method, status code, user agent
  extract_dns_domains: true
  dns_cache_size: 50000
  ja4_signatures_file: "configs/ja4_signatures.yaml" # JA4 signature DB (browsers, bots, malware)

flow:
  mode: "unidirectional"       # "unidirectional" (Redborder Model A) or "bidirectional"
  active_timeout_sec: 60
  inactive_timeout_sec: 15
  max_active_flows: 500000
  shards: 64

exporter:
  type: "stdout"               # Options: stdout, kafka, ipfix, netflow9, netflow5, sflow
  target: "127.0.0.1"          # For NetFlow / IPFIX / sFlow
  port: 2055
  engine_id: 1
  source_id: 1001
  template_interval_sec: 30
  sflow_sampling_rate: 1000

kafka:
  brokers:
    - "127.0.0.1:9092"
  topic: "rb-flows"            # Kafka topic for JSON stream
  batch_size: 100
  compression: "snappy"        # snappy, lz4, gzip, zstd, none
```

---

## Live Probe Statistics Monitor Socket

`redborder-flow-agent` embeds an ultra-low-overhead statistics monitor server designed for integration with monitor daemons (like `redborder-monitor`), healthchecks, and observability tools.

### Querying the Unix Domain Socket
Connecting to the UNIX socket `/var/run/redborder-flow-agent.sock` immediately returns a JSON snapshot of live engine metrics and closes the connection:

```bash
nc -U /var/run/redborder-flow-agent.sock | jq .
# or with socat:
socat - UNIX-CONNECT:/var/run/redborder-flow-agent.sock | jq .
```

### CLI Inspection Commands (redborder-ai-dpi style)
You can directly inspect a running agent instance using the CLI:

```bash
# 1. Print formatted snapshot of probe metrics
sudo redborder-flow-agent --stats

# 2. Launch live top monitor with real-time pps, Mbps, active flows, drop %, and telemetry
sudo redborder-flow-agent --top

# 3. For multi-instance deployments (e.g. eth0 instance)
sudo redborder-flow-agent --stats-socket /var/run/redborder-flow-agent-eth0.sock --stats
sudo redborder-flow-agent --stats-socket /var/run/redborder-flow-agent-eth0.sock --top
```

### Querying via HTTP (Optional)
When `stats.http_addr: ":9100"` or `--stats-http :9100` is configured:
```bash
curl -s http://127.0.0.1:9100/stats | jq .
curl -s http://127.0.0.1:9100/health
```

---

## CLI Options

| Flag | Default | Description |
| :--- | :--- | :--- |
| **`--mode`** | `"unidirectional"` | Flow accounting mode: `unidirectional` (Redborder Model A with separate upstream/downstream JSONs) or `bidirectional` |
| **`--exporter`** | `"stdout"` | Output format: `stdout`, `kafka`, `ipfix`, `netflow9`, `netflow5`, `sflow` |
| **`--cores`** | `0` (all) | Number of CPU cores / `GOMAXPROCS` to utilize (0 = all available host cores) |
| **`--cpu-affinity`**| `""` | Pin process threads to specific CPU cores / ranges (e.g. `0-3` or `0,2,4,6`) |
| **`--inactive-timeout`** | `15` | Inactive flow timeout in seconds before exporting |
| **`--active-timeout`** | `60` | Active flow maximum duration in seconds before periodic export |
| **`--stats`** | `false` | Connect to live agent socket and print formatted metrics snapshot (redborder-ai-dpi style) |
| **`--top`** | `false` | Launch interactive real-time top console (pps, Mbps, flows, drops, protocols) |
| **`--stats-socket`**| `"/var/run/redborder-flow-agent.sock"` | Unix domain socket path for live probe statistics |
| **`--stats-http`** | `""` | HTTP listen address for metrics & health endpoints (e.g. `:9100`) |
| **`--iface`** | Config file | Network interface to sniff (e.g. `eth0`, `ens18`) |
| **`--sensor-name`** | Config file | Override default sensor name identifier |
| **`--sensor-ip`** | Config file | Override default sensor probe IP address |
| **`--tag`** | Config file | Override primary metadata tag |
| **`--tag2`** | Config file | Override secondary metadata tag |
| **`--kafka-brokers`**| `"127.0.0.1:9092"` | Comma-separated Kafka broker addresses |
| **`--kafka-topic`** | `"rb-flows"` | Kafka topic for JSON flow stream |
| **`--target`** | `"127.0.0.1"` | IPFIX / NetFlow / sFlow collector host |
| **`--port`** | `2055` | IPFIX / NetFlow / sFlow collector port |
| **`--pcap`** | `""` | Offline PCAP file to read for offline testing |
| **`--ja4-signatures`** | `"configs/ja4_signatures.yaml"` | Custom JA4 signature YAML/JSON file for bot and threat classification |
| **`--debug`** | `false` | Enable verbose debug logging |
| **`--version`** | `false` | Display version and nDPI support status |

---

## Running

```bash
# Print formatted Model A unidirectional JSON flow records directly to stdout (pipe to jq)
sudo ./bin/redborder-flow-agent --iface eth0 --mode unidirectional --exporter stdout | jq .

# Stream directly to Apache Kafka with sensor metadata
sudo ./bin/redborder-flow-agent --iface eth0 --mode unidirectional --sensor-name edge_probe_01 --sensor-ip 192.168.1.10 --exporter kafka --kafka-brokers 192.168.1.50:9092 --kafka-topic rb-flows

# Export IPFIX to collector
sudo ./bin/redborder-flow-agent --iface eth0 --exporter ipfix --target 192.168.1.100 --port 2055

# Replay offline PCAP file for testing
./bin/redborder-flow-agent --pcap testdata/sample.pcap --exporter stdout | jq .
```

---

## Multi-Instance Systemd Services

`redborder-flow-agent` includes a systemd template unit (`redborder-flow-agent@.service`) that enables running multiple isolated agent instances simultaneously on a single host (e.g. per interface or per environment), each with its own configuration file and stats socket.

### Setup Multiple Instances
1. Create configuration files in `/etc/redborder-flow-agent/<instance-name>.yaml`:
   - `/etc/redborder-flow-agent/eth0.yaml`
   - `/etc/redborder-flow-agent/eth1.yaml`

2. Enable and start individual instances:
   ```bash
   sudo systemctl enable --now redborder-flow-agent@eth0
   sudo systemctl enable --now redborder-flow-agent@eth1
   ```

3. Query stats per instance:
   ```bash
   nc -U /var/run/redborder-flow-agent-eth0.sock | jq .
   nc -U /var/run/redborder-flow-agent-eth1.sock | jq .
   ```

4. View logs per instance:
   ```bash
   journalctl -u redborder-flow-agent@eth0 -f
   ```

---

## Testing

```bash
make test
```
