---
title: Suricata — Network Intrusion Detection and MQTT Inspection
aliases:
  - Suricata IDS
  - Suricata Network Inspection
  - Network Monitoring
tags:
  - cybersecurity
  - suricata
  - ids
  - nids
  - mqtt
  - eve-json
  - community-id
  - smart-home
date: 2025-06-29
author: Abdelrahman Ashraf Selim
related:
  - "[[11.1_Preparation_Studies_and_Tools]]"
  - "[[11.2_Methodology_and_Implementation]]"
  - "[[Wazuh]]"
  - "[[Splunk]]"
---

# Suricata — Network Intrusion Detection and MQTT Inspection

## 1. Introduction and Role in the Security Stack

[[Suricata]] occupies the **network perimeter detection layer** — the outermost ring of the concentric defence model defined in [[11.2_Methodology_and_Implementation#11.2.1 Multi-Layered Defense Architecture and Hardware Integration|Section 11.2.1]]. It is the first analytical layer that sees inbound and outbound network traffic, operating below the application level: a packet traverse the NIC driver, enters the AF_PACKET capture ring, and is inspected by Suricata *before* any application (including the [[Mosquitto]] broker) processes it.

This positioning gives Suricata a detection advantage that is architecturally inaccessible to [[Wazuh]]'s host-based rules: it can detect and alert on malicious network behaviour from clients that have not yet authenticated, clients that are being actively scanned, or attack traffic that never reaches the application layer because it is blocked by UFW. It is precisely this pre-authentication, pre-application visibility that makes Suricata the appropriate tool for detecting port scanning (Red Team Exercise 4) and TLS probing activity before any credential exchange occurs.

Suricata was installed from the OISF stable PPA (`ppa:oisf/suricata-stable`) at version 7.x, which includes a native MQTT application-layer parser — a feature absent in the 6.x series and critical for the MQTT-specific detection rules described in this document.

---

## 2. AF_PACKET Capture Mode

### 2.1 What AF_PACKET Is

AF_PACKET is a Linux socket type that enables a userspace process to receive raw Ethernet frames directly from the kernel's network stack, bypassing the userspace TCP/IP stack entirely. Unlike `libpcap`-based capture (which copies packet data from kernel memory to userspace for every frame), AF_PACKET in `cluster_flow` mode uses a **memory-mapped ring buffer** (`PACKET_MMAP`) that allows Suricata worker threads to read frames directly from a shared memory region without a system call per packet. This is referred to as zero-copy capture.

The performance implication is significant for an edge server handling concurrent MQTT TLS sessions from four [[ESP32]] nodes, an AI engine, a ThingsBoard gateway, and Wazuh agent traffic: conventional `libpcap` capture at high packet rates introduces measurable CPU overhead that would compete with the [[AI Decision Engine]]'s inference workload. AF_PACKET's zero-copy model minimises this overhead.

### 2.2 Configuration

The active LAN interface was identified at deployment time using:

```bash
ip route | grep default
# Example output: default via 192.168.1.1 dev ens33 proto dhcp
```

The interface name (`ens33` in the example above; substituted with the actual interface at deployment) was then specified in `/etc/suricata/suricata.yaml`:

```yaml
af-packet:
  - interface: ens33
    # Number of receive threads. Set to number of CPU cores
    # available for Suricata minus one (leave one for the main thread).
    threads: auto

    # cluster_flow assigns all packets from the same TCP/UDP flow
    # to the same worker thread, ensuring reassembly and stateful
    # analysis are coherent for multi-packet protocols like TLS.
    cluster-type: cluster_flow
    cluster-id: 99

    # defrag: yes enables kernel-level IP fragment reassembly
    # before Suricata sees the packets, preventing fragmentation
    # evasion techniques.
    defrag: yes

    # use-mmap: yes activates the PACKET_MMAP ring buffer
    use-mmap: yes

    # ring-size controls the number of frames in the shared ring.
    # Larger values reduce packet loss at burst traffic rates.
    ring-size: 2048

    # tpacket-v3 is the kernel's third-generation AF_PACKET
    # implementation, offering batch-mode packet delivery that
    # further reduces context-switching overhead.
    tpacket-v3: yes
```

### 2.3 HOME_NET Definition

The `HOME_NET` variable defines which address space Suricata treats as "internal." Rules referencing `$HOME_NET` fire differently depending on whether a host is classified as internal or external, which directly affects the directionality of alert semantics (e.g., "external host scanning internal host" vs. "internal host scanning another internal host"):

```yaml
vars:
  address-groups:
    HOME_NET: "[192.168.1.0/24]"
    EXTERNAL_NET: "!$HOME_NET"
    # MQTT_SERVERS is a custom variable used in project rules
    MQTT_SERVERS: "[192.168.1.100]"
    # ESP32_NET represents the address range assigned to IoT devices
    ESP32_NET: "[192.168.1.0/24]"
```

---

## 3. EVE JSON Output Format

### 3.1 Structure and Purpose

EVE (Extensible Event Format) JSON is Suricata's unified, machine-readable event log. Every event class that Suricata can detect — network alerts, protocol metadata, flow records, TLS session details, DNS queries, SSH handshakes, and MQTT messages — is written as a single JSON document to `/var/log/suricata/eve.json`, one document per line (NDJSON format).

This is the critical output format for cross-tool integration. Both [[Wazuh]] (via `<localfile>` with `log_format json`) and [[Splunk]] (via universal monitor with `KV_MODE = json`) consume `eve.json` natively without requiring intermediate log transformation. The NDJSON format means each line is a self-contained, independently parseable JSON document, eliminating the need for multi-line log handling.

### 3.2 EVE Configuration

```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json

      # community-id generates a deterministic hash of the 5-tuple
      # (src IP, dst IP, src port, dst port, protocol) for each flow.
      # This hash is IDENTICAL across Suricata, Wazuh, Zeek, and other
      # tools that implement the community-id specification.
      # It is the JOIN KEY used in Splunk correlation queries to link
      # a Suricata network alert to the Wazuh host-based alert
      # generated by the same attack event.
      community-id: true

      types:
        # alert: fires when a Suricata rule matches a packet/flow.
        # Contains: rule sid, msg, category, severity, src/dst IP,
        # src/dst port, protocol, and the community-id.
        - alert:
            tagged-packets: yes

        # http: metadata for every HTTP request/response observed.
        # Relevant if the ThingsBoard gateway uses HTTP REST.
        - http:
            extended: yes

        # dns: every DNS query and response.
        # Used to detect DNS-based exfiltration (unusually long
        # query names) in the custom rule set.
        - dns:
            query: yes
            answer: yes

        # tls: TLS handshake metadata for every TLS session.
        # Includes: TLS version negotiated, cipher suite, SNI,
        # certificate subject, and validity dates.
        # Applied to MQTT TLS sessions on port 8883.
        - tls:
            extended: yes

        # flow: per-flow statistics (byte counts, packet counts,
        # start/end timestamps, TCP state machine outcome).
        # Used to detect connection floods and abnormal flow patterns.
        - flow

        # ssh: SSH handshake metadata.
        # Applied to sessions on port 2222 (hardened SSH port).
        - ssh

        # mqtt: MQTT protocol metadata.
        # REQUIRES Suricata 7.x with MQTT app-layer parser.
        # Includes: client ID, topic, QoS, payload length, packet type.
        - mqtt
```

### 3.3 The community-id Field — Cross-Tool Correlation Key

The `community-id` field is the architectural linchpin of cross-tool alert correlation in this project. Its value is a Base64-encoded SHA-1 hash of the network 5-tuple, computed identically by any tool implementing the community-id specification (RFC draft by Corelight).

**Example:** An MQTT brute-force attack from `192.168.1.200:54321` to `192.168.1.100:8883` generates:

- A Suricata `alert` EVE event with `"community_id": "1:abc123xyz..."`
- A Wazuh alert (rule 100001/100002) derived from the Mosquitto log, which — if Suricata's flow event is also ingested — carries the same `community_id`

In [[Splunk|Splunk]], this shared identifier enables a direct `JOIN` between network-layer and host-layer alerts for the same attack:

```spl
index=suricata event_type=alert
| rename community_id AS cid
| join cid [
    search index=wazuh_alerts rule.id IN (100001,100002)
    | rename network.community_id AS cid
  ]
| table _time, src_ip, cid, alert.signature, rule.description
```

Without `community-id`, correlating a Suricata network alert with the corresponding Wazuh host alert would require a lossy IP-address join that fails when multiple concurrent connections exist from the same source.

---

## 4. MQTT Protocol Awareness

### 4.1 Suricata's MQTT Application-Layer Parser

Suricata 7.x includes a native MQTT dissector that decodes MQTT protocol messages above the TLS layer (after decryption, if TLS decryption keys are available) or at the plaintext level (on port 1883). The MQTT parser extracts the following fields into EVE events:

| EVE Field | Description |
|---|---|
| `mqtt.connect.client_id` | MQTT client ID string |
| `mqtt.connect.username` | Username in CONNECT packet |
| `mqtt.publish.topic` | Topic string in PUBLISH packet |
| `mqtt.publish.qos` | QoS level (0, 1, or 2) |
| `mqtt.publish.payload_length` | Byte length of payload |
| `mqtt.connack.return_code` | Broker response code |
| `mqtt.type` | Packet type (CONNECT, PUBLISH, SUBSCRIBE, etc.) |

These fields are available in Suricata rule conditions via the `mqtt.*` keyword family, enabling rules that match on MQTT application-layer semantics rather than only TCP/IP characteristics.

### 4.2 Scope Limitation — TLS-Encrypted Traffic

The plain MQTT listener (port 1883) is bound to `127.0.0.1` and inaccessible to AF_PACKET capture, which only sees LAN-facing traffic. The TLS listener (port 8883) carries encrypted traffic that Suricata cannot decrypt without the broker's private key (which is not shared with Suricata in this deployment). Therefore, Suricata's MQTT application-layer parser applies only to:

- Any plaintext MQTT traffic observed on the LAN interface (which should not exist under the enforced configuration, and whose presence itself constitutes a detectable anomaly — see Rule SH-004 below)
- Connection metadata visible before the TLS handshake (client IP, packet timing, connection frequency)

TLS-layer metadata (certificate subject, negotiated cipher, protocol version) is extracted by Suricata's TLS parser from the handshake messages, which are transmitted in plaintext before the encrypted tunnel is established. This provides partial MQTT session visibility even on the encrypted port.

---

## 5. Ruleset

### 5.1 Community Ruleset — ET/Open

The Emerging Threats Open (ET/Open) community ruleset was installed via `suricata-update`:

```bash
sudo suricata-update
sudo suricata-update enable-source et/open
sudo suricata-update
```

ET/Open provides approximately 40,000 signatures covering known malware command-and-control patterns, exploit payloads, scanning tools, and protocol abuse. Rules relevant to the smart home deployment include the SSH scanning category, generic TCP SYN flood detection, and DNS anomaly rules.

### 5.2 Custom Rules — `smarthome.rules`

Project-specific rules were authored at `/etc/suricata/rules/smarthome.rules` to address threat scenarios specific to the smart home architecture. Each rule is annotated with its detection logic and mapping to the [[11.2_Methodology_and_Implementation|Red Team exercise]] that validated it.

```suricata
# ════════════════════════════════════════════════════════════════════
# FILE: /etc/suricata/rules/smarthome.rules
# PROJECT: Hybrid Edge-Computing AI Smart Home
# AUTHOR: Abdelrahman Ashraf Selim
# ════════════════════════════════════════════════════════════════════

# ── SH-001: Plain MQTT on LAN Interface ─────────────────────────────
# Fires if an MQTT CONNECT packet is observed on the LAN interface
# on port 1883 (the plaintext listener). Under the enforced config,
# port 1883 is bound to 127.0.0.1 and is unreachable from the LAN.
# Any such packet indicates either a misconfigured device, a rogue
# device, or an attacker attempting to bypass TLS.
# Maps to: Red Team Exercise — ACL verification (indirect)
# MITRE: T1040 — Network Sniffing (setup step for interception)
alert tcp $EXTERNAL_NET any -> $MQTT_SERVERS 1883 (
  msg:"SMARTHOME: Unencrypted MQTT CONNECT on LAN interface";
  flow:established,to_server;
  content:"|10|";
  offset:0;
  depth:1;
  classtype:policy-violation;
  sid:9000001;
  rev:1;
  metadata:author Selim, project SmartHome;
)

# ── SH-002: MQTT Connection Flood ────────────────────────────────────
# Detects more than 20 TCP SYN packets to port 8883 from the same
# source IP within a 60-second window. Legitimate ESP32 devices
# connect once at boot. This pattern indicates either a connection
# flood DoS attempt or automated credential scanning.
# MITRE: T1499 — Endpoint Denial of Service
alert tcp $EXTERNAL_NET any -> $MQTT_SERVERS 8883 (
  msg:"SMARTHOME: MQTT port connection flood detected";
  flags:S;
  threshold:type both, track by_src, count 20, seconds 60;
  classtype:attempted-dos;
  sid:9000002;
  rev:1;
  metadata:author Selim, project SmartHome;
)

# ── SH-003: Oversized MQTT Payload ───────────────────────────────────
# Fires on MQTT PUBLISH packets with a payload length field
# indicating more than 10,000 bytes. Legitimate smart home sensor
# payloads are JSON objects under 512 bytes. An oversized payload
# may indicate data exfiltration via the MQTT channel or an
# attempt to exploit a broker buffer handling vulnerability.
# Note: Applies to plaintext MQTT only (TLS payload is opaque).
# MITRE: T1030 — Data Transfer Size Limits (evasion variant)
alert mqtt any any -> $MQTT_SERVERS any (
  msg:"SMARTHOME: Oversized MQTT payload — possible exfiltration";
  mqtt.publish.payload_length:>10000;
  classtype:policy-violation;
  sid:9000003;
  rev:1;
  metadata:author Selim, project SmartHome;
)

# ── SH-004: Port Scan Targeting MQTT TLS Port ────────────────────────
# Detects TCP SYN packets to port 8883 not followed by a completed
# handshake, characteristic of port scanner probing (nmap SYN scan).
# This rule provides pre-authentication detection: the scanner never
# presents credentials to Mosquitto, so no Wazuh MQTT rule would fire.
# Validated in Red Team Exercise 4.
# MITRE: T1046 — Network Service Discovery
alert tcp $EXTERNAL_NET any -> $MQTT_SERVERS 8883 (
  msg:"SMARTHOME: Port scan detected against MQTT TLS port 8883";
  flags:S;
  flow:stateless;
  threshold:type threshold, track by_src, count 3, seconds 10;
  classtype:network-scan;
  sid:9000004;
  rev:1;
  metadata:author Selim, project SmartHome;
)

# ── SH-005: SSH Brute Force on Hardened Port ─────────────────────────
# Detects repeated TCP SYN attempts to the hardened SSH port 2222.
# Complements the Fail2ban sshd jail and Wazuh built-in rule 5712
# by providing a network-layer detection point independent of the
# auth.log parsing chain.
# MITRE: T1110 — Brute Force
alert tcp $EXTERNAL_NET any -> $HOME_NET 2222 (
  msg:"SMARTHOME: SSH brute force targeting hardened SSH port 2222";
  flags:S;
  threshold:type both, track by_src, count 10, seconds 60;
  classtype:attempted-admin;
  sid:9000005;
  rev:1;
  metadata:author Selim, project SmartHome;
)

# ── SH-006: DNS Exfiltration — Long Query Name ───────────────────────
# Detects DNS queries with an unusually long QNAME (>100 characters).
# DNS exfiltration encodes stolen data in subdomain labels of DNS
# queries to an attacker-controlled domain, generating queries with
# QNAME lengths far exceeding legitimate hostnames.
# MITRE: T1048.003 — Exfiltration Over Unencrypted Non-C2 Protocol
alert dns $HOME_NET any -> any 53 (
  msg:"SMARTHOME: Possible DNS exfiltration — abnormally long query";
  dns.query;
  pcre:"/^.{100}/";
  classtype:policy-violation;
  sid:9000006;
  rev:1;
  metadata:author Selim, project SmartHome;
)

# ── SH-007: Unexpected Outbound Port ─────────────────────────────────
# The PC Server should only initiate outbound connections on:
# 443 (ThingsBoard HTTPS), 8883 (MQTT to cloud if applicable),
# 80/443 (apt updates), 53 (DNS).
# Any outbound connection on an unexpected port may indicate
# a reverse shell or command-and-control channel.
# MITRE: T1071 — Application Layer Protocol (C2)
alert tcp $MQTT_SERVERS any -> $EXTERNAL_NET !443 (
  msg:"SMARTHOME: Unexpected outbound TCP connection from edge server";
  flow:established,to_server;
  threshold:type limit, track by_dst, count 1, seconds 300;
  classtype:policy-violation;
  sid:9000007;
  rev:1;
  metadata:author Selim, project SmartHome;
)
```

### 5.3 Rule Validation Procedure

Before enabling the service, all rules — both ET/Open and custom — were validated with Suricata's built-in configuration test:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v 2>&1 | tail -5
# Expected: "Configuration provided was successfully loaded."
```

Custom rules were additionally unit-tested by replaying `pcap` traffic against the ruleset using `suricata -r capture.pcap` to confirm each rule fires on its intended traffic pattern before deployment to the live capture interface.

---

## 6. Integration with Wazuh

Suricata's `eve.json` is monitored by the [[Wazuh|Wazuh Agent]] as a JSON-format log source:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```

When Suricata writes an `alert` event to `eve.json`, the Wazuh Agent tails it within seconds (inotify-driven) and forwards the JSON document to the Wazuh Manager. The Manager applies Wazuh's built-in Suricata ruleset (rule group `86600+`) to generate a Wazuh-level alert from the Suricata event, making Suricata detections visible in the Wazuh Dashboard alongside host-based alerts. This dual visibility is the basis of the cross-tool correlation capability described in [[Splunk]].

---

## 7. Integration with Fail2ban

The `suricata` Fail2ban jail monitors `/var/log/suricata/fast.log` (Suricata's human-readable alert log, distinct from `eve.json`) for any alert entry. It is configured with `maxretry = 1`, meaning a single Suricata alert from a given source IP triggers an immediate UFW ban:

```ini
[suricata]
enabled  = true
filter   = suricata
logpath  = /var/log/suricata/fast.log
maxretry = 1
bantime  = 86400
```

This creates a direct pipeline from **network detection** (Suricata rule fires) to **network enforcement** (UFW drops all subsequent packets from that source), bypassing the need for operator intervention and providing autonomous perimeter closure within seconds of detection.

---

## 8. Operational Verification

```bash
# Confirm Suricata is running and capturing
sudo systemctl status suricata

# Watch live alerts
sudo tail -f /var/log/suricata/fast.log

# Watch live EVE JSON events (pretty-printed)
sudo tail -f /var/log/suricata/eve.json \
  | python3 -c "
import sys, json
for line in sys.stdin:
    try: print(json.dumps(json.loads(line), indent=2))
    except: pass
  " | head -60

# Count alerts by rule SID in the last 24 hours
sudo jq -r 'select(.event_type=="alert") | .alert.signature_id' \
  /var/log/suricata/eve.json \
  | sort | uniq -c | sort -rn | head -10

# Confirm community-id field is present
sudo jq '.community_id' /var/log/suricata/eve.json | head -5

# Test rule SH-004 (port scan) — run from a separate host
# nmap -sS -p 8883 192.168.1.100
# Then verify alert appears:
sudo grep "9000004" /var/log/suricata/fast.log | tail -3
```

---

## References

- OISF. *Suricata User Guide 7.x*. https://suricata.readthedocs.io/
- OISF. *Suricata EVE JSON Output Documentation*. https://suricata.readthedocs.io/en/latest/output/eve/
- OISF. *Suricata MQTT Application Layer Parser*. https://suricata.readthedocs.io/en/latest/protocols/mqtt.html
- Corelight. *Community ID Flow Hashing Specification*. https://github.com/corelight/community-id-spec
- Emerging Threats. *ET/Open Ruleset*. https://rules.emergingthreats.net/open/
- MITRE Corporation. *ATT&CK for Enterprise v14*. https://attack.mitre.org/
