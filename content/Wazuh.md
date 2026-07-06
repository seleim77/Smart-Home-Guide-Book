---
title: Wazuh — Architecture, Deployment, and Custom Ruleset
aliases:
  - Wazuh HIDS
  - Wazuh Ruleset
  - Wazuh Agent
  - Wazuh Manager
tags:
  - cybersecurity
  - wazuh
  - hids
  - siem
  - fim
  - mitre-attack
  - mqtt
  - smart-home
date: 2025-06-29
author: Abdelrahman Ashraf Selim
related:
  - "[[11.1_Preparation_Studies_and_Tools]]"
  - "[[11.2_Methodology_and_Implementation]]"
  - "[[Suricata]]"
  - "[[Splunk]]"
---

# Wazuh — Architecture, Deployment, and Custom Ruleset

## 1. Introduction and Role in the Security Stack

[[Wazuh|Wazuh]] occupies the **host-based detection layer** of the smart home cybersecurity architecture — the fourth of the five concentric defence rings defined in [[11.2_Methodology_and_Implementation#11.2.1 Multi-Layered Defense Architecture and Hardware Integration|Section 11.2.1]]. Where [[Suricata|Suricata]] inspects packets traversing the network interface before they reach any application, Wazuh operates *inside* the [[PC Server]] host, monitoring the filesystem, process table, active log streams, and system call audit trail for evidence of compromise that has already bypassed the network perimeter.

Wazuh was deployed in version `4.14.5-1` across four interdependent components, all co-located on the single Ubuntu 24.04 edge server due to the single-host constraint of the graduation project. This document details the architecture of each component, the full configuration applied, and the complete custom detection ruleset authored specifically for the smart home threat model.

---

## 2. Component Architecture

### 2.1 Deployment Topology

All four Wazuh components run on the [[PC Server]] as independent `systemd` services. Their dependency and communication relationships are as follows:

```
┌─────────────────────────────────────────────────────┐
│                   PC Server (Ubuntu 24.04)           │
│                                                      │
│  ┌─────────────┐    alerts     ┌──────────────────┐  │
│  │ wazuh-agent │ ─────────────►│  wazuh-manager   │  │
│  │  (port 1514)│               │  (API: port 55000)│  │
│  └─────────────┘               └────────┬─────────┘  │
│    monitors:                            │ indexes     │
│    - /var/log/*                         ▼             │
│    - /etc/mosquitto                ┌──────────────┐  │
│    - /opt/smarthome                │wazuh-indexer │  │
│    - inotify FIM                   │  (port 9200) │  │
│                                    └──────┬───────┘  │
│                                           │ queries   │
│                                           ▼           │
│                                    ┌──────────────┐  │
│                                    │wazuh-dashboard│  │
│                                    │  (port 443)  │  │
│                                    └──────────────┘  │
└─────────────────────────────────────────────────────┘
```

### 2.2 Wazuh Indexer

**Package:** `wazuh-indexer`
**Port:** `9200/tcp`
**Bound interface:** `[::ffff:127.0.0.1]` (loopback only)
**Technology base:** OpenSearch

The Wazuh Indexer is the persistent data store for all processed alert output. It receives structured JSON alert documents from the Wazuh Manager and writes them into time-sharded indices, retaining them for the configured retention period. The binding to the loopback IPv4-mapped IPv6 address (`[::ffff:127.0.0.1]`) ensures the raw alert corpus is inaccessible from any LAN-facing interface — a critical constraint given that alert data contains the detailed behavioural fingerprint of the entire smart home system.

Health is verified with:

```bash
curl -sk -u admin:admin \
  https://127.0.0.1:9200/_cluster/health?pretty
# Expected: "status": "yellow" (single-node, no replica shards)
```

### 2.3 Wazuh Manager

**Package:** `wazuh-manager`
**Ports:** `55000/tcp` (REST API), `1514/tcp` (agent event data), `1515/tcp` (agent registration)

The Manager is the analytical core. Its processing pipeline for each incoming event is:

1. **Receive** raw log line forwarded by the Agent over port 1514
2. **Pre-decode** — extract the program name and hostname from the syslog header
3. **Decode** — apply matching decoder from `/var/ossec/etc/decoders/` to extract structured fields (e.g., `srcip`, `extra_data`, `url`)
4. **Rule matching** — evaluate extracted fields against the rule set in `/var/ossec/etc/rules/`
5. **Alert generation** — if a rule matches, write a JSON alert document to `/var/ossec/logs/alerts/alerts.json`
6. **Active response** (if configured) — invoke a response script (e.g., `firewall-drop`) based on the matched rule ID

The Manager was the component most affected by deployment complications during the project — a prior partial removal left the package in `dpkg` state `rc` (removed, config files remaining), which caused `systemd` to have no service unit for `wazuh-manager` despite the Indexer and Dashboard reporting healthy status. Resolution required `sudo apt purge -y wazuh-manager` to remove residual state, followed by clean reinstallation.

### 2.4 Wazuh Agent

**Package:** `wazuh-agent`
**Agent ID on this deployment:** `001`
**Manager target:** `127.0.0.1`

The Agent runs on the [[PC Server]] itself, making the server simultaneously a security monitoring platform and a monitored endpoint. This is methodologically sound: the Agent's host-level visibility (filesystem events, process spawning, log tailing) is precisely what provides detection coverage for the attack scenarios that would evade network-level controls — specifically, insider-threat scenarios and attacks that have already established a foothold on the host.

The Agent communicates with the Manager over the loopback interface on port 1514, ensuring the agent-manager channel is not exposed to the LAN segment.

### 2.5 Wazuh Dashboard

**Package:** `wazuh-dashboard`
**Port:** `443/tcp`
**Technology base:** OpenSearch Dashboards

The Dashboard provides the primary operational interface for Blue Team activity. It communicates exclusively with the Manager via the port 55000 REST API using the `wazuh-wui` service account, whose password was reset to a project-defined value using `/var/ossec/bin/wazuh-passwords-tool` post-deployment. The Dashboard is restricted to loopback access via UFW (`ufw allow from 127.0.0.1 to any port 443`) and is accessible only through a local browser session on the server.

---

## 3. Log Collection Configuration

The Agent's `ossec.conf` was extended with `<localfile>` directives targeting every security-relevant log source in the smart home stack. The rationale for each monitor target is documented below:

```xml
<!-- /var/log/auth.log
     SSH authentication events. Source for the built-in Wazuh
     rule 5712 (SSH brute force) and active-response triggering. -->
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/auth.log</location>
</localfile>

<!-- /var/log/mosquitto/mosquitto.log
     MQTT broker events. Source for custom rules 100001-100010.
     log_format is syslog because our custom decoder handles
     the Mosquitto-specific line structure within that wrapper. -->
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/mosquitto/mosquitto.log</location>
</localfile>

<!-- /var/log/suricata/eve.json
     Suricata unified event log in JSON format.
     log_format json enables native JSON field extraction
     without requiring a regex decoder for Suricata events. -->
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>

<!-- /var/log/fail2ban.log
     Fail2ban ban/unban events. Provides SIEM visibility into
     the automated response layer's enforcement decisions. -->
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/fail2ban.log</location>
</localfile>

<!-- /var/log/ufw.log
     UFW firewall drop events. Every packet rejected by the
     default-deny policy generates an entry here, providing
     visibility into unsolicited inbound connection attempts. -->
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/ufw.log</location>
</localfile>

<!-- /var/log/syslog
     General system log. Captures service start/stop events
     and kernel-level messages not appearing in auth.log. -->
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/syslog</location>
</localfile>
```

---

## 4. File Integrity Monitoring Configuration

### 4.1 Design Rationale

FIM is the host-level equivalent of a tamper-evident seal. It establishes a cryptographic baseline of each monitored file's content (SHA-256 hash), ownership (`uid`/`gid`), permissions (`chmod` value), and `inode`, then alerts on any deviation from that baseline. In the context of this architecture, FIM serves two primary detection purposes:

1. **Configuration integrity** — detecting unauthorised changes to the Mosquitto broker, Suricata, or Fail2ban configurations that would weaken the security posture (e.g., re-enabling anonymous MQTT access, removing a Suricata rule, or reducing a Fail2ban `bantime`).
2. **Credential infrastructure integrity** — detecting TLS certificate substitution as the preparatory step of a Man-in-the-Middle attack against the MQTT TLS listener.

### 4.2 Monitored Directory Set

The `<syscheck>` block in `ossec.conf` was configured as follows:

```xml
<syscheck>
  <!-- Scan frequency for non-realtime directories (seconds) -->
  <frequency>300</frequency>

  <!-- Alert when new files are created in monitored directories -->
  <alert_new_files>yes</alert_new_files>

  <!-- MQTT broker configuration — realtime via inotify
       Detects: allow_anonymous re-enabled, ACL file modified,
       password file replaced, TLS configuration weakened -->
  <directories check_all="yes" report_changes="yes" realtime="yes">
    /etc/mosquitto
  </directories>

  <!-- TLS certificate directory — realtime via inotify
       Detects: certificate substitution (MITM setup),
       private key replacement, CA certificate tampering.
       Maps to Wazuh rule 100006 at severity level 14. -->
  <directories check_all="yes" report_changes="yes" realtime="yes">
    /etc/mosquitto/certs
  </directories>

  <!-- AI engine source code — realtime via inotify
       The ai_engine identity holds the broadest MQTT ACL
       (read home/sensors/#, write home/actuators/#).
       Unauthorised modification of this code is treated as
       a critical-severity event for this reason. -->
  <directories check_all="yes" report_changes="yes" realtime="yes">
    /opt/smarthome
  </directories>

  <!-- Security tool configurations — 5-minute poll
       Detects: Fail2ban jail removal, Suricata rule deletion,
       SSH config weakening. 5-minute polling accepted here
       as these directories are not active attack targets. -->
  <directories check_all="yes" report_changes="yes">
    /etc/fail2ban
  </directories>
  <directories check_all="yes" report_changes="yes">
    /etc/suricata
  </directories>
  <directories check_all="yes" report_changes="yes">
    /etc/ssh
  </directories>

  <!-- Wazuh's own rule and decoder files
       Prevents an attacker who gains host access from
       silently disabling detection rules. -->
  <directories check_all="yes" report_changes="yes">
    /var/ossec/etc/rules
  </directories>
  <directories check_all="yes" report_changes="yes">
    /var/ossec/etc/decoders
  </directories>

  <!-- Exclude high-churn runtime files to suppress false positives -->
  <ignore>/var/log</ignore>
  <ignore>/etc/mosquitto/passwd</ignore>
</syscheck>
```

### 4.3 The realtime="yes" Directive

The `realtime="yes"` attribute replaces the default poll-based scanning (which runs every `<frequency>` seconds) with an `inotify`-based kernel event subscription. `inotify` is a Linux kernel subsystem that generates events synchronously at the moment a filesystem operation occurs — a file write, rename, permission change, or deletion — rather than waiting for a scheduled scan cycle. The practical implication for the TLS certificate directory is that the time-to-detection for a certificate substitution is bounded by the Wazuh event processing pipeline latency (typically 1–3 seconds), rather than up to 300 seconds for a polled scan. This distinction was validated empirically during Red Team Exercise 3 (described in [[11.2_Methodology_and_Implementation#Exercise 3 — TLS Certificate Tampering Simulation (T1557)|Section 11.2.4]]).

---

## 5. Custom Decoder — `mosquitto_decoder.xml`

### 5.1 Decoder Hierarchy

Wazuh's decoding engine uses a parent-child hierarchy: a root (parent) decoder identifies that a log line belongs to a given source, and child decoders perform field extraction on lines that have already been classified by the parent. The Mosquitto decoder set is structured as follows:

**Root decoder — timestamp anchor:**

```xml
<decoder name="mosquitto">
  <prematch>^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}:</prematch>
</decoder>
```

The `<prematch>` regex anchors on the ISO 8601 timestamp at the start of every Mosquitto log line (format `%Y-%m-%dT%H:%M:%S:`, enforced by `log_timestamp_format %Y-%m-%dT%H:%M:%S` in `mosquitto.conf`). Any log line beginning with this pattern is classified as a Mosquitto event and passed to the child decoders.

### 5.2 Child Decoders

```xml
<!-- New TCP connection (before authentication) -->
<decoder name="mosquitto-new-connection">
  <parent>mosquitto</parent>
  <regex>New connection from (\S+) on port (\d+)</regex>
  <order>srcip, dstport</order>
</decoder>

<!-- Successful authenticated session established -->
<decoder name="mosquitto-client-connected">
  <parent>mosquitto</parent>
  <regex>New client connected from (\S+) as (\S+) \(</regex>
  <order>srcip, extra_data</order>
</decoder>

<!-- Authentication failure — credential invalid or not authorised -->
<decoder name="mosquitto-auth-failure">
  <parent>mosquitto</parent>
  <regex>Client (\S+) failed to connect, not authorised</regex>
  <order>extra_data</order>
</decoder>

<!-- Clean client disconnection -->
<decoder name="mosquitto-disconnected">
  <parent>mosquitto</parent>
  <regex>Client (\S+) disconnected</regex>
  <order>extra_data</order>
</decoder>

<!-- Topic subscription event -->
<decoder name="mosquitto-subscribed">
  <parent>mosquitto</parent>
  <regex>Client (\S+) subscribed to (\S+), QoS (\d)</regex>
  <order>extra_data, url, id</order>
</decoder>

<!-- ACL denied — valid credential, forbidden topic -->
<decoder name="mosquitto-acl-denied">
  <parent>mosquitto</parent>
  <regex>ACL check denied access to topic '(\S+)' for client '(\S+)'</regex>
  <order>url, extra_data</order>
</decoder>

<!-- TLS/OpenSSL handshake error -->
<decoder name="mosquitto-tls-error">
  <parent>mosquitto</parent>
  <regex>OpenSSL Error: (.+)</regex>
  <order>extra_data</order>
</decoder>

<!-- Abnormal disconnection (no MQTT DISCONNECT packet) -->
<decoder name="mosquitto-socket-error">
  <parent>mosquitto</parent>
  <regex>Socket error on client (\S+), disconnecting</regex>
  <order>extra_data</order>
</decoder>
```

### 5.3 Field Extraction Mapping

| Decoder | Extracted Field | Wazuh Field Name | Used By Rule |
|---|---|---|---|
| `mosquitto-new-connection` | Source IP address | `srcip` | 100004 |
| `mosquitto-new-connection` | Destination port | `dstport` | — |
| `mosquitto-client-connected` | Source IP address | `srcip` | 100004 |
| `mosquitto-client-connected` | Client ID | `extra_data` | — |
| `mosquitto-auth-failure` | Client ID | `extra_data` | 100001, 100002 |
| `mosquitto-acl-denied` | Topic attempted | `url` | 100003 |
| `mosquitto-acl-denied` | Client ID | `extra_data` | 100003 |
| `mosquitto-tls-error` | OpenSSL error message | `extra_data` | 100007, 100008 |
| `mosquitto-socket-error` | Client ID | `extra_data` | 100009 |

---

## 6. Custom Rule Set — `smarthome_rules.xml`

### 6.1 Rule Design Principles

Three principles governed the authoring of custom rules:

1. **Proportional severity** — Rule severity levels (1–15 in Wazuh's scale) were assigned in proportion to the potential impact of the detected event. A single failed MQTT authentication (level 5) is treated as a normal operational event that may indicate a misconfigured device; the same pattern repeated five times in two minutes (level 10) is treated as a deliberate brute-force attempt. TLS certificate modification (level 14) is the highest severity rule in the set because it represents preparation for a cryptographic interception attack against all device communications simultaneously.

2. **MITRE ATT&CK alignment** — Every rule is tagged with the corresponding ATT&CK technique ID, enabling the Wazuh Dashboard's MITRE module to surface technique coverage and allowing [[Splunk]] correlation queries to reference standardised technique identifiers across tools.

3. **Escalation chaining** — Where appropriate, rules reference parent rule SIDs using `<if_matched_sid>`, creating frequency-based escalation chains (e.g., rule 100001 → 100002) that avoid alert fatigue from low-severity individual events while ensuring high-severity pattern alerts fire reliably.

### 6.2 Complete Rule Set with Annotation

```xml
<group name="smarthome,mqtt,authentication,">

  <!-- ════════════════════════════════════════════════════════
       RULE 100001 — MQTT Single Authentication Failure
       Severity: 5 (Low-Medium)
       Source decoder: mosquitto-auth-failure
       Fires on: single "failed to connect, not authorised" entry
       Notes: A single failure may indicate a misconfigured ESP32
       firmware with stale credentials. Logged but not alarming.
       MITRE: T1110 — Brute Force (credential attack family)
       ════════════════════════════════════════════════════════ -->
  <rule id="100001" level="5">
    <decoded_as>mosquitto-auth-failure</decoded_as>
    <description>MQTT: Client authentication failure on broker</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>

  <!-- ════════════════════════════════════════════════════════
       RULE 100002 — MQTT Brute Force Attack
       Severity: 10 (High)
       Escalation chain: if rule 100001 fires 5 times in 120s
       Active response: firewall-drop (bantime 3600s)
       Notes: A legitimate ESP32 device connects once at boot
       and maintains the session. Five authentication failures
       within two minutes is impossible under normal operation
       and unambiguously indicates a credential attack.
       MITRE: T1110.001 — Password Guessing
       ════════════════════════════════════════════════════════ -->
  <rule id="100002" level="10" frequency="5" timeframe="120">
    <if_matched_sid>100001</if_matched_sid>
    <description>MQTT: Brute force attack — 5+ auth failures in 2 minutes</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
  </rule>

  <!-- ════════════════════════════════════════════════════════
       RULE 100003 — MQTT ACL Boundary Violation
       Severity: 8 (Medium-High)
       Source decoder: mosquitto-acl-denied
       Fires on: valid credential attempting a forbidden topic
       Notes: Indicates either a compromised device credential
       being misused or a misconfigured firmware publishing to
       the wrong topic. Both require investigation.
       MITRE: T1078 — Valid Accounts (credential misuse)
       ════════════════════════════════════════════════════════ -->
  <rule id="100003" level="8">
    <decoded_as>mosquitto-acl-denied</decoded_as>
    <description>MQTT: ACL violation — client attempted unauthorized topic access</description>
    <mitre>
      <id>T1078</id>
    </mitre>
  </rule>

  <!-- ════════════════════════════════════════════════════════
       RULE 100004 — Anonymous MQTT Connection Attempt
       Severity: 6 (Medium)
       Source decoder: mosquitto-client-connected (match: unknown)
       Fires on: client presenting no credential
       Notes: allow_anonymous false is enforced in mosquitto.conf.
       Any anonymous attempt is rejected by the broker and should
       not occur from any legitimate project device.
       MITRE: T1133 — External Remote Services
       ════════════════════════════════════════════════════════ -->
  <rule id="100004" level="6">
    <decoded_as>mosquitto-client-connected</decoded_as>
    <match>unknown</match>
    <description>MQTT: Client connected with unknown/anonymous client ID</description>
    <mitre>
      <id>T1133</id>
    </mitre>
  </rule>

  <!-- ════════════════════════════════════════════════════════
       RULE 100005 — Mosquitto Configuration File Modified
       Severity: 12 (Critical)
       Parent SID: 550 (Wazuh built-in: file modified)
       Field match: file path contains /etc/mosquitto/
       Notes: Any change to the broker configuration in a
       production deployment must be authorised and documented.
       An unscheduled change is treated as potential sabotage
       of the security posture (e.g., re-enabling anonymous
       access or weakening the TLS version requirement).
       MITRE: T1565.001 — Stored Data Manipulation
       ════════════════════════════════════════════════════════ -->
  <rule id="100005" level="12">
    <if_sid>550</if_sid>
    <field name="file">/etc/mosquitto/</field>
    <description>CRITICAL: Mosquitto configuration file modified</description>
    <mitre>
      <id>T1565.001</id>
    </mitre>
  </rule>

  <!-- ════════════════════════════════════════════════════════
       RULE 100006 — TLS Certificate Directory Modified
       Severity: 14 (Critical — highest in custom rule set)
       Parent SIDs: 550, 554 (file modified / file added)
       Field match: file path contains /etc/mosquitto/certs/
       Notes: Modification of the certificate directory is the
       preparatory step for a MITM attack against the MQTT TLS
       listener. An adversary must introduce or replace a cert
       before they can intercept TLS sessions. Realtime FIM on
       this directory ensures sub-minute detection latency.
       Active response: host-deny (bantime 86400s)
       MITRE: T1557 — Adversary-in-the-Middle
       ════════════════════════════════════════════════════════ -->
  <rule id="100006" level="14">
    <if_sid>550,554</if_sid>
    <field name="file">/etc/mosquitto/certs/</field>
    <description>CRITICAL: MQTT TLS certificate modified — possible MITM setup</description>
    <mitre>
      <id>T1557</id>
    </mitre>
  </rule>

  <!-- ════════════════════════════════════════════════════════
       RULE 100007 — TLS Handshake Error
       Severity: 6 (Medium)
       Source decoder: mosquitto-tls-error
       Fires on: OpenSSL error during TLS negotiation
       Notes: A single TLS error may indicate a client using
       an outdated TLS library or presenting an invalid cert.
       The parent rule for frequency-based escalation in 100008.
       MITRE: T1040 — Network Sniffing
       ════════════════════════════════════════════════════════ -->
  <rule id="100007" level="6">
    <decoded_as>mosquitto-tls-error</decoded_as>
    <description>MQTT: TLS handshake error — cert mismatch or scanning</description>
    <mitre>
      <id>T1040</id>
    </mitre>
  </rule>

  <!-- ════════════════════════════════════════════════════════
       RULE 100008 — Repeated TLS Errors (Certificate Scanning)
       Severity: 9 (High)
       Escalation chain: if rule 100007 fires 5 times in 60s
       Notes: Repeated TLS handshake failures in rapid succession
       indicate an adversary probing the broker's TLS configuration,
       testing certificate validation strictness, or scanning for
       exploitable TLS implementation vulnerabilities.
       MITRE: T1595.002 — Active Scanning: Vulnerability Scanning
       ════════════════════════════════════════════════════════ -->
  <rule id="100008" level="9" frequency="5" timeframe="60">
    <if_matched_sid>100007</if_matched_sid>
    <description>MQTT: Multiple TLS errors — possible certificate scanning</description>
    <mitre>
      <id>T1595.002</id>
    </mitre>
  </rule>

  <!-- ════════════════════════════════════════════════════════
       RULE 100009 — Repeated Abnormal Disconnections
       Severity: 5 (Low-Medium — escalates to 7 by frequency)
       Source decoder: mosquitto-socket-error
       Escalation: 3 occurrences in 60s
       Notes: Socket errors without a preceding MQTT DISCONNECT
       packet indicate the TCP connection was terminated abruptly.
       Repeated occurrences from the same client may indicate a
       connection flood or network-layer DoS attempt.
       MITRE: T1499 — Endpoint Denial of Service
       ════════════════════════════════════════════════════════ -->
  <rule id="100009" level="5" frequency="3" timeframe="60">
    <decoded_as>mosquitto-socket-error</decoded_as>
    <description>MQTT: Repeated abnormal disconnections — possible connection flood</description>
    <mitre>
      <id>T1499</id>
    </mitre>
  </rule>

  <!-- ════════════════════════════════════════════════════════
       RULE 100010 — Mosquitto Broker Unexpected Restart
       Severity: 10 (High)
       Source decoder: mosquitto (root)
       Match: startup banner in log
       Notes: Fires every time Mosquitto starts. Expected once
       at system boot. Any additional firing outside scheduled
       maintenance indicates either a process crash (potential
       exploitation attempt) or deliberate service disruption.
       MITRE: T1489 — Service Stop
       ════════════════════════════════════════════════════════ -->
  <rule id="100010" level="10">
    <decoded_as>mosquitto</decoded_as>
    <match>mosquitto version .* running</match>
    <description>MQTT: Broker restarted — verify no tampering occurred</description>
    <mitre>
      <id>T1489</id>
    </mitre>
  </rule>

</group>
```

### 6.3 Rule Severity and Response Matrix

| Rule ID | Level | Response | Destination |
|---|---|---|---|
| 100001 | 5 | Log only | Wazuh Dashboard, Splunk `wazuh_alerts` |
| 100002 | 10 | `firewall-drop` (1 hour) | UFW ban via Wazuh active-response |
| 100003 | 8 | Log only | Wazuh Dashboard, Splunk `wazuh_alerts` |
| 100004 | 6 | Log only | Wazuh Dashboard |
| 100005 | 12 | Log + email (if configured) | Wazuh Dashboard, Splunk `wazuh_alerts` |
| 100006 | 14 | `host-deny` (24 hours) | UFW ban via Wazuh active-response |
| 100007 | 6 | Log only | Wazuh Dashboard |
| 100008 | 9 | Log only | Wazuh Dashboard, Splunk `wazuh_alerts` |
| 100009 | 5 | Log only | Wazuh Dashboard |
| 100010 | 10 | Log only | Wazuh Dashboard, Splunk `wazuh_alerts` |

---

## 7. Active Response Configuration

Active response blocks in `ossec.conf` instruct the Manager to invoke a named command script when a specified rule fires. The `firewall-drop` command is a built-in Wazuh active-response script that adds a `DROP` rule to `iptables` for the source IP extracted from the triggering alert.

```xml
<!-- Block source IP on MQTT brute force (rule 100002) -->
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100002</rules_id>
  <timeout>3600</timeout>
</active-response>

<!-- Block source IP on SSH brute force (built-in rule 5712) -->
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>5712</rules_id>
  <timeout>7200</timeout>
</active-response>

<!-- Host deny on TLS certificate tampering (rule 100006) -->
<active-response>
  <command>host-deny</command>
  <location>local</location>
  <rules_id>100006</rules_id>
  <timeout>86400</timeout>
</active-response>
```

---

## 8. Alert Output and Splunk Forwarding

All Wazuh alerts are written to `/var/ossec/logs/alerts/alerts.json` in NDJSON format (one JSON document per line). Each document includes the full decoded fields, the matched rule metadata (ID, level, description, MITRE technique), the agent ID and hostname, and the original log line. This file is simultaneously monitored by:

1. **Wazuh Indexer** — for Dashboard visualisation
2. **Splunk universal monitor** — for ingestion into the `wazuh_alerts` index (see [[Splunk]])
3. **Splunk HEC integration** — for real-time push via the `<integration>` block in `ossec.conf` (forwarding all alerts at level ≥ 3)

The combination of file-based monitoring and HEC push provides both bulk historical ingestion and near-real-time streaming, ensuring the [[Splunk|Splunk SIEM]] always reflects the current alert state.

---

## 9. Operational Verification Queries

```bash
# Confirm all four components are active
sudo systemctl is-active \
  wazuh-indexer wazuh-manager wazuh-dashboard wazuh-agent

# Confirm agent 001 is registered and active
sudo /var/ossec/bin/agent_control -l

# Test decoder against a sample Mosquitto auth failure line
sudo /var/ossec/bin/ossec-logtest
# Paste: 2024-01-15T14:32:07: Client hacker failed to connect, not authorised.
# Expected output: Rule: 100001 (level 5) — MQTT: Client authentication failure

# Confirm alerts are being written
sudo tail -5 /var/ossec/logs/alerts/alerts.json | python3 -m json.tool

# Count alerts by rule ID in the last 24 hours
sudo grep '"id":"1000' /var/ossec/logs/alerts/alerts.json \
  | python3 -c "
import sys, json, collections
c = collections.Counter()
for line in sys.stdin:
    try:
        d = json.loads(line)
        c[d['rule']['id']] += 1
    except: pass
for k,v in sorted(c.items()): print(f'Rule {k}: {v} alerts')
"
```

---

## References

- Wazuh Inc. *Wazuh 4.x Documentation — Manager Configuration*. https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/
- Wazuh Inc. *Wazuh 4.x Documentation — Custom Rules and Decoders*. https://documentation.wazuh.com/current/user-manual/ruleset/
- MITRE Corporation. *ATT&CK for Enterprise v14*. https://attack.mitre.org/
- Linux man pages. *inotify(7)*. https://man7.org/linux/man-pages/man7/inotify.7.html
