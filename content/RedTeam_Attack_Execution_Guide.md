---
title: "Red Team — Internal Attack Execution Guide"
aliases:
  - "Attack Execution Guide"
  - "Red Team Playbook"
  - "Penetration Test Commands"
tags:
  - cybersecurity
  - red-team
  - penetration-testing
  - mqtt
  - wazuh
  - suricata
  - validation
date: 2025-06-29
author: "Abdelrahman Ashraf Selim"
related:
  - "[[11.2_Methodology_and_Implementation]]"
  - "[[11.3_Results]]"
  - "[[Wazuh_Architecture_and_Ruleset]]"
  - "[[Suricata_Network_Inspection]]"
warning: "FOR INTERNAL VALIDATION ONLY — All exercises must be conducted exclusively against project-owned hardware on the isolated test network. No external targets."
---

# Red Team — Internal Attack Execution Guide

> **SCOPE DECLARATION:** All five exercises documented here were conducted exclusively against the project's isolated LAN (`192.168.1.0/24`) using only project-owned hardware. No external systems, public networks, or third-party infrastructure were targeted at any point. This guide exists solely for academic validation of the Blue Team defensive controls described in [[11.2_Methodology_and_Implementation]].

---

## Pre-Exercise Setup

### Required Tools

Install all tools on the **attacker machine** (a second host on the same LAN, or the server itself using loopback — noted per exercise):

```bash
# On Ubuntu/Debian attacker machine
sudo apt update
sudo apt install -y \
  nmap \
  mosquitto-clients \
  hydra \
  python3 \
  netcat-openbsd \
  hping3 \
  curl

# Verify mosquitto_pub is available
mosquitto_pub --help 2>&1 | head -2
# Expected: mosquitto_pub is a simple mqtt client...

# Verify nmap version (need 7.x for service detection)
nmap --version | head -1
```

### Target Reference

| Variable | Value |
|---|---|
| Target (PC Server) IP | `192.168.1.100` |
| MQTT TLS port | `8883` |
| MQTT plain port | `1883` (localhost only) |
| SSH port | `2222` |
| CA certificate path (on server) | `/etc/mosquitto/certs/ca.crt` |
| Valid ESP32 credential | `esp32_sensor_1` / `[password]` |

### Pre-Exercise Monitoring Terminal Layout

Open **four terminal windows** on the [[PC Server]] before running any exercise. Keep them all visible simultaneously:

```bash
# Terminal 1 — Mosquitto log live tail
sudo tail -f /var/log/mosquitto/mosquitto.log

# Terminal 2 — Suricata fast alert log
sudo tail -f /var/log/suricata/fast.log

# Terminal 3 — Fail2ban live log
sudo tail -f /var/log/fail2ban.log

# Terminal 4 — Wazuh alert stream (JSON, filtered to custom rules)
sudo tail -f /var/ossec/logs/alerts/alerts.json \
  | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        d = json.loads(line)
        rid = str(d.get('rule',{}).get('id',''))
        if rid.startswith('1000') or int(rid or 0) in [5712,86601]:
            print(f\"[WAZUH] Rule {rid} Level {d['rule']['level']}: {d['rule']['description']}\")
    except: pass
"
```

---

## Exercise 1 — MQTT Credential Brute Force (T1110.001)

### Objective

Trigger Wazuh rules `100001` (single failure, level 5) and `100002` (brute force confirmed, level 10), and cause Fail2ban's `mosquitto` jail to ban the attacker IP.

### Tools Required

- `mosquitto_pub` (mosquitto-clients package)
- `bash` scripting loop
- Optionally: `hydra` for higher-volume simulation

### Step 1 — Copy CA Certificate to Attacker Machine

The TLS listener on port 8883 requires the CA cert to establish the TLS session even before authentication. Without it the connection is refused at the TLS layer and no authentication attempt reaches Mosquitto, meaning no log entry is generated.

```bash
# From attacker machine — copy CA cert from server
scp user@192.168.1.100:/etc/mosquitto/certs/ca.crt ~/mqtt-ca.crt

# Verify
ls -lh ~/mqtt-ca.crt
```

### Step 2 — Run the Brute Force Loop

```bash
#!/bin/bash
# Save as: ~/mqtt_bruteforce.sh
# chmod +x ~/mqtt_bruteforce.sh

TARGET="192.168.1.100"
PORT="8883"
CA_CERT="$HOME/mqtt-ca.crt"
TARGET_USER="esp32_sensor_1"   # valid username, invalid passwords
ATTEMPTS=8
DELAY=10  # seconds between attempts (stay within 120s window for rule 100002)

echo "[*] Starting MQTT brute force simulation against $TARGET:$PORT"
echo "[*] $ATTEMPTS attempts with ${DELAY}s intervals"
echo "[*] Watch Terminal 1 (mosquitto.log) and Terminal 4 (wazuh alerts)"
echo ""

for i in $(seq 1 $ATTEMPTS); do
  FAKE_PASS="wrongpassword_attempt_${i}"
  echo "[$(date +%H:%M:%S)] Attempt $i/$ATTEMPTS — user: $TARGET_USER pass: $FAKE_PASS"

  mosquitto_pub \
    -h "$TARGET" \
    -p "$PORT" \
    --cafile "$CA_CERT" \
    -u "$TARGET_USER" \
    -P "$FAKE_PASS" \
    -t "home/sensors/esp32_1/test" \
    -m "{\"attempt\": $i}" \
    --tls-version tlsv1.3 \
    2>&1 | grep -v "^$"

  sleep $DELAY
done

echo ""
echo "[*] Brute force sequence complete."
echo "[*] Check Fail2ban: sudo fail2ban-client status mosquitto"
```

```bash
chmod +x ~/mqtt_bruteforce.sh
bash ~/mqtt_bruteforce.sh
```

### Step 3 — Verify with Hydra (Optional Higher-Volume Test)

```bash
# Generate a small wordlist for hydra
printf "wrongpass1\nwrongpass2\nwrongpass3\nwrongpass4\nwrongpass5\nadmin\npassword\n123456\n" \
  > ~/mqtt_passwords.txt

# Hydra MQTT brute force
# Note: hydra's mqtt module sends over plain TCP — use against port 1883 locally
# For TLS testing, use the bash loop above against port 8883
hydra \
  -l esp32_sensor_1 \
  -P ~/mqtt_passwords.txt \
  -s 1883 \
  -t 1 \
  192.168.1.100 mqtt \
  -V
```

### Expected Log Entries

**Terminal 1 — `/var/log/mosquitto/mosquitto.log`:**

```
2024-01-15T14:32:07: New connection from 192.168.1.200 on port 8883.
2024-01-15T14:32:07: Client esp32_sensor_1 failed to connect, not authorised.
2024-01-15T14:32:17: New connection from 192.168.1.200 on port 8883.
2024-01-15T14:32:17: Client esp32_sensor_1 failed to connect, not authorised.
[... repeated ...]
```

**Terminal 3 — `/var/log/fail2ban.log`:**

```
2024-01-15 14:33:07,412 fail2ban.actions [PID]: NOTICE  [mosquitto] Ban 192.168.1.200
```

**Terminal 4 — Wazuh alert stream:**

```
[WAZUH] Rule 100001 Level 5: MQTT: Client authentication failure on broker
[WAZUH] Rule 100001 Level 5: MQTT: Client authentication failure on broker
[WAZUH] Rule 100001 Level 5: MQTT: Client authentication failure on broker
[WAZUH] Rule 100001 Level 5: MQTT: Client authentication failure on broker
[WAZUH] Rule 100001 Level 5: MQTT: Client authentication failure on broker
[WAZUH] Rule 100002 Level 10: MQTT: Brute force attack — 5+ auth failures in 2 minutes
```

### Step 4 — Verify Ban and Cleanup

```bash
# On the server — confirm ban is active
sudo fail2ban-client status mosquitto
# Expected output includes: "Banned IP list: 192.168.1.200"

# Confirm UFW rule was added
sudo ufw status | grep 192.168.1.200
# Expected: 192.168.1.200 DENY IN Anywhere

# CLEANUP — unban before next exercise
sudo fail2ban-client set mosquitto unbanip 192.168.1.200
```

---

## Exercise 2 — MQTT ACL Boundary Violation (T1078)

### Objective

Using a **valid, legitimately issued credential** (`esp32_sensor_1`), attempt to publish to a topic outside its ACL scope (`home/sensors/esp32_2/`). Confirm Wazuh rule `100003` fires.

### Context

This exercise simulates the scenario where an attacker has extracted credential from an [[ESP32]] device (e.g., via UART flash dump) but has not compromised the broker itself. It validates that **authentication and authorisation are enforced as independent controls**.

### Step 1 — Establish a Baseline (Authorised Publish)

First confirm the credential works for its legitimate topic:

```bash
# This SHOULD succeed — esp32_sensor_1's authorised topic
mosquitto_pub \
  -h 192.168.1.100 \
  -p 8883 \
  --cafile ~/mqtt-ca.crt \
  -u esp32_sensor_1 \
  -P "YOUR_ESP32_1_PASSWORD" \
  -t "home/sensors/esp32_1/dht22" \
  -m '{"temp": 24.5, "humidity": 61.0, "test": "authorised_baseline"}' \
  --tls-version tlsv1.3 \
  -d
# Expected last line: "Client null sending PUBLISH..."
# Mosquitto log: "Sending PUBLISH to [subscriber]..." — publish accepted
```

### Step 2 — Attempt Cross-Device Topic Write (ACL Violation)

```bash
# This SHOULD be rejected by ACL
# esp32_sensor_1 attempting to write to esp32_sensor_2's topic
mosquitto_pub \
  -h 192.168.1.100 \
  -p 8883 \
  --cafile ~/mqtt-ca.crt \
  -u esp32_sensor_1 \
  -P "YOUR_ESP32_1_PASSWORD" \
  -t "home/sensors/esp32_2/dht22" \
  -m '{"temp": 99.9, "injected": true}' \
  --tls-version tlsv1.3 \
  -d
# Connection will succeed (auth valid), publish will be silently dropped by ACL
```

### Step 3 — Attempt Cross-Device Topic Subscription (ACL Violation)

```bash
# esp32_sensor_1 attempting to subscribe to esp32_sensor_3's actuator topic
mosquitto_sub \
  -h 192.168.1.100 \
  -p 8883 \
  --cafile ~/mqtt-ca.crt \
  -u esp32_sensor_1 \
  -P "YOUR_ESP32_1_PASSWORD" \
  -t "home/actuators/esp32_3/#" \
  --tls-version tlsv1.3 \
  -d \
  -C 1 \
  -W 5
# -C 1 = receive 1 message then exit
# -W 5 = timeout after 5 seconds
```

### Step 4 — Systematic Topic Enumeration (Elevated Threat Simulation)

```bash
#!/bin/bash
# Simulate an attacker with stolen credentials systematically
# probing the topic namespace. This generates multiple 100003 alerts.

CA="$HOME/mqtt-ca.crt"
TARGET="192.168.1.100"
TOPICS=(
  "home/sensors/esp32_2/dht22"
  "home/sensors/esp32_3/door"
  "home/sensors/esp32_4/power"
  "home/actuators/esp32_2/relay"
  "home/actuators/esp32_3/lock"
  "home/ai/decisions"
  "home/#"
)

for TOPIC in "${TOPICS[@]}"; do
  echo "[*] Attempting publish to: $TOPIC"
  mosquitto_pub \
    -h "$TARGET" -p 8883 \
    --cafile "$CA" \
    -u esp32_sensor_1 \
    -P "YOUR_ESP32_1_PASSWORD" \
    -t "$TOPIC" \
    -m '{"probe":true}' \
    --tls-version tlsv1.3 2>&1
  sleep 2
done
```

### Expected Log Entries

**Terminal 1 — `/var/log/mosquitto/mosquitto.log`:**

```
2024-01-15T14:40:01: New client connected from 192.168.1.200 as esp32_sensor_1 (...)
2024-01-15T14:40:01: ACL check denied access to topic 'home/sensors/esp32_2/dht22' for client 'esp32_sensor_1'
2024-01-15T14:40:03: ACL check denied access to topic 'home/actuators/esp32_3/lock' for client 'esp32_sensor_1'
```

**Terminal 4 — Wazuh alert stream:**

```
[WAZUH] Rule 100003 Level 8: MQTT: ACL violation — client attempted unauthorized topic access
[WAZUH] Rule 100003 Level 8: MQTT: ACL violation — client attempted unauthorized topic access
```

> **Note:** Fail2ban does **not** auto-ban on rule 100003 — this is by design. ACL violations are logged and alerted but not automatically blocked, since the source may be a legitimately-owned but misconfigured device. Human review is required before a ban decision.

---

## Exercise 3 — TLS Certificate Tampering (T1557)

### Objective

Write a file into `/etc/mosquitto/certs/` to simulate the preparatory phase of a MITM attack. Validate that Wazuh's realtime FIM detects the change within seconds and fires rule `100006` at level 14.

### Step 1 — Generate a Fake Certificate (on the server)

```bash
# Generate a dummy certificate that an attacker might try to substitute
openssl req -newkey rsa:2048 -nodes \
  -keyout /tmp/fake_attacker.key \
  -x509 -days 1 \
  -out /tmp/fake_attacker.crt \
  -subj "/CN=FakeMITMCert/O=Attacker" \
  2>/dev/null

echo "[*] Fake certificate generated at /tmp/fake_attacker.crt"
echo "[*] Simulating attacker copying cert into /etc/mosquitto/certs/"
echo "[*] Watch Terminal 4 for rule 100006 — should fire within 3 seconds"
```

### Step 2 — Execute the Tamper (Triggers FIM)

```bash
# Record exact time before the action
echo "[*] T_write = $(date +%T.%N)"

# Simulate certificate introduction
sudo cp /tmp/fake_attacker.crt /etc/mosquitto/certs/fake_attacker.crt

# Record time immediately after
echo "[*] T_write_complete = $(date +%T.%N)"
echo "[*] Now waiting for Wazuh FIM alert..."
```

### Step 3 — Measure Time-to-Detection

```bash
# On the server — watch for the FIM alert in Wazuh alerts with timestamp
sudo tail -f /var/ossec/logs/alerts/alerts.json \
  | python3 -c "
import sys, json, time

write_time = time.time()
print(f'Monitoring for FIM alert... (write time: {time.strftime(\"%H:%M:%S\", time.localtime(write_time))})')

for line in sys.stdin:
    try:
        d = json.loads(line)
        rule_id = str(d.get('rule',{}).get('id',''))
        if rule_id in ['100005','100006','550','554']:
            alert_time = time.time()
            latency = alert_time - write_time
            filepath = d.get('syscheck',{}).get('path','unknown')
            print(f'')
            print(f'=== FIM ALERT DETECTED ===')
            print(f'Rule ID   : {rule_id}')
            print(f'Level     : {d[\"rule\"][\"level\"]}')
            print(f'File      : {filepath}')
            print(f'Latency   : {latency:.2f} seconds')
            print(f'Description: {d[\"rule\"][\"description\"]}')
            break
    except: pass
"
```

### Expected Log Entries

**Terminal 4 — Wazuh alert stream:**

```
[WAZUH] Rule 100006 Level 14: CRITICAL: MQTT TLS certificate modified — possible MITM setup
```

**Raw Wazuh alert JSON (from `/var/ossec/logs/alerts/alerts.json`):**

```json
{
  "rule": {
    "id": "100006",
    "level": 14,
    "description": "CRITICAL: MQTT TLS certificate modified — possible MITM setup",
    "mitre": {"technique": ["T1557"]}
  },
  "syscheck": {
    "path": "/etc/mosquitto/certs/fake_attacker.crt",
    "event": "added",
    "sha256_after": "a3f9c2...",
    "mode": "realtime"
  },
  "agent": {"id": "001", "name": "sh-iaet"}
}
```

### Step 4 — Cleanup

```bash
sudo rm /etc/mosquitto/certs/fake_attacker.crt
rm /tmp/fake_attacker.crt /tmp/fake_attacker.key
echo "[*] Cleanup complete — FIM will log the deletion as a second event"
```

---

## Exercise 4 — Network Port Scanning and Reconnaissance (T1595.002 / T1046)

### Objective

Run a TCP SYN scan against the [[PC Server]] targeting port 8883 and surrounding ports. Validate that [[Suricata]] rule `SH-004` fires, the event appears in `eve.json`, and Fail2ban's `suricata` jail bans the scanner IP.

### Tools Required

- `nmap` — on a **separate attacker machine** on the same LAN
- `hping3` — for raw SYN packet generation as an alternative

### Step 1 — SYN Scan with Nmap (from attacker machine)

```bash
# Full SYN scan against MQTT TLS port and surrounding range
# -sS: TCP SYN scan (stealth scan — sends SYN, does not complete handshake)
# -p: port range including 8883, 8880-8890, 1883, 22, 2222, 443, 55000
# -T4: aggressive timing (fast scan, generates burst traffic Suricata catches)
# -n: no DNS resolution (faster, cleaner)
# -Pn: skip host discovery (assume host is up)
# --open: only show open ports
# -v: verbose output

sudo nmap \
  -sS \
  -p 8883,8880-8890,1883,22,2222,443,55000,9200 \
  -T4 \
  -n \
  -Pn \
  -v \
  192.168.1.100

echo "[*] Scan complete. Check Suricata fast.log on server."
```

### Step 2 — Service Version Detection Scan

```bash
# Service version detection generates more probe packets — higher Suricata signal
sudo nmap \
  -sV \
  -p 8883,2222,443 \
  -T3 \
  -n \
  -Pn \
  --version-intensity 5 \
  192.168.1.100
```

### Step 3 — Raw SYN Flood with hping3 (Triggers SH-002 DoS Rule)

```bash
# hping3 generates raw TCP SYN packets at controlled rate
# --syn: send SYN packets
# -p 8883: target port
# --fast: approximately 10 packets/second
# -c 30: send 30 packets total
sudo hping3 \
  --syn \
  -p 8883 \
  --fast \
  -c 30 \
  192.168.1.100
```

### Expected Log Entries

**Terminal 2 — `/var/log/suricata/fast.log`:**

```
01/15/2024-14:45:01.123456  [**] [1:9000004:1] SMARTHOME: Port scan detected against MQTT TLS port 8883 [**] [Classification: Network Scan] [Priority: 2] {TCP} 192.168.1.200:54321 -> 192.168.1.100:8883
01/15/2024-14:45:02.234567  [**] [1:9000002:1] SMARTHOME: MQTT port connection flood detected [**] [Classification: Attempted Denial of Service] [Priority: 2] {TCP} 192.168.1.200:54322 -> 192.168.1.100:8883
```

**`/var/log/suricata/eve.json` — Alert event (pretty-printed):**

```json
{
  "timestamp": "2024-01-15T14:45:01.123456+0200",
  "event_type": "alert",
  "src_ip": "192.168.1.200",
  "src_port": 54321,
  "dest_ip": "192.168.1.100",
  "dest_port": 8883,
  "proto": "TCP",
  "community_id": "1:abc123xyz456...",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 9000004,
    "rev": 1,
    "signature": "SMARTHOME: Port scan detected against MQTT TLS port 8883",
    "category": "Network Scan",
    "severity": 2
  }
}
```

**Terminal 3 — `/var/log/fail2ban.log`:**

```
2024-01-15 14:45:02,891 fail2ban.actions [PID]: NOTICE  [suricata] Ban 192.168.1.200
```

### Step 4 — Extract community_id for Splunk Correlation

```bash
# On the server — extract the community_id from the Suricata alert
# This value will be used to join with Wazuh alerts in Splunk
sudo jq -r 'select(.event_type=="alert" and .dest_port==8883) | .community_id' \
  /var/log/suricata/eve.json | tail -5

# Record the community_id value for the Splunk correlation query in 11.3
```

### Step 5 — Cleanup

```bash
sudo fail2ban-client set suricata unbanip 192.168.1.200
```

---

## Exercise 5 — Configuration Tampering Detection (T1565.001)

### Objective

Simulate an adversary with partial host access modifying the Mosquitto broker configuration to weaken its security posture. Validate Wazuh FIM rule `100005` fires at level 12.

### Step 1 — Record Current File Hash

```bash
# Establish the pre-tampering baseline hash
sha256sum /etc/mosquitto/conf.d/smarthome.conf
# Record this value — it should appear as sha256_before in the Wazuh FIM alert
```

### Step 2 — Execute Tampering (Non-Destructive)

The modification appends a comment line to avoid disrupting the live broker configuration while still changing the file's SHA-256 hash:

```bash
echo "[*] T_write = $(date +%T.%N)"

# Append a comment — does not alter broker behaviour but changes file hash
sudo bash -c 'echo "# TAMPER TEST $(date)" >> /etc/mosquitto/conf.d/smarthome.conf'

echo "[*] Modification written. Waiting for Wazuh FIM alert (realtime)..."
```

### Step 3 — Confirm FIM Alert

```bash
# Watch for rule 100005 in Wazuh alerts
sudo tail -f /var/ossec/logs/alerts/alerts.json \
  | python3 -c "
import sys, json, time
t0 = time.time()
for line in sys.stdin:
    try:
        d = json.loads(line)
        if str(d.get('rule',{}).get('id','')) in ['100005','550']:
            print(f'[{time.time()-t0:.2f}s] ALERT: {d[\"rule\"][\"description\"]}')
            sc = d.get('syscheck',{})
            print(f'  File    : {sc.get(\"path\")}')
            print(f'  Event   : {sc.get(\"event\")}')
            print(f'  SHA before: {sc.get(\"sha256_before\",\"N/A\")}')
            print(f'  SHA after : {sc.get(\"sha256_after\",\"N/A\")}')
            break
    except: pass
"
```

**Expected Wazuh alert stream output:**

```
[WAZUH] Rule 100005 Level 12: CRITICAL: Mosquitto configuration file modified
```

### Step 4 — Escalation Test: Simulate `allow_anonymous true` Injection

This is a more realistic tampering scenario. The `--dry-run` flag ensures the actual file is not modified — use only the `sed` command below for the actual test:

```bash
# SIMULATION ONLY — shows what the attack command would look like
# Do NOT run this on a production system without immediate cleanup

# Attacker's goal: re-enable anonymous access
# sudo sed -i 's/allow_anonymous false/allow_anonymous true/' \
#   /etc/mosquitto/conf.d/smarthome.conf

# SAFE TEST VERSION — appends a commented-out version instead
sudo bash -c \
  'echo "# INJECTED: allow_anonymous true" >> /etc/mosquitto/conf.d/smarthome.conf'
```

### Step 5 — Cleanup

```bash
# Remove the appended test lines
sudo sed -i '/TAMPER TEST/d' /etc/mosquitto/conf.d/smarthome.conf
sudo sed -i '/INJECTED/d' /etc/mosquitto/conf.d/smarthome.conf

# Verify broker config is still valid
sudo mosquitto -c /etc/mosquitto/conf.d/smarthome.conf --test-config
# Expected: no output (no errors)

sudo systemctl reload mosquitto
```

---

## Post-Exercise Verification Checklist

Run this block after completing all five exercises to generate a consolidated evidence summary:

```bash
#!/bin/bash
echo "════════════════════════════════════════════════"
echo " RED TEAM EXERCISE — POST-EXECUTION SUMMARY"
echo " $(date)"
echo "════════════════════════════════════════════════"

echo ""
echo "── EXERCISE 1: MQTT Brute Force ──────────────"
echo "Auth failures in mosquitto.log (last 100 lines):"
sudo grep -c "failed to connect, not authorised" \
  /var/log/mosquitto/mosquitto.log
echo "Wazuh rule 100002 alert count:"
sudo grep -c '"id":"100002"' /var/ossec/logs/alerts/alerts.json 2>/dev/null || echo "0"

echo ""
echo "── EXERCISE 2: ACL Violations ────────────────"
echo "ACL denial count in mosquitto.log:"
sudo grep -c "ACL check denied" /var/log/mosquitto/mosquitto.log
echo "Wazuh rule 100003 alert count:"
sudo grep -c '"id":"100003"' /var/ossec/logs/alerts/alerts.json 2>/dev/null || echo "0"

echo ""
echo "── EXERCISE 3: TLS Certificate Tampering ─────"
echo "Wazuh rule 100006 alert count:"
sudo grep -c '"id":"100006"' /var/ossec/logs/alerts/alerts.json 2>/dev/null || echo "0"
echo "Current cert directory contents:"
ls -la /etc/mosquitto/certs/

echo ""
echo "── EXERCISE 4: Port Scanning ─────────────────"
echo "Suricata SMARTHOME rule alerts:"
sudo grep -c "SMARTHOME" /var/log/suricata/fast.log 2>/dev/null || echo "0"
echo "Suricata SID 9000004 (port scan) count:"
sudo jq -r 'select(.event_type=="alert" and .alert.signature_id==9000004) | .src_ip' \
  /var/log/suricata/eve.json 2>/dev/null | sort | uniq -c

echo ""
echo "── EXERCISE 5: Config Tampering ──────────────"
echo "Wazuh rule 100005 alert count:"
sudo grep -c '"id":"100005"' /var/ossec/logs/alerts/alerts.json 2>/dev/null || echo "0"

echo ""
echo "── FAIL2BAN STATUS ───────────────────────────"
sudo fail2ban-client status | grep "Jail list"
for JAIL in mosquitto sshd suricata wazuh-api; do
  echo ""
  echo "Jail: $JAIL"
  sudo fail2ban-client status $JAIL 2>/dev/null \
    | grep -E "Currently banned|Total banned|Banned IP"
done

echo ""
echo "════════════════════════════════════════════════"
echo " SUMMARY COMPLETE"
echo "════════════════════════════════════════════════"
```

---

## References

- MITRE ATT&CK. *T1110.001 — Brute Force: Password Guessing*. https://attack.mitre.org/techniques/T1110/001/
- MITRE ATT&CK. *T1078 — Valid Accounts*. https://attack.mitre.org/techniques/T1078/
- MITRE ATT&CK. *T1557 — Adversary-in-the-Middle*. https://attack.mitre.org/techniques/T1557/
- MITRE ATT&CK. *T1595.002 — Active Scanning: Vulnerability Scanning*. https://attack.mitre.org/techniques/T1595/002/
- MITRE ATT&CK. *T1565.001 — Data Manipulation: Stored Data Manipulation*. https://attack.mitre.org/techniques/T1565/001/
- Nmap.org. *Nmap Reference Guide*. https://nmap.org/book/man.html
- Eclipse Mosquitto. *mosquitto_pub man page*. https://mosquitto.org/man/mosquitto_pub-1.html
