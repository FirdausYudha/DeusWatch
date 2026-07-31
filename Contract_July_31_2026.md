# DeusWatch Extended Capabilities Contract
**Date:** July 31, 2026  
**Version:** 1.0  
**Status:** Active Development  

---

## Executive Summary

This contract defines two major feature additions to DeusWatch v2.3.0:

1. **Android Agent for Mobile Security** — Jailbreak/root detection with banking app integration
2. **Process-Level Malware Detection (Linux/Windows)** — Backend-driven threat analysis

Both features follow a **lightweight agent + heavyweight manager** architecture to minimize endpoint overhead.

---

## Part 1: Android Agent for DeusWatch

### Goal
Enable DeusWatch to monitor Android endpoints for jailbreak/root conditions and provide automatic device lockout mechanism for banking applications.

### Scope: Root Detection

#### 1.1 Detection Targets
- **Magisk** (v23.0+) with Zygisk + DenyList
- **KernelSU** (kernel-integrated rooting)
- **APatch** (alternative patching framework)
- Other common rooting tools (SuperSU legacy, KingRoot, Phh's SuperUser)

#### 1.2 Detection Layers (Multi-Tier Approach)

**Layer 1: Basic Indicators (Catches 60-80% of unprotected roots)**
- ✅ SU binary presence (`/data/adb/magisk/`, `/system/bin/su`)
- ✅ Magisk package detection (com.topjohnwu.magisk + randomized variants)
- ✅ System property checks (`ro.secure=0`, `ro.debuggable=1`)
- ✅ Known rooting app installation checks

**Layer 2: Advanced Heuristics (Catches 20-30% of hidden roots)**
- ✅ Mount namespace analysis (`/proc/self/mountinfo` comparison across threads)
- ✅ Process memory map scanning (`/proc/self/maps` for Magisk/KernelSU libraries)
- ✅ Namespace consistency checks (UID/GID/PID mismatches)
- ✅ Syscall fingerprinting (detecting hooked syscalls via errno patterns)

**Layer 3: Attestation API (Most reliable, 90%+ accuracy)**
- ✅ Google Play Integrity API integration
  - Request integrity token on app startup
  - Send to banking backend for verification
  - Supports hardware-backed attestation (as of May 2025)
  - Three verdict levels: MEETS_DEVICE_INTEGRITY, MEETS_STRONG_INTEGRITY, FAILS

#### 1.3 Known Limitations (Accepted)
- ❌ Cannot reliably detect Magisk with modern DenyList + Shamiko modules
- ❌ Cannot detect KernelSU with 100% confidence (kernel-level obfuscation)
- ❌ Cannot catch zero-day rooting exploits
- ⚠️ False positives possible on certain custom ROM devices

**Mitigation Strategy:**
- Treat detection as **risk scoring** (0-100) rather than binary yes/no
- Layer detection: accept higher false negatives on Layer 1, use Layer 3 as ground truth
- Backend implements **appeal/override** mechanism for legitimate use cases

---

### Scope: Banking App Integration

#### 1.4 Signal Mechanism: DeusWatch → Banking App

**Architecture:**
```
DeusWatch Agent (detects root)
    ↓ (send authenticated signal via Broadcast Intent)
Banking App Receiver
    ↓ (verify signature, lock UUID)
Encrypted UUID Lock Record
    ↓ (backend database)
Customer Service Portal
```

**Signal Protocol:**
- **Method:** Android Broadcast Intent (secure, signature-protected)
- **Action:** `com.yourbank.ACTION_LOCK_DEVICE`
- **Receiver:** Banking app BroadcastReceiver (restricted to com.yourbank.banking package)
- **Payload:**
  ```json
  {
    "uuid": "device-uuid-xxx",
    "reason": "ROOT_DETECTED",
    "timestamp": 1722470400000,
    "nonce": "random-value-xxx",
    "signature": "HMAC-SHA256(payload, DEUSWATCH_PRIVATE_KEY)"
  }
  ```
- **Replay Protection:** Timestamp + 5-second window + nonce
- **Authentication:** HMAC-SHA256 signature (DeusWatch private key, verified against hardcoded public key in banking app)

#### 1.5 UUID Locking Strategy

**Option A: Permanent Lock (Recommended for Banking)**
- Lock persists until customer service manually unlocks
- Requires identity verification (KYC, OTP, security questions)
- User receives unlock code via email/SMS
- Prevents automated re-unlock

**Option B: Time-Limited Auto-Unlock**
- Lock expires after N days (e.g., 30 days for investigation)
- User can appeal for faster unlock
- Less secure but user-friendly

**Selected: Option A** (permanent until verified unlock)

#### 1.6 UUID Lock State Machine

```
States:
  ACTIVE     → Device UUID operational, app can authenticate
  LOCKED     → UUID locked, app rejects all transactions
  RECOVERING → Manual unlock code entered, grace period before restore
  RESTORED   → UUID restored after verification

Transitions:
  ACTIVE → LOCKED         (root detected)
  LOCKED → RECOVERING     (user enters unlock code)
  RECOVERING → RESTORED   (24-hour grace period expires)
  RESTORED → ACTIVE       (immediate after grace period)
```

#### 1.7 User Experience Flow

1. **Detection Phase**
   - DeusWatch agent runs background scan
   - Root detected → sends lock signal

2. **Lock Phase**
   - Banking app receives signal (< 1 sec)
   - Verifies signature + timestamp
   - Locks UUID in EncryptedSharedPreferences
   - User-facing notification: "Your device has been locked due to security concerns. Contact Customer Service."

3. **Recovery Phase**
   - User calls: `1-800-BANK-NOW`
   - CS rep verifies identity (KYC + OTP)
   - CS rep triggers unlock in backend admin panel
   - System sends unlock code to user email/SMS
   - User enters code in app → enters 24-hour recovery window

4. **Restoration Phase**
   - After 24 hours without new root detection → UUID restored
   - User can resume normal banking

#### 1.8 Acceptance Criteria

**Agent Detection:**
- ✅ Detects Magisk v30.7+ (February 2026 release)
- ✅ Detects KernelSU with >70% confidence
- ✅ Detects APatch installations
- ✅ False positive rate < 5% (legitimate devices)
- ✅ Detection latency < 5 seconds
- ✅ Battery impact < 2% per 10-minute scan

**Banking App Integration:**
- ✅ Signal received and processed < 100ms
- ✅ UUID locked immediately upon valid signal
- ✅ Signal cannot be spoofed (signature verification passes)
- ✅ Replay attacks rejected (timestamp + nonce validation)
- ✅ User notification shown within 2 seconds
- ✅ Lock survives app restart and device reboot
- ✅ Unlock code works correctly after CS approval

**End-to-End:**
- ✅ Root detected on device → UUID locked within 1 minute
- ✅ Legitimate user can recover UUID via customer service
- ✅ No legitimate (non-rooted) devices incorrectly locked
- ✅ Audit trail logs all lock/unlock events with reason and timestamp

---

## Part 2: Process-Level Malware Detection (Linux & Windows)

### Goal
Enable DeusWatch to detect trojans, malware, and suspicious processes on Linux and Windows endpoints using **lightweight agent collection** + **heavyweight manager analysis**.

### Scope: Architecture

#### 2.1 Division of Labor

**Agent Responsibilities (Minimal):**
- Collect process list every 5 minutes
- Capture: PID, name, parent PID, command line, user, file path, memory usage
- Compute file hash (MD5 or SHA-256, one-time per process)
- Ship snapshot to manager via API

**Manager Responsibilities (Heavy Lifting):**
- Multi-stage analysis pipeline
- YARA signature scanning
- VirusTotal API queries (cached)
- Behavioral heuristic scoring
- Machine learning inference (future)
- Threat reporting and response

#### 2.2 Process Snapshot Data Model

**Collected per Process:**
```json
{
  "pid": 1234,
  "name": "svchost.exe",
  "parent_pid": 456,
  "cmdline": "C:\\Windows\\System32\\svchost.exe -k netsvcs",
  "user": "SYSTEM",
  "path": "C:\\Windows\\System32\\svchost.exe",
  "start_time": "2026-07-31T08:00:00Z",
  "memory_mb": 45,
  "file_hash": "a1b2c3d4e5f6g7h8..."
}
```

**Ship Frequency:** Every 5 minutes (configurable)  
**Payload Size:** ~50-100 KB per agent (typical system with 100-200 processes)

---

### Scope: Backend Analysis Pipeline

#### 2.3 Detection Stages (Sequential, Fast → Slow)

**Stage 1: YARA Signature Scan (< 100ms)**
- Load local YARA rules into memory on manager startup
- Scan process file path against rules
- Return immediately on first match
- Example rules: Emotet, Trickbot, Cerber, generic trojans

**Stage 2: Hash Lookup (< 10ms, cached)**
- Check file hash against local known-bad database
- Database seeded with YARA matches + user submissions
- Fast cache layer (in-memory or Redis)

**Stage 3: VirusTotal API Query (< 2 sec, async cached)**
- Query only if hash not in cache
- Check if ≥1 vendor flags as malicious
- Cache result for future hits (same hash = skip API)
- Use bulk API to amortize cost

**Stage 4: Behavioral Heuristic Scoring (< 50ms)**
- Rule-based scoring (no ML)
- Detect suspicious patterns:
  - Suspicious parent-child relationships (e.g., svchost.exe → cmd.exe)
  - Process spawned from unusual paths (%TEMP%, %APPDATA%)
  - Obfuscated command lines (Base64, PowerShell -enc)
  - "Living-off-land" tools (rundll32, regsvcs) used suspiciously
  - High memory footprint + network activity

**Stage 5: Machine Learning (Future)**
- Train on labeled dataset (3000+ samples)
- Features: behavior, network traffic, file I/O patterns
- Inference on process snapshot
- Target: 92%+ accuracy (from research baseline)

---

#### 2.4 Threat Classification

**Threat Levels:**
- **MALICIOUS** (High Confidence)
  - Triggers: YARA match, known-bad hash, VirusTotal ≥1 vendor
  - Action: Auto-create ticket, optional auto-kill, notify SOC
  
- **SUSPICIOUS** (Medium Confidence)
  - Triggers: Behavioral score > 70, anomalous network patterns
  - Action: Create ticket, alert, request human review
  
- **CLEAN** (Low Risk)
  - No indicators detected
  - No action

**Stored as:**
```json
{
  "tenant_id": "xxx",
  "agent_id": "yyy",
  "pid": 1234,
  "name": "svchost.exe",
  "file_hash": "a1b2c3d4...",
  "threat_level": "MALICIOUS",
  "reasons": [
    "YARA match: Emotet.trojan",
    "VirusTotal: 45 vendors flagged"
  ],
  "detected_at": "2026-07-31T10:30:00Z"
}
```

---

### Scope: Response Actions

#### 2.5 Automated Responses

**On MALICIOUS Detection:**
1. **Ticket Creation**
   - Title: "Malware detected: {process_name} (PID {pid})"
   - Severity: CRITICAL
   - Assign to SOC team
   - Include detection reasons + VirusTotal link

2. **User/Admin Notification**
   - Email alert to tenant admins
   - Dashboard alert badge
   - Slack/webhook integration (if configured)

3. **Optional: Process Termination**
   - Can be configured per tenant
   - Agent receives kill command via response engine
   - Use existing `killproc` infrastructure (Linux/Windows)
   - Log termination reason + timestamp

4. **Device Isolation** (Future)
   - Network quarantine
   - Firewall rule injection
   - Out-of-band C2 communication prevention

**On SUSPICIOUS Detection:**
- Same as MALICIOUS but lower urgency
- No auto-kill (manual review recommended)

---

### Scope: Acceptance Criteria

#### 2.6 Agent Collection

- ✅ Collects all running processes (Linux: /proc, Windows: WMI)
- ✅ Computes file hash within 100ms per process
- ✅ Snapshots ship every 5 minutes (no more than 100KB per agent)
- ✅ Agent CPU overhead < 2% during collection
- ✅ Memory usage < 10MB additional
- ✅ Survives process restart and network interruption (queued locally)

#### 2.7 Backend Analysis

- ✅ YARA scan < 100ms per snapshot
- ✅ Hash lookups < 10ms (cache hit)
- ✅ VirusTotal queries cached (max 100 API calls/day per instance)
- ✅ Behavioral scoring completes in < 50ms
- ✅ Detects common trojans: Emotet, Trickbot, Cerber, IcedID, Qbot
- ✅ False positive rate < 10% on legitimate processes
- ✅ Scaling: Handle 10,000+ processes/minute from all agents

#### 2.8 Data Integrity

- ✅ Process threat records properly scoped to tenant (RLS enforced)
- ✅ No cross-tenant data leakage
- ✅ Audit trail logs all detections + responses
- ✅ Threat records retained for ≥90 days
- ✅ VirusTotal cache invalidated after 30 days

#### 2.9 Response Actions

- ✅ Ticket created within 5 seconds of detection
- ✅ User notification sent immediately
- ✅ Process kill (if enabled) executes within 2 seconds
- ✅ Kill result logged with exit code
- ✅ No response cascade (same process not killed twice)

---

## Part 3: Implementation Phases

### Phase 1: Contract Review & Architecture Finalization (July 31 - Aug 1)
- [ ] Review and approve this contract
- [ ] Confirm threat response policies (auto-kill? network isolation?)
- [ ] Decide YARA rule sources (Yara-Rules.github, custom, commercial?)
- [ ] Finalize VirusTotal API budget (queries per day)

### Phase 2: Android Agent - Root Detection (Aug 1 - Aug 15)
- [ ] Implement Layer 1 detection (basic indicators)
- [ ] Implement Layer 2 detection (advanced heuristics)
- [ ] Integrate Play Integrity API
- [ ] Test on real devices (Magisk v30.7, KernelSU latest)
- [ ] Accuracy validation (false positive rate)

### Phase 3: Android Agent - Banking Integration (Aug 15 - Aug 29)
- [ ] Implement Broadcast Intent signal mechanism
- [ ] Banking app receiver implementation
- [ ] UUID lock state machine
- [ ] HMAC-SHA256 signature verification
- [ ] Customer service admin portal for unlocks
- [ ] End-to-end testing

### Phase 4: Malware Detection - Agent Collection (Aug 29 - Sept 5)
- [ ] Add `ProcessSnapshot` type to agent schema
- [ ] Implement `CollectProcesses()` for Linux & Windows
- [ ] Implement file hashing (cached)
- [ ] Ship snapshots to backend API
- [ ] Test with 10K+ processes

### Phase 5: Malware Detection - Backend Analysis (Sept 5 - Sept 19)
- [ ] Implement YARA scanner integration
- [ ] Build VirusTotal API client with caching
- [ ] Implement behavioral scoring engine
- [ ] Multi-stage pipeline orchestration
- [ ] Database schema for threats + VT cache

### Phase 6: Malware Detection - Response & Integration (Sept 19 - Oct 3)
- [ ] Wire response actions (ticket creation, notifications, kill)
- [ ] Integration with existing response engine
- [ ] Admin dashboard for threat review
- [ ] Audit trail logging
- [ ] End-to-end testing

### Phase 7: Testing & Hardening (Oct 3 - Oct 17)
- [ ] Security review (signature spoofing, signal injection)
- [ ] Load testing (10K+ agents, 100K+ processes)
- [ ] False positive tuning
- [ ] Documentation & runbooks
- [ ] Multi-tenancy isolation verification

---

## Part 4: Risk Assessment

### Android Agent Risks

**Risk 1: False Positives on Custom ROMs**
- *Impact:* User frustration, support burden
- *Mitigation:* Use Play Integrity as tiebreaker; implement appeal mechanism

**Risk 2: Root Hiding Defeats Detection**
- *Impact:* Missed detections
- *Mitigation:* Accept as known limitation; Layer 3 (Play Integrity) mitigates

**Risk 3: Signal Spoofing**
- *Impact:* Unauthorized device lockout
- *Mitigation:* HMAC-SHA256 signature + timestamp validation

---

### Malware Detection Risks

**Risk 1: VirusTotal API Rate Limits**
- *Impact:* Detection delays during high activity
- *Mitigation:* Cache aggressively, use bulk API, set daily query limit

**Risk 2: High False Positives**
- *Impact:* Alert fatigue, wasted SOC time
- *Mitigation:* Conservative thresholds (> 70 for heuristic), multiple data sources

**Risk 3: Process Kill Cascades**
- *Impact:* Unintended system instability
- *Mitigation:* Limit kill to single process, validate process age (avoid fresh starts), require explicit policy

**Risk 4: Agent Performance Overhead**
- *Impact:* Endpoint slowdown
- *Mitigation:* Lightweight collection only; manager does analysis

---

## Part 5: Success Metrics

### Android Agent
- ✅ Magisk detection accuracy > 85%
- ✅ KernelSU detection accuracy > 70%
- ✅ False positive rate < 5%
- ✅ Signal delivery reliability > 99%
- ✅ Customer support tickets < 10/month for false lockouts

### Malware Detection
- ✅ Detects > 95% of VirusTotal-flagged malware
- ✅ False positive rate < 10% on clean systems
- ✅ Detection latency < 5 seconds (cold) / < 1 second (cached)
- ✅ 99.9% uptime on manager analysis pipeline
- ✅ Support for 10,000+ agents per manager instance

---

## Part 6: Out of Scope (Future Work)

- ❌ Memory-resident malware (kernel rootkits)
- ❌ Supply chain attack detection
- ❌ Zero-day vulnerability patching
- ❌ Behavioral replay & game-theoretic evasion detection
- ❌ Mobile malware detection beyond root (code injection, data exfiltration)
- ❌ Custom ROM support for Android (policy decision)

---

## Approval & Sign-Off

**Created:** July 31, 2026  
**By:** Development Team  
**Status:** Active Development  
**Next Review:** September 15, 2026

**Approvals:**
- [ ] Product Owner
- [ ] Security Lead
- [ ] DevOps Lead
- [ ] QA Lead

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | July 31, 2026 | Initial contract: Android root detection + malware detection |

