Security Incident Report: SQL-Based Investigation Portfolio
I'll create a professional incident report for your portfolio. Here it is:

markdown# Security Incident Investigation Report
## Leveraging SQL for Rapid Threat Detection and Response

**Author:** [Noah Page]  
**Date:** April 25, 2024  
**Classification:** Portfolio Demonstration  
**Incident ID:** INC-2024-0425-001

---

## Executive Summary

This report demonstrates a comprehensive security incident investigation conducted entirely through SQL database queries. The investigation identified and analyzed a multi-stage cyber attack involving phishing, credential compromise, and data exfiltration.

**Key Findings:**
- **Attack Vector:** Phishing email campaign targeting Finance department
- **Compromised Assets:** 3 employee accounts, 1 workstation
- **Data Breach:** 1,253.7 MB exfiltrated (125,000+ customer PII records)
- **Time to Detection:** 15 minutes from initial alert
- **Time to Full Investigation:** 2 hours using SQL queries
- **Regulatory Impact:** GDPR/CCPA breach notification required

**Investigation Methodology:** All findings were obtained through structured SQL queries against centralized security databases, demonstrating the critical role of SQL proficiency in modern security operations.

---

## Table of Contents

1. [Incident Overview](#incident-overview)
2. [Investigation Methodology](#investigation-methodology)
3. [Technical Analysis](#technical-analysis)
4. [Attack Timeline](#attack-timeline)
5. [SQL Query Examples](#sql-query-examples)
6. [Impact Assessment](#impact-assessment)
7. [Lessons Learned](#lessons-learned)
8. [Appendix: Complete SQL Queries](#appendix-complete-sql-queries)

---

## Incident Overview

### Initial Alert

**Time:** April 25, 2024 at 14:47:22  
**Source:** SIEM Platform  
**Severity:** High
ALERT: Possible data exfiltration detected
User: mrodriguez
Source IP: 10.50.23.142
Destination: 185.220.101.88 (External, TOR exit node)
Data transferred: 847 MB
Duration: 14:32:15 - 14:47:22 (15 minutes)

### Incident Classification

- **Type:** Data Breach / Unauthorized Access
- **Category:** Phishing → Credential Compromise → Data Exfiltration
- **Severity:** Critical
- **Affected Systems:** Employee workstation, email server, file systems
- **Threat Actor:** External (likely APT based on TOR usage and methodology)

---

## Investigation Methodology

### Approach

This investigation followed a structured SQL-based analysis methodology:

1. **Triage (0-15 min):** Verify alert legitimacy and establish baseline behavior
2. **Timeline Development (15-30 min):** Reconstruct attack sequence
3. **Scope Assessment (30-60 min):** Identify all affected assets and data
4. **IOC Discovery (60-90 min):** Find related indicators and other victims
5. **Impact Quantification (90-120 min):** Calculate breach scope and regulatory impact

### Data Sources

All queries executed against the organization's centralized security database:

- `employees` - Employee records and device assignments
- `machines` - Device inventory and patch status
- `log_in_attempts` - Authentication logs
- `email_access_logs` - Email system access records
- `file_access_logs` - File system activity
- `network_connections` - Network traffic metadata
- `audit_logs` - System change tracking
- `file_metadata` - File classification and sensitivity

### Tools Used

- **Database:** MariaDB 10.x
- **Query Interface:** MySQL command line
- **Documentation:** Real-time query logging

---

## Technical Analysis

### Phase 1: Initial Triage (0-15 Minutes)

#### Objective: Verify alert authenticity and establish user baseline

**Query 1: Validate User Account**

```sql
SELECT employee_id, username, department, office, status
FROM employees
WHERE username = 'mrodriguez';
```

**Result:**
| employee_id | username | department | office | status |
|-------------|----------|------------|--------|--------|
| 1089 | mrodriguez | Finance | East-245 | active |

**Analysis:** ✓ Legitimate Finance employee with access to sensitive data

---

**Query 2: Establish Normal Behavior Baseline**

```sql
SELECT 
    login_date,
    login_time,
    country,
    success,
    COUNT(*) as login_count
FROM log_in_attempts
WHERE username = 'mrodriguez'
AND login_date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
GROUP BY login_date, login_time, country, success
ORDER BY login_date DESC
LIMIT 10;
```

**Key Findings:**
- Consistent login pattern: Daily at ~08:15 AM from USA
- **Anomaly detected:** 14:28 PM login (unusual time)
- No previous failed login attempts in past 30 days

---

**Query 3: Today's Complete Activity**

```sql
SELECT 
    login_time,
    country,
    ip_address,
    success,
    event_id
FROM log_in_attempts
WHERE username = 'mrodriguez'
AND login_date = '2024-04-25'
ORDER BY login_time;
```

**Results:**
| login_time | country | ip_address | success | event_id |
|------------|---------|------------|---------|----------|
| 08:15:33 | USA | 10.50.23.142 | 1 | 2451 |
| 14:28:12 | USA | 10.50.23.142 | 1 | 2489 |

**Finding:** Second login at 14:28 PM (4 minutes before exfiltration) - **same IP as normal login**

---

### Phase 2: Attack Vector Identification (15-30 Minutes)

#### Objective: Determine how attacker gained access

**Query 4: Check for Brute Force Attempts**

```sql
SELECT 
    login_date,
    login_time,
    ip_address,
    country,
    success
FROM log_in_attempts
WHERE username = 'mrodriguez'
AND login_date >= '2024-04-23'
AND success = 0
ORDER BY login_date DESC, login_time DESC;
```

**Critical Discovery:**

| login_date | login_time | ip_address | country | success |
|------------|------------|------------|---------|---------|
| 2024-04-24 | 19:45:22 | 203.0.113.88 | Russia | 0 |
| 2024-04-24 | 19:45:18 | 203.0.113.88 | Russia | 0 |
| 2024-04-24 | 19:45:14 | 203.0.113.88 | Russia | 0 |
| 2024-04-24 | 19:45:10 | 203.0.113.88 | Russia | 0 |
| 2024-04-24 | 19:45:06 | 203.0.113.88 | Russia | 0 |

**Analysis:**
- 🚨 5 failed attempts from Russia on 4/24
- 🚨 4-second intervals = automated attack
- 🚨 Different IP from today's successful login

**Question:** If brute force failed, how did they get in?

---

**Query 5: Account Modifications**

```sql
SELECT 
    username,
    action,
    timestamp,
    performed_by,
    details
FROM audit_logs
WHERE username = 'mrodriguez'
AND action IN ('password_reset', 'password_change', 'mfa_disabled')
AND timestamp >= '2024-04-24 00:00:00'
ORDER BY timestamp DESC;
```

**Result:**
| username | action | timestamp | performed_by | details |
|----------|--------|-----------|--------------|---------|
| mrodriguez | password_reset | 2024-04-25 14:22:33 | mrodriguez | Self-service reset via email link |

**Critical Finding:** Password reset 6 minutes before suspicious login via self-service email link

**Hypothesis:** Email account compromised → Password reset → System access

---

**Query 6: Email Account Access Verification**

```sql
SELECT 
    username,
    access_time,
    ip_address,
    country,
    user_agent,
    action
FROM email_access_logs
WHERE username = 'mrodriguez'
AND access_date >= '2024-04-24'
ORDER BY access_time DESC;
```

**Smoking Gun:**

| username | access_time | ip_address | country | user_agent | action |
|----------|-------------|------------|---------|------------|--------|
| mrodriguez | 2024-04-25 14:20:15 | 203.0.113.88 | **Russia** | Mozilla/5.0 | login_success |
| mrodriguez | 2024-04-25 14:20:22 | 203.0.113.88 | **Russia** | Mozilla/5.0 | view_message |
| mrodriguez | 2024-04-25 14:22:30 | 203.0.113.88 | **Russia** | Mozilla/5.0 | click_link |

**Attack Chain Confirmed:**
1. ✓ Email compromised from Russia (same IP as brute force)
2. ✓ Attacker viewed messages
3. ✓ Clicked password reset link
4. ✓ Gained system access with new credentials

---

### Phase 3: Damage Assessment (30-60 Minutes)

#### Objective: Quantify data breach scope

**Query 7: Files Accessed During Incident**

```sql
SELECT 
    file_path,
    file_name,
    sensitivity_level,
    file_size_mb,
    action_type,
    timestamp
FROM file_access_logs
WHERE username = 'mrodriguez'
AND timestamp BETWEEN '2024-04-25 14:28:00' AND '2024-04-25 14:50:00'
ORDER BY timestamp;
```

**Data Exfiltration Summary:**

| file_name | sensitivity_level | file_size_mb | timestamp |
|-----------|-------------------|--------------|-----------|
| revenue_by_client.xlsx | confidential | 12.3 | 14:32:18 |
| profit_margins.xlsx | confidential | 8.7 | 14:33:45 |
| customer_database.csv | **highly_sensitive** | 245.8 | 14:35:12 |
| contract_2024_*.pdf | confidential | 487.3 | 14:38:22 |
| employee_salaries.xlsx | **highly_sensitive** | 15.2 | 14:44:10 |

**Total:** ~770 MB (matches 847 MB from initial alert when accounting for encryption overhead)

---

**Query 8: Lateral Movement Check**

```sql
SELECT 
    destination_device,
    destination_ip,
    port,
    protocol,
    timestamp,
    data_transferred_mb
FROM network_connections
WHERE source_device = (
    SELECT device_id FROM employees WHERE username = 'mrodriguez'
)
AND timestamp BETWEEN '2024-04-25 14:28:00' AND '2024-04-25 14:50:00'
AND destination_ip NOT LIKE '10.50.23.%'
ORDER BY timestamp;
```

**Results:**
| destination_ip | port | protocol | data_transferred_mb | timestamp |
|----------------|------|----------|---------------------|-----------|
| 185.220.101.88 | 443 | HTTPS | 847.2 | 14:32:15 |
| 10.60.10.15 (file-server) | 445 | SMB | 0.2 | 14:36:42 |

**Findings:**
- ✓ Confirmed exfiltration to TOR exit node
- ⚠️ Attempted lateral movement to file server (connection failed - access controls worked)

---

### Phase 4: Additional Victims (60-90 Minutes)

#### Objective: Identify campaign scope

**Query 9: Other Accounts from Attacker IPs**

```sql
SELECT DISTINCT
    l.username,
    e.department,
    l.ip_address,
    l.country,
    l.login_date,
    l.login_time
FROM log_in_attempts l
INNER JOIN employees e ON l.username = e.username
WHERE l.ip_address IN ('203.0.113.88', '185.220.101.88')
AND l.login_date >= '2024-04-20'
AND l.username != 'mrodriguez'
AND l.success = 1
ORDER BY l.login_date DESC, l.login_time DESC;
```

**Additional Compromised Accounts:**

| username | department | ip_address | country | login_date | login_time |
|----------|------------|------------|---------|------------|------------|
| jchen | **Finance** | 203.0.113.88 | Russia | 2024-04-23 | 21:15:33 |
| amorales | Sales | 203.0.113.88 | Russia | 2024-04-22 | 18:42:11 |

**Finding:** 2 additional compromised accounts (total: 3 victims)

---

**Query 10: Phishing Campaign Detection**

```sql
SELECT 
    sender,
    subject,
    received_time,
    COUNT(DISTINCT recipient) as victim_count,
    GROUP_CONCAT(DISTINCT recipient) as victims
FROM email_logs
WHERE recipient IN ('mrodriguez', 'jchen', 'amorales')
AND received_date >= '2024-04-20'
AND (
    sender NOT LIKE '%@securecorp.com'
    OR subject LIKE '%urgent%'
    OR subject LIKE '%verify%'
)
GROUP BY sender, subject, received_time
HAVING victim_count > 1
ORDER BY received_time DESC;
```

**Phishing Email Identified:**

| sender | subject | received_time | victim_count | victims |
|--------|---------|---------------|--------------|---------|
| it-support@**securecorphelp.com** | URGENT: Verify Your Account | 2024-04-20 09:15:22 | 3 | mrodriguez,jchen,amorales |

**Root Cause:** Typosquatting domain ("securecorp**help**.com" vs "securecorp.com")

---

### Phase 5: Impact Quantification (90-120 Minutes)

**Query 11: Comprehensive Breach Metrics**

```sql
SELECT 
    'Compromised Accounts' as metric,
    COUNT(DISTINCT username) as value
FROM log_in_attempts
WHERE ip_address IN ('203.0.113.88', '185.220.101.88')
AND login_date >= '2024-04-20'
AND success = 1

UNION ALL

SELECT 
    'Sensitive Files Accessed',
    COUNT(*)
FROM file_access_logs
WHERE username IN ('mrodriguez', 'jchen', 'amorales')
AND sensitivity_level IN ('confidential', 'highly_sensitive')
AND timestamp >= '2024-04-20 00:00:00'

UNION ALL

SELECT 
    'Total Data Exfiltrated (MB)',
    SUM(data_transferred_mb)
FROM network_connections
WHERE destination_ip = '185.220.101.88'
AND timestamp >= '2024-04-20 00:00:00';
```

**Impact Summary:**

| Metric | Value |
|--------|-------|
| Compromised Accounts | 3 |
| Sensitive Files Accessed | 47 |
| Total Data Exfiltrated (MB) | 1,253.7 |

---

**Query 12: Regulatory Impact (PII Breach Assessment)**

```sql
SELECT 
    f.file_name,
    f.contains_pii,
    f.contains_financial_data,
    f.record_count,
    f.file_size_mb
FROM file_access_logs fa
INNER JOIN file_metadata f ON fa.file_path = f.file_path
WHERE fa.username IN ('mrodriguez', 'jchen', 'amorales')
AND fa.timestamp >= '2024-04-20 00:00:00'
AND (f.contains_pii = 1 OR f.contains_financial_data = 1)
ORDER BY f.record_count DESC;
```

**Regulatory Findings:**

| file_name | contains_pii | contains_financial_data | record_count | file_size_mb |
|-----------|--------------|-------------------------|--------------|--------------|
| customer_database.csv | Yes | Yes | 125,000 | 245.8 |
| employee_salaries.xlsx | Yes | Yes | 2,847 | 15.2 |
| client_contracts.pdf | Yes | Yes | 1,243 | 487.3 |

**Regulatory Impact:**
- 🚨 **125,000 customer PII records** (triggers GDPR Article 33 notification - 72 hours)
- 🚨 **2,847 employee records** (CCPA notification required)
- 🚨 **Financial data breach** (SEC disclosure may be required)

---

## Attack Timeline

### Complete Chronological Reconstruction

```sql
-- Timeline query combining all event sources
SELECT 
    timestamp,
    event_type,
    username,
    details,
    source_ip,
    severity
FROM (
    -- Phishing emails
    SELECT 
        received_time as timestamp,
        'Phishing Email Received' as event_type,
        recipient as username,
        CONCAT('Subject: ', subject, ' | Sender: ', sender) as details,
        sender_ip as source_ip,
        'Medium' as severity
    FROM email_logs
    WHERE sender = 'it-support@securecorphelp.com'
    AND received_date >= '2024-04-20'
    
    UNION ALL
    
    -- Failed login attempts
    SELECT 
        CONCAT(login_date, ' ', login_time) as timestamp,
        'Brute Force Attempt' as event_type,
        username,
        CONCAT('Failed login from ', country) as details,
        ip_address,
        'High' as severity
    FROM log_in_attempts
    WHERE username IN ('mrodriguez', 'jchen', 'amorales')
    AND success = 0
    AND ip_address = '203.0.113.88'
    
    UNION ALL
    
    -- Email compromises
    SELECT 
        access_time as timestamp,
        'Email Compromise' as event_type,
        username,
        CONCAT('Action: ', action, ' from ', country) as details,
        ip_address,
        'Critical' as severity
    FROM email_access_logs
    WHERE username IN ('mrodriguez', 'jchen', 'amorales')
    AND ip_address = '203.0.113.88'
    AND access_time >= '2024-04-20'
    
    UNION ALL
    
    -- System access
    SELECT 
        CONCAT(login_date, ' ', login_time) as timestamp,
        'System Access' as event_type,
        username,
        'Successful authentication' as details,
        ip_address,
        'Critical' as severity
    FROM log_in_attempts
    WHERE username IN ('mrodriguez', 'jchen', 'amorales')
    AND success = 1
    AND login_date >= '2024-04-20'
    
    UNION ALL
    
    -- Data exfiltration
    SELECT 
        timestamp,
        'Data Exfiltration' as event_type,
        (SELECT e.username FROM employees e 
         INNER JOIN machines m ON e.device_id = m.device_id 
         WHERE m.device_id = n.source_device) as username,
        CONCAT(data_transferred_mb, ' MB to TOR exit node') as details,
        destination_ip,
        'Critical' as severity
    FROM network_connections n
    WHERE destination_ip = '185.220.101.88'
) combined_timeline
ORDER BY timestamp;
```

### Visual Timeline
Day 0 (April 20, 2024)
├─ 09:15 AM: Phishing emails sent to 3 Finance/Sales employees
└─ [Victims receive spoofed IT support email]
Day 4 (April 24, 2024)
├─ 07:45 PM: Brute force attack begins (mrodriguez)
│   └─ 5 failed attempts over 20 seconds
│   └─ Source: 203.0.113.88 (Russia)
└─ Attack method: Password spraying
Day 5 (April 25, 2024) - ACTIVE BREACH
├─ 02:20 PM: Email account compromised (mrodriguez)
│   └─ Attacker logs into webmail from Russia
├─ 02:22 PM: Password reset initiated
│   └─ Self-service link clicked from compromised email
├─ 02:28 PM: System access gained
│   └─ Login successful with new credentials
├─ 02:32 PM: Data exfiltration begins
│   ├─ Financial reports accessed
│   ├─ Customer database downloaded (245 MB)
│   └─ Employee data accessed
├─ 02:36 PM: Lateral movement attempted
│   └─ File server connection BLOCKED
├─ 02:47 PM: Alert triggered (SIEM detection)
│   └─ 847 MB transferred to TOR exit node
└─ 03:00 PM: Investigation initiated

---

## SQL Query Examples

### Most Valuable Queries from Investigation

#### 1. Baseline Behavior Analysis
```sql
-- Establish normal user activity pattern
SELECT 
    login_date,
    login_time,
    country,
    COUNT(*) as login_frequency
FROM log_in_attempts
WHERE username = 'mrodriguez'
AND login_date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
GROUP BY login_date, login_time, country
ORDER BY login_date DESC;
```
**Purpose:** Identify anomalies by comparing current activity to historical patterns

---

#### 2. Credential Compromise Detection
```sql
-- Find failed login attempts followed by successful password reset
SELECT 
    l.username,
    l.login_time as failed_attempt,
    a.timestamp as password_reset,
    TIMESTAMPDIFF(MINUTE, l.login_time, a.timestamp) as minutes_between
FROM log_in_attempts l
INNER JOIN audit_logs a ON l.username = a.username
WHERE l.success = 0
AND a.action = 'password_reset'
AND a.timestamp > l.login_time
AND TIMESTAMPDIFF(HOUR, l.login_time, a.timestamp) < 24
ORDER BY minutes_between;
```
**Purpose:** Correlate failed brute force with subsequent password resets (compromise indicator)

---

#### 3. Data Exfiltration Quantification
```sql
-- Calculate total sensitive data accessed during incident window
SELECT 
    e.username,
    e.department,
    COUNT(f.file_id) as files_accessed,
    SUM(f.file_size_mb) as total_mb,
    SUM(CASE WHEN f.sensitivity_level = 'highly_sensitive' THEN 1 ELSE 0 END) as critical_files
FROM employees e
INNER JOIN file_access_logs f ON e.username = f.username
WHERE f.timestamp BETWEEN '2024-04-20 00:00:00' AND '2024-04-26 00:00:00'
AND e.username IN ('mrodriguez', 'jchen', 'amorales')
GROUP BY e.username, e.department;
```
**Purpose:** Quantify breach impact for incident reporting

---

#### 4. Campaign Scope Identification
```sql
-- Find all victims of phishing campaign through email correlation
SELECT 
    e1.sender,
    e1.subject,
    e1.received_time,
    COUNT(DISTINCT e1.recipient) as potential_victims,
    GROUP_CONCAT(DISTINCT e1.recipient SEPARATOR ', ') as affected_users
FROM email_logs e1
WHERE e1.sender NOT LIKE '%@securecorp.com'
AND e1.received_date >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
GROUP BY e1.sender, e1.subject, e1.received_time
HAVING potential_victims > 2
ORDER BY potential_victims DESC;
```
**Purpose:** Identify coordinated attacks targeting multiple employees

---

#### 5. Lateral Movement Detection
```sql
-- Identify unusual inter-system connections during incident
SELECT 
    nc.source_device,
    e.username,
    nc.destination_device,
    nc.protocol,
    nc.port,
    nc.timestamp,
    CASE 
        WHEN nc.port IN (445, 139) THEN 'SMB (File Sharing)'
        WHEN nc.port = 3389 THEN 'RDP (Remote Desktop)'
        WHEN nc.port = 22 THEN 'SSH'
        ELSE 'Other'
    END as connection_type
FROM network_connections nc
INNER JOIN employees e ON nc.source_device = e.device_id
WHERE e.username IN ('mrodriguez', 'jchen', 'amorales')
AND nc.timestamp >= '2024-04-20 00:00:00'
AND nc.destination_device IS NOT NULL
ORDER BY nc.timestamp;
```
**Purpose:** Track attacker movement across internal systems

---

## Impact Assessment

### Technical Impact

| Category | Details | Severity |
|----------|---------|----------|
| **Confidentiality** | 1,253.7 MB of confidential/sensitive data exfiltrated | Critical |
| **Integrity** | 3 accounts compromised with credential changes | High |
| **Availability** | No systems taken offline (exfiltration only) | Low |
| **Scope** | 3 user accounts, 1 workstation, email server | Medium |

### Business Impact

| Area | Impact | Estimated Cost |
|------|--------|----------------|
| **Regulatory Fines** | GDPR Article 83 (up to €20M or 4% revenue) | $500K - $2M |
| **Notification Costs** | 125,000 breach notifications | $75K - $150K |
| **Legal Fees** | Investigation + potential lawsuits | $200K - $500K |
| **Reputation Damage** | Customer trust erosion, media coverage | Unquantified |
| **Incident Response** | Investigation + remediation (100+ hours) | $50K - $100K |
| **Security Improvements** | MFA deployment, training, monitoring | $150K - $300K |

**Total Estimated Impact:** $975,000 - $3,050,000

### Regulatory Obligations

**GDPR (General Data Protection Regulation):**
- ✓ Breach notification to supervisory authority within 72 hours (Article 33)
- ✓ Individual notification required (Article 34) - high risk to data subjects
- ⚠️ Potential fine: Up to €20M or 4% of annual global turnover

**CCPA (California Consumer Privacy Act):**
- ✓ California residents affected (estimated 15,000 of 125,000 records)
- ✓ Statutory damages: $100-$750 per consumer per incident
- ⚠️ Potential exposure: $1.5M - $11.25M

**SOX (Sarbanes-Oxley):**
- ⚠️ Financial data compromised requires disclosure
- ⚠️ Material cybersecurity incident (SEC reporting)

---

## Lessons Learned

### What Worked Well

#### 1. SQL-Based Investigation Efficiency
- **2-hour investigation** vs industry average of 8-24 hours for similar incidents
- Centralized database enabled rapid correlation across 6 different log sources
- Complex joins revealed attack chain that would be missed in isolated log analysis

#### 2. Structured Query Methodology
- Step-by-step SQL approach prevented tunnel vision
- Each query built upon previous findings logically
- Reproducible investigation (queries serve as documentation)

#### 3. Comprehensive Data Collection
- All necessary logs present in centralized database
- No critical data gaps encountered during investigation
- Historical data retention (30+ days) enabled baseline comparison

### What Could Be Improved

#### 1. Detection Speed
- **Issue:** 15-minute delay between exfiltration start and alert
- **Root Cause:** SIEM threshold required 500+ MB before alerting
- **Recommendation:** Lower threshold to 100 MB for external transfers
- **SQL Solution:**
```sql
  -- Proposed real-time alert query
  SELECT username, SUM(data_transferred_mb) as total_mb
  FROM network_connections
  WHERE destination_ip NOT LIKE '10.%'
  AND timestamp >= DATE_SUB(NOW(), INTERVAL 5 MINUTE)
  GROUP BY username
  HAVING total_mb > 100;
```

#### 2. Prevention Gaps

| Gap | Impact | SQL-Based Solution |
|-----|--------|-------------------|
| **No MFA** | Enabled password reset attack | Query to find accounts without MFA:<br>`SELECT username FROM employees WHERE mfa_enabled = 0` |
| **Outdated patches** | Machine vulnerable to exploits | Identify unpatched systems:<br>`SELECT * FROM machines WHERE OS_patch_date < DATE_SUB(CURDATE(), INTERVAL 30 DAY)` |
| **Email security** | Phishing email bypassed filters | Analyze sender patterns:<br>`SELECT sender, COUNT(*) FROM email_logs WHERE sender NOT LIKE '%@securecorp.com' GROUP BY sender` |

#### 3. Monitoring Blind Spots
- Email access logs not integrated into SIEM real-time alerting
- File classification metadata incomplete (only 60% of files tagged)
- No automated correlation between failed logins and password resets

---

## Recommendations

### Immediate Actions (0-30 Days)

1. **Deploy MFA Universally**
```sql
   -- Priority deployment list
   SELECT username, department, email
   FROM employees
   WHERE mfa_enabled = 0
   AND department IN ('Finance', 'Executive', 'IT', 'Legal')
   ORDER BY department;
```

2. **Enhanced Email Security**
   - Implement DMARC/DKIM/SPF
   - Deploy advanced phishing protection
   - Block typosquatting domains preemptively

3. **Improve Alert Tuning**
```sql
   -- New SIEM correlation rule
   SELECT l.username, l.ip_address, l.country, a.action
   FROM log_in_attempts l
   LEFT JOIN audit_logs a ON l.username = a.username
   WHERE l.success = 0
   AND a.action = 'password_reset'
   AND a.timestamp BETWEEN l.login_time AND DATE_ADD(l.login_time, INTERVAL 1 HOUR);
```

### Short-Term (30-90 Days)

4. **Automated Threat Hunting**
```sql
   -- Daily suspicious activity report
   SELECT 
       username,
       COUNT(DISTINCT country) as countries_accessed,
       COUNT(DISTINCT ip_address) as unique_ips,
       SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failed_attempts
   FROM log_in_attempts
   WHERE login_date = CURDATE()
   GROUP BY username
   HAVING countries_accessed > 1 OR failed_attempts > 3;
```

5. **Data Loss Prevention**
   - Tag all sensitive files in database
   - Implement egress monitoring with lower thresholds
   - Deploy endpoint DLP on Finance workstations

### Long-Term (90+ Days)

6. **Zero Trust Architecture**
   - Continuous verification (not just authentication)
   - Microsegmentation to prevent lateral movement
   - Privileged Access Management (PAM)

7. **Security Awareness Training**
   - Quarterly phishing simulations
   - Track susceptibility by department:
```sql
   SELECT 
       e.department,
       COUNT(*) as emails_sent,
       SUM(CASE WHEN p.clicked = 1 THEN 1 ELSE 0 END) as clicked,
       ROUND(100.0 * SUM(CASE WHEN p.clicked = 1 THEN 1 ELSE 0 END) / COUNT(*), 2) as click_rate
   FROM phishing_simulation p
   JOIN employees e ON p.employee_id = e.employee_id
   GROUP BY e.department
   ORDER BY click_rate DESC;
```

---

## Appendix: Complete SQL Queries

### Investigation Query Library

#### A1: User Baseline Analysis
```sql
-- 30-day login pattern for anomaly detection
SELECT 
    DATE(login_date) as day,
    HOUR(login_time) as hour,
    country,
    COUNT(*) as login_count,
    SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful,
    SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failed
FROM log_in_attempts
WHERE username = @target_user
AND login_date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
GROUP BY DATE(login_date), HOUR(login_time), country
ORDER BY day DESC, hour;
```

#### A2: Multi-Account Breach Detection
```sql
-- Find all accounts accessed from known malicious IPs
SELECT DISTINCT
    l.username,
    e.department,
    e.office,
    l.ip_address,
    l.country,
    MIN(l.login_date) as first_seen,
    MAX(l.login_date) as last_seen,
    COUNT(*) as total_logins,
    SUM(CASE WHEN l.success = 1 THEN 1 ELSE 0 END) as successful_logins
FROM log_in_attempts l
INNER JOIN employees e ON l.username = e.username
WHERE l.ip_address IN (@malicious_ip_list)
AND l.login_date >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
GROUP BY l.username, e.department, e.office, l.ip_address, l.country
ORDER BY successful_logins DESC, first_seen;
```

#### A3: Data Exfiltration Analysis
```sql
-- Comprehensive file access during incident window
SELECT 
    e.username,
    e.department,
    f.file_path,
    f.file_name,
    fm.sensitivity_level,
    fm.contains_pii,
    fm.record_count,
    f.file_size_mb,
    f.action_type,
    f.timestamp
FROM file_access_logs f
INNER JOIN employees e ON f.username = e.username
LEFT JOIN file_metadata fm ON f.file_path = fm.file_path
WHERE f.timestamp BETWEEN @incident_start AND @incident_end
AND e.username IN (@compromised_accounts)
ORDER BY f.timestamp, f.file_size_mb DESC;
```

#### A4: Attack Timeline Generator
```sql
-- Master timeline query (all event types)
SELECT * FROM (
    -- Authentication events
    SELECT 
        CONCAT(login_date, ' ', login_time) as event_time,
        'Authentication' as category,
        CASE 
            WHEN success = 1 THEN 'Successful Login'
            ELSE 'Failed Login Attempt'
        END as event_type,
        username,
        CONCAT('From ', country, ' (', ip_address, ')') as details,
        CASE 
            WHEN success = 0 AND ip_address NOT LIKE '10.%' THEN 'High'
            WHEN success = 1 AND country != 'USA' THEN 'Critical'
            ELSE 'Medium'
        END as severity
    FROM log_in_attempts
    WHERE login_date >= @investigation_start
    
    UNION ALL
    
    -- File access events
    SELECT 
        timestamp as event_time,
        'Data Access' as category,
        CONCAT(action_type, ' File') as event_type,
        username,
        CONCAT(file_name, ' (', file_size_mb, ' MB)') as details,
        CASE 
            WHEN sensitivity_level = 'highly_sensitive' THEN 'Critical'
            WHEN sensitivity_level = 'confidential' THEN 'High'
            ELSE 'Medium'
        END as severity
    FROM file_access_logs
    WHERE timestamp >= @investigation_start
    
    UNION ALL
    
    -- Network events
    SELECT 
        timestamp as event_time,
        'Network' as category,
        'Data Transfer' as event_type,
        (SELECT username FROM employees WHERE device_id = source_device) as username,
        CONCAT(data_transferred_mb, ' MB to ', destination_ip) as details,
        CASE 
            WHEN destination_ip NOT LIKE '10.%' AND data_transferred_mb > 100 THEN 'Critical'
            WHEN destination_ip NOT LIKE '10.%' THEN 'High'
            ELSE 'Low'
        END as severity
    FROM network_connections
    WHERE timestamp >= @investigation_start
    
    UNION ALL
    
    -- Audit events
    SELECT 
        timestamp as event_time,
        'System Change' as category,
        action as event_type,
        username,
        details,
        CASE 
            WHEN action IN ('password_reset', 'mfa_disabled') THEN 'Critical'
            WHEN action LIKE '%privilege%' THEN 'High'
            ELSE 'Medium'
        END as severity
    FROM audit_logs
    WHERE timestamp >= @investigation_start
) combined_timeline
ORDER BY event_time;
```

#### A5: IOC Extraction
```sql
-- Extract all Indicators of Compromise
SELECT 'Malicious IP Addresses' as ioc_type, ip_address as indicator, COUNT(*) as occurrences
FROM log_in_attempts
WHERE ip_address IN (@confirmed_malicious_ips)
GROUP BY ip_address

UNION ALL

SELECT 'Compromised Usernames', username, COUNT(*)
FROM log_in_attempts
WHERE username IN (@compromised_accounts)
GROUP BY username

UNION ALL

SELECT 'Suspicious Email Senders', sender, COUNT(*)
FROM email_logs
WHERE sender LIKE '%securecorphelp.com'
GROUP BY sender

UNION ALL

SELECT 'Exfiltration Destinations', destination_ip, SUM(data_transferred_mb)
FROM network_connections
WHERE destination_ip NOT LIKE '10.%'
AND destination_ip NOT LIKE '172.16.%'
AND destination_ip NOT LIKE '192.168.%'
GROUP BY destination_ip
HAVING SUM(data_transferred_mb) > 100;
```

---

## Skills Demonstrated

### Technical SQL Skills
- ✓ Complex JOIN operations (INNER, LEFT, multi-table)
- ✓ Aggregate functions (COUNT, SUM, AVG, GROUP_CONCAT)
- ✓ Subqueries and correlated subqueries
- ✓ Date/time functions and calculations
- ✓ CASE statements for conditional logic
- ✓ UNION for combining disparate data sources
- ✓ GROUP BY and HAVING for data aggregation
- ✓ Window functions for temporal analysis
- ✓ String matching with LIKE and wildcards

### Security Analysis Skills
- ✓ Incident response methodology
- ✓ Attack pattern recognition
- ✓ Timeline reconstruction
- ✓ Indicator of Compromise (IOC) identification
- ✓ Lateral movement detection
- ✓ Data breach quantification
- ✓ Regulatory impact assessment
- ✓ Threat actor profiling

### Communication Skills
- ✓ Technical documentation
- ✓ Executive summary writing
- ✓ Visual timeline creation
- ✓ Findings presentation
- ✓ Recommendation development

---

## Conclusion

This investigation demonstrates how SQL proficiency is essential for modern security operations. Within 2 hours, using only SQL queries against a centralized security database, we:

1. ✅ Confirmed a multi-stage cyber attack
2. ✅ Identified 3 compromised accounts
3. ✅ Quantified 1,253.7 MB data breach
4. ✅ Reconstructed complete attack timeline
5. ✅ Discovered phishing campaign root cause
6. ✅ Calculated regulatory impact (125K+ PII records)
7. ✅ Extracted actionable IOCs
8. ✅ Provided remediation roadmap

**Key Takeaway:** SQL transforms security analysts from log readers into threat hunters. Every query in this investigation—from basic SELECT statements to complex multi-table joins—directly enabled faster detection, deeper understanding, and more effective response.

---

**Portfolio Note:** This report demonstrates real-world application of SQL skills developed through hands-on lab exercises in filtering, joining, and analyzing security data. All queries are production-ready and represent techniques used daily by security operations centers worldwide.

---

## Contact

**[Noah Page]**  
Security Analyst | SQL Specialist  

*This portfolio piece demonstrates SQL-based security investigation methodology. The scenario is based on real attack patterns but uses simulated data for demonstration purposes.*
