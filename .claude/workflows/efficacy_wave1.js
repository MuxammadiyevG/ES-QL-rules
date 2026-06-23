export const meta = {
  name: 'efficacy-wave1-silent-enabled',
  description: 'Triage 194 silent enabled rules (rare-vs-broken) against live data, then fix the broken ones',
  phases: [
    { title: 'Triage', detail: 'classify each silent rule: rare (legit) vs broken' },
    { title: 'Fix', detail: 'rewrite + validate the broken ones' },
  ],
}
const ES = "http://10.10.10.60:9200", AUTH = "elastic:elasticpassword"

const BRIEF = `
CLUSTER ${ES} (auth ${AUTH}). Run ES|QL via:
  curl -s -u ${AUTH} ${ES}/_query -H 'Content-Type: application/json' -d @/tmp/q_$$.json
  (write {"query":"..."} to that file first). Result has "values" (rows) or "error".
DATA WINDOW: real data only 2026-03-23..2026-06-02. To probe/validate, filter @timestamp >= "2026-03-23T00:00:00Z" (covers ALL data). 0 rows over THAT full window = the event truly does not occur in this data.

WHICH INDICES HAVE DATA: logs-winlog* (Windows 12.8M), logs-updive.audit-* (Linux auditd 58M), logs-nginx.access-*/error-*, logs-eset.protect-*, logs-switch.syslog-*/logs-switch-sflow-* (1.3M), metrics-updive.metric-* (612M), logs-snmp.trap-*.
EMPTY indices (0 docs) — a rule pointing here is BROKEN if live data exists elsewhere:
  updive-syslog-*  -> EMPTY. Real switch syslog data is in logs-switch.syslog-* (and logs-switch-sflow-*). (switch rules wrongly use updive-syslog-*.)
  logs-linux.auth-*, winlogbeat-*, auditbeat-*, metricbeat-*, filebeat-* -> EMPTY (legacy names).

SCHEMA QUICK REF:
- Windows logs-winlog*: winlog.channel, event.code (STRING), winlog.event_data.* (TargetUserName/IpAddress/ObjectName/CommandLine/ServiceName...), winlog.computer_name, agent_id. NO ECS source.ip/process.command_line/file.path on Security events. Sysmon channel "Microsoft-Windows-Sysmon/Operational" (EventID 1 has CommandLine/Image). Defender channel "Microsoft-Windows-Windows Defender/Operational". Hosts are RUSSIAN-LOCALIZED (don't filter the literal "SYSTEM" account; use SID S-1-5-18 or "*$").
- Linux logs-updive.audit-*: auditd.message_type, auditd.result, event.action, auditd.data.* (acct/terminal/addr/uid/cmd/exe), auditd.summary.how, source.ip, host.hostname, user.name, process.args (array), agent_id. event.dataset == "updive-audit.log" (NOT "auditd.log"). process.command_line does NOT exist. COUNT_DISTINCT(event.code) is 0 on auditd (event.code not populated) — use message_type.
- Nginx logs-nginx.access-*: http.request.method, http.response.status_code (long), url.path, user_agent.original, source.ip, source.geo.geo.country_name (double-nested). event.action is always "http_request" (don't filter HTTP verb on it). error logs unstructured (GROK ip from message).
- ES|QL: RLIKE anchored (use .*...*); (?i) BROKEN -> TO_LOWER(); machine acct NOT field LIKE "*$"; DATE_EXTRACT("hour_of_day",...) not "hour"; is_null removed -> IS NULL. Heavy RLIKE on event.original OOMs -> scope to a small field.
`

const TRIAGE_SCHEMA = { type:"object", additionalProperties:false, properties:{
  file:{type:"string"},
  classification:{type:"string", enum:["broken","rare","already_fires"]},
  core_signal:{type:"string", description:"index + key filter the rule keys on (e.g. logs-winlog* event.code 4768)"},
  probe_rows:{type:"integer", description:"events matching the rule's CORE signal over the full data window"},
  reason:{type:"string"},
  suspected_fix:{type:"string", description:"if broken, the concrete fix"},
}, required:["file","classification","probe_rows","reason"] }

const FIX_SCHEMA = { type:"object", additionalProperties:false, properties:{
  file:{type:"string"}, status:{type:"string", enum:["fixed","still_broken","rare_confirmed"]},
  changed:{type:"array", items:{type:"string"}}, validation_rows:{type:"integer"}, summary:{type:"string"},
}, required:["file","status","validation_rows","summary"] }

function triagePrompt(p){ return `Triage ONE Elastic ES|QL detection rule that returned 0 rows over the last 7 days of real data. Decide WHY it is silent: is the threat simply ABSENT (rare — legitimately silent, rule is fine) or is the rule BROKEN (wrong index/field/value/threshold so it could never fire even when the event occurs)?

RULE FILE (exact path, quote in bash): ${p}
${BRIEF}
STEPS:
1. Read the rule. Identify its CORE detection signal: which index + the key discriminating filter (event.code/channel, auditd.message_type/result, http status, etc.).
2. PROBE the live data over the FULL window: does that core event/signal occur AT ALL? e.g. count events of that type ignoring the rule's fine-grained extra conditions. Also, if the rule's index is in the EMPTY list, check whether the real data lives under a different index.
3. CLASSIFY:
   - "broken": rule points at an empty index while data exists elsewhere; OR the core event EXISTS in data but the rule's filter/field/value/threshold guarantees 0 matches (wrong value, wrong field, (?i), impossible threshold, etc.). Give the concrete suspected_fix.
   - "rare": the core event genuinely does not occur (or is extremely rare) in this data -> legitimately silent, rule looks correct. 
   - "already_fires": you found it actually returns rows over the full window (was just quiet in the 7-day window).
Report probe_rows = count of the core signal over the full window. Do NOT modify the file in triage.` }

function fixPrompt(p, sf){ return `Fix ONE Elastic ES|QL detection rule that is BROKEN (parses but can never detect its threat). Triage said: ${sf||"(see rule)"}

RULE FILE (exact path, quote in bash): ${p}
${BRIEF}
STEPS:
1. Read the rule + understand intent. 2. Apply the fix so it ACTUALLY detects the intended threat against the real schema/index (repoint empty index to the live one; fix wrong field/value; fix (?i); fix thresholds/buckets). Preserve rule_id/name/tags/severity/compliance fields.
3. VALIDATE against the cluster over the full window (@timestamp >= "2026-03-23T00:00:00Z"): it MUST parse clean. Record rows. If the threat genuinely never occurs but the rule is now CORRECT (right index/fields), that's "rare_confirmed" with 0 rows is acceptable — but you must have FIXED any wrong index/field first.
4. Save with a PRODUCTION lookback (keep the rule's original NOW()-N window, NOT the probe window).
Return structured result.` }

const SILENT = [
  "eset/ESET Protect - Critical or High Severity Threat Detection.yml",
  "eset/ESET Protect - Multiple Blocked Malicious URLs.yml",
  "eset/ESET Protect - Multiple Device Shutdown or Reboot Tasks.yml",
  "eset/ESET Protect - Multiple Malware Detections on Single Host.yml",
  "eset/ESET Protect - Real-Time Protection or Firewall Disabled.yml",
  "eset/ESET Protect - Suspicious Blocked Network Communication.yml",
  "eset/ESET Protect - Threat Detected But Not Cleaned.yml",
  "eset/ESET Protect - Unhandled Security Threats.yml",
  "linux/Account Management: Linux Account Locked or Unlocked.yml",
  "linux/Agent Execution: Suspicious Process Executed via execve Syscall.yml",
  "linux/Agent FIM: File Ownership Changed by Non-Package-Manager Process.yml",
  "linux/Agent FIM: Linux Cron or Systemd Service File Modified.yml",
  "linux/Agent FIM: Linux Directory Ownership or Permission Changed.yml",
  "linux/Agent FIM: Linux File Changed From Baseline.yml",
  "linux/Agent FIM: Linux File Content Modified.yml",
  "linux/Agent FIM: Linux File Ownership or Permission Changed.yml",
  "linux/Agent FIM: Linux File or Directory Created.yml",
  "linux/Agent FIM: Linux File or Directory Deleted.yml",
  "linux/Agent FIM: Linux SSH Authorized Keys or Config File Modified.yml",
  "linux/Agent FIM: Windows Domain Controller Critical File Modified (NTDS, SYSVOL).yml",
  "linux/Agent FIM: Windows Event Log File Modified or Deleted (Log Tampering).yml",
  "linux/Agent FIM: Windows Executable or DLL Created or Modified Outside Program Files.yml",
  "linux/Agent FIM: Windows FIM Error — File Locked by Another Process (Possible Ransomware).yml",
  "linux/Agent FIM: Windows Large File Size Change Detected (Possible Data Staging).yml",
  "linux/Agent FIM: Windows New Host Initial Scan Detected.yml",
  "linux/Agent FIM: Windows ProgramData Suspicious File Activity.yml",
  "linux/Agent FIM: Windows Recycle Bin File Activity (Possible Data Hiding).yml",
  "linux/Agent FIM: Windows Sensitive Configuration File Modified.yml",
  "linux/Agent FIM: Windows Shadow Copy or Backup File Activity.yml",
  "linux/Agent FIM: Windows Startup Folder File Modified (Persistence).yml",
  "linux/Agent FIM: Windows System File or Log Modified.yml",
  "linux/Agent FIM: Windows Temp Directory Executable Activity.yml",
  "linux/Agent FIM: Windows User Profile Directory File Created or Modified.yml",
  "linux/Agent IAM: Linux Group Management Activity Detected.yml",
  "linux/Agent IAM: Linux User Account Created.yml",
  "linux/Agent Info: Auditd Sequence Gap Detected (Possible Log Tampering).yml",
  "linux/Agent Persistence: Audit Configuration Changed.yml",
  "linux/Agent Persistence: Cron Session for Non-Root or Unexpected Account.yml",
  "linux/Agent Persistence: Software Package Installed or Unpacked via dpkg.yml",
  "linux/Agent Privilege Escalation: Group Identity Changed via newgrp.yml",
  "linux/Audited file or directory content modified in SVN.yml",
  "linux/Defense Evasion: Log Files Cleared or Truncated.yml",
  "linux/Execution: Possible Reverse Shell Process Execution.yml",
  "linux/Impact: Mass File Deletion Detected (Possible Ransomware Activity).yml",
  "linux/Integrity: Critical Linux Directory Permissions or Ownership Changed.yml",
  "linux/Persistence - Defense Evasion: APT Sources List Modified.yml",
  "linux/Persistence: Cron or Systemd Scheduled Task Created or Modified.yml",
  "linux/Persistence: SSH Authorized Keys Access via Editor Execution.yml",
  "linux/Privilege Escalation  Discovery: Suspicious Software Installed or Removed via apt dpkg.yml",
  "linux/Privilege Escalation: New SUID or SGID File Created.yml",
  "linux/Privilege Escalation: Sudoers Modification via visudo or Direct Edit.yml",
  "metrics/Resource Anomaly: CPU Usage Above 90 Percent for More Than 10 Minutes.yml",
  "metrics/Resource: High CPU Utilization Detected.yml",
  "metrics/Resource: High CPU and Memory Utilization Detected.yml",
  "nginx/Nginx - Cross-Site Scripting (XSS) Attempts.yml",
  "nginx/Nginx - Directory Traversal Attack Attempts.yml",
  "nginx/Nginx - Excessive 403 Forbidden Responses.yml",
  "nginx/Nginx - Excessive Authentication Failures.yml",
  "nginx/Nginx - Invalid URI with Extremely Long Filename.yml",
  "nginx/Nginx - Multiple Web Authentication Failures.yml",
  "nginx/Nginx - Potential Command Injection Attempt.yml",
  "nginx/Nginx - SQL Injection Attempts Detected in URLs.yml",
  "nginx/Nginx - Sensitive File Discovery Attempt.yml",
  "nginx/Nginx - Shellshock Exploitation Attempts.yml",
  "nginx/Nginx - Suspicious HTTP 4xx Error Spike.yml",
  "nginx/Nginx - Suspicious HTTP 5xx Server Error Spike.yml",
  "nginx/Nginx - Suspicious POST Request Flood.yml",
  "nginx/Nginx - Unusual 4xx Error Rate (Fuzzing -Scanning).yml",
  "nginx/Nginx - Unusual HTTP Method Usage.yml",
  "switch/Switch AAA: Foydalanuvchi switch dan chiqdi.yml",
  "switch/Switch AAA: Foydalanuvchi switch ga kirdi.yml",
  "switch/Switch AAA: Sessiya uzildi (DISCONNECT).yml",
  "switch/Switch AAA: Switch ga kirish rad etildi.yml",
  "switch/Switch COPY: Barcha nusxalash operatsiyalari.yml",
  "switch/Switch COPY: Nusxalash operatsiyasi muvaffaqiyatli (TRAP).yml",
  "switch/Switch GCLI: Foydalanuvchi CLI buyruq berdi.yml",
  "switch/Switch LINK: Port holati o'zgardi.yml",
  "switch/Switch LINK: Port o'chdi (Interface Down).yml",
  "switch/Switch LINK: Port yondi (Interface Up).yml",
  "switch/Switch NT_GREEN: LLDP yoki EEE holati o'zgardi.yml",
  "switch/Switch NT_GREEN: Portda bir nechta LLDP qo'shni aniqlandi.yml",
  "switch/Switch STCK: Stack unit xabari.yml",
  "switch/Switch STP: Port Blocking holatida.yml",
  "switch/Switch STP: Port Forwarding holatida.yml",
  "switch/Switch STP: STP holat o'zgarishi (barcha).yml",
  "switch/Switch SYSLOG: Barcha logging konfiguratsiya o'zgarishlari.yml",
  "switch/Switch SYSLOG: Console logging darajasi o'zgardi (LOGGINGCNSL).yml",
  "switch/Switch SYSLOG: Console logging to'xtatildi (LOGGINGCNSLSTOP).yml",
  "switch/Switch SYSLOG: Log aggregation holati o'zgardi (AGGREGATION).yml",
  "switch/Switch SYSLOG: Logging sozlamalari o'zgardi.yml",
  "switch/Switch SYSLOG: Syslog server o'chirildi (NOSYSLOGSERVER).yml",
  "switch/Switch SYSLOG: Yangi syslog server qo'shildi (NEWSYSLOGSERVER).yml",
  "switch/Switch Syslog: Barcha hodisalar (umumiy).yml",
  "switch/Switch Syslog: Parse qilinmagan log aniqlandi.yml",
  "windows/AD Recon Command Burst.yml",
  "windows/AD_AD_Object_Access_Suspicious_4662.yml",
  "windows/AD_DCSync_Replication_4662.yml",
  "windows/AD_Directory_Object_Modified_5136.yml",
  "windows/AD_Service_Installed_4697.yml",
  "windows/AD_Successful_Logon_After_Failed_Attempts_4624_4625.yml",
  "windows/AS_Creds dumping process.yml",
  "windows/Account Lockout Policy Disabled or Weakened.yml",
  "windows/Active Directory Schema Modification Detected.yml",
  "windows/Active Directory Trust Enumeration Detected.yml",
  "windows/AdminSDHolder ACL Modification Detected.yml",
  "windows/Administrative Share Access Detection.yml",
  "windows/Adware process found.yml",
  "windows/Agent FIM: Active Directory Ownership or Permission Changed.yml",
  "windows/Agent FIM: Windows File Changed From Baseline.yml",
  "windows/Agent FIM: Windows File Content Modified.yml",
  "windows/Agent FIM: Windows File or Directory Archive Bit Changed.yml",
  "windows/Agent FIM: Windows File or Directory Created.yml",
  "windows/Agent FIM: Windows File or Directory Deleted.yml",
  "windows/COM Hijack InprocServer32.yml",
  "windows/Cleartext Password Network Logon.yml",
  "windows/Common Windows process launched by unusual parent.yml",
  "windows/Common Windows process launched from unusual path.yml",
  "windows/Computer Account Created.yml",
  "windows/DNS DGA-like Domain.yml",
  "windows/DNS Query to Suspicious TLD or Dynamic DNS.yml",
  "windows/DNS over HTTPS Provider Query.yml",
  "windows/Database Server Disk Latency Critical.yml",
  "windows/Defender Exclusion Added.yml",
  "windows/Defender Malware Detected.yml",
  "windows/Defender Protection Disabled.yml",
  "windows/Disabled or Expired Account Logon Attempt.yml",
  "windows/Domain Password Policy Weakened.yml",
  "windows/Group Policy Object Created or Modified.yml",
  "windows/Guest Account Usage.yml",
  "windows/IFEO Debugger Hijack.yml",
  "windows/Kerberos Pre-Authentication Failure - AS-REP Roasting.yml",
  "windows/Kerberos Service Ticket Request - Kerberoasting.yml",
  "windows/LOLBin Abuse - Download Execute.yml",
  "windows/LSA Security Package Injection.yml",
  "windows/LSASS Credential Dump Tooling.yml",
  "windows/Mass Computer Account Changes.yml",
  "windows/Multiple Account Lockouts Detected.yml",
  "windows/Multiple Accounts From Single Source.yml",
  "windows/New Scheduled Task Registered.yml",
  "windows/Office Application Spawning Shell.yml",
  "windows/Outbound Lateral Movement Protocols.yml",
  "windows/Outbound RDP From Host - Lateral Movement.yml",
  "windows/Outbound Scan or Beacon - Many Destinations.yml",
  "windows/Password Spraying - Multiple Users Single Source.yml",
  "windows/Potential DCSync Attack - Suspicious Replication.yml",
  "windows/Potential Golden Ticket Attack - Suspicious TGT Properties.yml",
  "windows/PowerShell AMSI ETW Bypass.yml",
  "windows/PowerShell Download Cradle.yml",
  "windows/PowerShell Encoded Command.yml",
  "windows/PowerShell Module Logging Suspicious.yml",
  "windows/PowerShell Offensive Tooling.yml",
  "windows/PowerShell Shellcode Reflection Injection.yml",
  "windows/PowerShell Suspicious Obfuscation.yml",
  "windows/PowerShell v2 Downgrade.yml",
  "windows/PrintNightmare - Spooler Spawning Process.yml",
  "windows/Privileged Account Interactive Logon.yml",
  "windows/PsExec Service Execution.yml",
  "windows/RDP Brute Force - Failed Logons Type 10.yml",
  "windows/RDP Logon From External Source.yml",
  "windows/RDP Session Hijack via tscon.yml",
  "windows/Rapid Network Logons Across Multiple Systems.yml",
  "windows/Registry Run Key Persistence.yml",
  "windows/Remote Tool Drop to Admin Share.yml",
  "windows/Scheduled Task Created Through AD-GPO.yml",
  "windows/Security Process Terminated.yml",
  "windows/Security Service Start Type Changed.yml",
  "windows/Service Account Interactive Logon Detected.yml",
  "windows/Service Registry Modification.yml",
  "windows/Shadow Copy and Backup Deletion.yml",
  "windows/Startup Folder File Drop.yml",
  "windows/Suspicious Kerberos Delegation Activity.yml",
  "windows/Suspicious Process Outbound Connection.yml",
  "windows/Suspicious Service Installed for Persistence.yml",
  "windows/Sysmon Configuration Changed.yml",
  "windows/System32 Binary Drop.yml",
  "windows/UAC Bypass via Auto-Elevated Process.yml",
  "windows/User Logon From Unusual Workstation.yml",
  "windows/WMI Event Subscription for Persistence.yml",
  "windows/Web Shell Drop.yml",
  "windows/WinRM Remote Execution.yml",
  "windows/Windows File Server: File ACL Changed.yml",
  "windows/Windows File Server: File Attribute Change.yml",
  "windows/Windows File Server: File Creation via Detailed File Share.yml",
  "windows/Windows File Server: File Deletion via NTFS Audit.yml",
  "windows/Windows File Server: File Handle Closed.yml",
  "windows/Windows File Server: File Modification via Detailed File Share.yml",
  "windows/Windows File Server: File Open via Handle Request.yml",
  "windows/Windows File Server: File Owner Changed.yml",
  "windows/Windows File Server: File Read via Detailed File Share.yml",
  "windows/Windows File Server: Possible File Copy.yml",
  "windows/Windows File Server: Possible File Move.yml",
  "windows/Windows File Server: Possible File Rename.yml",
  "windows/Windows Succession login attemmpt.yml",
  "windows/Winlogon Persistence.yml"
]

log(`Wave1: triage ${SILENT.length} silent-enabled rules`)
phase('Triage')
const tri = (await parallel(SILENT.map(p => () =>
  agent(triagePrompt(p), {label:`triage:${p.split('/').pop().slice(0,34)}`, phase:'Triage', model:'sonnet', effort:'low', schema:TRIAGE_SCHEMA})
))).filter(Boolean)

const broken = tri.filter(t => t.classification === 'broken')
log(`Triage done. broken=${broken.length} rare=${tri.filter(t=>t.classification==='rare').length} already_fires=${tri.filter(t=>t.classification==='already_fires').length}`)

phase('Fix')
const fixes = (await parallel(broken.map(b => () =>
  agent(fixPrompt(b.file, b.suspected_fix), {label:`fix:${b.file.split('/').pop().slice(0,38)}`, phase:'Fix', model:'sonnet', schema:FIX_SCHEMA})
))).filter(Boolean)

return {
  counts:{ triaged:tri.length, broken:broken.length, fixed:fixes.filter(f=>f.status==='fixed').length, still_broken:fixes.filter(f=>f.status==='still_broken').length, rare_confirmed:fixes.filter(f=>f.status==='rare_confirmed').length },
  rare: tri.filter(t=>t.classification==='rare').map(t=>({file:t.file, signal:t.core_signal, reason:t.reason})),
  broken_fixed: fixes.filter(f=>f.status==='fixed').map(f=>({file:f.file, rows:f.validation_rows, changed:f.changed, summary:f.summary})),
  still_broken: fixes.filter(f=>f.status!=='fixed').map(f=>({file:f.file, status:f.status, summary:f.summary})),
}
