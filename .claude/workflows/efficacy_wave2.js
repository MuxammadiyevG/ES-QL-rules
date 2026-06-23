export const meta = {
  name: 'efficacy-wave2-firing-noise',
  description: 'Review 111 firing rules for false-positive/noise risk; conservatively tune the noisy ones',
  phases: [ { title: 'Noise', detail: 'assess volume + FP risk, tune only clear noise' } ],
}
const ES = "http://10.10.10.60:9200", AUTH = "elastic:elasticpassword"
const BRIEF = `
CLUSTER ${ES} (auth ${AUTH}). Run ES|QL: write {"query":"..."} to /tmp/n_$$.json then
  curl -s -u ${AUTH} ${ES}/_query -H 'Content-Type: application/json' -d @/tmp/n_$$.json
Result has "values" (rows) / "error". DATA WINDOW: 2026-03-23..2026-06-02 (~71 days). To measure true volume, run the rule body with the time filter set to @timestamp >= "2026-03-23T00:00:00Z" (NOT the production NOW() window).
PRODUCTION window = the rule's own NOW()-N lookback (often 15 min). A 15-min rule firing on 71 days of data: est alerts per run ≈ rows_full / (71*24*60/N_minutes).
SCHEMA: Windows logs-winlog* (winlog.channel/event.code/winlog.event_data.*); Linux logs-updive.audit-* (auditd.message_type/result/data.*); nginx logs-nginx.access-* (http.*/source.ip); switch logs-switch.syslog-*; eset logs-eset.protect-*. Machine accts end "*$". (?i) broken->TO_LOWER.
`
const SCHEMA = { type:"object", additionalProperties:false, properties:{
  file:{type:"string"}, rows_full_window:{type:"integer"}, distinct_entities:{type:"integer", description:"distinct hosts/users/ips in output"},
  hits_limit_cap:{type:"boolean"}, noise:{type:"string", enum:["ok","noisy","very_noisy"]},
  action:{type:"string", enum:["none","tuned"]}, changed:{type:"array", items:{type:"string"}}, summary:{type:"string"},
}, required:["file","rows_full_window","noise","action","summary"] }
function prompt(p){ return `Assess ONE firing Elastic ES|QL detection rule for FALSE-POSITIVE / NOISE risk. Tune it ONLY if it is clearly too noisy — be conservative, never weaken a sound detection.

RULE FILE (exact path, quote in bash): ${p}
${BRIEF}
STEPS:
1. Read the rule. Run its query over the FULL window (@timestamp >= "2026-03-23T00:00:00Z") and record rows_full_window and how many distinct hosts/users/ips appear.
2. Judge noise: does it hit its LIMIT cap (e.g. 1000)? Estimate alerts-per-production-run. A detection meant for real incidents that would fire on essentially EVERY interval, or on hundreds of distinct benign entities, is NOISY. A rule that surfaces a handful of meaningful hits is OK even if it returned many rows over 71 days.
3. If clearly noisy/very_noisy AND you can tune WITHOUT losing the real signal: tune conservatively — raise an over-low threshold, add a precise allowlist for confirmed-benign sources, tighten an over-broad filter, or aggregate. PRESERVE rule_id/name/intent; keep a production lookback in the saved file; re-validate it still parses and still returns the meaningful hits.
4. If it's fine, action "none" and do NOT modify the file.
Return the structured result (set hits_limit_cap, distinct_entities when known).` }
const FIRING = [
  "eset/Agent ESET: Alert Detected.yml",
  "eset/Agent ESET: Blocked Action Detected.yml",
  "linux/Access: SSH Session Login — user_start Event.yml",
  "linux/Access: SSH Session Logout — cred_disp Event.yml",
  "linux/Account Management: Linux User Created, Deleted, Password Changed or Added to Privileged Group.yml",
  "linux/Agent Credential Access: Multiple sudo Failures Followed by Success (Brute Force).yml",
  "linux/Agent Credential Access: SSH Brute Force — Multiple Failures Then Success from Same IP.yml",
  "linux/Agent Credential Access: SSH Login Failure from Remote Host.yml",
  "linux/Agent Defense Evasion: AppArmor Policy Violation (AVC Denied).yml",
  "linux/Agent Defense Evasion: BPF Program Loaded or Unloaded.yml",
  "linux/Agent Defense Evasion: SSHD Process Respawned or Restarted.yml",
  "linux/Agent FIM: File Content or Attributes Modified (File Integrity).yml",
  "linux/Agent FIM: Linux Configuration File Modified in etc Directory.yml",
  "linux/Agent FIM: Linux Executable File Created or Modified in System Directories.yml",
  "linux/Agent Info: File Integrity Monitoring — Any File Change.yml",
  "linux/Agent Info: Network Interface Activity Observed.yml",
  "linux/Agent Info: PAM Credential Acquired (Service Login).yml",
  "linux/Agent Info: Process Execution Activity (execve).yml",
  "linux/Agent Info: User Session Closed (Logout).yml",
  "linux/Agent Info: User Session Opened (SSH Login Success).yml",
  "linux/Agent Info: sudo Command Executed Successfully.yml",
  "linux/Agent Initial Access: New Login Session Established.yml",
  "linux/Agent Initial Access: Successful SSH Login from Remote Host.yml",
  "linux/Agent Lateral Movement: SSH Outbound Connection to External Host.yml",
  "linux/Agent Network: Promiscuous Mode Enabled on Network Interface.yml",
  "linux/Agent Privilege Escalation: sudo Authentication Attempt.yml",
  "linux/Agent Process: Linux Critical Service Stopped with Failure.yml",
  "linux/Agent Process: Linux Service Started as Root (Unexpected Execution).yml",
  "linux/Credential Access: SSH Brute Force — Failures Then Success.yml",
  "linux/Credential Access: SSH Brute Force — Multiple Failures Then Success.yml",
  "linux/Credential Access: SSH Brute Force — Multiple Failures from Single IP (1m >5).yml",
  "linux/Credential Access: SSH Brute Force — Multiple Failures from Single IP.yml",
  "linux/Defense Evasion: Firewall Rules Modified or Cleared.yml",
  "linux/Execution: New Executable File Created or Executed in Temp Directories.yml",
  "linux/Execution: Sudo Command Activity Logging.yml",
  "linux/Execution: Suspicious Command After SSH Brute Force Success.yml",
  "linux/Execution: Wget-Curl Download Followed by File Execution.yml",
  "linux/Initial Access: After-Hours Successful Login — SSH or Local.yml",
  "linux/Integrity: Critical Linux Account Files Modified.yml",
  "linux/PCI DSS 10.2.2 - Privileged User Actions (Linux sudo-su).yml",
  "linux/PCI DSS 11.5 - Critical File Modification Detected (Linux).yml",
  "linux/PCI DSS 8.1.6 - Brute Force Login Attempt (Linux Auditd).yml",
  "linux/Privilege Escalation: Root Session Close via sudo - su.yml",
  "linux/Privilege Escalation: Root Session Open via sudo or su.yml",
  "linux/lnx_auditd_data_compressed_esql.yml",
  "linux/lnx_auditd_hidden_binary_execution_esql.yml",
  "linux/lnx_auditd_load_module_insmod_esql.yml",
  "linux/lnx_auditd_modify_system_firewall_esql.yml",
  "linux/lnx_auditd_network_service_scanning_esql.yml",
  "linux/lnx_auditd_susp_c2_commands_esql.yml",
  "linux/lnx_auditd_susp_exe_folders_esql.yml",
  "linux/lnx_auditd_system_info_discovery_esql.yml",
  "linux/lnx_auditd_user_discovery_esql.yml",
  "metrics/Resource: High Memory Utilization Detected.yml",
  "metrics/Resource: Host Resource Pressure Detected.yml",
  "metrics/Resource: Low Disk Space Detected.yml",
  "nginx/Dangerous HTTP Method Usage.yml",
  "nginx/Malicious User-Agent Detection.yml",
  "nginx/Nginx - Suspicious or Malicious User Agents.yml",
  "nginx/Web Application Attack Detection.yml",
  "windows/AD_Kerberos_Anomaly_4768_4769.yml",
  "windows/AD_NTLM_Failure_Spike_4776.yml",
  "windows/AD_Service_Installed_DC_7045.yml",
  "windows/AD_Special_Privileges_Assigned_4672.yml",
  "windows/AD_Suspicious_Success_Logon_DC_4624.yml",
  "windows/AD_Suspicious_User_Change_4738.yml",
  "windows/Account Lockout Cleared - Normal Helpdesk.yml",
  "windows/Audit System Failure or Attack.yml",
  "windows/Brute Force.yml",
  "windows/Computer Account Logons - Domain Joined Systems.yml",
  "windows/Concurrent Logon From Multiple Sources.yml",
  "windows/CreateRemoteThread Injection.yml",
  "windows/DNS Tunneling - Many Unique Queries.yml",
  "windows/Defender Tampering via Registry.yml",
  "windows/Execution From Suspicious Path.yml",
  "windows/Firewall Policy Modification.yml",
  "windows/GDPR Art.25(1) - Data Protection by Design Controls Failure.yml",
  "windows/GDPR Art.30(1)(g) - Security Measures Record Completeness Failure.yml",
  "windows/GDPR Art.32(1)(b) - Confidentiality and Integrity of Processing Systems Compromised.yml",
  "windows/GDPR Art.32(1)(c) - Personal Data Processing System Availability Loss.yml",
  "windows/GDPR Art.32(1)(d) - Security Controls Effectiveness Degradation.yml",
  "windows/GDPR Art.33(1) - Personal Data Breach Detection Trigger (72h Notification Clock).yml",
  "windows/GDPR Art.34(1) - High-Risk Breach Indicators Requiring Data Subject Notification.yml",
  "windows/GDPR Art.5(1)(f) - Unauthorized Access to Personal Data Systems.yml",
  "windows/Kerberos Ticket Renewal - Normal Operations.yml",
  "windows/LNK or Script in Suspicious Location.yml",
  "windows/NTLM Authentication Where Kerberos Expected.yml",
  "windows/Normal Kerberos Service Ticket Requests.yml",
  "windows/Normal Kerberos TGT Requests - Baseline.yml",
  "windows/PCI DSS 10.2.2 - Privileged User Actions (Windows Admin).yml",
  "windows/PCI DSS 10.2.4 - Invalid Logical Access Attempts Spike.yml",
  "windows/PCI DSS 10.2.5 - User Account Privilege Changes and New Admin Accounts (Windows).yml",
  "windows/PCI DSS 8.1.8 - Long-Running Idle Interactive Sessions (Windows).yml",
  "windows/Pass-the-Hash - NTLM Network Logon.yml",
  "windows/PowerShell Unusual Host Process.yml",
  "windows/RDP Session Reconnect Tracking.yml",
  "windows/Scheduled Task Launched Suspicious Process.yml",
  "windows/Script Interpreter DNS Query.yml",
  "windows/Security Group Membership Queries.yml",
  "windows/Service Account Normal Operations.yml",
  "windows/Shared Account Concurrent Usage.yml",
  "windows/Successful Kerberos Pre-Authentication.yml",
  "windows/Successful User Logon Events - Baseline.yml",
  "windows/Suspicious Process Execution Pattern.yml",
  "windows/Token Privilege Elevation Detected.yml",
  "windows/Unauthorized Software Installation.yml",
  "windows/User Account Attribute Modifications.yml",
  "windows/User Logoff Events - Session Tracking.yml",
  "windows/User Logon Outside Business Hours.yml",
  "windows/User Password Change Events - Self Service.yml",
  "windows/User Password Reset By Administrator.yml"
]
log(`Wave2: noise-review ${FIRING.length} firing rules`)
phase('Noise')
const res = (await parallel(FIRING.map(p => () =>
  agent(prompt(p), {label:`noise:${p.split('/').pop().slice(0,36)}`, phase:'Noise', model:'sonnet', effort:'low', schema:SCHEMA})
))).filter(Boolean)
return {
  counts:{ reviewed:res.length, ok:res.filter(r=>r.noise==='ok').length, noisy:res.filter(r=>r.noise==='noisy').length, very_noisy:res.filter(r=>r.noise==='very_noisy').length, tuned:res.filter(r=>r.action==='tuned').length },
  tuned: res.filter(r=>r.action==='tuned').map(r=>({file:r.file, changed:r.changed, summary:r.summary})),
  noisy_untuned: res.filter(r=>r.noise!=='ok' && r.action==='none').map(r=>({file:r.file, rows:r.rows_full_window, noise:r.noise, summary:r.summary})),
}
