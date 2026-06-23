export const meta = {
  name: 'efficacy-wave3-silent-disabled',
  description: 'Triage 121 silent DISABLED baseline rules (rare-vs-broken) against live data, then fix the broken ones',
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
  "linux/file_event_lnx_doas_conf_creation_esql.yml",
  "linux/file_event_lnx_persistence_cron_files_esql.yml",
  "linux/file_event_lnx_persistence_sudoers_files_esql.yml",
  "linux/file_event_lnx_susp_filename_with_embedded_base64_command_esql.yml",
  "linux/file_event_lnx_susp_shell_script_under_profile_directory_esql.yml",
  "linux/file_event_lnx_triple_cross_rootkit_lock_file_esql.yml",
  "linux/file_event_lnx_triple_cross_rootkit_persistence_esql.yml",
  "linux/file_event_lnx_wget_download_file_in_tmp_dir_esql.yml",
  "linux/lnx_auditd_audio_capture_esql.yml",
  "linux/lnx_auditd_auditing_config_change_esql.yml",
  "linux/lnx_auditd_binary_padding_esql.yml",
  "linux/lnx_auditd_bpfdoor_file_accessed_esql.yml",
  "linux/lnx_auditd_bpfdoor_port_redirect_esql.yml",
  "linux/lnx_auditd_capabilities_discovery_esql.yml",
  "linux/lnx_auditd_change_file_time_attr_esql.yml",
  "linux/lnx_auditd_chattr_immutable_removal_esql.yml",
  "linux/lnx_auditd_clean_disable_dmesg_logs_via_syslog_esql.yml",
  "linux/lnx_auditd_clipboard_collection_esql.yml",
  "linux/lnx_auditd_clipboard_image_collection_esql.yml",
  "linux/lnx_auditd_coinminer_esql.yml",
  "linux/lnx_auditd_create_account_esql.yml",
  "linux/lnx_auditd_data_exfil_wget_esql.yml",
  "linux/lnx_auditd_dd_delete_file_esql.yml",
  "linux/lnx_auditd_disable_aslr_protection_esql.yml",
  "linux/lnx_auditd_disable_system_firewall_esql.yml",
  "linux/lnx_auditd_file_or_folder_permissions_esql.yml",
  "linux/lnx_auditd_find_cred_in_files_esql.yml",
  "linux/lnx_auditd_hidden_files_directories_esql.yml",
  "linux/lnx_auditd_hidden_zip_files_steganography_esql.yml",
  "linux/lnx_auditd_keylogging_with_pam_d_esql.yml",
  "linux/lnx_auditd_ld_so_preload_mod_esql.yml",
  "linux/lnx_auditd_logging_config_change_esql.yml",
  "linux/lnx_auditd_magic_system_request_key_esql.yml",
  "linux/lnx_auditd_masquerading_crond_esql.yml",
  "linux/lnx_auditd_network_sniffing_esql.yml",
  "linux/lnx_auditd_password_policy_discovery_esql.yml",
  "linux/lnx_auditd_screencapture_import_esql.yml",
  "linux/lnx_auditd_screencaputre_xwd_esql.yml",
  "linux/lnx_auditd_split_file_into_pieces_esql.yml",
  "linux/lnx_auditd_steghide_embed_steganography_esql.yml",
  "linux/lnx_auditd_steghide_extract_steganography_esql.yml",
  "linux/lnx_auditd_susp_cmds_esql.yml",
  "linux/lnx_auditd_susp_discovery_sysinfo_syscall_esql.yml",
  "linux/lnx_auditd_susp_histfile_operations_esql.yml",
  "linux/lnx_auditd_susp_service_reload_or_restart_esql.yml",
  "linux/lnx_auditd_susp_special_file_creation_via_mknod_syscall_esql.yml",
  "linux/lnx_auditd_system_info_discovery2_esql.yml",
  "linux/lnx_auditd_system_shutdown_reboot_esql.yml",
  "linux/lnx_auditd_systemd_service_creation_esql.yml",
  "linux/lnx_auditd_unix_shell_configuration_modification_esql.yml",
  "linux/lnx_auditd_unzip_hidden_zip_files_steganography_esql.yml",
  "linux/lnx_auditd_web_rce_esql.yml",
  "linux/lnx_cron_crontab_file_modification.yml",
  "linux/lnx_sshd_susp_ssh.yml",
  "linux/lnx_syslog_security_tools_disabling_syslog.yml",
  "linux/lnx_syslog_susp_named.yml",
  "linux/lnx_vsftpd_susp_error_messages.yml",
  "nginx/Administrative Interface Probing.yml",
  "nginx/Nginx - CRLF Injection HTTP Response Splitting.yml",
  "nginx/Nginx - Information: Legacy Protocol Usage.yml",
  "nginx/Nginx - Information: User-Agent Switching Anomaly.yml",
  "nginx/Nginx - Log4Shell JNDI Exploitation Attempt.yml",
  "nginx/Nginx - Open Redirect Attempt.yml",
  "nginx/Nginx - Successful Request After WAF 4xx Burst.yml",
  "nginx/Nginx - Webshell Suspicious Script Upload or Access.yml",
  "nginx/Suspicious Large HTTP POST.yml",
  "nginx/Web Login Brute Force Attack.yml",
  "windows/AD_Account_Deleted_4726.yml",
  "windows/AD_Account_Disabled_4725.yml",
  "windows/AD_Account_Enabled_4722.yml",
  "windows/AD_Account_Lockout_Spike_4740.yml",
  "windows/AD_Audit_Policy_Changed_4719.yml",
  "windows/AD_Domain_Policy_Changed_4739.yml",
  "windows/AD_Explicit_Credential_Use_4648.yml",
  "windows/AD_Kerberos_PreAuth_Failure_Spike_4771.yml",
  "windows/AD_New_User_Created_4720.yml",
  "windows/AD_Password_Spray_4625.yml",
  "windows/AD_Privileged_Group_Add_4728_4732_4756.yml",
  "windows/AD_Privileged_Group_Remove_4729_4733_4757.yml",
  "windows/Account Locked -Domain.yml",
  "windows/Active Directory Object Read Operations.yml",
  "windows/Attack Kill Chain Completion.yml",
  "windows/Audit Policy Configuration - Current State.yml",
  "windows/Audit Policy Disabled or Modified.yml",
  "windows/Audit Policy Modification Detection.yml",
  "windows/Auto Service Stopped.yml",
  "windows/Computer Account Deleted From Active Directory.yml",
  "windows/Critical Configuration File Modification.yml",
  "windows/Critical System File Tampering.yml",
  "windows/Daily Active Directory Access Summary.yml",
  "windows/Domain Trust Relationship Modified.yml",
  "windows/Excessive Destination Windows DC Replication Failure.yml",
  "windows/Excessive Failed Privileged Access.yml",
  "windows/Executable With Mark-of-the-Web ADS.yml",
  "windows/GDPR Art.33(2) - Third-Party Vendor or Processor Account Anomaly.yml",
  "windows/GDPR Art.33(5) - Audit Trail Completeness Gap (Breach Documentation Impaired).yml",
  "windows/Group Membership Enumeration - Normal Activity.yml",
  "windows/Multiple Failed Logon Attempts - Potential Brute Force.yml",
  "windows/Network Share Access - Normal Usage Patterns.yml",
  "windows/New User Account Created in Active Directory.yml",
  "windows/Normal Domain Controller Replication.yml",
  "windows/PCI DSS 10.2.6 - Audit Log Service Stopped or Paused (Windows).yml",
  "windows/PCI DSS 8.1.6 - Brute Force Login Attempt (Windows).yml",
  "windows/PCI DSS 8.3 - Remote Access Without MFA - Single-Factor Auth (Windows).yml",
  "windows/Previously Disabled User Account Re-enabled.yml",
  "windows/Privileged Access Workstation (PAW) Activity.yml",
  "windows/RDP Successful Logon Baseline.yml",
  "windows/Remote Access Brute Force Detection.yml",
  "windows/Scheduled Task Deleted.yml",
  "windows/Security Event Log Cleared.yml",
  "windows/Security Group Membership Changes - Audit Trail.yml",
  "windows/Security Software Disabled.yml",
  "windows/Sensitive Privilege Used - Potential Abuse.yml",
  "windows/Sensitive Privileges Assigned at Logon.yml",
  "windows/Successful Logon After Multiple Failed Attempts.yml",
  "windows/Suspicious Outbound Connection.yml",
  "windows/Suspicious Scheduled Task Creation.yml",
  "windows/Unauthorized Service Installation.yml",
  "windows/User Account Deleted From Active Directory.yml",
  "windows/User Added to Privileged Security Group.yml",
  "windows/User Added to Security Group.yml"
]
log(`Wave3: triage ${SILENT.length} silent-disabled baselines`)
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
