export const meta = {
  name: 'build-correlation-chains-batch3',
  description: 'Each agent designs + cluster-validates one multi-stage attack chain; returns structured stages for uniform rendering',
  phases: [ { title: 'Design', detail: 'one agent per attack chain, validating each stage query' } ],
}
const ES = "http://10.10.10.60:9200", AUTH = "elastic:elasticpassword"

const BRIEF = `
CLUSTER ${ES} (auth ${AUTH}). Validate ES|QL: write {"query":"..."} to /tmp/c_$$.json then
  curl -s -u ${AUTH} ${ES}/_query -H 'Content-Type: application/json' -d @/tmp/c_$$.json
Result has "values" (rows) or "error". DATA only spans 2026-03-23..2026-06-02 — to validate, set the time filter to @timestamp >= "2026-03-23T00:00:00Z" (covers ALL data). A query that PARSES with 0 rows is acceptable (the threat may simply be absent — these are threat-hunting stages); a query that ERRORS must be fixed.

INDICES WITH DATA: Windows logs-winlog* ; Linux auditd logs-updive.audit-* ; nginx logs-nginx.access-* ; eset logs-eset.protect-*.
WINDOWS (logs-winlog*): winlog.channel, event.code (STRING), winlog.event_data.*, winlog.computer_name, agent_id. Security channel = "Security"; Sysmon = "Microsoft-Windows-Sysmon/Operational"; Defender = "Microsoft-Windows-Windows Defender/Operational". NO ECS source.ip/process.command_line/file.path on Security events — normalize with EVAL to dotted ECS names for correlation keys, e.g. EVAL source.ip = winlog.event_data.IpAddress, user.name = winlog.event_data.TargetUserName, host.name = winlog.computer_name (dotted EVAL targets WORK). Key fields: 4624/4625 TargetUserName/IpAddress/LogonType ("2","3","10"); 4672 SubjectUserName/PrivilegeList; 4720 TargetUserName; 4728/4732/4756 TargetUserName(group)/MemberName; 4769 TargetUserName/ServiceName; 7045 ServiceName/ImagePath; 7036 param1; 4778 ClientAddress/AccountName; Sysmon 1 Image/CommandLine/ParentImage/User; Sysmon 11 TargetFilename/Image; Sysmon 13 TargetObject/Details; 4104 ScriptBlockText; 5156 Application/DestAddress/DestPort/Direction. Hosts are RUSSIAN-LOCALIZED — don't filter the literal "SYSTEM"; exclude machine accounts with NOT user.name LIKE "*$".
LINUX auditd (logs-updive.audit-*): auditd.message_type (user_login/user_start/user_auth/user_cmd/user_acct), auditd.result (success|fail), event.action ("executed","added-user-account","added-group-account-to","modified-group-account"), event.module=="file_integrity"+event.type=="change"+file.path, auditd.data.* (acct/terminal/uid/auid/addr/cmd), auditd.summary.how, source.ip, host.hostname, user.name, process.name/args(ARRAY)/executable, agent_id. NO process.command_line -> use MV_CONCAT(process.args," "). NOT "auditd.log" for dataset (it's "updive-audit.log"). Normalize: EVAL host.name = host.hostname, user.name = auditd.data.acct.
NGINX (logs-nginx.access-*): source.ip, url.path, url.original, http.request.method, http.response.status_code (long), user_agent.original.
ES|QL GOTCHAS: RLIKE anchored (use ".*x.*"); "(?i)" BROKEN -> TO_LOWER(); "\\d \\w \\s \\." inside a normal "string" = lexer error -> use [0-9]/[a-z] or triple-quote; LIKE to match a Windows backslash path needs FOUR backslashes in the ES|QL string ("*\\\\\\\\temp\\\\\\\\*") OR just avoid it with a "*temp*" substring; is_null removed -> IS NULL.

CHAIN/CORRELATION MODEL: the query is SIMPLE (filter + EVAL normalize to ECS names + KEEP the correlation key fields + LIMIT 500-1000). The detection logic lives in two metadata blocks the SIEM engine reads:
  correlation: { same_fields:[...], different_field?:"x" (count UNIQUE values — for scanners/spray), frequency?:N (events needed), timeframe_sec:N, dedup_fields?:[...], ignore_sec?:N, check_diff?:true, escalate_severity?:"high|critical" }
  chain: { stage:1|2|3, depends_on_rule_ids:[prev], correlate_by:[field], timeframe_sec:3600 }
Stage 1 has NO deps; later stages depend on the previous stage; the engine links members within the active-chain window by the shared correlate_by entity (e.g. host.name or source.ip or user.name). KEEP must expose every field named in same_fields/dedup_fields/correlate_by.
`

const STAGE = {
  type: "object", additionalProperties: false,
  properties: {
    stage_name: { type: "string", description: "short, e.g. 'Mass File Modification'" },
    index: { type: "string" },
    query: { type: "string", description: "VALIDATED ES|QL, production lookback (e.g. NOW() - 15 minutes), simple KEEP style" },
    same_fields: { type: "array", items: { type: "string" } },
    different_field: { type: "string" },
    frequency: { type: "integer" },
    timeframe_sec: { type: "integer" },
    dedup_fields: { type: "array", items: { type: "string" } },
    ignore_sec: { type: "integer" },
    check_diff: { type: "boolean" },
    escalate_severity: { type: "string" },
    correlate_by: { type: "array", items: { type: "string" } },
    severity: { type: "string", enum: ["low","medium","high","critical"] },
    risk_score: { type: "integer" },
    tags: { type: "array", items: { type: "string" } },
    mitre_tactic: { type: "string", description: "e.g. TA0008" },
    mitre_techniques: { type: "array", items: { type: "string" }, description: "e.g. [\"T1021.001\"]" },
    validation_rows: { type: "integer", description: "rows over the full 2026-03-23 window" },
  },
  required: ["stage_name","index","query","same_fields","timeframe_sec","correlate_by","severity","risk_score","tags","mitre_tactic","mitre_techniques","validation_rows"],
}
const CHAIN_SCHEMA = {
  type: "object", additionalProperties: false,
  properties: {
    chain_title: { type: "string" },
    source: { type: "string" },
    stages: { type: "array", items: STAGE },
    all_parse_ok: { type: "boolean" },
    notes: { type: "string" },
  },
  required: ["chain_title","stages","all_parse_ok"],
}

function prompt(c){ return `Design ONE multi-stage correlation/attack CHAIN as Elastic ES|QL detection stages, and VALIDATE every stage query against the live cluster. Return structured stages (do NOT write files — the orchestrator renders YAML and wires rule_ids/depends_on).

CHAIN TO BUILD: ${c.title}
SOURCE: ${c.source}
STAGE PLAN (turn each into one stage; adjust to what the data actually supports):
${c.stages.map((s,i)=>`  Stage ${i+1}: ${s}`).join("\n")}

${BRIEF}

REQUIREMENTS:
- Each stage: a SIMPLE query (filter for that stage's signal + EVAL normalize correlation keys to ECS dotted names + KEEP the key fields + LIMIT). Keep a PRODUCTION lookback in the returned query (e.g. NOW() - 15 minutes), but VALIDATE by temporarily swapping to NOW window -> "2026-03-23T00:00:00Z" via curl. Every stage query MUST parse with no error; record validation_rows (0 is OK if the threat is simply absent).
- Pick correlate_by as the entity that links the stages (usually host.name; or source.ip for network; or user.name for account-based). Ensure that field (and all same_fields/dedup_fields) appear in the stage's KEEP.
- Stage 1 has no dependency. Set correlation thresholds sensibly (frequency for "burst" stages; different_field for "many unique X" like scanners/kerberoasting; escalate_severity high/critical on later stages).
- severity/risk_score increase across stages. Provide tags (incl. "correlation","chain", the data source, and an attack.* tag) and mitre_tactic + mitre_techniques per stage.
- Return all stages in ORDER (stage 1 first). Set all_parse_ok=true only if every stage validated clean.`
}

const CHAINS = [
  { title: "Windows DCSync Replication Attack", source: "windows (logs-winlog*)", stages: [
    "Directory Service replication rights exercised by a NON-machine account (Security 4662; Properties or AccessMask references DS-Replication-Get-Changes GUIDs 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 / 1131f6ad / 89e95b76; SubjectUserName not ending in $). NOTE: 4662 Properties is multi-line, RLIKE .* matches across lines; lowercase the GUID match. correlate by host.name",
    "Special privileges assigned to that account right after (Security 4672) — depends stage 1, host.name" ] },
  { title: "Windows Password Spray", source: "windows (logs-winlog*)", stages: [
    "Failed logons (Security 4625) where ONE source/host sees MANY DISTINCT target accounts in a short window (same_fields source.ip or host.name, different_field user.name=TargetUserName) — spray pattern, not single-account brute. correlate by host.name",
    "Successful logon (Security 4624 type 2/3/10) shortly after from the same source/host — depends stage 1, host.name" ] },
  { title: "Windows Account Takeover via Password Reset", source: "windows (logs-winlog*)", stages: [
    "An administrator resets another user's password or modifies the account (Security 4724 password reset OR 4738 user account changed); EVAL the affected/target account. correlate by host.name",
    "Logon by the affected account afterwards (Security 4624) — depends stage 1, host.name" ] },
  { title: "Windows Process Injection", source: "windows (logs-winlog*)", stages: [
    "Remote thread created into another process (Sysmon event.code 8 CreateRemoteThread; SourceImage/TargetImage) — correlate by host.name",
    "Suspicious process activity on the same host right after (Sysmon 1, e.g. unusual child or network tool) — depends stage 1, host.name" ] },
  { title: "Windows LOLBin Download and Execute", source: "windows (logs-winlog*)", stages: [
    "A living-off-the-land binary used to download (Sysmon 1 where TO_LOWER(CommandLine) matches certutil.*urlcache, bitsadmin.*transfer, mshta.*http, regsvr32.*/i:http, or curl/wget to http) — correlate by host.name",
    "Outbound network connection or follow-on process right after (5156 Direction Outbound, or Sysmon 1) — depends stage 1, host.name" ] },
  { title: "Windows Account Lockout Storm", source: "windows (logs-winlog*)", stages: [
    "Multiple account lockouts in a short window (Security 4740) — burst, correlate by host.name (track TargetUserName)",
    "Account unlocked then a successful logon (Security 4767 unlock or 4624) for an affected account — depends stage 1, host.name" ] },
  { title: "Windows Sensitive Privilege Abuse", source: "windows (logs-winlog*)", stages: [
    "Special privileges assigned at logon to a non-system account (Security 4672; exclude SYSTEM/service via SID or *$) — correlate by user.name",
    "Sensitive privileged operation/service called by that account afterwards (Security 4673 or 4674) — depends stage 1, user.name" ] },
  { title: "Windows Admin Share Access Recon", source: "windows (logs-winlog*)", stages: [
    "Access to administrative network shares C$/ADMIN$/IPC$ from a remote source (Security 5140 share connected or 5145 detailed file share; ShareName) — burst, correlate by host.name (track source.ip via IpAddress/SourceAddress)",
    "Write/file operation or process execution after the share access (5145 with WriteData, or Sysmon 1) — depends stage 1, host.name" ] },
  { title: "Linux Reverse Shell", source: "linux (logs-updive.audit-*)", stages: [
    "A reverse-shell style command executed (auditd executed where MV_CONCAT(process.args,\" \") matches: bash -i, sh -i, nc -e, ncat -e, /dev/tcp/, python -c with socket, socat, mkfifo+nc) — correlate by host.name",
    "Follow-on post-exploitation activity on the same host (recon/download/priv-esc process) — depends stage 1, host.name" ] },
  { title: "Linux Kernel Module Rootkit Load", source: "linux (logs-updive.audit-*)", stages: [
    "A kernel module loaded (auditd executed insmod/modprobe, or rmmod) — correlate by host.name",
    "Suspicious activity on same host after the module load (hidden file create, /dev access, defense evasion) — depends stage 1, host.name" ] },
  { title: "Linux Shell RC Persistence", source: "linux (logs-updive.audit-*)", stages: [
    "A shell startup/profile file modified (file_integrity change where file.path matches /.bashrc, /.bash_profile, /.profile, /etc/profile.d/, /.zshrc, /.bash_logout) — correlate by host.name",
    "A login or interactive shell on the same host afterwards (auditd user_start success, or bash/sh executed) — depends stage 1, host.name" ] },
  { title: "Linux Credential Access via Shadow File", source: "linux (logs-updive.audit-*)", stages: [
    "Sensitive credential file accessed (auditd opened-file where file.path is /etc/shadow or /etc/gshadow) — correlate by host.name (track process and user)",
    "Copy/exfil of credentials after access (auditd executed cp/cat/scp/curl/tar referencing shadow, or an archive/upload) — depends stage 1, host.name" ] },
  { title: "Cross-Source: ESET Threat then Endpoint Process", source: "eset + windows/linux", stages: [
    "ESET detects malware/threat on a host (logs-eset.protect-* event.category Threat_Event; EVAL host.name) — correlate by host.name",
    "A suspicious process runs on that same host around that time (logs-winlog* Sysmon event.code 1, OR logs-updive.audit-* executed from /tmp or a recon/download tool) — depends stage 1, correlate by host.name. NOTE: best-effort cross-source host-name correlation." ] },
  { title: "Windows Audit Policy Tampering then Activity", source: "windows (logs-winlog*)", stages: [
    "Audit/logging policy changed (Security 4719 system audit policy changed) — defense evasion, correlate by host.name",
    "Privileged or suspicious activity on the same host right after (Security 4672, or Sysmon 1 suspicious process) — depends stage 1, host.name" ] },
]
phase('Design')
const results = (await parallel(CHAINS.map((c, i) => () =>
  agent(prompt(c), { label: `chain:${c.title.slice(0,32)}`, phase: 'Design', model: 'sonnet', schema: CHAIN_SCHEMA })
))).filter(Boolean)

return {
  count: results.length,
  chains: results.map(r => ({ chain_title: r.chain_title, source: r.source, all_parse_ok: r.all_parse_ok, notes: r.notes,
    stages: (r.stages||[]).map(s => ({ stage_name: s.stage_name, index: s.index, query: s.query,
      same_fields: s.same_fields, different_field: s.different_field, frequency: s.frequency, timeframe_sec: s.timeframe_sec,
      dedup_fields: s.dedup_fields, ignore_sec: s.ignore_sec, check_diff: s.check_diff, escalate_severity: s.escalate_severity,
      correlate_by: s.correlate_by, severity: s.severity, risk_score: s.risk_score, tags: s.tags,
      mitre_tactic: s.mitre_tactic, mitre_techniques: s.mitre_techniques, validation_rows: s.validation_rows })) })),
}
