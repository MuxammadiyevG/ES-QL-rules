export const meta = {
  name: 'build-correlation-chains-batch4',
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
  { title: "Windows Kerberos TGT Abuse", source: "windows (logs-winlog*)", stages: [
    "Anomalous Kerberos TGT request activity (Security 4768): a burst of TGT requests, or requests for many distinct accounts from one source, or weak/RC4 encryption type (winlog.event_data.TicketEncryptionType 0x17). EVAL user.name=TargetUserName, host.name=computer_name, src=IpAddress. (NOTE: in this env tickets are mostly AES 0x12, so favor a burst/enumeration pattern with frequency + different_field user.name over RC4.) correlate by host.name",
    "Privileged or special-privilege logon shortly after (Security 4672, non-system account) — depends stage 1, host.name" ] },
  { title: "Windows Explicit Credential Lateral Movement", source: "windows (logs-winlog*)", stages: [
    "Explicit (alternate) credentials used to authenticate — RunAs / pass-the-cred (Security 4648). EVAL actor=SubjectUserName, target_user=TargetUserName, target_host=TargetServerName, host.name=computer_name. Exclude machine accounts. correlate by host.name",
    "Network logon or privileged logon following the explicit-cred use (Security 4624 LogonType 3, or 4672) — depends stage 1, host.name" ] },
  { title: "Windows Scheduled Task Persistence", source: "windows (logs-winlog*)", stages: [
    "A scheduled task is created or updated (Security 4698 created or 4702 updated). EVAL task=TaskName, actor=SubjectUserName, host.name=computer_name. correlate by host.name",
    "A process executed via the task scheduler shortly after (Sysmon event.code 1 where TO_LOWER(ParentImage) matches taskeng/taskhostw/svchost schedule, or any new process on the same host) — depends stage 1, host.name" ] },
  { title: "Windows WMI Persistence", source: "windows (logs-winlog*)", stages: [
    "WMI permanent event subscription / consumer activity (WMI-Activity events 5857,5858,5859,5860,5861). IMPORTANT: these events store their fields under winlog.user_data.* (e.g. winlog.user_data.Operation, winlog.user_data.User, winlog.user_data.Consumer, winlog.user_data.Namespace, winlog.user_data.Query), NOT winlog.event_data.*. EVAL host.name=computer_name. correlate by host.name",
    "A suspicious process executed on the same host after the WMI activity (Sysmon event.code 1) — depends stage 1, host.name" ] },
  { title: "Linux Container Privileged Escape", source: "linux (logs-updive.audit-*)", stages: [
    "A dangerous/privileged container invocation (auditd executed where process.name in docker/podman/runc/ctr AND MV_CONCAT(process.args,\" \") matches --privileged, -v /:/ , --pid=host, --net=host, --cap-add, or 'exec ... sh|bash'). docker exec is high-volume so REQUIRE one of these dangerous flags. EVAL host.name=host.hostname, cmdline=MV_CONCAT(process.args,\" \"). correlate by host.name",
    "A host-level suspicious process right after (auditd executed from /tmp, or recon/download/priv-esc tool) — depends stage 1, host.name" ] },
  { title: "Linux PAM Backdoor", source: "linux (logs-updive.audit-*)", stages: [
    "A PAM configuration file modified (file_integrity change where file.path matches /etc/pam.d/ or /etc/security/ or pam_*.so). EVAL host.name=host.hostname. correlate by host.name",
    "An authentication or login on the same host afterwards (auditd user_auth or user_start with result success) — depends stage 1, host.name" ] },
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
