export const meta = {
  name: 'fix-esql-rules',
  description: 'Fix broken live-data ES|QL rules + logic-review compliance rules, validating each against the live cluster',
  phases: [
    { title: 'Fix', detail: 'rewrite broken rules to the real schema + validate' },
    { title: 'Review', detail: 'logic-check OK compliance rules + validate data' },
  ],
}

const ES = "http://10.10.10.60:9200"
const AUTH = "elastic:elasticpassword"

const BRIEFING = `
CLUSTER: ${ES}  (basic auth ${AUTH}). Validate ANY ES|QL query with bash:
  curl -s -u ${AUTH} ${ES}/_query -H 'Content-Type: application/json' --data-binary @- <<'JSON'
  {"query": "<ESQL ON ONE LOGICAL QUERY>"}
  JSON
  (or write the JSON to /tmp/q.json and: curl -s -u ${AUTH} ${ES}/_query -H 'Content-Type: application/json' -d @/tmp/q.json)
A clean parse returns JSON with "columns"/"values". A failure returns {"error":{..."reason":"..."}}. Count rows = length of "values".

DATA WINDOW: real data only spans 2026-03-23..2026-06-02; today is later, so a production "NOW() - 15 minutes" window matches NOTHING. For VALIDATION ONLY, temporarily replace the lookback with "NOW() - 100 days" so you can confirm fields resolve and see real row counts. The SAVED rule file MUST keep a production lookback (keep the original duration the rule had, e.g. NOW() - 15 minutes).

WHICH INDEX HAS DATA (use these; everything else is empty in this cluster):
  Windows  -> logs-winlog*        (12.8M docs)
  Linux    -> logs-updive.audit-* (58M docs, auditd)
  Nginx    -> logs-nginx.access-* / logs-nginx.error-*
  ESET     -> logs-eset.protect-* ; Switch -> logs-switch* ; Metrics -> metrics-updive.metric-*

WINDOWS schema (logs-winlog*):
- winlog.channel ("Security","System","Microsoft-Windows-Sysmon/Operational","Microsoft-Windows-Windows Defender/Operational","Microsoft-Windows-PowerShell/Operational"...), event.code is a STRING ("4624"), winlog.event_data.*, winlog.computer_name, agent_id.
- There is NO ECS source.ip / destination.ip / process.command_line / file.path on Windows Security events. Map instead:
    source.ip            -> winlog.event_data.IpAddress
    destination.ip       -> (Sysmon 3) winlog.event_data.DestinationIp ; (WFP 5156) winlog.event_data.DestAddress
    process.command_line -> (4688 has NONE) use Sysmon EventID 1 (channel Microsoft-Windows-Sysmon/Operational): winlog.event_data.CommandLine / Image / ParentImage / ParentCommandLine
    file.path            -> (4663 object access) winlog.event_data.ObjectName
- Logon events 4624/4625: real user is winlog.event_data.TargetUserName (SubjectUserName is often "-"); winlog.event_data.IpAddress, LogonType, WorkstationName; 4625 has SubStatus.
- Service install: System 7045 winlog.event_data.ServiceName/ImagePath/param*; Security 4697 winlog.event_data.ServiceName.
- Scheduled task: TaskScheduler/Operational 106/129/140/141 (TaskName/UserContext/Path) OR Security 4698.
- Defender: channel "Microsoft-Windows-Windows Defender/Operational"; some fields have SPACES -> use backticks, e.g. \`winlog.event_data.Threat Name\`.
- geo enrichment is NOT present on windows logs -> if a rule references source.geo.* / country_iso_code, DROP that clause (no geo for windows).

LINUX auditd schema (logs-updive.audit-*):
- auditd.message_type (user_login,user_auth,user_acct,user_start,user_end,syscall,...), auditd.result (success|fail), event.action, source.ip, host.hostname, user.name, agent_id, process.args (ARRAY), process.title.
- Real auditd data fields: auditd.data.acct, auditd.data.terminal, auditd.data.op, auditd.data.addr (remote address), auditd.data.uid / auid / ouid / fsuid, auditd.data.exe, auditd.data.socket.saddr.
- WRONG paths some rules use -> correct: auditd.log.data.uid -> auditd.data.uid ; auditd.log.rport -> auditd.data.addr (or source.ip) ; process.command_line -> MV_CONCAT(process.args, " ").
- event.dataset value is "updive-audit.log" (NOT "auditd") — don't filter dataset == "auditd".

NGINX schema: access has http.request.method, http.response.status_code (long), url.path, user_agent.original, source.ip, source.geo.geo.country_name (DOUBLE-nested 'geo.geo'). error logs are unstructured (only message) -> GROK the IP.

ES|QL ENGINE GOTCHAS (verified live):
- RLIKE is ANCHORED/full-match: use ".*(a|b|c).*" for "contains". Inline "(?i)" does NOT work (matches nothing) -> use TO_LOWER(field) RLIKE "lowercase". \\b word-boundary -> parse error.
- Machine accounts end in one "$": exclude with  NOT field LIKE "*$"  (NOT  RLIKE ".*\\$$").
- DATE_EXTRACT chrono field for hour-of-day is "hour_of_day" NOT "hour":  DATE_EXTRACT("hour_of_day", @timestamp). Verify with: FROM logs-winlog* | EVAL h = DATE_EXTRACT("hour_of_day", @timestamp) | KEEP h | LIMIT 1.
- "is_null(x)" is removed -> use  x IS NULL / x IS NOT NULL.
- Keep DATE_TRUNC bucket <= schedule_interval where the rule buckets time.
- Don't put VALUES()/CONCAT_WS inside a post-STATS EVAL; compute flags pre-STATS.
`

const FIX_SCHEMA = {
  type: "object",
  additionalProperties: false,
  properties: {
    file: { type: "string" },
    data_source: { type: "string", description: "windows | linux | nginx | ..." },
    status: { type: "string", enum: ["fixed", "still_broken", "skipped"] },
    fields_changed: { type: "array", items: { type: "string" } },
    parse_ok: { type: "boolean" },
    validation_rows: { type: "integer", description: "rows returned by the rewritten query with a 100-day lookback" },
    summary: { type: "string", description: "1-3 sentences: what was wrong and what you changed" },
  },
  required: ["file", "status", "parse_ok", "validation_rows", "summary"],
}

const REVIEW_SCHEMA = {
  type: "object",
  additionalProperties: false,
  properties: {
    file: { type: "string" },
    verdict: { type: "string", enum: ["good", "fixed", "still_broken"] },
    issues_found: { type: "array", items: { type: "string" } },
    parse_ok: { type: "boolean" },
    validation_rows: { type: "integer" },
    summary: { type: "string" },
  },
  required: ["file", "verdict", "parse_ok", "validation_rows", "summary"],
}

function fixPrompt(path) {
  return `You are fixing ONE broken Elastic ES|QL detection rule so it parses and runs correctly against the LIVE cluster.

RULE FILE (exact repo-relative path — it has spaces/colons/parens; QUOTE it in bash and use the EXACT path in Read/Edit/Write):
${path}

${BRIEFING}

STEPS:
1. Read the rule file. Understand the detection intent from name/description.
2. Pick the correct real data source by intent (Windows -> logs-winlog* ; Linux -> logs-updive.audit-*). Some "NIST/GDPR/PCI" rules are generic templates mixing Windows+Linux fields — choose the ONE source that matches the intent and rewrite cleanly for it.
3. For every "Unknown column" / wrong field, find the correct real field (use the briefing; if unsure, inspect the mapping: curl -s -u ${AUTH} '${ES}/<index>/_mapping' or run a tiny  FROM <index> | KEEP <guess> | LIMIT 1).
4. Rewrite ONLY what's needed to be correct against the real schema. PRESERVE rule_id, name, tags, severity, risk_score, schedule_interval, and compliance fields (nist/pci_dss/gdpr/mitre_attack). Keep detection logic & thresholds sensible. Keep query_language: esql and the index: list pointing at the real data source.
5. VALIDATE: run the rewritten query via curl with the lookback widened to NOW() - 100 days. It MUST return NO error. Record the row count. If it still errors, iterate until it parses clean.
6. Write the fixed YAML back to the SAME path. In the SAVED file keep a PRODUCTION lookback (restore the original duration, e.g. NOW() - 15 minutes — do NOT save the 100-day window).
7. If the rule's only correct source genuinely has NO data in this cluster (e.g. needs Sysmon-for-Linux or sshd auth logs), set status "skipped" and explain — do not invent a fake index.

Return the structured result. Be precise about fields_changed.`
}

function reviewPrompt(path) {
  return `Review ONE Elastic ES|QL detection rule that currently PARSES OK, for LOGICAL correctness against the LIVE cluster. Fix it ONLY if you find a real bug.

RULE FILE (exact path — quote in bash):
${path}

${BRIEFING}

WHAT TO CHECK:
- Does it key on the right event.code / winlog.channel / message_type for its stated intent?
- Are field names real (no silently-wrong fields that happen to parse, e.g. SubjectUserName="-" on logon events where TargetUserName is meant)?
- Case-sensitivity: any "(?i)" (broken) -> must be TO_LOWER(...). Anchored RLIKE without ".*" (matches nothing). Machine-account exclusion using RLIKE ".*\\$$" (wrong).
- Thresholds that can never fire; DATE_TRUNC bucket larger than schedule.
- Does it actually return data? VALIDATE with a 100-day lookback (curl). Record row count. (0 rows can be legitimate if the event is simply rare/absent — judge by whether the FIELDS are correct, not only by row count.)

If you find a real bug: fix it (preserve rule_id/name/tags/compliance fields; keep a production lookback in the saved file), re-validate, set verdict "fixed". If it's already correct, set verdict "good" and do NOT modify the file. If it's broken and you cannot make it correct against available data, set "still_broken" and explain.

Return the structured result.`
}

const FIX = [
  "linux/PCI DSS 10.2.2 - Privileged User Actions (Linux sudo-su).yml",
  "windows/Agent FIM: Active Directory Ownership or Permission Changed.yml",
  "windows/Audit Policy Modification Detection.yml",
  "windows/Critical Configuration File Modification.yml",
  "windows/Critical System File Tampering.yml",
  "windows/Firewall Policy Modification.yml",
  "windows/GDPR Art.32(1)(c) - Personal Data Processing System Availability Loss.yml",
  "windows/GDPR Art.33(1) - Personal Data Breach Detection Trigger (72h Notification Clock).yml",
  "windows/GDPR Art.33(2) - Third-Party Vendor or Processor Account Anomaly.yml",
  "windows/GDPR Art.34(1) - High-Risk Breach Indicators Requiring Data Subject Notification.yml",
  "windows/PCI DSS 8.1.6 - Brute Force Login Attempt (Windows).yml",
  "windows/PCI DSS 8.1.8 - Long-Running Idle Interactive Sessions (Windows).yml",
  "windows/PCI DSS 8.3 - Remote Access Without MFA - Single-Factor Auth (Windows).yml",
  "windows/Remote Access Brute Force Detection.yml",
  "windows/Suspicious Outbound Connection.yml",
  "windows/Suspicious Process Execution Pattern.yml",
  "windows/Suspicious Scheduled Task Creation.yml",
  "windows/Unauthorized Software Installation.yml",
]
const REVIEW = [
  "linux/PCI DSS 11.5 - Critical File Modification Detected (Linux).yml",
  "linux/PCI DSS 8.1.6 - Brute Force Login Attempt (Linux Auditd).yml",
  "nginx/Dangerous HTTP Method Usage.yml",
  "windows/Audit System Failure or Attack.yml",
  "windows/Excessive Failed Privileged Access.yml",
  "windows/GDPR Art.25(1) - Data Protection by Design Controls Failure.yml",
  "windows/GDPR Art.30(1)(g) - Security Measures Record Completeness Failure.yml",
  "windows/GDPR Art.32(1)(b) - Confidentiality and Integrity of Processing Systems Compromised.yml",
  "windows/GDPR Art.32(1)(d) - Security Controls Effectiveness Degradation.yml",
  "windows/GDPR Art.33(5) - Audit Trail Completeness Gap (Breach Documentation Impaired).yml",
  "windows/GDPR Art.5(1)(f) - Unauthorized Access to Personal Data Systems.yml",
  "windows/PCI DSS 10.2.2 - Privileged User Actions (Windows Admin).yml",
  "windows/PCI DSS 10.2.4 - Invalid Logical Access Attempts Spike.yml",
  "windows/PCI DSS 10.2.5 - User Account Privilege Changes and New Admin Accounts (Windows).yml",
  "windows/PCI DSS 10.2.6 - Audit Log Service Stopped or Paused (Windows).yml",
  "windows/Security Software Disabled.yml",
  "windows/Shared Account Concurrent Usage.yml",
  "windows/Unauthorized Service Installation.yml",
]

phase('Fix')
const fixResults = await parallel(FIX.map((f, i) => () =>
  agent(fixPrompt(f), { label: `fix:${f.split('/').pop().slice(0, 40)}`, phase: 'Fix', model: 'sonnet', schema: FIX_SCHEMA })
))

phase('Review')
const reviewResults = await parallel(REVIEW.map((f, i) => () =>
  agent(reviewPrompt(f), { label: `rev:${f.split('/').pop().slice(0, 40)}`, phase: 'Review', model: 'sonnet', schema: REVIEW_SCHEMA })
))

const fixOk = fixResults.filter(Boolean)
const revOk = reviewResults.filter(Boolean)
return {
  fixed: fixOk.filter(r => r.status === 'fixed').map(r => ({ file: r.file, rows: r.validation_rows, changed: r.fields_changed, summary: r.summary })),
  fix_skipped: fixOk.filter(r => r.status === 'skipped').map(r => ({ file: r.file, summary: r.summary })),
  fix_failed: fixOk.filter(r => r.status === 'still_broken').map(r => ({ file: r.file, summary: r.summary })),
  review_good: revOk.filter(r => r.verdict === 'good').map(r => ({ file: r.file, rows: r.validation_rows })),
  review_fixed: revOk.filter(r => r.verdict === 'fixed').map(r => ({ file: r.file, issues: r.issues_found, summary: r.summary })),
  review_broken: revOk.filter(r => r.verdict === 'still_broken').map(r => ({ file: r.file, summary: r.summary })),
  counts: { fix_total: FIX.length, fix_returned: fixOk.length, review_total: REVIEW.length, review_returned: revOk.length },
}
