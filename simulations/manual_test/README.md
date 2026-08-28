# Manual test kit — correlation-engine chain va stage-2 gate

Bu papka SIEM correlation-engine'ni **qo'lda** test qilish uchun: rule qo'shadigan
va bazaga (Elasticsearch) ma'lumot tiqadigan skriptlar + toza `curl` qadamlar.

## Nima ko'rsatadi
1. **Correlation ishlaydi**: SSH auth-fail burst inject qilinsa, stage-1 rule (832)
   o'q otadi, severity medium→high escalate bo'ladi, `/alerts?tab=chain` da chain row paydo bo'ladi.
2. **Multi-stage chain buzuq**: stage-2 rule (833) bir xil data mos kelsa ham alert
   chiqarmaydi; chain stage-1 da qotib qoladi (`expected_stages=null`, `members=0`).
3. **Sabab = chain gate** (control bilan isbot): 833'ning chain-siz kloni **o'q otadi**,
   chain-li versiyasi **0** — bir xil query+data.

## Talablar
- `python3` (stdlib yetarli), `curl`.
- Tarmoq: SIEM API `http://10.10.10.60:8008`, Elasticsearch `http://10.10.10.60:9200`.

## Sozlash (env)
```bash
export ES_URL=http://10.10.10.60:9200      ES_AUTH=elastic:elasticpassword
export SIEM_URL=http://10.10.10.60:8008/v1 SIEM_USER=siem SIEM_PASS=password
```

---

## A qism — real chain rulelarni test qilish (rule qo'shmasdan)
Rulelar (832/833/724) allaqachon SIEM'da yuklangan. Faqat data tiqib, kuzatasan.

```bash
# 1) ma'lumot tiqish (fresh timestamp; rulelar NOW()-10min oynada qaraydi)
#    5 to'lqin x 120s = ~10min davomida data yangi turadi (bir necha scheduler sikli)
python3 inject_chain.py 5 120

# 2) ~6-12 daqiqa kut (rulelar har 5m ishlaydi), keyin kuzat:
python3 check.py
```
Kutilgan natija (bug): `stage1 alerts>0`, `stage2 alerts=0`, chain `expected_stages=null members=0`.
UI: http://10.10.10.60:8086/alerts  va  http://10.10.10.60:8086/alerts?tab=chain

## B qism — chain gate'ni isbotlash (2 ta control rule qo'shish)
`control_rules.py` 833'ning IKKI klonini qo'shadi (bir xil query+correlation):
`MT-CTRL-nochain` (chain YO'Q) va `MT-CTRL-withchain` (chain BOR).

```bash
python3 control_rules.py add          # 2 control rule qo'shadi (UI /rules da ko'rinadi)
python3 inject_chain.py 5 120         # data tiq (yoki A qismdan hali fresh bo'lsa, skip)
# ~6-12min kut, keyin:
python3 control_rules.py status       # nochain>0, withchain=0 => gate suppress qiladi
```

## Tozalash
```bash
python3 control_rules.py cleanup      # control rulelarni o'chiradi (nom bo'yicha, total bilan tekshiradi)
python3 cleanup_data.py               # sintetik ES doclarni o'chiradi (faqat sim-victim-ssh.lab)
```

---

## Toza `curl` bilan qo'lda (skriptsiz)

### Login (token ol)
```bash
TOK=$(curl -s -X POST http://10.10.10.60:8008/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"siem","password":"password"}' | python3 -c 'import json,sys;print(json.load(sys.stdin)["data"]["token"])')
echo "$TOK"
```

### Bitta stage-2 event tiqish (ES `_bulk` — MUHIM: `Content-Type: application/x-ndjson`)
```bash
TS=$(python3 -c 'import datetime;print(datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"))')
printf '%s\n%s\n' \
 '{"create":{"_index":"logs-updive.audit-simtest"}}' \
 "{\"@timestamp\":\"$TS\",\"source\":{\"ip\":\"198.51.100.77\"},\"host\":{\"hostname\":\"sim-victim-ssh.lab\"},\"process\":{\"executable\":\"/usr/sbin/sshd\"},\"auditd\":{\"message_type\":\"user_start\",\"result\":\"success\",\"data\":{\"op\":\"PAM:session_open\",\"terminal\":\"ssh\",\"acct\":\"svc-sim\"}},\"event\":{\"category\":[\"authentication\"],\"action\":\"logged-in\",\"outcome\":\"success\"},\"tags\":[\"sim-manual-chain\"]}" \
 | curl -s -X POST http://10.10.10.60:9200/_bulk \
     -u elastic:elasticpassword -H 'Content-Type: application/x-ndjson' --data-binary @-
# (to'liq chain uchun inject_chain.py ishlat — 8 fail + 1 success + 3 proc)
```

### Rule qo'shish (POST /detection-rules)
```bash
curl -s -X POST http://10.10.10.60:8008/v1/detection-rules \
  -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' -d '{
   "name":"MT-CTRL-nochain (manual-test)","description":"control","type":"esql","enabled":true,
   "params":"[]","query_language":"esql","schedule_interval":"5m","index":["logs-updive.audit-*"],
   "query":"FROM logs-updive.audit-* | WHERE @timestamp >= NOW() - 10 minutes | WHERE auditd.message_type == \"user_start\" AND auditd.result == \"success\" AND process.executable == \"/usr/sbin/sshd\" AND source.ip IS NOT NULL | EVAL host.name = host.hostname, user.name = auditd.data.acct | KEEP @timestamp, source.ip, user.name, host.name | LIMIT 500",
   "severity":"high","risk_score":90,"max_signals":100,
   "correlation":{"enabled":true,"frequency":1,"same_fields":["source.ip"],"timeframe_sec":300},
   "tags":["manual-test"]}'
```
Chain-li versiya uchun yuqoridagiga qo'sh:
```json
"chain":{"enabled":true,"stage":2,"timeframe_sec":3600,
         "depends_on_rule_ids":["c7683cc7-c4d3-4f67-9d1b-96ab7385fa35"]}
```

### Natijani ko'rish
```bash
# stage-2 rule 833 bugun alert chiqarganmi? (0 kutiladi = bug)
curl -s "http://10.10.10.60:8008/v1/alerts?per_page=100" -H "Authorization: Bearer $TOK" \
 | python3 -c 'import json,sys;a=json.load(sys.stdin)["data"]["items"];print("833 alerts:",sum(1 for x in a if x["detection_rule_id"]==833))'
# chainlar
curl -s "http://10.10.10.60:8008/v1/alert-chains?per_page=100" -H "Authorization: Bearer $TOK" | python3 -m json.tool | head -40
```

### Rule o'chirish
```bash
curl -s -X DELETE http://10.10.10.60:8008/v1/detection-rules/<ID> -H "Authorization: Bearer $TOK"
```

---

## ⚠️ API xatolari (kuzatilgan — skriptlar buni hisobga oladi)
- `POST /detection-rules` **javobdagi `id` noto'g'ri** (haqiqiy saqlangandan +1). Rule'ni
  qaytgan id bilan emas, **nom bilan** (`?search=` yoki full-list scan) top.
- Bitta POST `total` ni **+2** oshirishi mumkin (dublikat/hisoblash bug'i). Cleanup barcha
  nom-mosliklarini o'chiradi va `total` bilan tekshiradi.
- `DELETE` **404 qaytaradi lekin o'chiradi** (total kamayadi). Status code'ga ishonma — `total` bilan tekshir.
- `POST /detection-rules/{id}/execute` → **500** (server cache yozib bo'lmaydi) → on-demand run yo'q, scheduler kut.
- `/alert-chains` ro'yxati id bo'yicha tartiblanmagan — yangi chain topish uchun **hamma sahifani** skan qil.

## Fayllar
- `inject_chain.py`   — ES ga SSH kill-chain data tiqadi (bazaga ma'lumot tiqadigan)
- `control_rules.py`  — 2 control rule add/cleanup/status (nom bo'yicha, robust)
- `check.py`          — real chain rulelar (832/833/724) + chain holatini ko'rsatadi
- `cleanup_data.py`   — sintetik doclarni o'chiradi
