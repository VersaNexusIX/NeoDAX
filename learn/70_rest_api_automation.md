# REST API Automation

**Level:** 7 - Integration and Automation
**Prerequisites:** 66_daxc_snapshots.md
**What You Will Learn:** How to use the NeoDAX REST API server to integrate binary analysis into scripts, pipelines, and external tools.

## Starting the Server

```bash
node js/server/server.js
```

By default the server reads `config.dax-ng` for port and host:

```ini
[server]
port  = 7070
host  = 127.0.0.1
```

Override at runtime:

```bash
PORT=9000 node js/server/server.js
HOST=0.0.0.0 PORT=9000 node js/server/server.js
```

The web UI is available at `http://localhost:7070/ui`.

## All API Endpoints

Every endpoint accepts `POST` with a JSON body and returns JSON. CORS is enabled for all origins.

| Endpoint | Required body fields | Returns |
|----------|---------------------|---------|
| `POST /api/info` | `file` | Binary metadata object |
| `POST /api/sections` | `file` | Array of sections |
| `POST /api/symbols` | `file` | Array of symbols |
| `POST /api/functions` | `file` | Array of functions |
| `POST /api/xrefs` | `file` | Array of xrefs |
| `POST /api/xrefs-to` | `file`, `address` | Xrefs targeting address |
| `POST /api/xrefs-from` | `file`, `address` | Xrefs originating from address |
| `POST /api/disasm` | `file` | Plain-text disassembly |
| `POST /api/disasm/json` | `file`, `section?`, `limit?` | Structured disassembly array |
| `POST /api/analyze` | `file` | Full analysis - all fields combined |
| `POST /api/strings` | `file` | ASCII string scan |
| `POST /api/unicode` | `file` | Unicode string scan |
| `POST /api/blocks` | `file` | CFG basic blocks |
| `POST /api/hottest` | `file`, `n?` | Most-called functions |
| `POST /api/read-bytes` | `file`, `address`, `length` | Raw bytes at address |
| `POST /api/section-at` | `file`, `address` | Section containing address |
| `POST /api/sym-at` | `file`, `address` | Symbol at address |
| `POST /api/func-at` | `file`, `address` | Function containing address |
| `POST /api/symexec` | `file`, `funcIdx` | Symbolic execution result |
| `POST /api/ssa` | `file`, `funcIdx` | NR form for function |
| `POST /api/decompile` | `file`, `funcIdx` | Pseudo-C decompilation |
| `POST /api/emulate` | `file`, `funcIdx`, `r0?`, `r1?`, `r2?` | Concrete emulation trace |
| `POST /api/entropy` | `file` | Entropy scan per section |
| `POST /api/rda` | `file`, `section?` | Recursive descent analysis |
| `POST /api/ivf` | `file` | Instruction validity filter |

## Quick Examples

### curl

```bash
curl -s -X POST http://localhost:7070/api/info \
  -H "Content-Type: application/json" \
  -d '{"file":"/bin/ls"}' | jq .

curl -s -X POST http://localhost:7070/api/functions \
  -H "Content-Type: application/json" \
  -d '{"file":"/bin/ls"}' | jq '.[0:5]'

curl -s -X POST http://localhost:7070/api/hottest \
  -H "Content-Type: application/json" \
  -d '{"file":"/bin/ls","n":10}' | jq .
```

### Python

```python
import requests

BASE = "http://localhost:7070"

def api(route, **kwargs):
    r = requests.post(f"{BASE}{route}", json=kwargs, timeout=60)
    r.raise_for_status()
    return r.json()

info = api("/api/info", file="/bin/ls")
print(f"arch={info['arch']}  stripped={info['isStripped']}  funcs={info['nfunctions']}")

fns = api("/api/functions", file="/bin/ls")
for fn in fns[:5]:
    print(f"  0x{fn['start']:016x}  {fn['name']}")

insns = api("/api/disasm/json", file="/bin/ls", section=".text", limit=20)
for i in insns:
    print(f"  {i['address']}  {i['mnemonic']:<10} {i['operands']}")
```

### JavaScript / Node.js

```javascript
const BASE = 'http://localhost:7070';

async function api(route, body) {
    const res = await fetch(BASE + route, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(await res.text());
    return res.json();
}

const info = await api('/api/info', { file: '/bin/ls' });
console.log(info.arch, info.nfunctions);

const fns = await api('/api/functions', { file: '/bin/ls' });
fns.slice(0, 5).forEach(fn => console.log(fn.name, fn.start.toString(16)));
```

## The `/api/analyze` Endpoint

`/api/analyze` runs the full analysis pipeline in one call and returns all data:

```json
{
  "info":      { ... },
  "sections":  [ ... ],
  "symbols":   [ ... ],
  "functions": [ ... ],
  "xrefs":     [ ... ],
  "strings":   [ ... ],
  "unicode":   [ ... ],
  "blocks":    [ ... ],
  "hottest":   [ ... ]
}
```

Use this when you need everything. Use individual endpoints when you need only one thing - they are faster because they skip unneeded analysis steps.

## Batch Analysis Script

```python
import requests
import os
import json
import sys

BASE = "http://localhost:7070"

def scan_binary(path):
    try:
        r = requests.post(f"{BASE}/api/analyze", json={"file": path}, timeout=120)
        if r.status_code != 200:
            return {"file": path, "error": r.json().get("error", "unknown")}
        d = r.json()
        return {
            "file":      path,
            "arch":      d["info"]["arch"],
            "format":    d["info"]["format"],
            "stripped":  d["info"]["isStripped"],
            "pie":       d["info"]["isPie"],
            "functions": len(d["functions"]),
            "symbols":   len(d["symbols"]),
            "strings":   len(d["strings"]),
        }
    except Exception as e:
        return {"file": path, "error": str(e)}

def scan_dir(directory):
    results = []
    for name in sorted(os.listdir(directory)):
        path = os.path.join(directory, name)
        if not os.path.isfile(path):
            continue
        result = scan_binary(path)
        print(json.dumps(result))
        results.append(result)
    return results

scan_dir(sys.argv[1] if len(sys.argv) > 1 else "/usr/bin")
```

Run it:

```bash
node js/server/server.js &
python3 batch_scan.py /usr/bin > results.jsonl
```

## Error Handling

All endpoints return `{ "error": "message" }` with an appropriate HTTP status code on failure:

- `400` - missing required body field
- `404` - file not found
- `500` - analysis error

```python
r = requests.post(f"{BASE}/api/info", json={"file": "/nonexistent"})
if not r.ok:
    print("Error:", r.json()["error"])
```

## Practice

1. Start the server: `node js/server/server.js`
2. Hit `/api/info` for `/bin/ls` with curl and inspect the output.
3. Write a script that prints the top 5 hottest functions for every binary in `/usr/bin`.
4. Use `/api/disasm/json` to find all `call` instructions in `/bin/ls`.

## Next

Continue to `71_building_analysis_scripts.md`.
