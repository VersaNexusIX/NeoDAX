# REST API Automation

**Level:** 7 - Integration and Automation
**Prerequisites:** 66_daxc_snapshots.md
**What You Will Learn:** How to use the NeoDAX REST API to integrate binary analysis into other tools.

## The REST API Server

NeoDAX ships with a Node.js REST API server:

```bash
node js/server/server.js
```

By default it listens on port 7070. Access the web UI at `http://localhost:7070/ui`.

## API Endpoints

All endpoints accept POST requests with JSON bodies:

| Endpoint | Body | Returns |
|----------|------|---------|
| /api/info | { file } | Binary metadata |
| /api/sections | { file } | Section list |
| /api/symbols | { file } | Symbol list |
| /api/functions | { file } | Function list |
| /api/xrefs | { file } | Xref list |
| /api/disasm | { file, section, limit } | Disassembly |
| /api/analyze | { file } | Full analysis |
| /api/entropy | { file } | Entropy report |
| /api/decompile | { file, funcIdx } | Pseudo-C |
| /api/symexec | { file, funcIdx } | Symbolic execution |
| /api/ivf | { file } | Validity filter |
| /api/strings | { file } | String extraction |
| /api/hottest | { file, n } | Hottest functions |

## Making API Calls

From any HTTP client:

```bash
curl -X POST http://localhost:7070/api/sections      -H "Content-Type: application/json"      -d '{"file": "/bin/ls"}'
```

From Python:

```python
import requests, json

def analyze(binary_path):
    base = "http://localhost:7070"
    payload = {"file": binary_path}

    r = requests.post(f"{base}/api/analyze", json=payload)
    result = r.json()

    print(f"Arch: {result['info']['arch']}")
    print(f"Functions: {len(result['functions'])}")
    return result
```

From JavaScript (client-side or Node.js):

```javascript
async function getDisassembly(file, section = '.text', limit = 100) {
    const res = await fetch('http://localhost:7070/api/disasm', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ file, section, limit })
    })
    return res.json()
}
```

## Building a Simple Analysis Pipeline

A Python script that analyzes a directory of binaries:

```python
import requests
import os
import json

BASE = "http://localhost:7070"

def quick_scan(directory):
    results = []
    for name in os.listdir(directory):
        path = os.path.join(directory, name)
        if not os.path.isfile(path):
            continue
        try:
            r = requests.post(f"{BASE}/api/analyze", json={"file": path}, timeout=30)
            if r.status_code == 200:
                data = r.json()
                results.append({
                    "name": name,
                    "arch": data["info"]["arch"],
                    "functions": len(data["functions"]),
                    "stripped": data["info"]["isStripped"],
                })
        except Exception as e:
            results.append({"name": name, "error": str(e)})
    return results

results = quick_scan("/usr/bin")
for r in sorted(results, key=lambda x: x.get("functions", 0), reverse=True)[:10]:
    print(r)
```

## Practice

1. Start the NeoDAX REST API server.
2. Make a curl request to `/api/sections` for `/bin/ls`.
3. Write a Python or shell script that prints the function count for each binary in a directory.

## Next

Continue to `71_building_analysis_scripts.md`.
