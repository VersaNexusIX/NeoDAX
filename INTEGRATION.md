# Integration Guide

How to integrate NeoDAX into editors, IDEs, CI pipelines, and other tools.

> **Repository:** https://github.com/VersaNexusIX/NeoDAX

---

## VS Code

### Tasks

Create `.vscode/tasks.json` in your analysis workspace:

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "NeoDAX: Analyze",
      "type": "shell",
      "command": "/path/to/NeoDAX/neodax",
      "args": ["-x", "${file}"],
      "presentation": { "reveal": "always", "panel": "new" },
      "group": "test"
    },
    {
      "label": "NeoDAX: CFG only",
      "type": "shell",
      "command": "/path/to/NeoDAX/neodax",
      "args": ["-f", "-C", "${file}"],
      "presentation": { "reveal": "always" }
    },
    {
      "label": "NeoDAX: Entropy scan",
      "type": "shell",
      "command": "/path/to/NeoDAX/neodax",
      "args": ["-e", "${file}"],
      "presentation": { "reveal": "always" }
    },
    {
      "label": "NeoDAX: Start web UI",
      "type": "shell",
      "command": "node",
      "args": ["/path/to/NeoDAX/js/server/server.js"],
      "isBackground": true,
      "problemMatcher": []
    }
  ]
}
```

Press `Ctrl+Shift+P` → `Tasks: Run Task` → select a NeoDAX task.

### Extension (future)

A VS Code extension for NeoDAX is planned — it will provide syntax highlighting for `.daxc` files and inline CFG visualization.

---

## Neovim / Vim

Add to your config:

```lua
-- Neovim: analyze current file with neodax
vim.keymap.set('n', '<leader>nx', function()
    vim.cmd('split | terminal neodax -x ' .. vim.fn.expand('%'))
end, { desc = 'NeoDAX full analysis' })

vim.keymap.set('n', '<leader>ne', function()
    vim.cmd('split | terminal neodax -e ' .. vim.fn.expand('%'))
end, { desc = 'NeoDAX entropy scan' })
```

```vim
" Vim: analyze current file
nnoremap <leader>nx :split \| execute 'terminal neodax -x ' . expand('%')<CR>
```

---

## Ghidra Integration

NeoDAX output can complement Ghidra analysis:

```bash
# Export symbol list from NeoDAX
./neodax -y -f -n ./binary | grep "^\[ENTRY\]\|^  │" > symbols.txt

# Generate annotated assembly for import
./neodax -x -o snap.daxc ./binary
./neodax -c snap.daxc > annotated.S
# Import annotated.S into Ghidra via File → Import File
```

---

## Python Scripting

Call NeoDAX from Python scripts via `subprocess`:

```python
import subprocess, json, sys

def analyze(binary_path, flags='-x -n'):
    """Run neodax and capture output."""
    result = subprocess.run(
        ['/path/to/neodax'] + flags.split() + [binary_path],
        capture_output=True, text=True, timeout=60
    )
    return result.stdout

def get_json(binary_path, endpoint='analyze'):
    """Query the REST server."""
    import urllib.request
    req = urllib.request.Request(
        f'http://localhost:7070/api/{endpoint}',
        data=json.dumps({'file': binary_path}).encode(),
        headers={'Content-Type': 'application/json'},
        method='POST'
    )
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())

if __name__ == '__main__':
    binary = sys.argv[1]
    
    # Get analysis via REST API (requires server running)
    data = get_json(binary, 'info')
    print(f"arch: {data['arch']}, sha256: {data['sha256'][:16]}...")
    
    fns = get_json(binary, 'functions')
    print(f"functions: {len(fns['functions'])}")
```

---

## CI Pipeline Integration

### GitHub Actions — analyze on PR

```yaml
- name: Check binary for packed content
  run: |
    # Install NeoDAX
    git clone https://github.com/VersaNexusIX/NeoDAX.git /tmp/neodax
    cd /tmp/neodax && make 2>/dev/null
    
    # Scan the built binary
    OUTPUT=$(/tmp/neodax/neodax -e ./mybinary 2>/dev/null)
    if echo "$OUTPUT" | grep -q "PACKED\|ENCRYPTED"; then
      echo "::warning::Binary contains high-entropy sections — possible packing"
      echo "$OUTPUT"
    fi
```

### Makefile integration

```makefile
# Add to your project Makefile
NEODAX ?= /path/to/neodax

.PHONY: analyze security-scan
analyze: $(TARGET)
    $(NEODAX) -x $(TARGET)

security-scan: $(TARGET)
    @echo "=== Entropy Analysis ==="
    $(NEODAX) -e -n $(TARGET)
    @echo ""
    @echo "=== Validity Filter ==="
    $(NEODAX) -V -n $(TARGET)
```

---

## Docker

```dockerfile
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    build-essential nodejs libnode-dev git \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/VersaNexusIX/NeoDAX.git /neodax \
    && cd /neodax && make

ENV PATH="/neodax:$PATH"

# Start the REST API server
EXPOSE 7070
CMD ["node", "/neodax/js/server/server.js"]
```

```bash
docker build -t neodax .
docker run -p 7070:7070 -v /path/to/binaries:/binaries neodax

# Analyze via REST from host
curl -s -X POST http://localhost:7070/api/info \
  -H 'Content-Type: application/json' \
  -d '{"file":"/binaries/target"}'
```

---

## Web Frontend → REST Backend

If you build a custom frontend that talks to the NeoDAX REST server:

```js
// BigInt addresses come back as "0x..." strings
const res = await fetch('http://localhost:7070/api/functions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ file: '/path/to/binary' }),
});
const { functions } = await res.json();
// functions[0].start is a string like "0x0000000000004010"
```

All 26 endpoints are documented in [js/README.md](js/README.md).
