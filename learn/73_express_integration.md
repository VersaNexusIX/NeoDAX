# Express Integration

**Level:** 7 - Integration and Automation
**Prerequisites:** 72_web_ui_usage.md
**What You Will Learn:** How to integrate NeoDAX into an Express web application.

## Adding NeoDAX to an Existing Express App

If you have an existing Express application and want to add binary analysis:

```javascript
const express = require('express')
const neodax  = require('neodax')
const app     = express()

app.use(express.json())

// Cache binaries by SHA-256
const cache = new Map()

function getBinary(filePath) {
    const bin = neodax.load(filePath)
    const key = bin.sha256
    if (cache.has(key)) { bin.close(); return cache.get(key) }
    cache.set(key, bin)
    return bin
}

// Analysis endpoint
app.post('/analyze', (req, res) => {
    const { file } = req.body
    if (!file) return res.status(400).json({ error: 'file required' })

    try {
        const bin = getBinary(file)
        const r   = bin.analyze()
        res.json({
            arch:      r.info.arch,
            format:    r.info.format,
            sha256:    r.info.sha256,
            functions: r.functions.length,
            sections:  r.sections.length,
        })
    } catch (e) {
        res.status(500).json({ error: e.message })
    }
})

app.listen(3000)
```

## Handling BigInt in JSON Responses

NeoDAX addresses are BigInt values. `JSON.stringify` cannot serialize BigInt natively. Use a replacer:

```javascript
function safeSer(obj) {
    return JSON.parse(JSON.stringify(obj, (_, v) =>
        typeof v === 'bigint' ? '0x' + v.toString(16) : v
    ))
}

res.json(safeSer(result))
```

## Middleware for Analysis

If multiple routes need analysis, create middleware:

```javascript
const loadBinary = (req, res, next) => {
    const file = req.body.file || req.query.file
    if (!file) return res.status(400).json({ error: 'file parameter required' })

    try {
        req.bin = getBinary(file)
        next()
    } catch (e) {
        res.status(404).json({ error: `Cannot open: ${e.message}` })
    }
}

app.post('/sections', loadBinary, (req, res) => {
    res.json(safeSer({ sections: req.bin.sections() }))
})

app.post('/functions', loadBinary, (req, res) => {
    res.json(safeSer({ functions: req.bin.functions() }))
})
```

## Rate Limiting

Analysis is CPU-intensive. Protect your server:

```javascript
const rateLimit = {}

const rateLimiter = (req, res, next) => {
    const ip  = req.ip
    const now = Date.now()
    if (rateLimit[ip] && now - rateLimit[ip] < 5000) {
        return res.status(429).json({ error: 'Too many requests' })
    }
    rateLimit[ip] = now
    next()
}

app.post('/analyze', rateLimiter, loadBinary, (req, res) => {
    // ...
})
```

## Practice

1. Build a minimal Express server with one `/analyze` endpoint.
2. Test it with curl.
3. Add a `/disasm` endpoint that accepts a section name parameter.
4. Add the BigInt serializer to all responses.

## Next

Continue to `74_batch_analysis.md`.
