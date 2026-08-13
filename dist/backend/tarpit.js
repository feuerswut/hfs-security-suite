// Derived from feuerswut/hfs-tarpit (GPLv3). Part of security-suite, AGPL-3.0.

const fs = require('fs')
const { Readable, PassThrough } = require('stream')

const CHUNK_SIZE = 64
const MAX_STREAMS = 20
const STREAM_TIMEOUT_MS = 10 * 60 * 1000 // 10 minutes

function matchesPattern(str, pattern) {
    if (!str || !pattern) return false
    const regexPattern = pattern
        .replace(/[.+^${}()|[\]\\]/g, '\\$&')
        .replace(/\*/g, '.*')
        .replace(/\?/g, '.')
    return new RegExp('^' + regexPattern + '$', 'i').test(str)
}

function ipToInt(str) {
    return str.split('.').reduce((acc, octet) => ((acc << 8) + parseInt(octet, 10)) >>> 0, 0)
}

function isWhitelisted(ip, whitelist, api) {
    if (!whitelist || whitelist.length === 0) return false
    for (const entry of whitelist) {
        if (!entry.enabled || !entry.ip) continue
        try {
            const [network, prefix] = entry.ip.split('/')
            const mask = prefix !== undefined
                ? (~0 << (32 - parseInt(prefix, 10))) >>> 0
                : 0xFFFFFFFF
            if ((ipToInt(ip) & mask) === (ipToInt(network) & mask)) return true
        } catch (e) {
            api.log('tarpit: invalid IP/CIDR in whitelist:', entry.ip, e.message)
        }
    }
    return false
}

function createTarpit(api) {
    // -------------------------------------------------------------------------
    // Stream pool -- hard cap of 20 concurrent tarpit/honeypot streams.
    // Map preserves insertion order so the first entry is always the oldest.
    // Each slot: { kill(), timeoutTimer, startTime, ip }
    // -------------------------------------------------------------------------
    const streamPool = new Map()
    let nextStreamId = 0

    function registerStream(ip, killFn) {
        if (streamPool.size >= MAX_STREAMS) {
            const [oldestId, oldest] = streamPool.entries().next().value
            api.log(`tarpit: pool full (${MAX_STREAMS}), evicting oldest stream id=${oldestId} ip=${oldest.ip}`)
            oldest.kill()
            releaseStream(oldestId) // force-remove; 'close' will be a no-op
        }

        const id = ++nextStreamId
        const timeoutTimer = setTimeout(() => {
            const entry = streamPool.get(id)
            if (!entry) return
            api.log(`tarpit: stream id=${id} ip=${entry.ip} killed after 10-minute timeout`)
            entry.kill()
            releaseStream(id)
        }, STREAM_TIMEOUT_MS)

        streamPool.set(id, { kill: killFn, timeoutTimer, startTime: Date.now(), ip })
        api.log(`tarpit: stream id=${id} registered for ip=${ip} (pool size=${streamPool.size})`)
        return id
    }

    function releaseStream(id) {
        const entry = streamPool.get(id)
        if (!entry) return
        clearTimeout(entry.timeoutTimer)
        streamPool.delete(id)
        api.log(`tarpit: stream id=${id} released (pool size=${streamPool.size})`)
    }

    // -------------------------------------------------------------------------
    // Honeypot IP tracking
    // -------------------------------------------------------------------------
    const honeypotIPs = new Map() // ip -> { timer, startTime }

    function activateHoneypot(ip, duration, logMatches) {
        if (honeypotIPs.has(ip)) {
            clearTimeout(honeypotIPs.get(ip).timer)
        }
        const timer = setTimeout(() => {
            honeypotIPs.delete(ip)
            if (logMatches) api.log(`Honeypot deactivated for ${ip} (timeout)`)
        }, duration * 1000)

        honeypotIPs.set(ip, { timer, startTime: Date.now() })
        if (logMatches) api.log(`Honeypot activated for ${ip} (duration: ${duration}s)`)
    }

    function resetHoneypotTimer(ip, duration) {
        if (!honeypotIPs.has(ip)) return
        const entry = honeypotIPs.get(ip)
        clearTimeout(entry.timer)
        entry.timer = setTimeout(() => { honeypotIPs.delete(ip) }, duration * 1000)
        entry.startTime = Date.now()
    }

    // -------------------------------------------------------------------------
    // Custom-file honeypot body: read once, cache by path, re-read if path changes.
    // -------------------------------------------------------------------------
    let fileBufferCache = null // { path, buffer }

    function getHoneypotFileBuffer(filePath) {
        if (!filePath) return null
        if (fileBufferCache && fileBufferCache.path === filePath) return fileBufferCache.buffer
        try {
            const buffer = fs.readFileSync(filePath)
            if (!buffer.length) {
                api.log(`tarpit: honeypot file "${filePath}" is empty, falling back to garbage bytes`)
                fileBufferCache = null
                return null
            }
            fileBufferCache = { path: filePath, buffer }
            return buffer
        } catch (e) {
            api.log(`tarpit: honeypot file "${filePath}" could not be read (${e.message}), falling back to garbage bytes`)
            fileBufferCache = null
            return null
        }
    }

    // -------------------------------------------------------------------------
    // Stream factories -- all go through registerStream / releaseStream
    // -------------------------------------------------------------------------

    // Infinite stream for honeypot connections: either a repeated 'a' filler,
    // or (bodySource==='file') the configured file's bytes looped from the start.
    function createHoneypotStream(ip, speed, bodySource, filePath) {
        const stream = new Readable({ read() {} })
        const chunkDelay = (1000 / (speed || 0.1)) * CHUNK_SIZE
        const fileBuffer = bodySource === 'file' ? getHoneypotFileBuffer(filePath) : null
        const garbageChunk = fileBuffer ? null : Buffer.alloc(CHUNK_SIZE, 0x61) // 'a'
        let fileOffset = 0
        let stopped = false

        const kill = () => {
            stopped = true
            stream.destroy()
        }

        const id = registerStream(ip, kill)

        stream.on('close', () => {
            stopped = true
            releaseStream(id)
        })

        const sendChunk = () => {
            if (stopped) return
            if (fileBuffer) {
                const end = Math.min(fileOffset + CHUNK_SIZE, fileBuffer.length)
                stream.push(fileBuffer.slice(fileOffset, end))
                // wrap back to the start once we reach the end, so the file loops forever
                fileOffset = end >= fileBuffer.length ? 0 : end
            } else {
                stream.push(garbageChunk)
            }
            setTimeout(sendChunk, chunkDelay)
        }
        sendChunk()

        return stream
    }

    // Throttled stream for a finite string/Buffer body
    function createSlowBufferStream(ip, buffer, speed) {
        const stream = new Readable({ read() {} })
        const chunkDelay = (1000 / (speed || 100)) * CHUNK_SIZE
        let offset = 0
        let stopped = false

        const kill = () => {
            stopped = true
            stream.destroy()
        }

        const id = registerStream(ip, kill)

        stream.on('close', () => {
            stopped = true
            releaseStream(id)
        })

        const sendChunk = () => {
            if (stopped) {
                stream.push(null)
                return
            }
            if (offset >= buffer.length) {
                stream.push(null)
                return
            }
            const end = Math.min(offset + CHUNK_SIZE, buffer.length)
            stream.push(buffer.slice(offset, end))
            offset = end
            setTimeout(sendChunk, chunkDelay)
        }
        sendChunk()

        return stream
    }

    // Throttled PassThrough wrapper for a streaming body
    function createSlowPassThrough(ip, originalStream, speed) {
        const throttle = new PassThrough()
        const chunkDelay = (1000 / (speed || 100)) * CHUNK_SIZE
        let stopped = false

        const kill = () => {
            stopped = true
            throttle.destroy()
        }

        const id = registerStream(ip, kill)

        throttle.on('close', () => {
            stopped = true
            releaseStream(id)
        })

        originalStream.on('data', chunk => {
            originalStream.pause()
            let offset = 0

            const sendChunk = () => {
                if (stopped) {
                    throttle.destroy()
                    return
                }
                if (offset >= chunk.length) {
                    originalStream.resume()
                    return
                }
                const end = Math.min(offset + CHUNK_SIZE, chunk.length)
                throttle.write(chunk.slice(offset, end))
                offset = end
                setTimeout(sendChunk, chunkDelay)
            }
            sendChunk()
        })

        originalStream.on('end', () => { if (!stopped) throttle.end() })
        originalStream.on('error', err => throttle.destroy(err))

        return throttle
    }

    function readConfig() {
        return {
            enabled:            api.getConfig('tarpit_enabled'),
            speed:              api.getConfig('tarpit_speed'),
            honeypotSpeed:      api.getConfig('tarpit_honeypotSpeed'),
            honeypotDuration:   api.getConfig('tarpit_honeypotDuration'),
            userAgentMasks:     api.getConfig('tarpit_userAgentMasks'),
            urlMasks:           api.getConfig('tarpit_urlMasks'),
            responseCodes:      api.getConfig('tarpit_responseCodes'),
            logMatches:         api.getConfig('tarpit_logMatches'),
            whitelistIPs:       api.getConfig('tarpit_whitelistIPs'),
            honeypotBodySource: api.getConfig('tarpit_honeypotBodySource'),
            honeypotFilePath:   api.getConfig('tarpit_honeypotFilePath'),
        }
    }

    // -------------------------------------------------------------------------
    // checkPre: downstream phase (equivalent to the sync part of upstream's
    // middleware, before it returns its async upstream closure)
    // -------------------------------------------------------------------------
    function checkPre(ctx) {
        const config = readConfig()
        if (!config.enabled) return false

        const clientIP = ctx.ip

        if (isWhitelisted(clientIP, config.whitelistIPs, api)) return false

        // ---- Honeypot: IP already trapped ----
        if (honeypotIPs.has(clientIP)) {
            resetHoneypotTimer(clientIP, config.honeypotDuration)
            if (config.logMatches) api.log(`Honeypot response sent to ${clientIP} (timer reset)`)

            ctx.status = 200
            ctx.type = 'text/plain'
            ctx.body = createHoneypotStream(clientIP, config.honeypotSpeed, config.honeypotBodySource, config.honeypotFilePath)
            return true
        }

        let shouldTarpit = false
        let shouldActivateHoneypot = false
        let reason = ''

        // ---- User-Agent check ----
        const userAgent = ctx.get('user-agent') || ''
        if (config.userAgentMasks && config.userAgentMasks.length > 0) {
            for (const mask of config.userAgentMasks) {
                if (!mask.enabled) continue
                if (matchesPattern(userAgent, mask.pattern)) {
                    shouldTarpit = true
                    reason = `User-Agent matches "${mask.pattern}"`
                    break
                }
            }
        }

        // ---- URL check ----
        if (!shouldTarpit && config.urlMasks && config.urlMasks.length > 0) {
            for (const mask of config.urlMasks) {
                if (!mask.enabled) continue
                if (matchesPattern(ctx.path, mask.pattern)) {
                    shouldTarpit = true
                    reason = `URL matches "${mask.pattern}"`
                    if (mask.honeypot) shouldActivateHoneypot = true
                    break
                }
            }
        }

        // ---- Honeypot activation ----
        if (shouldActivateHoneypot) {
            activateHoneypot(clientIP, config.honeypotDuration, config.logMatches)
            ctx.status = 200
            ctx.type = 'text/plain'
            ctx.body = createHoneypotStream(clientIP, config.honeypotSpeed, config.honeypotBodySource, config.honeypotFilePath)
            return true
        }

        // checkPre and wrapUpstream are two separate calls for the same request
        // (unlike upstream's single closure), so the UA/URL verdict has to be
        // handed off via ctx.state -- the object Koa reserves exactly for this
        // kind of plugin-to-plugin / phase-to-phase data passing.
        if (shouldTarpit)
            ctx.state.securitySuite_tarpitReason = reason

        return false
    }

    // -------------------------------------------------------------------------
    // wrapUpstream: upstream phase (equivalent to upstream's `return async () =>
    // {...}`). Called once ctx.status is known, so the response-code check can
    // run synchronously here; only the actual body-wrapping is deferred into the
    // returned async closure, matching the shape of the original middleware.
    // -------------------------------------------------------------------------
    function wrapUpstream(ctx) {
        const config = readConfig()
        if (!config.enabled) return undefined

        const clientIP = ctx.ip
        let reason = ctx.state && ctx.state.securitySuite_tarpitReason
        let shouldTarpit = !!reason

        if (!shouldTarpit && config.responseCodes && config.responseCodes.length > 0) {
            for (const codeEntry of config.responseCodes) {
                if (!codeEntry.enabled) continue
                if (ctx.status === codeEntry.code) {
                    shouldTarpit = true
                    reason = `Response code is ${ctx.status}`
                    break
                }
            }
        }

        if (!shouldTarpit) return undefined

        return async () => {
            if (config.logMatches) api.log(`Tarpit activated for ${clientIP}: ${reason}`)

            const body = ctx.body
            if (!body) return

            if (typeof body === 'string' || Buffer.isBuffer(body)) {
                const buf = Buffer.isBuffer(body) ? body : Buffer.from(body)
                ctx.body = createSlowBufferStream(clientIP, buf, config.speed)
            } else if (body.pipe) {
                ctx.body = createSlowPassThrough(clientIP, body, config.speed)
            }
            // all other body types pass through unchanged
        }
    }

    // -------------------------------------------------------------------------
    // Cleanup
    // -------------------------------------------------------------------------
    function unload() {
        for (const [, entry] of streamPool.entries()) {
            entry.kill()
            clearTimeout(entry.timeoutTimer)
        }
        streamPool.clear()

        for (const [, entry] of honeypotIPs.entries()) {
            clearTimeout(entry.timer)
        }
        honeypotIPs.clear()

        api.log('tarpit: unloaded, all streams and honeypot timers cleared')
    }

    return { checkPre, wrapUpstream, unload }
}

exports.createTarpit = createTarpit
exports.matchesPattern = matchesPattern
exports.isWhitelisted = isWhitelisted

exports.configSchema = {
    tarpit_enabled: {
        type: 'boolean',
        label: 'Enable Tarpit',
        defaultValue: true,
        helperText: 'Master switch to enable/disable the tarpit',
    },
    tarpit_speed: {
        type: 'number',
        label: 'Response Speed (bytes/second)',
        defaultValue: 0.5,
        min: 0.001,
        max: 1000,
        helperText: 'How many bytes per second to send when tarpit is triggered',
        showIf: values => values.tarpit_enabled,
    },
    tarpit_honeypotSpeed: {
        type: 'number',
        label: 'Honeypot Speed (bytes/second)',
        defaultValue: 4,
        min: 0.001,
        max: 1000,
        helperText: 'How many bytes per second to send when honeypot is active',
        showIf: values => values.tarpit_enabled,
    },
    tarpit_honeypotDuration: {
        type: 'number',
        label: 'Honeypot Duration (seconds)',
        defaultValue: 60,
        min: 15,
        max: 6000,
        helperText: 'How long an IP stays in honeypot mode (resets on each request)',
        showIf: values => values.tarpit_enabled,
    },
    tarpit_userAgentMasks: {
        type: 'array',
        label: 'User Agent Patterns',
        defaultValue: [],
        helperText: 'Patterns to match against User-Agent header (supports wildcards)',
        showIf: values => values.tarpit_enabled,
        fields: {
            pattern: {
                type: 'string',
                label: 'Pattern',
                helperText: 'Use * as wildcard (e.g., *bot*, curl*, *scanner*)',
                $width: 4,
            },
            enabled: {
                type: 'boolean',
                label: 'Enabled',
                defaultValue: true,
                $width: 2,
            },
        },
    },
    tarpit_urlMasks: {
        type: 'array',
        label: 'URL Patterns',
        defaultValue: [],
        helperText: 'Patterns to match against requested URLs (supports wildcards)',
        showIf: values => values.tarpit_enabled,
        fields: {
            pattern: {
                type: 'string',
                label: 'Pattern',
                helperText: 'Use * as wildcard (e.g., *.php, /admin/*, *.env)',
                $width: 4,
            },
            honeypot: {
                type: 'boolean',
                label: 'Honeypot',
                defaultValue: false,
                helperText: 'Activate honeypot mode for this pattern',
                $width: 1.4,
            },
            enabled: {
                type: 'boolean',
                label: 'Enabled',
                defaultValue: true,
                $width: 1.2,
            },
        },
    },
    tarpit_responseCodes: {
        type: 'array',
        label: 'Response Code Patterns',
        defaultValue: [],
        helperText: 'Slow down responses with specific HTTP status codes',
        showIf: values => values.tarpit_enabled,
        fields: {
            code: {
                type: 'number',
                label: 'Status Code',
                helperText: 'HTTP status code (e.g., 404, 403)',
                min: 100,
                max: 599,
                $width: 4,
            },
            enabled: {
                type: 'boolean',
                label: 'Enabled',
                defaultValue: true,
                $width: 2,
            },
        },
    },
    tarpit_logMatches: {
        type: 'boolean',
        label: 'Log Tarpit Activations',
        defaultValue: true,
        helperText: 'Log when tarpit is triggered',
        showIf: values => values.tarpit_enabled,
    },
    tarpit_whitelistIPs: {
        type: 'array',
        label: 'IP Whitelist',
        defaultValue: [],
        helperText: 'IPs that will never be tarpitted (supports CIDR notation)',
        showIf: values => values.tarpit_enabled,
        fields: {
            ip: {
                type: 'net_mask',
                label: 'IP/CIDR',
                helperText: 'e.g., 192.168.1.0/24 or 10.0.0.5',
                $width: 4,
            },
            enabled: {
                type: 'boolean',
                label: 'Enabled',
                defaultValue: true,
                $width: 2,
            },
        },
    },
    tarpit_honeypotBodySource: {
        type: 'select',
        label: 'Honeypot Body Source',
        defaultValue: 'garbage',
        options: { "Garbage bytes ('a' repeated)": 'garbage', 'Custom file (looped)': 'file' },
        helperText: 'What bytes to stream to a trapped IP: an infinite repeat of \'a\', or a custom file looped from the start',
        showIf: values => values.tarpit_enabled,
    },
    tarpit_honeypotFilePath: {
        type: 'real_path',
        label: 'Honeypot File',
        files: true,
        folders: false,
        helperText: 'File whose bytes are looped to trapped IPs. Falls back to garbage bytes if unreadable.',
        showIf: values => values.tarpit_enabled && values.tarpit_honeypotBodySource === 'file',
    },
}
