// New module for security-suite (AGPL-3.0). Optional client for the companion security-suite-backend project.

const http = require('http')
const https = require('https')
const path = require('path')
const fs = require('fs')
const crypto = require('crypto')

function createBackendClient(api) {
    let violations = new Map() // ip -> { categories: Map<category,count>, firstSeen, lastSeen, extra? }
    let reportTimer = null
    let fetchTimer = null
    let lastFeedHash = null
    let feedUpdatedCallback = null

    const feedFilePath = path.join(api.storageDir, 'backend-feed.txt')
    const feedTmpPath = feedFilePath + '.tmp'

    // Reporting is batched/aggregated instead of one HTTP call per violation: per-request
    // calls would hammer the backend and leak timing/volume info per-request; an aggregate
    // flushed on an interval is both cheaper and more private (only counts, not events).
    function reportViolation(ip, category, extra) {
        if (!ip || !category) return
        if (!api.getConfig('backend_enabled') || !api.getConfig('backend_reportEnabled')) return
        const now = Date.now()
        let entry = violations.get(ip)
        if (!entry) {
            entry = { categories: new Map(), firstSeen: now, lastSeen: now }
            violations.set(ip, entry)
        }
        entry.lastSeen = now
        entry.categories.set(category, (entry.categories.get(category) || 0) + 1)
        if (extra)
            entry.extra = Object.assign({}, entry.extra, extra)
    }

    // Extended-fields gate is applied here, at send time, rather than at collection time,
    // so flipping the config off always yields anonymized payloads even for entries
    // collected while it was on.
    function buildReports(batch, includeExtra) {
        const reports = []
        for (const [ip, entry] of batch) {
            const categories = {}
            for (const [cat, count] of entry.categories) categories[cat] = count
            const item = {
                ip,
                categories,
                firstSeen: new Date(entry.firstSeen).toISOString(),
                lastSeen: new Date(entry.lastSeen).toISOString(),
            }
            if (includeExtra && entry.extra)
                item.extra = entry.extra
            reports.push(item)
        }
        return reports
    }

    function httpRequest(urlString, options, body) {
        return new Promise((resolve, reject) => {
            let url
            try { url = new URL(urlString) }
            catch (e) { reject(e); return }
            const mod = url.protocol === 'https:' ? https : http
            const req = mod.request(url, options, res => {
                const chunks = []
                res.on('data', c => chunks.push(c))
                res.on('end', () => resolve({ statusCode: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }))
            })
            req.on('error', reject)
            req.end(body)
        })
    }

    function authHeaders() {
        const key = api.getConfig('_backend_apiKey')
        return key ? { Authorization: 'Bearer ' + key } : {}
    }

    function joinUrl(base, suffix) {
        return base.replace(/\/+$/, '') + suffix
    }

    async function flushReports() {
        if (!api.getConfig('backend_enabled') || !api.getConfig('backend_reportEnabled')) return
        const url = api.getConfig('backend_url')
        const apiKey = api.getConfig('_backend_apiKey')
        if (!url || !apiKey) return
        if (violations.size === 0) return
        const batch = violations
        violations = new Map()
        const payload = JSON.stringify({ reports: buildReports(batch, !!api.getConfig('backend_reportExtendedFields')) })
        try {
            const res = await httpRequest(joinUrl(url, '/v1/reports'), {
                method: 'POST',
                headers: Object.assign({
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(payload),
                }, authHeaders()),
            }, payload)
            if (res.statusCode < 200 || res.statusCode >= 300)
                api.log('backend-client: report POST failed with status', res.statusCode)
        } catch (e) {
            // Best-effort telemetry: drop the batch on failure, don't retry-storm the backend.
            api.log('backend-client: report POST error', String(e && e.message || e))
        }
    }

    async function fetchBlocklist() {
        if (!api.getConfig('backend_enabled') || !api.getConfig('backend_fetchEnabled')) return
        const url = api.getConfig('backend_url')
        if (!url) return
        try {
            const res = await httpRequest(joinUrl(url, '/v1/blocklist'), { method: 'GET', headers: authHeaders() })
            if (res.statusCode < 200 || res.statusCode >= 300) {
                api.log('backend-client: blocklist GET failed with status', res.statusCode)
                return
            }
            const text = res.body
            const hash = crypto.createHash('sha256').update(text).digest('hex')
            if (hash === lastFeedHash) return
            fs.writeFileSync(feedTmpPath, text, 'utf8')
            fs.renameSync(feedTmpPath, feedFilePath)
            lastFeedHash = hash
            if (feedUpdatedCallback)
                try { feedUpdatedCallback() } catch (e) { api.log('backend-client: onFeedUpdated callback error', String(e && e.message || e)) }
        } catch (e) {
            api.log('backend-client: blocklist GET error', String(e && e.message || e))
        }
    }

    function getFeedFilePath() {
        return feedFilePath
    }

    function onFeedUpdated(callback) {
        feedUpdatedCallback = callback
    }

    function start() {
        if (!reportTimer) {
            const seconds = Math.max(60, Number(api.getConfig('backend_reportInterval')) || 300)
            reportTimer = api.setInterval(() => { flushReports() }, seconds * 1000)
        }
        if (!fetchTimer) {
            const seconds = Math.max(300, Number(api.getConfig('backend_fetchInterval')) || 3600)
            fetchTimer = api.setInterval(() => { fetchBlocklist() }, seconds * 1000)
            fetchBlocklist() // populate the feed file right away instead of waiting a full interval
        }
    }

    function stop() {
        if (reportTimer) { clearInterval(reportTimer); reportTimer = null }
        if (fetchTimer) { clearInterval(fetchTimer); fetchTimer = null }
    }

    return { reportViolation, start, stop, getFeedFilePath, onFeedUpdated }
}

exports.createBackendClient = createBackendClient

exports.configSchema = {
    backend_enabled: {
        type: 'boolean',
        defaultValue: false,
        label: 'Enable backend integration',
        helperText: 'Master switch. Off by default: no data ever leaves this server, and nothing is fetched, unless this is on.',
    },
    backend_url: {
        type: 'string',
        label: 'Backend URL',
        helperText: 'Leave empty to disable all backend integration',
        showIf: values => !!values.backend_enabled,
    },
    // Named with a leading underscore (not the "backend_" prefix used by the rest of this
    // section) so HFS's "export without passwords" feature automatically strips it; see
    // FieldDescriptor rules in dev-plugins.md.
    _backend_apiKey: {
        type: 'string',
        label: 'API Key',
        inputProps: { type: 'password' },
        showIf: values => !!values.backend_enabled,
    },
    backend_reportEnabled: {
        type: 'boolean',
        defaultValue: false,
        label: 'Report anonymized violations',
        helperText: 'Periodically send aggregated counts of violations (ip, category, counts, timestamps) to the backend',
        showIf: values => !!values.backend_enabled,
    },
    backend_reportExtendedFields: {
        type: 'boolean',
        defaultValue: false,
        label: 'Include extended fields in reports',
        helperText: 'Also include an optional non-anonymized "extra" object passed by the caller (e.g. path, User-Agent) instead of only ip/categories/timestamps',
        showIf: values => !!values.backend_reportEnabled,
    },
    backend_reportInterval: {
        type: 'number',
        defaultValue: 300,
        min: 60,
        label: 'Report flush interval (seconds)',
        showIf: values => !!values.backend_reportEnabled,
    },
    backend_fetchEnabled: {
        type: 'boolean',
        defaultValue: false,
        label: 'Fetch shared blocklist',
        helperText: 'Periodically download a shared blocklist (CIDR/range list) from the backend',
        showIf: values => !!values.backend_enabled,
    },
    backend_fetchInterval: {
        type: 'number',
        defaultValue: 3600,
        min: 300,
        label: 'Fetch interval (seconds)',
        showIf: values => !!values.backend_fetchEnabled,
    },
}
