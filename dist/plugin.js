// security-suite - combines antidos, hfs-blocker, hfs-cors-by-path,
// hfs-dot-rewrite-paths, hfs-ip-blocklist and hfs-tarpit (all GPLv3) into one
// AGPL-3.0 plugin. See LICENSE for the full attribution notice and texts.
exports.description = "Combined IP blocklist, rate-limit banning, header blocking, CORS-by-path, dot-path rewriting and tarpit/honeypot in one plugin"
exports.version = 0.3
exports.apiRequired = 13
exports.repo = "feuerswut/security-suite"
exports.author = "feuerswut"
exports.changelog = [
    { version: 0.3, message: "Split the config into labeled sections (Whitelist, CORS, Dot-path rewriting, IP Blocklist, Rate-limit banning, Header blocking, Tarpit, Backend sync) so it's clear which field belongs to which feature. Also moved CORS out of the whitelist gate: it and dot-path rewriting are utilities, not enforcement, so both always run regardless of the whitelist." },
    { version: 0.2, message: "Master 'Enable backend integration' toggle, off by default, gating the backend URL/API key/report/fetch fields and their actual runtime behavior." },
    { version: 0.1, message: "Initial release, combining six plugins into one middleware plus one newSocket listener." },
]

const fs = require('fs')
const path = require('path')
const { Worker } = require('worker_threads')

const ipStoreModule = require('./backend/ip-store')
const rateLimiterModule = require('./backend/rate-limiter')
const headerBlocker = require('./backend/header-blocker')
const cors = require('./backend/cors')
const dotRewrite = require('./backend/dot-rewrite')
const tarpitModule = require('./backend/tarpit')
const backendClientModule = require('./backend/backend-client')

const { IPStore } = ipStoreModule
const { createRateLimiter } = rateLimiterModule
const { createTarpit } = tarpitModule
const { createBackendClient } = backendClientModule

// `config` is one flat object, but HFS renders "show_html" entries as static
// content in place, so a heading placed right before a group of real fields
// visually splits the admin form into sections without needing anything
// fancier than object key order.
function sectionHeader(title, desc) {
    return {
        type: 'show_html',
        html: `<hr/><h3 style="margin:.3em 0">${title}</h3>`
            + `<div style="opacity:.65;font-size:.85em;margin-bottom:.5em">${desc}</div>`,
    }
}

exports.config = Object.assign({
    header_whitelist: sectionHeader('Whitelist',
        'Exempts these IPs from the IP blocklist, rate-limit banning, header blocking and tarpit below. '
            + 'CORS and dot-path rewriting are utilities, not enforcement, so they always run for everyone regardless of this list.'),
    whitelist: {
        type: 'array',
        label: "Whitelist",
        defaultValue: [],
        helperText: "IPs the plugin does not run for at all: no IP blocklist, no rate-limit banning, no header blocking, no tarpit.",
        fields: {
            ip: { type: 'net_mask', label: "IP/CIDR", helperText: "e.g. 192.168.1.0/24 or 10.0.0.5", $width: 4 },
            enabled: { type: 'boolean', label: "Enabled", defaultValue: true, $width: 2 },
        },
    },

    header_cors: sectionHeader('CORS by path',
        'Always runs, not affected by the whitelist above. Adds permissive CORS headers, filtered by path. Replaces hfs-cors-by-path.'),
},
    cors.configSchema,
    {
        header_dotRewrite: sectionHeader('Dot-path rewriting',
            'Always runs, not affected by the whitelist above. Off unless a prefix is listed below. Strips a leading dot from path segments. Replaces hfs-dot-rewrite-paths.'),
    },
    dotRewrite.configSchema,
    {
        header_ipBlock: sectionHeader('IP Blocklist',
            'Bulk blocklist with a roaring-bitmap / sorted-ranges auto-switching lookup. Replaces hfs-ip-blocklist.'),
    },
    ipStoreModule.configSchema,
    {
        header_rateLimit: sectionHeader('Rate-limit banning',
            'Bans an IP after too many requests in a short window. Replaces antidos.'),
    },
    rateLimiterModule.configSchema,
    {
        header_headerBlock: sectionHeader('Header / User-Agent blocking',
            'Disconnects requests whose headers match a regular expression. Replaces hfs-blocker.'),
    },
    headerBlocker.configSchema,
    {
        header_tarpit: sectionHeader('Tarpit / honeypot',
            'Slows down or traps suspicious requests. Replaces hfs-tarpit.'),
    },
    tarpitModule.configSchema,
    {
        header_backend: sectionHeader('Backend sync',
            'Off by default. Reports anonymized violation counts and/or fetches a shared blocklist from a companion server.'),
    },
    backendClientModule.configSchema,
)

exports.configDialog = { maxWidth: 'lg' }

// Config keys that change what the bulk blocklist looks like on disk -- a
// change to any of these forces a full worker rebuild, not just a reload.
const PROCESSING_KEYS = ['ip_source', 'ip_url', 'ip_filePath', 'ip_lookupMode', 'ip_enableIPv6', 'backend_enabled', 'backend_fetchEnabled']

function processingSignature(config) {
    return PROCESSING_KEYS.map(k => `${k}=${JSON.stringify(config[k])}`).join('|')
}

exports.init = api => {
    const { disconnect } = api.require('./connections')

    const ipStore = new IPStore(api)
    const rateLimiter = createRateLimiter(api, ipStore)
    const tarpit = createTarpit(api)
    const backendClient = createBackendClient(api)

    let worker = null
    let refreshTimer = null
    let lastSig = null
    let headerCompiled = { compiled: {}, errors: [] }
    const unsubscribers = []

    function log(msg) { api.log('[security-suite]', msg) }

    function buildSources() {
        const config = api.getConfig()
        const sources = []
        if (config.ip_source === 'file') {
            if (config.ip_filePath) sources.push({ type: 'file', location: config.ip_filePath, label: 'configured-file' })
        } else if (config.ip_url) {
            sources.push({ type: 'url', location: config.ip_url, label: 'configured-url' })
        }
        if (config.backend_enabled && config.backend_fetchEnabled) {
            const feedPath = backendClient.getFeedFilePath()
            if (fs.existsSync(feedPath)) sources.push({ type: 'file', location: feedPath, label: 'backend-feed' })
        }
        return sources
    }

    function startWorker(forceReprocess) {
        if (worker) { worker.terminate(); worker = null }

        const sources = buildSources()
        if (!sources.length) {
            log('no blocklist source configured, skipping bulk list build (connection-level IP checks still run whitelist/dynamic-ban only)')
            return
        }

        const config = api.getConfig()
        worker = new Worker(path.join(__dirname, 'backend', 'blocklist-worker.js'), {
            workerData: {
                storageDir: api.storageDir,
                config: {
                    sources,
                    ip_lookupMode: config.ip_lookupMode,
                    ip_enableIPv6: config.ip_enableIPv6,
                    forceReprocess: !!forceReprocess,
                },
            },
        })

        worker.on('message', async msg => {
            switch (msg.type) {
                case 'debug':
                    if (api.getConfig('ip_debugLog')) log(msg.msg)
                    break
                case 'log':
                    log(msg.msg)
                    break
                case 'progress':
                    break
                case 'ready': {
                    const ok = await ipStore.load()
                    ipStore.setWhitelist(api.getConfig('whitelist'))
                    if (ok)
                        log(`blocklist ${msg.skipped ? 'unchanged' : 'ready'}: ${msg.totalRanges} IPv4 + ${msg.totalIPv6Ranges} IPv6 ranges, ${msg.diskUsageMB} MB (${msg.format})`)
                    else
                        log('worker finished but the store could not load the result, see prior warnings')
                    break
                }
                case 'error':
                    log(`worker error: ${msg.error}`)
                    break
            }
        })
        worker.on('error', err => log(`worker crashed: ${err.message}`))
        worker.on('exit', code => { if (code !== 0) log(`worker exited with code ${code}`) })
    }

    function scheduleRefresh() {
        if (refreshTimer) { clearInterval(refreshTimer); refreshTimer = null }
        const seconds = Number(api.getConfig('ip_refreshInterval')) || 0
        if (seconds > 0) {
            refreshTimer = setInterval(() => startWorker(false), seconds * 1000)
            if (refreshTimer.unref) refreshTimer.unref()
        }
    }

    ;(async () => {
        await ipStore.load()
        ipStore.setWhitelist(api.getConfig('whitelist'))

        unsubscribers.push(api.subscribeConfig('headerBlock_headers', v => {
            headerCompiled = headerBlocker.compileHeaderRules(v)
            for (const e of headerCompiled.errors) log(`header-blocker: ${e}`)
        }))

        unsubscribers.push(api.subscribeConfig('whitelist', v => ipStore.setWhitelist(v)))

        // Any change to a processing key forces a rebuild; anything else (e.g.
        // logging toggles) just applies on the next request, no rebuild needed.
        unsubscribers.push(api.subscribeConfig(PROCESSING_KEYS, () => {
            const config = api.getConfig()
            const sig = processingSignature(config)
            const firstRun = lastSig === null
            const changed = sig !== lastSig
            lastSig = sig
            if (changed) startWorker(!firstRun)
            scheduleRefresh()
        }))

        backendClient.onFeedUpdated(() => startWorker(true))
        const backendShouldRun = v => v.backend_enabled && (v.backend_reportEnabled || v.backend_fetchEnabled)
        if (backendShouldRun(api.getConfig())) backendClient.start()
        unsubscribers.push(api.subscribeConfig(['backend_enabled', 'backend_reportEnabled', 'backend_fetchEnabled'], v => {
            if (backendShouldRun(v)) backendClient.start()
            else backendClient.stop()
        }))
    })()

    // Earliest possible reject: runs before HTTP parsing even starts, for both
    // the bulk blocklist and rate-limiter-issued dynamic bans. Kept separate
    // from `middleware` on purpose -- see README "Architecture".
    const cancelNewSocket = api.events.on('newSocket', ({ ip }) => {
        const res = ipStore.checkIP(ip)
        if (!res.blocked) return
        if (api.getConfig('ip_logBlocked')) log(`blocked at socket: ${ip} (${res.source})`)
        backendClient.reportViolation(ip, res.source === 'dynamic' ? 'rateLimitBan' : 'ipBlocklist')
        return 'security-suite'
    })

    return {
        unload() {
            cancelNewSocket()
            for (const u of unsubscribers) { try { u() } catch (_) {} }
            if (worker) worker.terminate()
            if (refreshTimer) clearInterval(refreshTimer)
            rateLimiter.unload()
            tarpit.unload()
            backendClient.stop()
            ipStore.cleanup()
            log('unloaded')
        },

        middleware(ctx) {
            // CORS and dot-path rewriting are utilities, not enforcement, so both
            // always run, even for whitelisted IPs -- unlike everything below them.
            cors.applyCorsIfNeeded(ctx, api.getConfig('cors_paths'))
            dotRewrite.rewriteDotPath(ctx, api.getConfig('dotRewrite_paths'), (oldPath, newPath) => {
                if (api.getConfig('dotRewrite_logging') !== false) log(`path rewrite ${oldPath} -> ${newPath}`)
            })

            if (ipStore.isWhitelisted(ctx.ip)) return

            const headerMatch = headerBlocker.matchHeaders(ctx, headerCompiled.compiled)
            if (headerMatch) {
                disconnect(ctx, 'security-suite')
                log(`blocked ${ctx.ip} for header ${headerMatch.name}`)
                backendClient.reportViolation(ctx.ip, 'headerBlock')
                return ctx.stop()
            }

            const tarpitHandled = tarpit.checkPre(ctx)
            if (tarpitHandled) {
                backendClient.reportViolation(ctx.ip, 'tarpit')
                return
            }

            return async () => {
                const wrapUpstream = tarpit.wrapUpstream(ctx)
                if (wrapUpstream) await wrapUpstream()
                rateLimiter.recordRequest(ctx)
            }
        },
    }
}
