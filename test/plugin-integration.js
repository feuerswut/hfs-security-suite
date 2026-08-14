'use strict'
// Standalone integration harness for security-suite's dist/plugin.js.
// Mocks HFS's `api` object and Koa's `ctx` object well enough to load the real
// plugin.js, call init(api), and drive middleware/newSocket through realistic
// scenarios. Run: node test/plugin-integration.js

const fs = require('fs')
const path = require('path')

const PLUGIN_PATH = path.join(__dirname, '..', 'dist', 'plugin.js')
const STORAGE_BASE = path.join(__dirname, '..', '.test-storage')

fs.mkdirSync(STORAGE_BASE, { recursive: true })

process.on('unhandledRejection', err => {
    console.log('  [unhandledRejection]', err && err.stack || err)
})

const results = []
function record(name, pass, reason) {
    results.push({ name, pass, reason })
    console.log(`[${pass ? 'PASS' : 'FAIL'}] ${name}${reason ? ' -- ' + reason : ''}`)
}

function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)) }

// --- mock api ----------------------------------------------------------

function seedConfigDefaults(configSchema) {
    const cfg = {}
    for (const [k, desc] of Object.entries(configSchema))
        cfg[k] = desc && Object.prototype.hasOwnProperty.call(desc, 'defaultValue') ? desc.defaultValue : undefined
    return cfg
}

function makeMockApi(storageDir, configSchema) {
    const store = seedConfigDefaults(configSchema)
    const subs = [] // { keys: [...], cb }
    const logs = []
    const addBlockCalls = []
    const disconnectCalls = []
    const eventListeners = {} // name -> array of { cb }

    function notify(sub) {
        if (sub.keys.length === 1) sub.cb(store[sub.keys[0]])
        else {
            const obj = {}
            for (const k of sub.keys) obj[k] = store[k]
            sub.cb(obj)
        }
    }

    const api = {
        storageDir,
        Const: { API_VERSION: 13 },
        getConfig(key) {
            if (key === undefined) return { ...store }
            return store[key]
        },
        setConfig(key, value) {
            store[key] = value
            for (const sub of subs) if (sub.keys.includes(key)) notify(sub)
        },
        subscribeConfig(keyOrKeys, cb) {
            const keys = Array.isArray(keyOrKeys) ? keyOrKeys : [keyOrKeys]
            const sub = { keys, cb }
            subs.push(sub)
            notify(sub)
            return () => {
                const idx = subs.indexOf(sub)
                if (idx !== -1) subs.splice(idx, 1)
            }
        },
        log(...args) {
            const line = args.map(a => (typeof a === 'string' ? a : JSON.stringify(a))).join(' ')
            logs.push(line)
            console.log('    [plugin-log]', line)
        },
        addBlock(rule, mergeOpts) {
            addBlockCalls.push({ rule, mergeOpts })
        },
        events: {
            on(name, cb) {
                if (!eventListeners[name]) eventListeners[name] = []
                const entry = { cb }
                eventListeners[name].push(entry)
                return () => {
                    const arr = eventListeners[name]
                    const idx = arr.indexOf(entry)
                    if (idx !== -1) arr.splice(idx, 1)
                }
            },
        },
        require(modulePath) {
            if (modulePath === './connections') {
                return {
                    disconnect(ctx, reason) {
                        disconnectCalls.push({ ip: ctx.ip, reason })
                        ctx.status = 403
                    },
                }
            }
            if (modulePath === './misc') {
                return {
                    isLocalHost() { return false },
                    makeNetMatcher() { return () => false },
                }
            }
            throw new Error(`mock api.require: unhandled module "${modulePath}"`)
        },
        setInterval: (...a) => setInterval(...a),
        setTimeout: (...a) => setTimeout(...a),
    }

    return { api, logs, addBlockCalls, disconnectCalls, eventListeners, store }
}

// --- mock ctx ------------------------------------------------------------

function makeCtx({ ip = '192.0.2.1', path: p = '/', headers = {}, method = 'GET', host = 'example.org' } = {}) {
    const lowerHeaders = {}
    for (const [k, v] of Object.entries(headers)) lowerHeaders[k.toLowerCase()] = v
    const respHeaders = {}
    const ctx = {
        ip, path: p, method, host,
        status: 200,
        body: undefined,
        state: {},
        _stopped: false,
        _socketDestroyed: false,
        _respHeaders: respHeaders,
        get(name) { return lowerHeaders[String(name).toLowerCase()] || '' },
        set(name, value) { respHeaders[name] = value },
        stop() { ctx._stopped = true; return undefined },
        socket: { destroy() { ctx._socketDestroyed = true } },
    }
    return ctx
}

// --- scenarios -------------------------------------------------------------

async function scenario1(plugin) {
    const storageDir = path.join(STORAGE_BASE, 's1')
    fs.mkdirSync(storageDir, { recursive: true })
    const { api } = makeMockApi(storageDir, plugin.config)

    let instance = null, threw = null
    try { instance = plugin.init(api) }
    catch (e) { threw = e }

    const hasMw = !!instance && typeof instance.middleware === 'function'
    const hasUnload = !!instance && typeof instance.unload === 'function'
    const cfgKeys = Object.keys(plugin.config || {})
    const expectedKeys = ['ip_lookupMode', 'rateLimit_max', 'headerBlock_headers', 'cors_paths', 'dotRewrite_paths', 'tarpit_enabled', 'backend_url']
    const missing = expectedKeys.filter(k => !cfgKeys.includes(k))
    const pass = !threw && hasMw && hasUnload && cfgKeys.length > 0 && missing.length === 0

    record('1. Plugin loads cleanly', pass,
        pass ? '' : `threw=${threw && threw.stack} hasMw=${hasMw} hasUnload=${hasUnload} cfgKeyCount=${cfgKeys.length} missing=${missing.join(',')}`)

    await sleep(150)
    if (instance) { try { instance.unload() } catch (e) { console.log('  [scenario1 unload error]', e.stack) } }
}

async function scenario2(plugin) {
    const storageDir = path.join(STORAGE_BASE, 's2')
    fs.mkdirSync(storageDir, { recursive: true })
    const { api, logs, eventListeners } = makeMockApi(storageDir, plugin.config)
    const instance = plugin.init(api)
    await sleep(150)

    const listFile = path.join(storageDir, 'blocklist.txt')
    fs.writeFileSync(listFile, '203.0.113.0/24\n')

    api.setConfig('ip_source', 'file')
    api.setConfig('ip_filePath', listFile)

    const deadline = Date.now() + 20000
    let outcome = null
    while (Date.now() < deadline) {
        if (logs.some(l => /blocklist (ready|unchanged):/.test(l))) { outcome = 'ready'; break }
        if (logs.some(l => /worker finished but the store could not load/.test(l))) { outcome = 'load-failed'; break }
        if (logs.some(l => /worker error:|worker crashed:/.test(l))) { outcome = 'worker-error'; break }
        await sleep(150)
    }

    if (outcome !== 'ready') {
        record('2. newSocket blocking', false, `worker did not report a usable blocklist in time (outcome=${outcome}). Last logs: ${logs.slice(-5).join(' | ')}`)
        try { instance.unload() } catch (_) {}
        return
    }

    const listeners = eventListeners['newSocket'] || []
    if (!listeners.length) {
        record('2. newSocket blocking', false, 'no newSocket listener was registered via api.events.on')
        try { instance.unload() } catch (_) {}
        return
    }
    const cb = listeners[0].cb

    const blockedRes = cb({ ip: '203.0.113.5' })
    const notBlockedRes = cb({ ip: '198.51.100.1' })

    const pass = blockedRes === 'security-suite' && notBlockedRes === undefined
    record('2. newSocket blocking', pass,
        pass ? '' : `blockedRes=${JSON.stringify(blockedRes)} notBlockedRes=${JSON.stringify(notBlockedRes)}`)

    try { instance.unload() } catch (e) { console.log('  [scenario2 unload error]', e.stack) }
}

async function scenario3(plugin) {
    const storageDir = path.join(STORAGE_BASE, 's3')
    fs.mkdirSync(storageDir, { recursive: true })
    const { api, disconnectCalls } = makeMockApi(storageDir, plugin.config)
    const instance = plugin.init(api)
    await sleep(150)

    api.setConfig('headerBlock_headers', [{ name: 'User-Agent', regexp: 'badbot' }])

    const ctx = makeCtx({ ip: '192.0.2.30', path: '/x', headers: { 'User-Agent': 'badbot-3000' } })
    instance.middleware(ctx)

    const pass = disconnectCalls.length === 1 && disconnectCalls[0].ip === ctx.ip && ctx._stopped === true
    record('3. Header blocking', pass,
        pass ? '' : `disconnectCalls=${JSON.stringify(disconnectCalls)} stopped=${ctx._stopped}`)

    try { instance.unload() } catch (e) { console.log('  [scenario3 unload error]', e.stack) }
}

async function scenario4(plugin) {
    const storageDir = path.join(STORAGE_BASE, 's4')
    fs.mkdirSync(storageDir, { recursive: true })
    const { api, disconnectCalls } = makeMockApi(storageDir, plugin.config)
    const instance = plugin.init(api)
    await sleep(150)

    // Off by default: must explicitly list a matching prefix (checked against
    // the pre-rewrite path) or nothing gets rewritten.
    api.setConfig('dotRewrite_paths', [{ prefix: '/.secret', enabled: true }])

    const ctxOff = makeCtx({ ip: '192.0.2.41', path: '/.other/file.txt', headers: { 'User-Agent': 'normal-browser/1.0' } })
    instance.middleware(ctxOff)
    const offPass = ctxOff.path === '/.other/file.txt'

    const ctx = makeCtx({ ip: '192.0.2.40', path: '/.secret/file.txt', headers: { 'User-Agent': 'normal-browser/1.0' } })
    instance.middleware(ctx)

    const pass = offPass && ctx.path === '/secret/file.txt' && disconnectCalls.length === 0
    record('4. Dot-path rewrite (off by default, opt-in per prefix)', pass,
        pass ? '' : `offPass=${offPass} otherPath=${ctxOff.path} path=${ctx.path} disconnectCalls=${disconnectCalls.length}`)

    try { instance.unload() } catch (e) { console.log('  [scenario4 unload error]', e.stack) }
}

async function scenario5(plugin) {
    const storageDir = path.join(STORAGE_BASE, 's5')
    fs.mkdirSync(storageDir, { recursive: true })
    const { api } = makeMockApi(storageDir, plugin.config)
    const instance = plugin.init(api)
    await sleep(150)

    api.setConfig('cors_paths', [{ pattern: '/public', enabled: true }])

    const ctx = makeCtx({
        ip: '192.0.2.50', path: '/public/x.txt',
        headers: { Origin: 'https://example.com' }, host: 'files.internal.test',
    })
    instance.middleware(ctx)

    const pass = ctx._respHeaders['Access-Control-Allow-Origin'] === '*'
    record('5. CORS', pass, pass ? '' : `respHeaders=${JSON.stringify(ctx._respHeaders)}`)

    try { instance.unload() } catch (e) { console.log('  [scenario5 unload error]', e.stack) }
}

async function scenario6(plugin) {
    const storageDir = path.join(STORAGE_BASE, 's6')
    fs.mkdirSync(storageDir, { recursive: true })
    const { api } = makeMockApi(storageDir, plugin.config)
    const instance = plugin.init(api)
    await sleep(150)

    api.setConfig('tarpit_enabled', true)
    api.setConfig('tarpit_urlMasks', [{ pattern: '/admin/*', honeypot: true, enabled: true }])
    // Speed up the honeypot stream drastically so the test doesn't have to wait
    // ~16s for the first chunk (default honeypot speed is 4 bytes/sec).
    api.setConfig('tarpit_honeypotSpeed', 1000000)

    const ctx = makeCtx({ ip: '192.0.2.60', path: '/admin/login' })
    const result = instance.middleware(ctx)

    const pass = result === undefined && ctx.status === 200 && !!ctx.body && typeof ctx.body.pipe === 'function'
    record('6. Tarpit honeypot', pass,
        pass ? '' : `result=${typeof result === 'undefined' ? 'undefined' : JSON.stringify(result)} status=${ctx.status} bodyType=${typeof ctx.body}`)

    if (ctx.body && typeof ctx.body.on === 'function') {
        await new Promise(resolve => {
            let done = false
            const finish = () => { if (!done) { done = true; try { ctx.body.destroy() } catch (_) {} resolve() } }
            ctx.body.once('data', finish)
            ctx.body.once('error', finish)
            ctx.body.once('close', finish)
            setTimeout(finish, 1000)
        })
    }

    try { instance.unload() } catch (e) { console.log('  [scenario6 unload error]', e.stack) }
}

async function scenario7(plugin) {
    const storageDir = path.join(STORAGE_BASE, 's7')
    fs.mkdirSync(storageDir, { recursive: true })
    const { api, addBlockCalls } = makeMockApi(storageDir, plugin.config)
    const instance = plugin.init(api)
    await sleep(150)

    api.setConfig('rateLimit_max', 3)
    api.setConfig('rateLimit_seconds', 60)
    api.setConfig('rateLimit_banSeconds', 30)

    const ip = '198.51.100.77'
    let trippedCtx = null
    for (let i = 1; i <= 4; i++) {
        const ctx = makeCtx({ ip, path: '/normal-resource' })
        const upstream = instance.middleware(ctx)
        ctx.status = 200
        if (typeof upstream === 'function') await upstream()
        if (i === 4) trippedCtx = ctx
    }

    const blockedCalled = addBlockCalls.some(c => c.rule && c.rule.ip === ip)
    const destroyed = !!trippedCtx && trippedCtx._socketDestroyed === true
    const pass = blockedCalled && destroyed

    record('7. Rate limiting', pass,
        pass ? '' : `addBlockCalled=${blockedCalled} destroyed=${destroyed} addBlockCalls=${JSON.stringify(addBlockCalls)}`)

    try { instance.unload() } catch (e) { console.log('  [scenario7 unload error]', e.stack) }
}

async function scenario8(plugin) {
    const storageDir = path.join(STORAGE_BASE, 's8')
    fs.mkdirSync(storageDir, { recursive: true })
    const { api, eventListeners } = makeMockApi(storageDir, plugin.config)
    const instance = plugin.init(api)
    await sleep(150)

    const cbRef = eventListeners['newSocket'] && eventListeners['newSocket'][0] && eventListeners['newSocket'][0].cb

    let threwUnload = null
    try { instance.unload() } catch (e) { threwUnload = e }

    let threwPostUnload = null
    try { if (cbRef) cbRef({ ip: '192.0.2.90' }) } catch (e) { threwPostUnload = e }

    const pass = !threwUnload && !threwPostUnload && !!cbRef
    record('8. Unload is clean', pass,
        pass ? '' : `unloadThrew=${threwUnload && threwUnload.stack} postUnloadThrew=${threwPostUnload && threwPostUnload.stack} hadListener=${!!cbRef}`)
}

async function scenario9(plugin) {
    const storageDir = path.join(STORAGE_BASE, 's9')
    fs.mkdirSync(storageDir, { recursive: true })
    const { api, disconnectCalls, eventListeners } = makeMockApi(storageDir, plugin.config)
    const instance = plugin.init(api)
    await sleep(150)

    const whitelistedIp = '192.0.2.99'

    // Bulk blocklist covers this IP too, but the shared whitelist must win at
    // the newSocket layer regardless of source (bulk list or dynamic ban).
    const listFile = path.join(storageDir, 'blocklist.txt')
    fs.writeFileSync(listFile, '192.0.2.0/24\n')
    api.setConfig('ip_source', 'file')
    api.setConfig('ip_filePath', listFile)
    api.setConfig('whitelist', [{ ip: whitelistedIp, enabled: true }])

    const deadline = Date.now() + 20000
    while (Date.now() < deadline && !(eventListeners['newSocket'] || []).length) await sleep(150)
    // give the worker a moment to finish even if the listener was already there
    await sleep(500)

    const cb = (eventListeners['newSocket'] || [])[0] && eventListeners['newSocket'][0].cb
    const whitelistedSocketRes = cb ? cb({ ip: whitelistedIp }) : 'NO_LISTENER'
    const otherInRangeRes = cb ? cb({ ip: '192.0.2.50' }) : 'NO_LISTENER'

    // Header blocking, CORS and tarpit must all be skipped for the whitelisted
    // IP, but dot-rewrite must still run for it.
    api.setConfig('headerBlock_headers', [{ name: 'User-Agent', regexp: 'badbot' }])
    api.setConfig('dotRewrite_paths', [{ prefix: '/.secret', enabled: true }])

    const ctx = makeCtx({ ip: whitelistedIp, path: '/.secret/x.txt', headers: { 'User-Agent': 'badbot-9000' } })
    instance.middleware(ctx)

    const pass = whitelistedSocketRes === undefined
        && otherInRangeRes === 'security-suite'
        && disconnectCalls.length === 0
        && ctx.path === '/secret/x.txt'

    record('9. Shared whitelist exempts everything except dot-rewrite', pass,
        pass ? '' : `whitelistedSocketRes=${JSON.stringify(whitelistedSocketRes)} otherInRangeRes=${JSON.stringify(otherInRangeRes)} disconnectCalls=${disconnectCalls.length} path=${ctx.path}`)

    try { instance.unload() } catch (e) { console.log('  [scenario9 unload error]', e.stack) }
}

// --- main --------------------------------------------------------------

async function main() {
    delete require.cache[require.resolve(PLUGIN_PATH)]
    const plugin = require(PLUGIN_PATH)

    await scenario1(plugin)
    await scenario2(plugin)
    await scenario3(plugin)
    await scenario4(plugin)
    await scenario5(plugin)
    await scenario6(plugin)
    await scenario7(plugin)
    await scenario8(plugin)
    await scenario9(plugin)

    const passCount = results.filter(r => r.pass).length
    console.log('\n=== SUMMARY ===')
    for (const r of results) console.log(`  [${r.pass ? 'PASS' : 'FAIL'}] ${r.name}`)
    console.log(`${passCount}/${results.length} scenarios passed`)

    try { fs.rmSync(STORAGE_BASE, { recursive: true, force: true }) } catch (e) { console.log('cleanup error', e.message) }

    process.exit(results.every(r => r.pass) ? 0 : 1)
}

main().catch(err => {
    console.log('FATAL', err.stack)
    process.exit(2)
})
