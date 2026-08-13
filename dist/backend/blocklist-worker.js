// Derived from feuerswut/hfs-ip-blocklist (GPLv3). Part of security-suite, AGPL-3.0.
'use strict'

const { parentPort, workerData } = require('worker_threads')
const fs = require('fs')
const fsp = fs.promises
const path = require('path')
const crypto = require('crypto')
const readline = require('readline')
const https = require('https')
const http = require('http')
const { URL } = require('url')
const utils = require('./utils')
const { loadRoaring } = require('./roaring-loader')

const { storageDir, config } = workerData

function post(m) { parentPort.postMessage(m) }
function debug(msg) { post({ type: 'debug', msg }) }
function log(msg) { post({ type: 'log', msg }) }
function progress(phase, percent) { post({ type: 'progress', phase, percent }) }

const DEFAULTS = {
    minRangeSize: 1,
    ignoreSingleIPs: false,
    downloadTimeoutMs: 300000,
    maxRedirects: 5,
}
const adv = { ...DEFAULTS, ...(config.advanced || {}) }

// --- download --------------------------------------------------------------

function downloadToFile(url, destPath, timeoutMs, redirectsLeft, label) {
    return new Promise((resolve, reject) => {
        let parsed
        try { parsed = new URL(url) } catch (_) { return reject(new Error(`Invalid URL: ${url}`)) }
        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:')
            return reject(new Error(`Unsupported protocol: ${parsed.protocol}`))

        const client = parsed.protocol === 'https:' ? https : http
        const req = client.get(url, { timeout: timeoutMs, headers: { 'user-agent': 'hfs-security-suite' } }, res => {
            const code = res.statusCode
            if (code >= 300 && code < 400 && res.headers.location) {
                res.resume()
                if (redirectsLeft <= 0) return reject(new Error('Too many redirects'))
                // Location may be relative; resolve against the current URL.
                const next = new URL(res.headers.location, url).toString()
                return downloadToFile(next, destPath, timeoutMs, redirectsLeft - 1, label).then(resolve, reject)
            }
            if (code !== 200) { res.resume(); return reject(new Error(`HTTP ${code} for ${url}`)) }

            const total = parseInt(res.headers['content-length'], 10) || 0
            let downloaded = 0, lastPercent = -1
            const out = fs.createWriteStream(destPath)

            res.on('data', chunk => {
                downloaded += chunk.length
                if (!total) return
                const pct = Math.floor(downloaded / total * 100)
                if (pct >= lastPercent + 10) { lastPercent = pct; progress('download', pct) }
            })
            res.on('error', err => { out.destroy(); reject(err) })
            out.on('error', err => { res.destroy(); reject(err) })
            out.on('finish', () => resolve())
            res.pipe(out)
        })
        req.on('error', reject)
        req.on('timeout', () => { req.destroy(new Error(`Download timeout for ${url}`)) })
    })
}

function hashFile(filePath) {
    return new Promise((resolve, reject) => {
        const h = crypto.createHash('sha256')
        const s = fs.createReadStream(filePath)
        s.on('data', c => h.update(c))
        s.on('end', () => resolve(h.digest('hex')))
        s.on('error', reject)
    })
}

function stableHash(obj) {
    return crypto.createHash('sha256').update(JSON.stringify(obj, (_, v) =>
        (v && typeof v === 'object' && !Array.isArray(v))
            ? Object.keys(v).sort().reduce((a, k) => (a[k] = v[k], a), {})
            : v)).digest('hex')
}

// --- range collection ------------------------------------------------------

function parseStream(filePath, sink) {
    return new Promise((resolve, reject) => {
        const rl = readline.createInterface({
            input: fs.createReadStream(filePath, { encoding: 'utf8' }),
            crlfDelay: Infinity,
        })
        rl.on('line', sink)
        rl.on('close', resolve)
        rl.on('error', reject)
    })
}

function writeBigInt128(buf, offset, value) {
    buf.writeBigUInt64BE((value >> 64n) & 0xFFFFFFFFFFFFFFFFn, offset)
    buf.writeBigUInt64BE(value & 0xFFFFFFFFFFFFFFFFn, offset + 8)
}

// roaring's addRange takes an EXCLUSIVE end, and it accepts 2**32 there, so the
// all-ones top address needs no special casing -- just end+1.
function addIPv4Range(bitmap, start, end) {
    bitmap.addRange(start, end + 1)
}

async function writeAtomic(dir, name, buf) {
    const tmp = path.join(dir, name + '.tmp')
    await fsp.writeFile(tmp, buf)
    await fsp.rename(tmp, path.join(dir, name))
}

// --- main ------------------------------------------------------------------

async function run() {
    const tempFiles = []
    try {
        const t0 = Date.now()
        debug('worker started')
        await fsp.mkdir(storageDir, { recursive: true })

        const sources = Array.isArray(config.sources) ? config.sources.filter(s => s && s.location) : []
        if (!sources.length) throw new Error('No blocklist sources configured')

        const roaring = loadRoaring()
        const mode = config.ip_lookupMode || 'auto'
        let useRoaring
        if (mode === 'ranges') {
            useRoaring = false
            log('Lookup mode "Sorted ranges" selected - building sorted-range index')
        } else if (mode === 'roaring') {
            useRoaring = !!roaring.cls
            if (!useRoaring) log(`WARNING: Lookup mode "Roaring bitmap" selected but the native addon is unavailable, falling back to sorted ranges. ${roaring.detail}`)
            else log(`Roaring bitmap active [${roaring.source}] - O(1) IPv4 lookup`)
        } else {
            useRoaring = !!roaring.cls
            if (useRoaring) log(`Roaring bitmap active [${roaring.source}] - O(1) IPv4 lookup`)
            else log(`Roaring bitmap unavailable, using sorted-range binary search. ${roaring.detail}`)
        }
        if (roaring.cls) debug(`roaring: ${roaring.source} ${roaring.detail}`)

        // --- fetch every source, then hash ALL of them ---
        progress('download', 0)
        const resolved = []
        for (let i = 0; i < sources.length; i++) {
            const s = sources[i]
            const label = s.label || s.location
            if (s.type === 'url') {
                const tmp = path.join(storageDir, `download-${i}.tmp`)
                tempFiles.push(tmp)
                debug(`downloading [${label}]`)
                await downloadToFile(s.location, tmp, adv.downloadTimeoutMs, adv.maxRedirects, label)
                resolved.push({ label, file: tmp })
            } else {
                if (!fs.existsSync(s.location)) throw new Error(`File not found: ${s.location}`)
                resolved.push({ label, file: s.location })
            }
            progress('download', Math.round((i + 1) / sources.length * 100))
        }

        // The skip-if-unchanged check must cover EVERY source, not just the first --
        // otherwise appending a second list (e.g. threat-intel sync) would hash
        // identically to the previous run and the rebuild would be skipped.
        const sourceHashes = []
        for (const r of resolved) sourceHashes.push({ label: r.label, hash: await hashFile(r.file) })
        const sourceHash = crypto.createHash('sha256')
            .update(JSON.stringify(sourceHashes)).digest('hex')
        const configHash = stableHash({
            adv,
            enableIPv6: !!config.ip_enableIPv6,
            format: useRoaring ? 'roaring' : 'ranges',
            sources: sources.map(s => ({ type: s.type, location: s.location })),
        })

        const metaFile = path.join(storageDir, 'meta.json')
        if (!config.forceReprocess && fs.existsSync(metaFile)) {
            try {
                const meta = JSON.parse(await fsp.readFile(metaFile, 'utf8'))
                if (meta.sourceHash === sourceHash && meta.configHash === configHash) {
                    debug('sources and config unchanged - skipping rebuild')
                    await cleanTemp(tempFiles)
                    post({ type: 'ready', skipped: true, ...meta })
                    return
                }
            } catch (_) {}
        }

        // --- parse ---
        progress('parsing', 0)
        const bitmap = useRoaring ? new roaring.cls() : null
        const ipv4Ranges = useRoaring ? null : []
        const ipv6Ranges = []
        let totalIPv4 = 0, totalIPv6 = 0, skipped = 0, ignoredSingles = 0

        for (let i = 0; i < resolved.length; i++) {
            const r = resolved[i]
            let mine = 0
            await parseStream(r.file, line => {
                const range = utils.parseIPRange(line)
                if (!range) { skipped++; return }

                if (range.isIPv6) {
                    if (!config.ip_enableIPv6) { skipped++; return }
                    // Drop only fully-local ranges: a wide range that merely overlaps
                    // local space is still useful, and checkIP exempts local IPs anyway.
                    if (utils.isLocalIPv6(range.start) && utils.isLocalIPv6(range.end)) { skipped++; return }
                    ipv6Ranges.push(range)
                    totalIPv6++; mine++
                    return
                }

                if (utils.isLocalIP(range.start) && utils.isLocalIP(range.end)) { skipped++; return }
                const size = range.end - range.start + 1
                if (adv.ignoreSingleIPs && size === 1) { ignoredSingles++; return }
                if (size < adv.minRangeSize) { skipped++; return }

                if (useRoaring) addIPv4Range(bitmap, range.start, range.end)
                else ipv4Ranges.push(range)
                totalIPv4++; mine++
            })
            debug(`[${r.label}] contributed ${mine} ranges`)
            progress('parsing', Math.round((i + 1) / resolved.length * 100))
        }

        await cleanTemp(tempFiles)
        debug(`parsed ${totalIPv4} IPv4 + ${totalIPv6} IPv6 ranges (skipped ${skipped}, ignored ${ignoredSingles} singles) from ${resolved.length} source(s)`)
        if (!totalIPv4 && !totalIPv6) throw new Error('No valid ranges found in any source')

        // --- save IPv4 ---
        progress('saving', 0)
        let ipv4Bytes = 0, mergedCount = 0, cardinality = 0
        const format = useRoaring ? 'roaring' : 'ranges'

        if (useRoaring) {
            bitmap.runOptimize()
            bitmap.shrinkToFit()
            cardinality = bitmap.size
            const serialized = bitmap.serialize(false)
            await writeAtomic(storageDir, 'ipv4.roar', serialized)
            ipv4Bytes = serialized.length
            await fsp.unlink(path.join(storageDir, 'ipv4-ranges.bin')).catch(() => {})
        } else {
            const merged = utils.mergeRanges(ipv4Ranges, 1)
            ipv4Ranges.length = 0
            mergedCount = merged.length
            const buf = Buffer.allocUnsafe(merged.length * 8)
            for (let i = 0; i < merged.length; i++) {
                buf.writeUInt32BE(merged[i].start >>> 0, i * 8)
                buf.writeUInt32BE(merged[i].end >>> 0, i * 8 + 4)
            }
            await writeAtomic(storageDir, 'ipv4-ranges.bin', buf)
            ipv4Bytes = buf.length
            await fsp.unlink(path.join(storageDir, 'ipv4.roar')).catch(() => {})
        }

        // --- save IPv6 ---
        let ipv6Bytes = 0, merged6Count = 0
        if (config.ip_enableIPv6 && ipv6Ranges.length) {
            const merged6 = utils.mergeRanges(ipv6Ranges, 1n)
            ipv6Ranges.length = 0
            merged6Count = merged6.length
            const buf6 = Buffer.allocUnsafe(merged6.length * 32)
            for (let i = 0; i < merged6.length; i++) {
                writeBigInt128(buf6, i * 32, merged6[i].start)
                writeBigInt128(buf6, i * 32 + 16, merged6[i].end)
            }
            await writeAtomic(storageDir, 'ipv6.bin', buf6)
            ipv6Bytes = buf6.length
        } else {
            await fsp.unlink(path.join(storageDir, 'ipv6.bin')).catch(() => {})
        }

        progress('saving', 100)

        const meta = {
            format,
            sourceHash,
            configHash,
            sources: sourceHashes.map(s => s.label),
            totalRanges: totalIPv4,
            mergedRanges: mergedCount,        // 0 in roaring mode, which has no range list
            ipv4Addresses: cardinality,       // 0 in ranges mode, which does not count them
            totalIPv6Ranges: totalIPv6,
            mergedIPv6Ranges: merged6Count,
            diskUsageMB: +((ipv4Bytes + ipv6Bytes) / 1048576).toFixed(2),
            processTime: +((Date.now() - t0) / 1000).toFixed(1),
            builtAt: new Date().toISOString(),
        }
        await writeAtomic(storageDir, 'meta.json', JSON.stringify(meta, null, 2))
        debug(`done in ${meta.processTime}s - ${meta.diskUsageMB} MB on disk (${format})`)
        post({ type: 'ready', skipped: false, ...meta })

    } catch (error) {
        await cleanTemp(tempFiles)
        post({ type: 'error', error: error.message, stack: error.stack })
    }
}

async function cleanTemp(files) {
    for (const f of files) await fsp.unlink(f).catch(() => {})
    files.length = 0
}

run()
