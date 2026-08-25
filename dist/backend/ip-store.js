// Derived from feuerswut/hfs-ip-blocklist and rejetto/antidos (GPLv3). Part of security-suite, AGPL-3.0.
'use strict'

const fs = require('fs')
const fsp = fs.promises
const path = require('path')
const utils = require('./utils')
const { loadRoaring } = require('./roaring-loader')

const V4_MAPPED_RE = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i

exports.configSchema = {
    ip_source: {
        type: 'select', label: "Blocklist source", defaultValue: 'url',
        options: { URL: 'url', "Local file": 'file' },
    },
    ip_url: {
        type: 'string', label: "Blocklist URL",
        helperText: "Plain-text list: one IP, CIDR or start-end range per line",
        showIf: v => v.ip_source === 'url',
    },
    ip_filePath: {
        type: 'string', label: "Blocklist file path",
        helperText: "Absolute path to a plain-text list on this server",
        showIf: v => v.ip_source === 'file',
    },
    ip_refreshInterval: {
        type: 'number', label: "Refresh interval", defaultValue: 86400, min: 3600,
        unit: "seconds", helperText: "How often to re-fetch the list (minimum 1 hour)",
    },
    ip_lookupMode: {
        type: 'select', label: "Lookup mode", defaultValue: 'auto',
        options: { Auto: 'auto', "Roaring bitmap": 'roaring', "Sorted ranges": 'ranges' },
        helperText: "Auto uses the roaring bitmap when the native addon is available, else sorted ranges",
    },
    ip_enableIPv6: {
        type: 'boolean', label: "Enable IPv6", defaultValue: true,
    },
    ip_logEnabled: {
        type: 'boolean', label: "Enable logging", defaultValue: true,
        helperText: "Log blocklist builds/reloads and connections blocked by the IP blocklist (batched, flushed every couple of minutes).",
    },
    ip_logVerbose: {
        type: 'boolean', label: "Verbose logging", defaultValue: false,
        helperText: "Log every event immediately instead of batching, and include fine-grained worker/loading detail.",
        showIf: v => v.ip_logEnabled,
    },
}

function binarySearch(ranges, value) {
    let lo = 0, hi = ranges.length - 1
    while (lo <= hi) {
        const mid = (lo + hi) >>> 1
        const r = ranges[mid]
        if (value < r.start) hi = mid - 1
        else if (value > r.end) lo = mid + 1
        else return true
    }
    return false
}

// Same binary search, but over parallel Uint32Array start/end lanes instead
// of an array of {start,end} objects -- see the comment on this.ipv4Ranges.
function binarySearchTyped(starts, ends, count, value) {
    let lo = 0, hi = count - 1
    while (lo <= hi) {
        const mid = (lo + hi) >>> 1
        if (value < starts[mid]) hi = mid - 1
        else if (value > ends[mid]) lo = mid + 1
        else return true
    }
    return false
}

function readBigInt128(buf, offset) {
    return (buf.readBigUInt64BE(offset) << 64n) | buf.readBigUInt64BE(offset + 8)
}

class IPStore {
    // `log` covers blocklist build/load events (IP Blocklist category); `banLog`
    // covers dynamic bans, which are issued exclusively by the rate-limiter, so
    // they're logged under the Rate-limit category instead even though the ban
    // state itself lives here.
    constructor(api, log, banLog) {
        this.api = api
        this.log = log || (() => {})
        this.banLog = banLog || this.log
        this.storageDir = api && api.storageDir
        this.bitmap = null          // RoaringBitmap32, O(1) IPv4
        // { starts: Uint32Array, ends: Uint32Array, length } instead of an array
        // of {start,end} objects: this is held in memory for the plugin's whole
        // lifetime, so for a multi-million-range list the per-object overhead of
        // a plain array would be a permanent, not just transient, memory cost.
        this.ipv4Ranges = null      // sorted parallel Uint32Arrays, O(log n)
        this.ipv6Ranges = null      // sorted {start,end} BigInts (IPv6 lists are small in practice)
        this.meta = null
        this.ready = false
        this.bulkFormat = null      // 'roaring' | 'ranges' | null
        this.dynamicBans = new Map()   // ip -> expire timestamp (0 = never)
        this.banTimers = new Map()     // ip -> Timeout
        this.whitelistV4 = []
        this.whitelistV6 = []
        this.whitelistMatcher = null   // HFS makeNetMatcher, when available
        this.stats = {
            checks: 0, blocked: 0,
            hitsWhitelist: 0, hitsDynamic: 0, hitsBulk: 0,
            local: 0, errors: 0,
        }
    }

    // --- bulk list loading -------------------------------------------------

    async load() {
        this.bitmap = null
        this.ipv4Ranges = null
        this.ipv6Ranges = null
        this.ready = false
        this.bulkFormat = null

        if (!this.storageDir) return false
        try {
            const metaPath = path.join(this.storageDir, 'meta.json')
            if (!fs.existsSync(metaPath)) return false
            this.meta = JSON.parse(await fsp.readFile(metaPath, 'utf8'))

            let ok = false
            if (this.meta.format === 'roaring') {
                ok = await this._loadRoaring()
                if (!ok) {
                    // The worker wrote a .roar but this process cannot read it (missing
                    // or ABI-mismatched addon). There is no ranges file to fall back to,
                    // so say so loudly instead of silently serving an empty blocklist.
                    this.log('WARNING: roaring bitmap on disk could not be loaded; trying sorted-ranges file')
                    ok = await this._loadRanges()
                    if (!ok) this.log('ERROR: no usable IPv4 blocklist on disk - rebuild required (set Lookup mode to "Sorted ranges" if the native addon is unavailable)')
                }
            } else {
                ok = await this._loadRanges()
            }

            await this._loadIPv6()

            this.ready = ok || !!(this.ipv6Ranges && this.ipv6Ranges.length)
            return this.ready
        } catch (err) {
            this.log(`load error: ${err.message}`)
            return false
        }
    }

    async _loadRoaring() {
        const p = path.join(this.storageDir, 'ipv4.roar')
        if (!fs.existsSync(p)) return false
        const roaring = loadRoaring()
        if (!roaring.cls) {
            this.log(`roaring unavailable: ${roaring.detail}`)
            return false
        }
        try {
            const buf = await fsp.readFile(p)
            this.bitmap = roaring.cls.deserialize(buf, false)
            this.bulkFormat = 'roaring'
            this.log(`IPv4 roaring bitmap loaded via [${roaring.source}], ${(buf.length / 1048576).toFixed(1)} MB serialized`)
            return true
        } catch (err) {
            this.log(`roaring deserialize failed: ${err.message}`)
            this.bitmap = null
            return false
        }
    }

    async _loadRanges() {
        const p = path.join(this.storageDir, 'ipv4-ranges.bin')
        if (!fs.existsSync(p)) return false
        const buf = await fsp.readFile(p)
        if (buf.length % 8) { this.log('ipv4-ranges.bin is truncated'); return false }
        const count = buf.length / 8
        const starts = new Uint32Array(count)
        const ends = new Uint32Array(count)
        for (let i = 0; i < count; i++) {
            starts[i] = buf.readUInt32BE(i * 8)
            ends[i] = buf.readUInt32BE(i * 8 + 4)
        }
        this.ipv4Ranges = { starts, ends, length: count }
        this.bulkFormat = 'ranges'
        this.log(`IPv4 sorted ranges loaded: ${count} merged ranges`)
        return true
    }

    async _loadIPv6() {
        const p = path.join(this.storageDir, 'ipv6.bin')
        if (!fs.existsSync(p)) return
        const buf = await fsp.readFile(p)
        if (buf.length % 32) { this.log('ipv6.bin is truncated'); return }
        const count = buf.length / 32
        const out = new Array(count)
        for (let i = 0; i < count; i++)
            out[i] = { start: readBigInt128(buf, i * 32), end: readBigInt128(buf, i * 32 + 16) }
        this.ipv6Ranges = out
        this.log(`IPv6 ranges loaded: ${count}`)
    }

    // --- whitelist ---------------------------------------------------------

    // `raw` is the `whitelist` array config: [{ ip: 'net_mask string', enabled }, ...]
    setWhitelist(raw) {
        const rows = Array.isArray(raw) ? raw : []
        const entries = rows
            .filter(e => e && e.enabled !== false && e.ip)
            .map(e => String(e.ip).trim())
            .filter(Boolean)
        this.whitelistV4 = []
        this.whitelistV6 = []
        this.whitelistMatcher = null

        // HFS' makeNetMatcher also understands globs like 192.168.1.*, which the
        // upstream plugins allowed; keep that behaviour when HFS exposes it.
        if (entries.length) {
            try {
                const { makeNetMatcher } = this.api.require('./misc')
                if (typeof makeNetMatcher === 'function')
                    this.whitelistMatcher = makeNetMatcher(entries.map(x => `(${x})`).join('|'))
            } catch (_) {}
        }

        for (const e of entries) {
            const r = utils.parseIPRange(e)
            if (!r) continue
            (r.isIPv6 ? this.whitelistV6 : this.whitelistV4).push(r)
        }
        this.whitelistV4 = utils.mergeRanges(this.whitelistV4, 1)
        this.whitelistV6 = utils.mergeRanges(this.whitelistV6, 1n)
        this.log(`whitelist: ${entries.length} entries (${this.whitelistV4.length} v4, ${this.whitelistV6.length} v6 ranges)`)
    }

    _isWhitelisted(ip, ipLong, addr6) {
        if (this.whitelistMatcher) {
            try { if (this.whitelistMatcher(ip)) return true } catch (_) {}
        }
        if (ipLong !== null && ipLong !== undefined && this.whitelistV4.length)
            return binarySearch(this.whitelistV4, ipLong)
        if (addr6 !== null && addr6 !== undefined && this.whitelistV6.length)
            return binarySearch(this.whitelistV6, addr6)
        return false
    }

    // Public entry point for other modules (rate-limiter, tarpit) that only
    // have a plain ip string, so the whitelist is defined and matched in
    // exactly one place instead of every feature parsing its own copy.
    isWhitelisted(ip) {
        if (typeof ip !== 'string' || !ip) return false
        const mapped = V4_MAPPED_RE.exec(ip)
        const target = mapped ? mapped[1] : ip
        const isV6 = target.includes(':')
        const ipLong = isV6 ? null : utils.ip2long(target)
        const addr6 = isV6 ? utils.ipv6ToBigInt(target) : null
        return this._isWhitelisted(ip, ipLong, addr6) || (target !== ip && this._isWhitelisted(target, ipLong, addr6))
    }

    // --- dynamic bans ------------------------------------------------------

    addDynamicBan(ip, expireMs) {
        if (!ip) return
        const ms = Number(expireMs) > 0 ? Number(expireMs) : 0
        const expire = ms ? Date.now() + ms : 0

        const prev = this.banTimers.get(ip)
        if (prev) { clearTimeout(prev); this.banTimers.delete(ip) }

        const isNew = !this.dynamicBans.has(ip)
        this.dynamicBans.set(ip, expire)

        if (ms) {
            const t = setTimeout(() => {
                this.dynamicBans.delete(ip)
                this.banTimers.delete(ip)
                this.banLog(`ban lifted ${ip}`)
            }, ms)
            if (t.unref) t.unref()
            this.banTimers.set(ip, t)
        }

        // Mirror into HFS' own block list so it shows up in the Admin panel.
        try {
            this.api.addBlock(
                { ip, comment: 'security-suite', ...(expire ? { expire: new Date(expire) } : {}) },
                { comment: 'security-suite' })
        } catch (err) {
            this.banLog(`addBlock failed for ${ip}: ${err.message}`)
        }

        if (isNew) this.banLog(`banned ${ip}${ms ? ` for ${Math.round(ms / 1000)}s` : ' (no expiry)'}`)
    }

    removeDynamicBan(ip) {
        const t = this.banTimers.get(ip)
        if (t) clearTimeout(t)
        this.banTimers.delete(ip)
        return this.dynamicBans.delete(ip)
    }

    isDynamicallyBanned(ip) {
        const expire = this.dynamicBans.get(ip)
        if (expire === undefined) return false
        if (expire && expire <= Date.now()) { this.removeDynamicBan(ip); return false }
        return true
    }

    // --- lookup ------------------------------------------------------------

    checkIP(ip) {
        this.stats.checks++
        if (typeof ip !== 'string' || !ip) {
            this.stats.errors++
            return { blocked: false, error: 'Invalid IP' }
        }

        let res
        try { res = this._check(ip) }
        catch (err) { this.stats.errors++; return { blocked: false, error: err.message } }

        if (res.error) this.stats.errors++
        else if (res.local) this.stats.local++
        else if (res.blocked) {
            this.stats.blocked++
            if (res.source === 'dynamic') this.stats.hitsDynamic++
            else if (res.source === 'bulk') this.stats.hitsBulk++
        } else if (res.source === 'whitelist') this.stats.hitsWhitelist++
        return res
    }

    _check(raw) {
        let ip = raw
        const mapped = V4_MAPPED_RE.exec(ip)
        if (mapped) ip = mapped[1]

        const isV6 = ip.includes(':')
        let ipLong = null, addr6 = null
        if (isV6) {
            addr6 = utils.ipv6ToBigInt(ip)
            if (addr6 === null) return { blocked: false, error: 'Invalid IPv6' }
            if (utils.isLocalIPv6(addr6)) return { blocked: false, local: true }
        } else {
            ipLong = utils.ip2long(ip)
            if (ipLong === null) return { blocked: false, error: 'Invalid IP' }
            if (utils.isLocalIP(ipLong)) return { blocked: false, local: true }
        }

        if (this._isWhitelisted(raw, ipLong, addr6) || (raw !== ip && this._isWhitelisted(ip, ipLong, addr6)))
            return { blocked: false, source: 'whitelist' }

        if (this.isDynamicallyBanned(raw) || (raw !== ip && this.isDynamicallyBanned(ip)))
            return { blocked: true, source: 'dynamic' }

        if (isV6) {
            if (this.ipv6Ranges && this.ipv6Ranges.length && binarySearch(this.ipv6Ranges, addr6))
                return { blocked: true, source: 'bulk' }
            return { blocked: false }
        }
        if (this.bitmap) {
            if (this.bitmap.has(ipLong)) return { blocked: true, source: 'bulk' }
            return { blocked: false }
        }
        if (this.ipv4Ranges && binarySearchTyped(this.ipv4Ranges.starts, this.ipv4Ranges.ends, this.ipv4Ranges.length, ipLong))
            return { blocked: true, source: 'bulk' }
        return { blocked: false }
    }

    // --- lifecycle ---------------------------------------------------------

    cleanup() {
        for (const t of this.banTimers.values()) clearTimeout(t)
        this.banTimers.clear()
        this.dynamicBans.clear()
        this.bitmap = null
        this.ipv4Ranges = null
        this.ipv6Ranges = null
        this.whitelistV4 = []
        this.whitelistV6 = []
        this.whitelistMatcher = null
        this.ready = false
        this.bulkFormat = null
    }

    getStats() {
        let bytes = 0
        if (this.ipv4Ranges) bytes += this.ipv4Ranges.length * 8 // two Uint32 lanes
        if (this.ipv6Ranges) bytes += this.ipv6Ranges.length * 80
        return {
            ready: this.ready,
            format: this.bulkFormat,
            ipv4Ranges: this.ipv4Ranges ? this.ipv4Ranges.length : 0,
            ipv6Ranges: this.ipv6Ranges ? this.ipv6Ranges.length : 0,
            bitmapSize: this.bitmap ? this.bitmap.size : 0,
            dynamicBans: this.dynamicBans.size,
            whitelistRanges: this.whitelistV4.length + this.whitelistV6.length,
            // Roaring lives in the C++ heap and is not counted here.
            jsMemoryMB: +(bytes / 1048576).toFixed(2),
            meta: this.meta,
            ...this.stats,
        }
    }
}

exports.IPStore = IPStore
