// Derived from feuerswut/hfs-ip-blocklist (GPLv3). Part of security-suite, AGPL-3.0.
'use strict'

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/

function ip2long(ip) {
    const m = IPV4_RE.exec(ip)
    if (!m) return null
    let out = 0
    for (let i = 1; i <= 4; i++) {
        const n = +m[i]
        if (n > 255) return null
        out = out * 256 + n
    }
    return out >>> 0
}

function long2ip(n) {
    return `${(n >>> 24) & 255}.${(n >>> 16) & 255}.${(n >>> 8) & 255}.${n & 255}`
}

function isLocalIP(ipLong) {
    return (
        ipLong === 0 ||
        (ipLong >= 0x0A000000 && ipLong <= 0x0AFFFFFF) ||   // 10.0.0.0/8
        (ipLong >= 0x7F000000 && ipLong <= 0x7FFFFFFF) ||   // 127.0.0.0/8
        (ipLong >= 0xA9FE0000 && ipLong <= 0xA9FEFFFF) ||   // 169.254.0.0/16
        (ipLong >= 0xAC100000 && ipLong <= 0xAC1FFFFF) ||   // 172.16.0.0/12
        (ipLong >= 0xC0A80000 && ipLong <= 0xC0A8FFFF) ||   // 192.168.0.0/16
        (ipLong >= 0xE0000000 && ipLong <= 0xEFFFFFFF) ||   // 224.0.0.0/4 multicast
        (ipLong >= 0xF0000000 && ipLong <= 0xFFFFFFFF)      // 240.0.0.0/4 reserved
    )
}

const V4_MAPPED_RE = /^(?:::ffff:)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i

// Returns a 128-bit BigInt, or null on parse error.
function ipv6ToBigInt(ip) {
    if (typeof ip !== 'string') return null
    ip = ip.trim()
    if (!ip) return null

    const zone = ip.indexOf('%')
    if (zone !== -1) ip = ip.slice(0, zone)

    const mapped = V4_MAPPED_RE.exec(ip)
    if (mapped) {
        const v4 = ip2long(mapped[1])
        if (v4 === null) return null
        return (0xFFFFn << 32n) | BigInt(v4)
    }

    // A trailing dotted-quad (e.g. 64:ff9b::1.2.3.4) stands for the last two groups.
    // Rewrite it to hex in place, so the '::' expansion below stays intact.
    const lastColon = ip.lastIndexOf(':')
    if (lastColon !== -1 && ip.indexOf('.', lastColon) !== -1) {
        const v4 = ip2long(ip.slice(lastColon + 1))
        if (v4 === null) return null
        ip = ip.slice(0, lastColon + 1)
            + ((v4 >>> 16) & 0xFFFF).toString(16) + ':' + (v4 & 0xFFFF).toString(16)
    }

    let left, right
    const dbl = ip.indexOf('::')
    if (dbl !== -1) {
        if (ip.indexOf('::', dbl + 1) !== -1) return null
        const a = ip.slice(0, dbl)
        const b = ip.slice(dbl + 2)
        left = a ? a.split(':') : []
        right = b ? b.split(':') : []
    } else {
        left = ip ? ip.split(':') : []
        right = []
    }
    const total = left.length + right.length
    const missing = 8 - total
    if (dbl === -1 ? missing !== 0 : missing < 0) return null

    const groups = dbl === -1 ? left : left.concat(Array(missing).fill('0'), right)
    if (groups.length !== 8) return null

    let result = 0n
    for (const g of groups) {
        if (!/^[0-9a-f]{1,4}$/i.test(g)) return null
        result = (result << 16n) | BigInt(parseInt(g, 16))
    }
    return result
}

function isLocalIPv6(addr) {
    if (addr === 0n || addr === 1n) return true           // :: and ::1
    if ((addr >> 118n) === 0x3FAn) return true            // fe80::/10 link-local
    if ((addr >> 121n) === 0x7En) return true             // fc00::/7 unique local
    if ((addr >> 32n) === 0xFFFFn)                        // ::ffff:0:0/96 IPv4-mapped
        return isLocalIP(Number(addr & 0xFFFFFFFFn))
    return false
}

function parseIPv4CIDR(ip, bits) {
    const ipLong = ip2long(ip)
    if (ipLong === null || !Number.isInteger(bits) || bits < 0 || bits > 32) return null
    if (bits === 0) return { start: 0, end: 0xFFFFFFFF, isIPv6: false }
    const hostBits = 32 - bits
    const start = ((ipLong >>> hostBits) * Math.pow(2, hostBits)) >>> 0
    const end = (start + Math.pow(2, hostBits) - 1) >>> 0
    return { start, end, isIPv6: false }
}

function parseIPv6CIDR(ip, bits) {
    const addr = ipv6ToBigInt(ip)
    if (addr === null || !Number.isInteger(bits) || bits < 0 || bits > 128) return null
    if (bits === 0) return { start: 0n, end: (1n << 128n) - 1n, isIPv6: true }
    const hostBits = BigInt(128 - bits)
    const start = (addr >> hostBits) << hostBits
    return { start, end: start | ((1n << hostBits) - 1n), isIPv6: true }
}

// Returns { start, end, isIPv6 } or null.
// IPv4 start/end are unsigned 32-bit numbers; IPv6 start/end are BigInts.
function parseIPRange(line) {
    if (typeof line !== 'string') return null
    line = line.trim()
    if (!line || line[0] === '#' || line[0] === ';' || line.startsWith('//')) return null

    // Many public lists are "ip<sep>label"; keep only the leading address token.
    const cut = line.search(/[\s,;#]/)
    if (cut !== -1) line = line.slice(0, cut)
    if (!line) return null

    const slash = line.lastIndexOf('/')
    if (slash !== -1) {
        const ipPart = line.slice(0, slash)
        const bitsPart = line.slice(slash + 1)
        if (!/^\d{1,3}$/.test(bitsPart)) return null
        const bits = +bitsPart
        return ipPart.includes(':') ? parseIPv6CIDR(ipPart, bits) : parseIPv4CIDR(ipPart, bits)
    }

    // Neither IPv4 nor IPv6 literals contain '-', so the first one always separates
    // the two endpoints. (The dev branch searched after the last ':' for IPv6, which
    // is past the dash and therefore never matched -- IPv6 ranges silently vanished.)
    const dash = line.indexOf('-')
    if (dash > 0) {
        const startStr = line.slice(0, dash)
        const endStr = line.slice(dash + 1)
        if (startStr.includes(':') || endStr.includes(':')) {
            const start = ipv6ToBigInt(startStr)
            const end = ipv6ToBigInt(endStr)
            if (start === null || end === null || start > end) return null
            return { start, end, isIPv6: true }
        }
        const start = ip2long(startStr)
        const end = ip2long(endStr)
        if (start === null || end === null || start > end) return null
        return { start, end, isIPv6: false }
    }

    if (line.includes(':')) {
        const addr = ipv6ToBigInt(line)
        return addr === null ? null : { start: addr, end: addr, isIPv6: true }
    }
    const ipLong = ip2long(line)
    return ipLong === null ? null : { start: ipLong, end: ipLong, isIPv6: false }
}

// Sorts in place and coalesces touching/overlapping ranges. Works for both the
// Number (IPv4) and BigInt (IPv6) variants; `one` selects 1 or 1n.
function mergeRanges(ranges, one) {
    if (!ranges.length) return []
    ranges.sort((a, b) => (a.start < b.start ? -1 : a.start > b.start ? 1 : 0))
    const out = [{ start: ranges[0].start, end: ranges[0].end }]
    for (let i = 1; i < ranges.length; i++) {
        const cur = ranges[i]
        const last = out[out.length - 1]
        if (cur.start <= last.end + one) {
            if (cur.end > last.end) last.end = cur.end
        } else out.push({ start: cur.start, end: cur.end })
    }
    return out
}

module.exports = {
    ip2long, long2ip, isLocalIP,
    ipv6ToBigInt, isLocalIPv6,
    parseIPRange, parseIPv4CIDR, parseIPv6CIDR,
    mergeRanges,
}
