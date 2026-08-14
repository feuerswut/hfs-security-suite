// Derived from feuerswut/hfs-ip-blocklist (GPLv3). Part of security-suite, AGPL-3.0.
'use strict'

const path = require('path')
const fs = require('fs')

// Priority 1: prebuilt .node shipped via dist-PLATFORM-ARCH/roaring/ (HFS merges
//             those folders into the plugin dir, so they sit next to dist/).
// Priority 2: null -> caller falls back to sorted ranges + binary search.
// No compilation ever happens on the target machine: if there's no prebuilt
// binary for this platform/arch/libc/ABI combo, the plugin just runs the
// pure-JS fallback automatically. There is no build step to run, manual or
// automatic.
const PREBUILT_BASE = path.join(__dirname, '..', 'roaring')

function detectLibc() {
    if (process.platform !== 'linux') return 'unknown'
    try {
        if (fs.readFileSync('/proc/self/maps', 'utf8').includes('musl')) return 'musl'
    } catch (_) {}
    return 'glibc'
}

function binaryDirName() {
    return `roaring-node-v${process.versions.modules}-${process.platform}-${process.arch}-${detectLibc()}`
}

// The addon exports a namespace object; the class hangs off .RoaringBitmap32.
// Verify the members we actually rely on before declaring success, so an
// incompatible build degrades to the ranges fallback instead of throwing later.
function extractClass(addon) {
    if (!addon) return null
    const cls = typeof addon === 'function' ? addon : addon.RoaringBitmap32
    if (typeof cls !== 'function') return null
    if (typeof cls.deserialize !== 'function') return null
    const p = cls.prototype
    if (!p || typeof p.addRange !== 'function' || typeof p.has !== 'function'
        || typeof p.serialize !== 'function' || typeof p.runOptimize !== 'function') return null
    return cls
}

// A native addon can load successfully and expose all the right method names
// (extractClass above) while still being functionally broken for a given
// platform -- e.g. a cross-compiled 32-bit ARM build that throws "Invalid
// RoaringBitmap32 object" the moment addRange is actually called, even on
// trivial input. Only a method-name check would never catch that; actually
// exercising the class is the only way to know it works before trusting it.
function selfTest(cls) {
    try {
        const b = new cls()
        b.addRange(0, 100)
        if (!b.has(0) || !b.has(99) || b.has(100)) return false
        b.runOptimize()
        const buf = b.serialize(false)
        const b2 = cls.deserialize(buf, false)
        return b2.has(50) && !b2.has(200)
    } catch (_) {
        return false
    }
}

let cached

function loadRoaring() {
    if (cached !== undefined) return cached

    const dirName = binaryDirName()
    const prebuiltPath = path.join(PREBUILT_BASE, dirName, 'roaring.node')
    const problems = []

    if (fs.existsSync(prebuiltPath)) {
        try {
            const cls = extractClass(require(prebuiltPath))
            if (cls && selfTest(cls)) return (cached = { cls, source: 'prebuilt', detail: dirName })
            problems.push(cls
                ? `prebuilt ${dirName} loaded but failed a functional self-test (addRange/has/serialize) -- likely a broken build for this platform`
                : `prebuilt ${dirName} loaded but exports no usable RoaringBitmap32`)
        } catch (err) {
            problems.push(`prebuilt ${dirName} failed to load: ${err.message}`)
        }
    } else {
        problems.push(`no prebuilt for ${dirName}`)
    }

    return (cached = {
        cls: null,
        source: null,
        detail: `${problems.join('; ')}. Using sorted-ranges fallback (binary search).`,
    })
}

function resetCache() { cached = undefined }

module.exports = { loadRoaring, resetCache, binaryDirName }
