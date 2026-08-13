// Part of security-suite, AGPL-3.0.
// Regression test for the roaring-node API contract that dist/backend relies on.
// Run: node test/roaring-smoke.js
'use strict'

const path = require('path')
const fs = require('fs')
const assert = require('assert')

const ROOT = path.join(__dirname, '..')
const results = []

function t(name, fn) {
    try { fn(); results.push(['OK  ', name, '']) }
    catch (e) { results.push(['FAIL', name, e.message]) }
}

function detectLibc() {
    if (process.platform !== 'linux') return 'unknown'
    try { if (fs.readFileSync('/proc/self/maps', 'utf8').includes('musl')) return 'musl' } catch (_) {}
    return 'glibc'
}

// The repo keeps binaries in dist-PLATFORM-ARCH/; an installed plugin has them
// merged next to dist/ content. No compile-from-source path exists -- only
// finished, vendored binaries are ever loaded.
function locate() {
    const dir = `roaring-node-v${process.versions.modules}-${process.platform}-${process.arch}-${detectLibc()}`
    const candidates = [
        [path.join(ROOT, `dist-${process.platform}-${process.arch}`, 'roaring', dir, 'roaring.node'), 'repo dist-PLATFORM-ARCH'],
        [path.join(ROOT, 'dist', 'roaring', dir, 'roaring.node'), 'installed layout'],
    ]
    for (const [p, how] of candidates)
        if (fs.existsSync(p)) {
            const m = require(p)
            return { cls: typeof m === 'function' ? m : m.RoaringBitmap32, how: `${how} (${dir})` }
        }
    return { cls: null, how: `no binary for ${dir}` }
}

const { cls: Cls, how } = locate()
console.log(`roaring source: ${how}`)
if (!Cls) {
    console.log('SKIP - no roaring binary for this platform/ABI; sorted-ranges fallback applies')
    process.exit(0)
}

t('addRange end is EXCLUSIVE', () => {
    const b = new Cls()
    b.addRange(0, 100)
    assert.strictEqual(b.has(0), true)
    assert.strictEqual(b.has(99), true)
    assert.strictEqual(b.has(100), false)
    assert.strictEqual(b.size, 100)
})

t('addRange accepts 2**32 as exclusive end', () => {
    const b = new Cls()
    b.addRange(4294967290, 4294967296)
    assert.strictEqual(b.has(4294967295), true)
    assert.strictEqual(b.size, 6)
})

t('out-of-range lookups', () => {
    const b = new Cls()
    b.addRange(10, 20)
    assert.strictEqual(b.has(9), false)
    assert.strictEqual(b.has(20), false)
    assert.strictEqual(b.has(0), false)
    assert.strictEqual(b.has(-1), false)
    assert.strictEqual(b.has(4294967296), false)
})

t('runOptimize + shrinkToFit', () => {
    const b = new Cls()
    b.addRange(0, 1000)
    b.runOptimize()
    b.shrinkToFit()
    assert.strictEqual(b.has(500), true)
    assert.strictEqual(b.size, 1000)
})

t('serialize(false) / static deserialize(buf, false) roundtrip', () => {
    const b = new Cls()
    b.addRange(0, 100)
    b.addRange(4294967290, 4294967296)
    b.add(1234567)
    b.runOptimize()
    b.shrinkToFit()
    const buf = b.serialize(false)
    assert.ok(Buffer.isBuffer(buf) || buf instanceof Uint8Array)
    assert.strictEqual(typeof Cls.deserialize, 'function')
    const b2 = Cls.deserialize(buf, false)
    assert.strictEqual(b2.size, b.size)
    for (const v of [0, 99, 1234567, 4294967294, 4294967295]) assert.strictEqual(b2.has(v), true, 'has ' + v)
    for (const v of [100, 1234568, 4294967289]) assert.strictEqual(b2.has(v), false, 'not has ' + v)
})

console.log('')
for (const [s, n, m] of results) console.log(`${s} ${n}${m ? '  -> ' + m : ''}`)
const failed = results.filter(r => r[0] === 'FAIL')
console.log(`\n${results.length - failed.length}/${results.length} passed`)
process.exit(failed.length ? 1 : 0)
