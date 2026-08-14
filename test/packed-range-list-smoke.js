'use strict'
// Regression test for utils.PackedRangeList: the memory-efficient replacement
// for building an array of {start,end} objects when sorting/merging a large
// IPv4 blocklist. Cross-validates against the older object-based mergeRanges
// on random large input, plus explicit edge cases. Run: node test/packed-range-list-smoke.js

const assert = require('assert')
const utils = require('../dist/backend/utils')

const results = []
function t(name, fn) {
    try { fn(); results.push(['OK  ', name, '']) }
    catch (e) { results.push(['FAIL', name, e.message]) }
}

function mergedFromPacked(list) {
    const view = list.sortAndMerge()
    const out = []
    for (let i = 0; i < view.length; i++)
        out.push({ start: utils.unpackStart(view[i]), end: utils.unpackEnd(view[i]) })
    return out
}

function mergedFromObjects(ranges) {
    return utils.mergeRanges(ranges.map(r => ({ start: r.start, end: r.end })), 1)
}

t('empty list merges to empty', () => {
    const list = new utils.PackedRangeList()
    const view = list.sortAndMerge()
    assert.strictEqual(view.length, 0)
})

t('single range round-trips', () => {
    const list = new utils.PackedRangeList()
    list.push(10, 20)
    const merged = mergedFromPacked(list)
    assert.deepStrictEqual(merged, [{ start: 10, end: 20 }])
})

t('touching ranges merge (end+1 == next start)', () => {
    const list = new utils.PackedRangeList()
    list.push(10, 20)
    list.push(21, 30)
    const merged = mergedFromPacked(list)
    assert.deepStrictEqual(merged, [{ start: 10, end: 30 }])
})

t('adjacent-but-not-touching ranges stay separate', () => {
    const list = new utils.PackedRangeList()
    list.push(10, 20)
    list.push(22, 30)
    const merged = mergedFromPacked(list)
    assert.deepStrictEqual(merged, [{ start: 10, end: 20 }, { start: 22, end: 30 }])
})

t('overlapping ranges merge, unsorted input', () => {
    const list = new utils.PackedRangeList()
    list.push(100, 200)
    list.push(50, 150)
    list.push(180, 250)
    const merged = mergedFromPacked(list)
    assert.deepStrictEqual(merged, [{ start: 50, end: 250 }])
})

t('a fully-contained range disappears into the outer one', () => {
    const list = new utils.PackedRangeList()
    list.push(0, 1000)
    list.push(100, 200)
    const merged = mergedFromPacked(list)
    assert.deepStrictEqual(merged, [{ start: 0, end: 1000 }])
})

t('address-space boundaries (0 and 0xFFFFFFFF) pack/unpack exactly', () => {
    const list = new utils.PackedRangeList()
    list.push(0, 0)
    list.push(0xFFFFFFFF, 0xFFFFFFFF)
    const merged = mergedFromPacked(list)
    assert.deepStrictEqual(merged, [{ start: 0, end: 0 }, { start: 0xFFFFFFFF, end: 0xFFFFFFFF }])
})

t('grows past its initial capacity correctly', () => {
    const list = new utils.PackedRangeList(4) // force multiple doublings
    for (let i = 0; i < 500; i++) list.push(i * 10, i * 10 + 1)
    assert.strictEqual(list.length, 500)
    const merged = mergedFromPacked(list)
    // every pushed range is 2 apart from the next (i*10+1 vs (i+1)*10), so none touch/merge
    assert.strictEqual(merged.length, 500)
    assert.deepStrictEqual(merged[0], { start: 0, end: 1 })
    assert.deepStrictEqual(merged[499], { start: 4990, end: 4991 })
})

t('matches the object-based mergeRanges on 20,000 random ranges', () => {
    const input = []
    // Deterministic PRNG so failures are reproducible.
    let seed = 12345
    function rand() { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff }

    for (let i = 0; i < 20000; i++) {
        const start = Math.floor(rand() * 0xF0000000)
        const size = 1 + Math.floor(rand() * 5000)
        input.push({ start, end: Math.min(start + size, 0xFFFFFFFF) })
    }

    const list = new utils.PackedRangeList()
    for (const r of input) list.push(r.start, r.end)

    const viaPacked = mergedFromPacked(list)
    const viaObjects = mergedFromObjects(input)

    assert.strictEqual(viaPacked.length, viaObjects.length, 'merged range count should match')
    for (let i = 0; i < viaObjects.length; i++)
        assert.deepStrictEqual(viaPacked[i], viaObjects[i], `range #${i} should match`)
})

console.log('')
for (const [s, n, m] of results) console.log(`${s} ${n}${m ? '  -> ' + m : ''}`)
const failed = results.filter(r => r[0] === 'FAIL')
console.log(`\n${results.length - failed.length}/${results.length} passed`)
process.exit(failed.length ? 1 : 0)
