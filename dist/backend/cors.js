// Derived from feuerswut/hfs-cors-by-path (GPLv3). Part of security-suite, AGPL-3.0.

function pathMatches(requestPath, pathRules) {
    if (!pathRules || pathRules.length === 0) return true
    for (const entry of pathRules) {
        if (!entry.enabled || !entry.pattern) continue
        try {
            if (entry.isRegex) {
                if (new RegExp(entry.pattern, 'i').test(requestPath)) return true
            } else {
                const prefix = entry.pattern.endsWith('/') ? entry.pattern : entry.pattern + '/'
                if (requestPath === entry.pattern || requestPath.startsWith(prefix)) return true
            }
        } catch (e) {}
    }
    return false
}

function applyCorsIfNeeded(ctx, pathRules) {
    const origin = ctx.get('origin')
    let isExternal = false
    if (origin) {
        try { isExternal = new URL(origin).host !== ctx.host }
        catch (e) {}
    }
    const normalizedPath = require('path').posix.normalize(ctx.path)
    if (isExternal && pathMatches(normalizedPath, pathRules)) {
        ctx.set('Access-Control-Allow-Methods', '*')
        ctx.set('Access-Control-Allow-Origin', '*')
        ctx.set('Access-Control-Allow-Headers', '*')
        return true
    }
    return false
}

exports.pathMatches = pathMatches
exports.applyCorsIfNeeded = applyCorsIfNeeded

exports.configSchema = {
    cors_paths: {
        type: 'array',
        label: 'Path Filters (empty = allow all)',
        defaultValue: [],
        fields: {
            pattern: { type: 'string', label: 'Path prefix or regex pattern', $width: 4 },
            isRegex: { type: 'boolean', label: 'Regex', defaultValue: false, $width: 1 },
            enabled: { type: 'boolean', label: 'Enabled', defaultValue: true, $width: 1 },
        },
    },
}
