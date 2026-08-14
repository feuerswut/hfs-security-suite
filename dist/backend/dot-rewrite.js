// Derived from feuerswut/hfs-dot-rewrite-paths (GPLv3). Part of security-suite, AGPL-3.0.

function rewriteDotPath(ctx, pathRules, onRewrite) {
    const entries = (pathRules || []).filter(e => e.enabled !== false)

    // Off by default: dot-rewriting only runs for paths explicitly listed below.
    if (!entries.length) return

    if (!entries.some(e => {
        const p = e.prefix || ''
        return p && (ctx.path === p || ctx.path.startsWith(p.endsWith('/') ? p : p + '/'))
    }))
        return

    // Strip leading dot from each path segment, but leave '..' alone
    const rewritten = ctx.path
        .split('/')
        .map(seg => (seg.startsWith('.') && !seg.startsWith('..')) ? seg.slice(1) : seg)
        .join('/')

    if (rewritten !== ctx.path) {
        if (onRewrite)
            onRewrite(ctx.path, rewritten)
        ctx.path = rewritten
    }
}

exports.rewriteDotPath = rewriteDotPath

exports.configSchema = {
    dotRewrite_logging: {
        type: 'boolean',
        label: 'Enable Logging',
        defaultValue: true,
        helperText: 'Log path rewrites to the console.',
    },
    dotRewrite_paths: {
        type: 'array',
        label: 'Path Prefixes',
        defaultValue: [],
        helperText: 'Off by default. Dot-rewriting only applies to the path prefixes listed here; add at least one to enable it.',
        fields: {
            prefix: { type: 'string', label: 'Prefix', helperText: 'e.g. /files or /public', $width: 3 },
            enabled: { type: 'boolean', label: 'Enabled', defaultValue: true, $width: 2 },
        },
    },
}
