// Derived from rejetto/hfs-blocker (GPLv3). Part of security-suite, AGPL-3.0.

function compileHeaderRules(rawArray) {
    const compiled = {}
    const errors = []
    if (rawArray)
        for (const x of rawArray)
            if (x.regexp)
                try { compiled[x.name] = new RegExp(x.regexp, 'i') }
                catch (e) { errors.push(String(e)) }
    return { compiled, errors }
}

function matchHeaders(ctx, compiledRules) {
    for (const [name, regexp] of Object.entries(compiledRules)) {
        const value = ctx.get(name)
        if (regexp.test(value))
            return { name, value }
    }
    return null
}

exports.compileHeaderRules = compileHeaderRules
exports.matchHeaders = matchHeaders

exports.configSchema = {
    headerBlock_headers: {
        type: 'array',
        defaultValue: [{ name: 'User-Agent' }],
        fields: {
            name: { helperText: 'Case-insensitive' },
            regexp: { label: 'Reg.exp.', helperText: 'If the header value matches this reg.exp. (case-insensitive), the request is blocked' },
        },
    },
}
