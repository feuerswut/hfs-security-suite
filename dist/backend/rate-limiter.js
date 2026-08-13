// Derived from rejetto/antidos (GPLv3). Part of security-suite, AGPL-3.0.
'use strict'

exports.configSchema = {
    rateLimit_max: {
        type: 'number', label: "Max requests", defaultValue: 500, min: 0, xs: 6,
    },
    rateLimit_seconds: {
        type: 'number', label: "Time window", defaultValue: 5, min: 1, xs: 6,
        unit: "seconds", helperText: "Limit in time",
    },
    rateLimit_banSeconds: {
        type: 'number', label: "Ban for", defaultValue: 0, min: 0, xs: 6,
        unit: "seconds", helperText: "0 = infinite",
    },
    rateLimit_whitelist: {
        type: 'string', label: "Whitelist", multiline: true,
        helperText: "one ip per line; masks are supported",
    },
    rateLimit_errors: {
        type: 'string', label: "Consider only errors",
        placeholder: "no, consider all requests",
        helperText: "you can specify HTTP error codes separated by | (pipe), and only those will be counted, or use * for all",
    },
}

function globToRegExp(pattern) {
    return new RegExp('^' + pattern.split('*').map(s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('.*') + '$')
}

function fallbackMatches(value, patterns) {
    return patterns.split('|').some(p => {
        p = p.trim()
        return p && globToRegExp(p).test(value)
    })
}

function createRateLimiter(api, ipStore) {
    const misc = (() => { try { return api.require('./misc') } catch (_) { return {} } })()
    const isLocalHost = typeof misc.isLocalHost === 'function' ? misc.isLocalHost : () => false
    const matches = (v, p) =>
        (api.misc && typeof api.misc.matches === 'function') ? api.misc.matches(v, p) : fallbackMatches(v, p)

    const reqsByIp = new Map()

    let isWhiteListed = () => false
    const unsubscribe = api.subscribeConfig('rateLimit_whitelist', v => {
        const entries = String(v || '').split('\n').map(x => x.trim()).filter(Boolean)
        if (!entries.length) { isWhiteListed = () => false; return }
        if (typeof misc.makeNetMatcher === 'function') {
            const m = misc.makeNetMatcher(entries.map(x => `(${x})`).join('|'))
            isWhiteListed = ip => { try { return !!m(ip) } catch (_) { return false } }
        } else {
            const res = entries.map(globToRegExp)
            isWhiteListed = ip => res.some(r => r.test(ip))
        }
    })

    const timer = setInterval(() => {
        const cutoff = Date.now() - api.getConfig('rateLimit_seconds') * 1000
        for (const [ip, reqs] of reqsByIp.entries()) {
            let n = 0
            while (n < reqs.length && reqs[n] < cutoff) n++
            if (!n) continue
            reqs.splice(0, n)
            if (!reqs.length) reqsByIp.delete(ip)
        }
    }, 1000)
    if (timer.unref) timer.unref()

    // false = exempt, true = already banned, undefined = eligible for counting
    function banState(ip) {
        if (isLocalHost(ip) || isWhiteListed(ip)) return false
        if (ipStore.isDynamicallyBanned(ip)) return true
        return undefined
    }

    return {
        // Call from the UPSTREAM (post-response) phase, i.e. middleware: ctx => () => recordRequest(ctx),
        // because the "consider only errors" filter needs the final ctx.status.
        recordRequest(ctx) {
            const { ip } = ctx
            const state = banState(ip)
            if (state === false) return

            const errors = (api.getConfig('rateLimit_errors') || '').trim()
            if (errors === '*' && ctx.status < 400) return
            if (errors && !matches(String(ctx.status), errors)) return

            if (state === undefined) {
                let a = reqsByIp.get(ip)
                if (!a) reqsByIp.set(ip, a = [])
                a.push(Date.now())
                if (a.length <= api.getConfig('rateLimit_max')) return
                reqsByIp.delete(ip)
                ipStore.addDynamicBan(ip, (api.getConfig('rateLimit_banSeconds') || 0) * 1000)
            }

            // Already over the limit: cut the current response short too, don't just
            // rely on newSocket catching the next connection.
            ctx.socket.destroy()
            return ctx.stop()
        },

        unload() {
            clearInterval(timer)
            if (typeof unsubscribe === 'function') unsubscribe()
            reqsByIp.clear()
        },
    }
}

exports.createRateLimiter = createRateLimiter
