#include "config.hpp"

#include <uci.h>

#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <net/if.h>

namespace nre {
namespace {

std::string fmt(const char *f, const char *a, const char *b = "", const char *c = "") {
    char buf[192];
    std::snprintf(buf, sizeof(buf), f, a, b, c);
    return buf;
}

// Reads a non-negative decimal. Missing -> 0. Junk/NaN/negative -> 0 (+warning).
// Too large -> clamped to `hi` (+warning).
double number(uci_context *ctx, uci_section *s, const char *name, double hi,
              const std::string &rule, std::vector<std::string> &warn) {
    const char *v = uci_lookup_option_string(ctx, s, name);
    if (!v || !*v) return 0;

    char *end = nullptr;
    errno = 0;
    double d = std::strtod(v, &end);
    if (end == v || *end != '\0' || std::isnan(d)) {
        warn.push_back(fmt("rule %s: %s='%s' is not a number, using 0", rule.c_str(), name, v));
        return 0;
    }
    if (d < 0) {
        warn.push_back(fmt("rule %s: %s='%s' is negative, using 0", rule.c_str(), name, v));
        return 0;
    }
    if (d > hi) {
        warn.push_back(fmt("rule %s: %s='%s' is too large, limited", rule.c_str(), name, v));
        return hi;
    }
    return d;
}

bool truthy(const char *v) {
    if (!v) return true; // default enabled
    return !(std::strcmp(v, "0") == 0 || std::strcmp(v, "false") == 0 ||
             std::strcmp(v, "off") == 0 || std::strcmp(v, "no") == 0 ||
             std::strcmp(v, "disabled") == 0);
}

} // namespace

const char *directionName(Direction d) {
    switch (d) {
    case DirEgress:  return "egress";
    case DirIngress: return "ingress";
    default:         return "both";
    }
}

bool loadRules(const std::string &package, const std::string &confdir,
               std::vector<Rule> &out, std::vector<std::string> &warnings,
               std::string &err) {
    uci_context *ctx = uci_alloc_context();
    if (!ctx) {
        err = "out of memory";
        return false;
    }
    if (!confdir.empty()) uci_set_confdir(ctx, confdir.c_str());

    uci_package *pkg = nullptr;
    if (uci_load(ctx, package.c_str(), &pkg) != UCI_OK || !pkg) {
        char *msg = nullptr;
        uci_get_errorstr(ctx, &msg, package.c_str());
        err = msg ? msg : "cannot load config";
        std::free(msg);
        uci_free_context(ctx);
        return false;
    }

    std::vector<Rule> rules;
    uci_element *e;
    uci_foreach_element(&pkg->sections, e) {
        uci_section *s = uci_to_section(e);
        if (std::strcmp(s->type, "port") != 0) continue;
        if (!truthy(uci_lookup_option_string(ctx, s, "enabled"))) continue;

        Rule r;
        r.section = s->e.name ? s->e.name : "?";

        const char *dev = uci_lookup_option_string(ctx, s, "device");
        if (!dev || !*dev) {
            warnings.push_back(fmt("rule %s: no device set, skipped", r.section.c_str(), ""));
            continue;
        }
        if (std::strlen(dev) >= IF_NAMESIZE) {
            warnings.push_back(fmt("rule %s: device name too long, skipped", r.section.c_str(), ""));
            continue;
        }
        r.device = dev;

        const char *dir = uci_lookup_option_string(ctx, s, "direction");
        if (!dir || std::strcmp(dir, "both") == 0)         r.dir = DirBoth;
        else if (std::strcmp(dir, "egress") == 0)          r.dir = DirEgress;
        else if (std::strcmp(dir, "ingress") == 0)         r.dir = DirIngress;
        else {
            warnings.push_back(fmt("rule %s: unknown direction '%s', using both",
                                   r.section.c_str(), dir));
            r.dir = DirBoth;
        }

        NetemParams p;
        p.latency_ms = number(ctx, s, "latency", kMaxLatencyMs, r.section, warnings);
        p.jitter_ms  = number(ctx, s, "jitter",  kMaxLatencyMs, r.section, warnings);
        p.loss_pct   = number(ctx, s, "loss",    100.0,         r.section, warnings);
        p.rate_mbit  = number(ctx, s, "rate",    kMaxRateMbit,  r.section, warnings);
        p.queue_pkts = static_cast<uint32_t>(
            number(ctx, s, "queue", static_cast<double>(kMaxQueue), r.section, warnings));
        if (p.jitter_ms > p.latency_ms)
            warnings.push_back(fmt("rule %s: jitter is larger than latency, limited to latency",
                                   r.section.c_str(), ""));
        r.params = p.sanitized();
        rules.push_back(std::move(r));
    }

    uci_unload(ctx, pkg);
    uci_free_context(ctx);
    out.swap(rules);
    return true;
}

} // namespace nre
