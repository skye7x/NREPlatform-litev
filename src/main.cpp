// nreplatformd - NREPlatform LiteV daemon
//
// Applies per-port latency / jitter / packet loss / speed limits (Linux netem)
// from /etc/config/nreplatform and keeps them applied when interfaces come and go.
//
//   SIGHUP   reload configuration (sent by procd when the UCI file changes)
//   SIGTERM  remove every rule and exit
//
// Options:  -v log to stderr too   -C dir UCI directory   -s file status file
//           -n dry run: print what would be applied and exit (needs no root)

#include "config.hpp"
#include "netlink.hpp"

#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <syslog.h>
#include <unistd.h>

#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <set>
#include <string>
#include <vector>

using namespace nre;

namespace {

const char *kIfbPrefix = "ifbnre";

void logf(int prio, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void logf(int prio, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsyslog(prio, fmt, ap);
    va_end(ap);
}

struct Applied {
    Rule        rule;
    NetemWire   wire;
    bool        egressDone = false;    // we installed a root qdisc on the device
    bool        ingressDone = false;   // we installed ingress qdisc + filter
    int         ifindex = 0;           // device the rule is currently applied to
    int         ifbIndex = 0;
    std::string ifbName;
    std::string state = "waiting";
    bool        blocked = false;       // duplicate rule, never applied
};

bool usesEgress(Direction d)  { return d == DirEgress || d == DirBoth; }
bool usesIngress(Direction d) { return d == DirIngress || d == DirBoth; }

class Engine : public LinkListener {
public:
    Engine(std::string confdir, std::string statusFile)
        : confdir_(std::move(confdir)), statusFile_(std::move(statusFile)) {}

    bool ready() const { return nl_.ok(); }

    void reload() {
        std::vector<Rule> rules;
        std::vector<std::string> warnings;
        std::string err;
        if (!loadRules("nreplatform", confdir_, rules, warnings, err)) {
            // Keep whatever is currently applied rather than dropping all rules.
            logf(LOG_ERR, "cannot read config, keeping current rules: %s", err.c_str());
            return;
        }
        for (const auto &w : warnings) logf(LOG_WARNING, "%s", w.c_str());
        if (rules.size() > 200) {
            logf(LOG_WARNING, "more than 200 rules, extra rules ignored");
            rules.resize(200);
        }

        clearAll();
        const uint32_t nsPerTick = pschedNsPerTick();
        std::set<std::string> usedE, usedI;
        for (size_t i = 0; i < rules.size(); ++i) {
            Applied a;
            a.rule = rules[i];
            a.wire = encodeNetem(a.rule.params, nsPerTick);
            char nm[32];
            std::snprintf(nm, sizeof(nm), "%s%zu", kIfbPrefix, i);
            a.ifbName = nm;

            const std::string &dev = a.rule.device;
            if (usesEgress(a.rule.dir) && !usedE.insert(dev).second) {
                a.blocked = true;
                a.state = "error: duplicate egress rule for " + dev;
            } else if (usesIngress(a.rule.dir) && !usedI.insert(dev).second) {
                a.blocked = true;
                a.state = "error: duplicate ingress rule for " + dev;
            }
            applied_.push_back(std::move(a));
        }
        for (auto &a : applied_) tryApply(a);
        writeStatus();
    }

    void clearAll() {
        for (auto &a : applied_) teardown(a, false);
        applied_.clear();
        writeStatus();
    }

    // LinkListener: an interface appeared, was recreated or disappeared.
    void onLink(const std::string &name, int ifindex, bool removed) override {
        if (name.compare(0, std::strlen(kIfbPrefix), kIfbPrefix) == 0) return;
        bool changed = false;
        for (auto &a : applied_) {
            if (a.blocked || a.rule.device != name) continue;
            if (removed) {
                if (a.ifindex == 0) continue;
                teardown(a, true);
                setState(a, "waiting: device not found");
                changed = true;
            } else if (a.ifindex != ifindex) {
                teardown(a, true);
                tryApply(a);
                changed = true;
            }
        }
        if (changed) writeStatus();
    }

    // Netlink events were lost: re-check every rule.
    void resync() {
        for (auto &a : applied_) {
            if (a.blocked) continue;
            int idx = static_cast<int>(if_nametoindex(a.rule.device.c_str()));
            if (idx != a.ifindex) {
                teardown(a, true);
                tryApply(a);
            }
        }
        writeStatus();
    }

private:
    void setState(Applied &a, const std::string &s) {
        if (a.state == s) return;
        a.state = s;
        logf(LOG_INFO, "%s: %s", a.rule.device.c_str(), s.c_str());
    }

    void fail(Applied &a, const char *what, const char *kmod, int err) {
        std::string msg = std::strerror(-err);
        if (err == -ENOENT || err == -EOPNOTSUPP || err == -EINVAL)
            msg += std::string(" (is ") + kmod + " installed and loaded?)";
        setState(a, std::string("error: ") + what + ": " + msg);
        rollback(a);
    }

    void tryApply(Applied &a) {
        if (a.blocked) return;
        const Rule &r = a.rule;
        if (!r.params.any()) {
            setState(a, "inactive: all values are 0");
            return;
        }
        int idx = static_cast<int>(if_nametoindex(r.device.c_str()));
        if (idx == 0) {
            setState(a, "waiting: device not found");
            return;
        }
        a.ifindex = idx;

        if (usesEgress(r.dir)) {
            int res = nl_.setNetem(idx, a.wire);
            if (res < 0) { fail(a, "egress netem", "kmod-netem", res); return; }
            a.egressDone = true;
        }
        if (usesIngress(r.dir)) {
            int ifb = 0;
            int res = nl_.createIfb(a.ifbName, ifb);
            if (res < 0) { fail(a, "create ifb", "kmod-ifb", res); return; }
            a.ifbIndex = ifb;
            res = nl_.setNetem(ifb, a.wire);
            if (res < 0) { fail(a, "ingress netem", "kmod-netem", res); return; }
            res = nl_.setIngressRedirect(idx, ifb);
            if (res < 0) { fail(a, "ingress redirect", "kmod-sched-core", res); return; }
            a.ingressDone = true;
        }
        setState(a, "active");
    }

    // Undo a partially applied rule after an error.
    void rollback(Applied &a) {
        teardown(a, false);
    }

    // Removes only what this rule installed.
    void teardown(Applied &a, bool deviceGone) {
        if (a.ifindex && !deviceGone) {
            if (a.egressDone)  nl_.clearRoot(a.ifindex);
            if (a.ingressDone) nl_.clearIngress(a.ifindex);
        }
        if (a.ifbIndex) {
            nl_.deleteLink(a.ifbIndex);
            a.ifbIndex = 0;
        }
        a.egressDone = a.ingressDone = false;
        a.ifindex = 0;
    }

    void writeStatus() {
        std::string tmp = statusFile_ + ".tmp";
        FILE *f = std::fopen(tmp.c_str(), "w");
        if (!f) return;
        std::fprintf(f, "nreplatformd running, %zu rule(s), psched %u ns/tick\n",
                     applied_.size(), pschedNsPerTick());
        for (const auto &a : applied_) {
            const NetemParams &p = a.rule.params;
            std::fprintf(f, "%-12s %-34s dir=%s delay=%gms jitter=%gms loss=%g%% rate=%gMbit/s queue=%u\n",
                         a.rule.device.c_str(), a.state.c_str(), directionName(a.rule.dir),
                         p.latency_ms, p.jitter_ms, p.loss_pct, p.rate_mbit, a.wire.limit);
        }
        std::fclose(f);
        std::rename(tmp.c_str(), statusFile_.c_str());
    }

    Netlink nl_;
    std::string confdir_;
    std::string statusFile_;
    std::vector<Applied> applied_;
};

// Remove ifb devices left behind by a crashed previous run.
void removeStaleIfbs() {
    Netlink nl;
    struct if_nameindex *list = if_nameindex();
    if (!list) return;
    for (struct if_nameindex *i = list; i->if_index != 0; ++i)
        if (std::strncmp(i->if_name, kIfbPrefix, std::strlen(kIfbPrefix)) == 0)
            nl.deleteLink(static_cast<int>(i->if_index));
    if_freenameindex(list);
}

int dryRun(const std::string &confdir) {
    std::vector<Rule> rules;
    std::vector<std::string> warnings;
    std::string err;
    if (!loadRules("nreplatform", confdir, rules, warnings, err)) {
        std::fprintf(stderr, "cannot read config: %s\n", err.c_str());
        return 1;
    }
    const uint32_t ns = pschedNsPerTick();
    std::printf("psched: %u ns per tick\n", ns);
    for (const auto &w : warnings) std::printf("warning: %s\n", w.c_str());
    for (const auto &r : rules) {
        NetemWire w = encodeNetem(r.params, ns);
        std::printf("%s dev=%s dir=%s\n", r.section.c_str(), r.device.c_str(),
                    directionName(r.dir));
        std::printf("  latency %gms -> %u ticks | jitter %gms -> %u ticks | loss %g%% -> %u\n",
                    r.params.latency_ms, w.latency, r.params.jitter_ms, w.jitter,
                    r.params.loss_pct, w.loss);
        std::printf("  rate %gMbit/s -> %llu bytes/s | queue %u packets | effect: %s\n",
                    r.params.rate_mbit, static_cast<unsigned long long>(w.rate), w.limit,
                    r.params.any() ? "yes" : "none (all values 0)");
    }
    return 0;
}

void usage(const char *argv0) {
    std::fprintf(stderr,
                 "Usage: %s [-v] [-n] [-C confdir] [-s statusfile]\n"
                 "  -v  log to stderr as well\n"
                 "  -n  dry run: show what would be applied, then exit\n"
                 "  -C  UCI config directory (default /etc/config)\n"
                 "  -s  status file (default /var/run/nreplatform.status)\n",
                 argv0);
}

} // namespace

int main(int argc, char **argv) {
    std::string confdir;
    std::string statusFile = "/var/run/nreplatform.status";
    int logopt = LOG_PID;
    bool dry = false;

    int c;
    while ((c = getopt(argc, argv, "vnC:s:h")) != -1) {
        switch (c) {
        case 'v': logopt |= LOG_PERROR; break;
        case 'n': dry = true; break;
        case 'C': confdir = optarg; break;
        case 's': statusFile = optarg; break;
        default:  usage(argv[0]); return c == 'h' ? 0 : 1;
        }
    }
    if (dry) return dryRun(confdir);

    openlog("nreplatformd", logopt, LOG_DAEMON);

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGHUP);
    sigprocmask(SIG_BLOCK, &mask, nullptr);
    int sfd = signalfd(-1, &mask, SFD_CLOEXEC);
    if (sfd < 0) {
        logf(LOG_ERR, "signalfd: %s", std::strerror(errno));
        return 1;
    }

    removeStaleIfbs();

    Engine engine(confdir, statusFile);
    LinkMonitor monitor;
    if (!engine.ready() || monitor.fd() < 0) {
        logf(LOG_ERR, "cannot open netlink socket (need root / CAP_NET_ADMIN)");
        return 1;
    }

    engine.reload();
    logf(LOG_INFO, "started");

    pollfd fds[2];
    fds[0].fd = sfd;        fds[0].events = POLLIN; fds[0].revents = 0;
    fds[1].fd = monitor.fd(); fds[1].events = POLLIN; fds[1].revents = 0;

    for (;;) {
        if (poll(fds, 2, -1) < 0) {
            if (errno == EINTR) continue;
            logf(LOG_ERR, "poll: %s", std::strerror(errno));
            break;
        }
        if (fds[0].revents & POLLIN) {
            signalfd_siginfo si;
            if (read(sfd, &si, sizeof(si)) == static_cast<ssize_t>(sizeof(si))) {
                if (si.ssi_signo == SIGHUP) {
                    logf(LOG_INFO, "reloading configuration");
                    engine.reload();
                } else {
                    break;
                }
            }
        }
        if (fds[1].revents & POLLIN) {
            if (monitor.dispatch(engine)) engine.resync();
        }
    }

    engine.clearAll();
    std::remove(statusFile.c_str());
    logf(LOG_INFO, "stopped, all rules removed");
    return 0;
}
