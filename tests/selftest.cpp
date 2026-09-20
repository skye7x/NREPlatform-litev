// Kernel-free unit test of the netlink message layout and the netem encoding.
// Build natively or for MIPS (big endian) and run; all numbers must match.
//   g++ -std=gnu++17 -I../src selftest.cpp ../src/netlink.cpp -o selftest && ./selftest

#include "netlink.hpp"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include <linux/tc_act/tc_mirred.h>

#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace nre;

static int checks = 0, fails = 0;
#define CHECK(c) do { ++checks; if (!(c)) { ++fails; std::printf("FAIL line %d: %s\n", __LINE__, #c); } } while (0)

// The structures must have the sizes the 4.14 kernel validates against.
static_assert(sizeof(tc_netem_qopt) == 24, "tc_netem_qopt");
static_assert(sizeof(tc_netem_rate) == 16, "tc_netem_rate");
static_assert(sizeof(tc_mirred) == 28, "tc_mirred");
static_assert(sizeof(tc_u32_sel) == 16, "tc_u32_sel");
static_assert(sizeof(tc_u32_key) == 16, "tc_u32_key");
static_assert(sizeof(tcmsg) == 20, "tcmsg");

struct Attr { uint16_t type; const uint8_t *data; size_t len; };

// Walks a list of rtattr, validating length and 4-byte alignment.
static std::vector<Attr> attrs(const uint8_t *p, size_t len) {
    std::vector<Attr> out;
    while (len > 0) {
        if (len < sizeof(rtattr)) { CHECK(!"truncated rtattr"); break; }
        const rtattr *a = reinterpret_cast<const rtattr *>(p);
        if (a->rta_len < RTA_LENGTH(0) || a->rta_len > len) { CHECK(!"bad rta_len"); break; }
        Attr x = { a->rta_type, p + RTA_LENGTH(0), static_cast<size_t>(a->rta_len) - RTA_LENGTH(0) };
        out.push_back(x);
        size_t adv = RTA_ALIGN(a->rta_len);
        if (adv > len) adv = len;
        p += adv;
        len -= adv;
    }
    return out;
}

static const Attr *find(const std::vector<Attr> &v, uint16_t t) {
    for (const Attr &a : v) if (a.type == t) return &a;
    return nullptr;
}

struct Parsed {
    const nlmsghdr *h;
    std::vector<Attr> a;
    tcmsg tc;
};

static Parsed parseTc(const Bytes &m, uint16_t type) {
    Parsed p;
    p.h = reinterpret_cast<const nlmsghdr *>(m.data());
    CHECK(m.size() >= NLMSG_LENGTH(sizeof(tcmsg)));
    CHECK(p.h->nlmsg_len == m.size());
    CHECK(m.size() % 4 == 0);
    CHECK(p.h->nlmsg_type == type);
    std::memcpy(&p.tc, m.data() + NLMSG_HDRLEN, sizeof(tcmsg));
    size_t off = NLMSG_LENGTH(sizeof(tcmsg));
    p.a = attrs(m.data() + off, m.size() - off);
    return p;
}

struct Netem {
    tc_netem_qopt q;
    bool hasRate = false, hasRate64 = false;
    tc_netem_rate rate;
    uint64_t rate64 = 0;
    int unknown = 0;
};

static Netem decodeNetem(const Bytes &m, int ifindex) {
    Netem n;
    std::memset(&n.q, 0, sizeof(n.q));
    std::memset(&n.rate, 0, sizeof(n.rate));
    Parsed p = parseTc(m, RTM_NEWQDISC);
    CHECK(p.h->nlmsg_flags == (NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE));
    CHECK(p.tc.tcm_ifindex == ifindex);
    CHECK(p.tc.tcm_parent == TC_H_ROOT);
    CHECK(p.tc.tcm_handle == 0x00010000u);
    const Attr *kind = find(p.a, TCA_KIND);
    CHECK(kind && std::strcmp(reinterpret_cast<const char *>(kind->data), "netem") == 0);
    const Attr *opt = find(p.a, TCA_OPTIONS);
    CHECK(opt && opt->len >= sizeof(tc_netem_qopt));
    if (!opt || opt->len < sizeof(tc_netem_qopt)) return n;
    std::memcpy(&n.q, opt->data, sizeof(n.q));
    std::vector<Attr> sub = attrs(opt->data + sizeof(tc_netem_qopt), opt->len - sizeof(tc_netem_qopt));
    for (const Attr &a : sub) {
        if (a.type == TCA_NETEM_RATE && a.len == sizeof(tc_netem_rate)) {
            n.hasRate = true;
            std::memcpy(&n.rate, a.data, sizeof(n.rate));
        } else if (a.type == TCA_NETEM_RATE64 && a.len == 8) {
            n.hasRate64 = true;
            std::memcpy(&n.rate64, a.data, 8);
        } else {
            ++n.unknown;   // nothing else may be sent (no LATENCY64/JITTER64 on 4.14)
        }
    }
    return n;
}

static Netem enc(NetemParams p, uint32_t nsPerTick = 64) {
    return decodeNetem(Netlink::buildNetem(3, encodeNetem(p, nsPerTick)), 3);
}

int main() {
    // ---- 1. everything at once (values match what iproute2 sends on 4.14)
    {
        NetemParams p; p.latency_ms = 50; p.jitter_ms = 5; p.loss_pct = 1; p.rate_mbit = 100;
        Netem n = enc(p);
        CHECK(n.q.latency == 781250);     // 50 ms / 64 ns
        CHECK(n.q.jitter == 78125);       // 5 ms / 64 ns
        CHECK(n.q.loss == 42949673u);     // 1 % of 2^32-1
        CHECK(n.q.limit == 1000);
        CHECK(n.q.gap == 0 && n.q.duplicate == 0);
        CHECK(n.hasRate && n.rate.rate == 12500000u && !n.hasRate64);
        CHECK(n.unknown == 0);
    }
    // ---- 2. each feature alone / zero values
    {
        NetemParams p;                               // all zero
        Netem n = enc(p);
        CHECK(n.q.latency == 0 && n.q.jitter == 0 && n.q.loss == 0);
        CHECK(n.hasRate && n.rate.rate == 0 && !n.hasRate64);   // rate=0 -> explicit "unlimited"
        CHECK(!p.any());
    }
    {
        NetemParams p; p.latency_ms = 10;            // jitter=0, loss=0, rate=0
        Netem n = enc(p);
        CHECK(n.q.latency == 156250 && n.q.jitter == 0 && n.q.loss == 0 && n.rate.rate == 0);
        CHECK(p.any());
    }
    {
        NetemParams p; p.loss_pct = 0.5;             // latency=0
        Netem n = enc(p);
        CHECK(n.q.latency == 0 && n.q.loss == 21474836u);
    }
    {
        NetemParams p; p.loss_pct = 100;
        CHECK(enc(p).q.loss == 0xffffffffu);
    }
    {
        NetemParams p; p.rate_mbit = 1;
        Netem n = enc(p);
        CHECK(n.rate.rate == 125000u && n.q.latency == 0);
    }
    // ---- 3. negative / NaN / infinity are neutralised
    {
        NetemParams p; p.latency_ms = -5; p.jitter_ms = -1; p.loss_pct = -3; p.rate_mbit = -100;
        Netem n = enc(p);
        CHECK(n.q.latency == 0 && n.q.jitter == 0 && n.q.loss == 0 && n.rate.rate == 0);
        CHECK(!p.any());
    }
    {
        NetemParams p; p.latency_ms = NAN; p.jitter_ms = NAN; p.loss_pct = NAN; p.rate_mbit = NAN;
        Netem n = enc(p);
        CHECK(n.q.latency == 0 && n.q.jitter == 0 && n.q.loss == 0 && n.rate.rate == 0);
        NetemParams q; q.rate_mbit = -INFINITY; q.loss_pct = INFINITY;
        Netem m = enc(q);
        CHECK(m.rate.rate == 0 && m.q.loss == 0xffffffffu);
    }
    // ---- 4. huge values: clamped, no overflow
    {
        NetemParams p; p.latency_ms = 1e30; p.jitter_ms = 1e30; p.loss_pct = 1e9;
        p.rate_mbit = 1e30; p.queue_pkts = 4000000000u;
        Netem n = enc(p);
        CHECK(n.q.latency == 937500000u);            // 60 s
        CHECK(n.q.jitter == n.q.latency);
        CHECK(n.q.loss == 0xffffffffu);
        CHECK(n.q.limit == 10000);
        CHECK(n.hasRate64 && n.rate64 == 12500000000ull && n.rate.rate == 0xffffffffu);
        CHECK(n.unknown == 0);
        // absurdly slow tick (would overflow 32 bit) saturates instead of wrapping
        NetemParams l; l.latency_ms = 60000;
        CHECK(enc(l, 1).q.latency == 0xffffffffu);
    }
    // ---- 5. jitter rules
    {
        NetemParams p; p.latency_ms = 10; p.jitter_ms = 50;
        Netem n = enc(p);
        CHECK(n.q.jitter == n.q.latency);            // never larger than latency
        NetemParams q; q.jitter_ms = 5;              // jitter without latency
        CHECK(enc(q).q.jitter == 0);
    }
    // ---- 6. tiny non-zero requests never round down to "off"
    {
        NetemParams p; p.latency_ms = 0.00001; p.loss_pct = 1e-12; p.rate_mbit = 1e-9;
        Netem n = enc(p);
        CHECK(n.q.latency == 1 && n.q.loss == 1 && n.rate.rate == 1);
    }
    // ---- 7. queue limit
    {
        NetemParams p; p.latency_ms = 500; p.rate_mbit = 100;
        CHECK(enc(p).q.limit == 4000);               // auto, capped
        NetemParams q; q.latency_ms = 100; q.rate_mbit = 1;
        CHECK(enc(q).q.limit == 1000);               // auto, floor
        NetemParams r; r.latency_ms = 1; r.queue_pkts = 5;
        CHECK(enc(r).q.limit == 16);                 // explicit, raised to minimum
        NetemParams s; s.latency_ms = 1; s.queue_pkts = 1234;
        CHECK(enc(s).q.limit == 1234);
    }
    // ---- 8. tick size comes from /proc/net/psched, not hard-coded
    {
        NetemParams p; p.latency_ms = 50;
        CHECK(enc(p, 1000).q.latency == 50000);
    }
    // ---- 9. ingress qdisc
    {
        Bytes m = Netlink::buildIngressQdisc(9);
        Parsed p = parseTc(m, RTM_NEWQDISC);
        CHECK(p.h->nlmsg_flags == (NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE));
        CHECK(p.tc.tcm_ifindex == 9 && p.tc.tcm_handle == 0xffff0000u && p.tc.tcm_parent == TC_H_INGRESS);
        const Attr *k = find(p.a, TCA_KIND);
        CHECK(k && std::strcmp(reinterpret_cast<const char *>(k->data), "ingress") == 0);
        Parsed d = parseTc(Netlink::buildDelIngress(9), RTM_DELQDISC);
        CHECK(d.tc.tcm_handle == 0xffff0000u && d.tc.tcm_parent == TC_H_INGRESS);
        Parsed r = parseTc(Netlink::buildDelRoot(9), RTM_DELQDISC);
        CHECK(r.tc.tcm_handle == 0 && r.tc.tcm_parent == TC_H_ROOT);
    }
    // ---- 10. u32 match-all + mirred redirect
    {
        Bytes m = Netlink::buildIngressFilter(9, 7);
        Parsed p = parseTc(m, RTM_NEWTFILTER);
        CHECK(p.h->nlmsg_flags == (NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL));
        CHECK(p.tc.tcm_ifindex == 9 && p.tc.tcm_parent == 0xffff0000u && p.tc.tcm_handle == 0);
        CHECK(TC_H_MAJ(p.tc.tcm_info) == (1u << 16));                 // priority 1
        CHECK(TC_H_MIN(p.tc.tcm_info) == htons(0x0003));              // ETH_P_ALL, network order
        const Attr *k = find(p.a, TCA_KIND);
        CHECK(k && std::strcmp(reinterpret_cast<const char *>(k->data), "u32") == 0);
        const Attr *o = find(p.a, TCA_OPTIONS);
        CHECK(o != nullptr);
        if (o) {
            std::vector<Attr> oa = attrs(o->data, o->len);
            const Attr *s = find(oa, TCA_U32_SEL);
            CHECK(s && s->len == sizeof(tc_u32_sel) + sizeof(tc_u32_key));
            if (s && s->len == sizeof(tc_u32_sel) + sizeof(tc_u32_key)) {
                tc_u32_sel sel; tc_u32_key key;
                std::memcpy(&sel, s->data, sizeof(sel));
                std::memcpy(&key, s->data + sizeof(sel), sizeof(key));
                CHECK(sel.nkeys == 1 && sel.flags == TC_U32_TERMINAL);
                CHECK(key.mask == 0 && key.val == 0 && key.off == 0 && key.offmask == 0);
            }
            const Attr *acts = find(oa, TCA_U32_ACT);
            CHECK(acts != nullptr);
            if (acts) {
                std::vector<Attr> aa = attrs(acts->data, acts->len);
                CHECK(aa.size() == 1 && aa[0].type == 1);
                std::vector<Attr> a1 = attrs(aa[0].data, aa[0].len);
                const Attr *ak = find(a1, TCA_ACT_KIND);
                CHECK(ak && std::strcmp(reinterpret_cast<const char *>(ak->data), "mirred") == 0);
                const Attr *ao = find(a1, TCA_ACT_OPTIONS);
                CHECK(ao != nullptr);
                if (ao) {
                    std::vector<Attr> mo = attrs(ao->data, ao->len);
                    const Attr *pm = find(mo, TCA_MIRRED_PARMS);
                    CHECK(pm && pm->len == sizeof(tc_mirred));
                    if (pm && pm->len == sizeof(tc_mirred)) {
                        tc_mirred mir;
                        std::memcpy(&mir, pm->data, sizeof(mir));
                        CHECK(mir.action == TC_ACT_STOLEN);
                        CHECK(mir.eaction == TCA_EGRESS_REDIR);
                        CHECK(mir.ifindex == 7);
                    }
                }
            }
        }
    }
    // ---- 11. ifb link create / up / delete
    {
        Bytes m = Netlink::buildIfbCreate("ifbnre0");
        const nlmsghdr *h = reinterpret_cast<const nlmsghdr *>(m.data());
        CHECK(h->nlmsg_type == RTM_NEWLINK && h->nlmsg_len == m.size() && m.size() % 4 == 0);
        CHECK(h->nlmsg_flags == (NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL));
        size_t off = NLMSG_LENGTH(sizeof(ifinfomsg));
        std::vector<Attr> a = attrs(m.data() + off, m.size() - off);
        const Attr *nm = find(a, IFLA_IFNAME);
        CHECK(nm && std::strcmp(reinterpret_cast<const char *>(nm->data), "ifbnre0") == 0);
        const Attr *li = find(a, IFLA_LINKINFO);
        CHECK(li != nullptr);
        if (li) {
            std::vector<Attr> la = attrs(li->data, li->len);
            const Attr *kd = find(la, IFLA_INFO_KIND);
            CHECK(kd && std::strcmp(reinterpret_cast<const char *>(kd->data), "ifb") == 0);
        }
        Bytes up = Netlink::buildLinkUp(7);
        ifinfomsg i;
        std::memcpy(&i, up.data() + NLMSG_HDRLEN, sizeof(i));
        CHECK(i.ifi_index == 7 && i.ifi_flags == IFF_UP && i.ifi_change == IFF_UP);
        Bytes del = Netlink::buildDelLink(7);
        CHECK(reinterpret_cast<const nlmsghdr *>(del.data())->nlmsg_type == RTM_DELLINK);
    }

    std::printf("%s: %d checks, %d failed\n", fails ? "FAILED" : "PASSED", checks, fails);
    return fails ? 1 : 0;
}
