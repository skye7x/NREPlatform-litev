#include "netlink.hpp"

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include <linux/tc_act/tc_mirred.h>

#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstring>

namespace nre {
namespace {

constexpr uint32_t kIngressHandle = 0xffff0000u;   // ffff:
constexpr uint32_t kRootHandle    = 0x00010000u;   // 1:
constexpr uint16_t kEthPAll       = 0x0003;        // ETH_P_ALL
constexpr uint32_t kDefaultNsPerTick = 64;         // PSCHED_SHIFT 6 on 4.14
constexpr uint64_t k2p32          = 4294967296ull;

inline size_t align4(size_t n) { return (n + 3u) & ~size_t(3); }

// Small netlink message builder (no libnl, no allocations besides one vector).
class Msg {
public:
    Msg(uint16_t type, uint16_t flags) : buf_(NLMSG_HDRLEN, 0) {
        nlmsghdr *h = reinterpret_cast<nlmsghdr *>(buf_.data());
        h->nlmsg_type = type;
        h->nlmsg_flags = flags;
    }

    template <class T> void payload(const T &v) { raw(&v, sizeof(v)); }

    void raw(const void *d, size_t n) {
        size_t off = buf_.size();
        buf_.resize(off + align4(n), 0);
        if (n) std::memcpy(buf_.data() + off, d, n);
    }

    void attr(uint16_t type, const void *d, size_t n) {
        size_t off = buf_.size();
        buf_.resize(off + align4(RTA_LENGTH(n)), 0);
        rtattr *a = reinterpret_cast<rtattr *>(buf_.data() + off);
        a->rta_type = type;
        a->rta_len = static_cast<unsigned short>(RTA_LENGTH(n));
        if (n) std::memcpy(buf_.data() + off + RTA_LENGTH(0), d, n);
    }

    void attrStr(uint16_t type, const char *s) { attr(type, s, std::strlen(s) + 1); }
    template <class T> void attrOf(uint16_t type, const T &v) { attr(type, &v, sizeof(v)); }

    size_t nestBegin(uint16_t type) {
        size_t off = buf_.size();
        attr(type, nullptr, 0);
        return off;
    }
    void nestEnd(size_t off) {
        rtattr *a = reinterpret_cast<rtattr *>(buf_.data() + off);
        a->rta_len = static_cast<unsigned short>(buf_.size() - off);
    }

    Bytes finish() {
        nlmsghdr *h = reinterpret_cast<nlmsghdr *>(buf_.data());
        h->nlmsg_len = static_cast<uint32_t>(buf_.size());
        return std::move(buf_);
    }

private:
    Bytes buf_;
};

const uint16_t kReq     = NLM_F_REQUEST | NLM_F_ACK;
const uint16_t kCreate  = kReq | NLM_F_CREATE | NLM_F_EXCL;
const uint16_t kReplace = kReq | NLM_F_CREATE | NLM_F_REPLACE;

tcmsg makeTc(int ifindex, uint32_t handle, uint32_t parent, uint32_t info = 0) {
    tcmsg t;
    std::memset(&t, 0, sizeof(t));
    t.tcm_family = AF_UNSPEC;
    t.tcm_ifindex = ifindex;
    t.tcm_handle = handle;
    t.tcm_parent = parent;
    t.tcm_info = info;
    return t;
}

double clampD(double v, double hi) {
    if (std::isnan(v) || v < 0) return 0;
    return v > hi ? hi : v;
}

uint32_t toTicks(double ms, uint32_t nsPerTick) {
    if (!(ms > 0)) return 0;
    double t = ms * 1e6 / static_cast<double>(nsPerTick);
    if (t >= 4294967295.0) return 0xffffffffu;
    uint32_t r = static_cast<uint32_t>(std::llround(t));
    return r ? r : 1u;   // never round a non-zero request down to "off"
}

} // namespace

// ------------------------------------------------------------ parameters

NetemParams NetemParams::sanitized() const {
    NetemParams s;
    s.latency_ms = clampD(latency_ms, kMaxLatencyMs);
    s.jitter_ms  = clampD(jitter_ms, kMaxLatencyMs);
    s.loss_pct   = clampD(loss_pct, 100.0);
    s.rate_mbit  = clampD(rate_mbit, kMaxRateMbit);
    if (s.latency_ms <= 0) s.jitter_ms = 0;             // jitter needs a base delay
    if (s.jitter_ms > s.latency_ms) s.jitter_ms = s.latency_ms; // no negative delays
    if (queue_pkts == 0) s.queue_pkts = 0;
    else s.queue_pkts = std::min(std::max(queue_pkts, kMinQueue), kMaxQueue);
    return s;
}

bool NetemParams::any() const {
    NetemParams s = sanitized();
    return s.latency_ms > 0 || s.loss_pct > 0 || s.rate_mbit > 0;
}

uint32_t pschedNsPerTick() {
    static uint32_t cached = 0;
    if (cached) return cached;
    uint32_t v = kDefaultNsPerTick;
    if (FILE *f = std::fopen("/proc/net/psched", "r")) {
        unsigned a = 0, b = 0, c = 0, d = 0;
        // Linux 4.14: "%08x %08x %08x %08x" = NSEC_PER_USEC, ns-per-tick, 1e6, hrtimer hz
        if (std::fscanf(f, "%x %x %x %x", &a, &b, &c, &d) == 4 && a == 1000 &&
            b >= 1 && b <= 1000000)
            v = b;
        std::fclose(f);
    }
    cached = v;
    return v;
}

NetemWire encodeNetem(const NetemParams &p, uint32_t nsPerTick) {
    if (nsPerTick == 0) nsPerTick = kDefaultNsPerTick;
    NetemParams s = p.sanitized();
    NetemWire w;

    w.latency = toTicks(s.latency_ms, nsPerTick);
    w.jitter  = s.latency_ms > 0 ? toTicks(s.jitter_ms, nsPerTick) : 0;
    if (w.jitter > w.latency) w.jitter = w.latency;

    if (s.loss_pct > 0) {
        uint64_t l = static_cast<uint64_t>(std::llround(s.loss_pct / 100.0 * 4294967295.0));
        w.loss = l ? static_cast<uint32_t>(std::min<uint64_t>(l, 0xffffffffull)) : 1u;
    }

    if (s.rate_mbit > 0) {
        // 1 Mbit/s = 125000 bytes/s. Unit of tc_netem_rate.rate on 4.14 is bytes/s.
        uint64_t r = static_cast<uint64_t>(std::llround(s.rate_mbit * 125000.0));
        w.rate = r ? r : 1;
    }

    if (s.queue_pkts) {
        w.limit = s.queue_pkts;
    } else {
        // Default like iproute2 (1000 packets), but grow with the bandwidth-delay
        // product so that a long delay does not tail-drop. Capped to protect the
        // few MB of RAM a small router has.
        double pps = s.rate_mbit > 0 ? s.rate_mbit * 1e6 / 8.0 / 1500.0 : 8333.0;
        double est = pps * (s.latency_ms + s.jitter_ms) / 1000.0 + 100.0;
        w.limit = static_cast<uint32_t>(std::min(std::max(est, 1000.0), 4000.0));
    }
    return w;
}

// -------------------------------------------------------- message builders

Bytes Netlink::buildNetem(int ifindex, const NetemWire &w) {
    Msg m(RTM_NEWQDISC, kReplace);
    m.payload(makeTc(ifindex, kRootHandle, TC_H_ROOT));
    m.attrStr(TCA_KIND, "netem");

    // Fill the structure completely BEFORE it is copied into the message.
    tc_netem_qopt qopt;
    std::memset(&qopt, 0, sizeof(qopt));
    qopt.latency = w.latency;   // psched ticks
    qopt.jitter  = w.jitter;    // psched ticks
    qopt.limit   = w.limit;
    qopt.loss    = w.loss;

    // TCA_OPTIONS = struct tc_netem_qopt followed by plain (non-nested) attributes.
    size_t opt = m.nestBegin(TCA_OPTIONS);
    m.payload(qopt);

    // Always sent, even when 0: on a "change" the kernel keeps the old rate if the
    // attribute is missing, so an explicit 0 is what really means "unlimited".
    tc_netem_rate rate;
    std::memset(&rate, 0, sizeof(rate));
    rate.rate = w.rate >= k2p32 ? 0xffffffffu : static_cast<uint32_t>(w.rate);
    m.attrOf(TCA_NETEM_RATE, rate);
    if (w.rate >= k2p32) {
        uint64_t r64 = w.rate;
        m.attrOf(TCA_NETEM_RATE64, r64);
    }
    m.nestEnd(opt);
    return m.finish();
}

Bytes Netlink::buildDelRoot(int ifindex) {
    Msg m(RTM_DELQDISC, kReq);
    m.payload(makeTc(ifindex, 0, TC_H_ROOT));
    return m.finish();
}

Bytes Netlink::buildIngressQdisc(int ifindex) {
    Msg m(RTM_NEWQDISC, kReplace);
    m.payload(makeTc(ifindex, kIngressHandle, TC_H_INGRESS));
    m.attrStr(TCA_KIND, "ingress");
    return m.finish();
}

Bytes Netlink::buildDelIngress(int ifindex) {
    Msg m(RTM_DELQDISC, kReq);
    m.payload(makeTc(ifindex, kIngressHandle, TC_H_INGRESS));
    return m.finish();
}

Bytes Netlink::buildIngressFilter(int ifindex, int ifbIndex) {
    Msg m(RTM_NEWTFILTER, kCreate);
    // tcm_info = prio << 16 | protocol (network byte order, as the kernel expects)
    m.payload(makeTc(ifindex, 0, kIngressHandle,
                     TC_H_MAKE(1u << 16, static_cast<uint32_t>(htons(kEthPAll)))));
    m.attrStr(TCA_KIND, "u32");

    size_t opt = m.nestBegin(TCA_OPTIONS);

    // match-all selector: one key with mask 0 always matches
    tc_u32_sel sel;
    std::memset(&sel, 0, sizeof(sel));
    sel.flags = TC_U32_TERMINAL;
    sel.nkeys = 1;
    tc_u32_key key;
    std::memset(&key, 0, sizeof(key));
    uint8_t selbuf[sizeof(sel) + sizeof(key)];
    std::memcpy(selbuf, &sel, sizeof(sel));
    std::memcpy(selbuf + sizeof(sel), &key, sizeof(key));
    m.attr(TCA_U32_SEL, selbuf, sizeof(selbuf));

    // action 1: mirred egress redirect -> ifb
    size_t acts = m.nestBegin(TCA_U32_ACT);
    size_t act1 = m.nestBegin(1);
    m.attrStr(TCA_ACT_KIND, "mirred");
    size_t aopt = m.nestBegin(TCA_ACT_OPTIONS);
    tc_mirred mir;
    std::memset(&mir, 0, sizeof(mir));
    mir.action  = TC_ACT_STOLEN;
    mir.eaction = TCA_EGRESS_REDIR;
    mir.ifindex = static_cast<__u32>(ifbIndex);
    m.attrOf(TCA_MIRRED_PARMS, mir);
    m.nestEnd(aopt);
    m.nestEnd(act1);
    m.nestEnd(acts);

    m.nestEnd(opt);
    return m.finish();
}

Bytes Netlink::buildIfbCreate(const char *name) {
    Msg m(RTM_NEWLINK, kCreate);
    ifinfomsg i;
    std::memset(&i, 0, sizeof(i));
    i.ifi_family = AF_UNSPEC;
    m.payload(i);
    m.attrStr(IFLA_IFNAME, name);
    size_t li = m.nestBegin(IFLA_LINKINFO);
    m.attrStr(IFLA_INFO_KIND, "ifb");
    m.nestEnd(li);
    return m.finish();
}

Bytes Netlink::buildLinkUp(int ifindex) {
    Msg m(RTM_NEWLINK, kReq);
    ifinfomsg i;
    std::memset(&i, 0, sizeof(i));
    i.ifi_family = AF_UNSPEC;
    i.ifi_index = ifindex;
    i.ifi_flags = IFF_UP;
    i.ifi_change = IFF_UP;
    m.payload(i);
    return m.finish();
}

Bytes Netlink::buildDelLink(int ifindex) {
    Msg m(RTM_DELLINK, kReq);
    ifinfomsg i;
    std::memset(&i, 0, sizeof(i));
    i.ifi_family = AF_UNSPEC;
    i.ifi_index = ifindex;
    m.payload(i);
    return m.finish();
}

// ---------------------------------------------------------------- Netlink

Netlink::Netlink() {
    fd_ = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd_ < 0) return;

    sockaddr_nl sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (::bind(fd_, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)) < 0) {
        ::close(fd_);
        fd_ = -1;
        return;
    }
    timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    ::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

Netlink::~Netlink() {
    if (fd_ >= 0) ::close(fd_);
}

int Netlink::request(Bytes msg) {
    if (fd_ < 0) return -EBADF;

    nlmsghdr *h = reinterpret_cast<nlmsghdr *>(msg.data());
    h->nlmsg_seq = ++seq_;

    sockaddr_nl sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (::sendto(fd_, msg.data(), msg.size(), 0,
                 reinterpret_cast<sockaddr *>(&sa), sizeof(sa)) < 0)
        return -errno;

    uint8_t buf[8192];
    for (;;) {
        ssize_t n = ::recv(fd_, buf, sizeof(buf), 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -errno;
        }
        int len = static_cast<int>(n);
        for (nlmsghdr *r = reinterpret_cast<nlmsghdr *>(buf); NLMSG_OK(r, len);
             r = NLMSG_NEXT(r, len)) {
            if (r->nlmsg_seq != seq_) continue;
            if (r->nlmsg_type == NLMSG_ERROR) {
                if (r->nlmsg_len < NLMSG_LENGTH(sizeof(nlmsgerr))) return -EBADMSG;
                return reinterpret_cast<nlmsgerr *>(NLMSG_DATA(r))->error; // 0 = ACK
            }
            if (r->nlmsg_type == NLMSG_DONE) return 0;
        }
    }
}

int Netlink::setNetem(int ifindex, const NetemWire &w) {
    // Start from a clean root: replacing an existing netem qdisc in place would be a
    // "change" in which options that are not resent (e.g. a previous rate) survive.
    clearRoot(ifindex);
    return request(buildNetem(ifindex, w));
}

int Netlink::clearRoot(int ifindex) { return request(buildDelRoot(ifindex)); }

int Netlink::clearIngress(int ifindex) { return request(buildDelIngress(ifindex)); }

int Netlink::setIngressRedirect(int ifindex, int ifbIndex) {
    clearIngress(ifindex); // never stack duplicate filters
    int r = request(buildIngressQdisc(ifindex));
    if (r < 0) return r;
    return request(buildIngressFilter(ifindex, ifbIndex));
}

int Netlink::createIfb(const std::string &name, int &ifindex) {
    int r = request(buildIfbCreate(name.c_str()));
    if (r < 0 && r != -EEXIST) return r;

    ifindex = static_cast<int>(::if_nametoindex(name.c_str()));
    if (ifindex == 0) return -ENODEV;
    return request(buildLinkUp(ifindex));
}

int Netlink::deleteLink(int ifindex) { return request(buildDelLink(ifindex)); }

// ------------------------------------------------------------ LinkMonitor

LinkMonitor::LinkMonitor() {
    fd_ = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE);
    if (fd_ < 0) return;
    sockaddr_nl sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = RTMGRP_LINK;
    if (::bind(fd_, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)) < 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

LinkMonitor::~LinkMonitor() {
    if (fd_ >= 0) ::close(fd_);
}

bool LinkMonitor::dispatch(LinkListener &l) {
    bool lost = false;
    uint8_t buf[8192];
    for (;;) {
        ssize_t n = ::recv(fd_, buf, sizeof(buf), 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == ENOBUFS) { lost = true; continue; }
            break; // EAGAIN: drained
        }
        int len = static_cast<int>(n);
        for (nlmsghdr *h = reinterpret_cast<nlmsghdr *>(buf); NLMSG_OK(h, len);
             h = NLMSG_NEXT(h, len)) {
            if (h->nlmsg_type != RTM_NEWLINK && h->nlmsg_type != RTM_DELLINK) continue;
            if (h->nlmsg_len < NLMSG_LENGTH(sizeof(ifinfomsg))) continue;
            ifinfomsg *i = reinterpret_cast<ifinfomsg *>(NLMSG_DATA(h));
            int alen = static_cast<int>(IFLA_PAYLOAD(h));
            std::string name;
            for (rtattr *a = IFLA_RTA(i); RTA_OK(a, alen); a = RTA_NEXT(a, alen))
                if (a->rta_type == IFLA_IFNAME)
                    name.assign(static_cast<const char *>(RTA_DATA(a)));
            if (!name.empty())
                l.onLink(name, i->ifi_index, h->nlmsg_type == RTM_DELLINK);
        }
    }
    return lost;
}

} // namespace nre
