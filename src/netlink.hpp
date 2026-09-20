// NREPlatform LiteV - minimal rtnetlink layer for Linux 4.14 (OpenWrt 19.07)
//
// Only UAPI that exists in Linux 4.14.275 is used:
//   * netem is configured through the legacy struct tc_netem_qopt, where
//     latency/jitter are expressed in PSCHED TICKS (1 tick = 64 ns on 4.14),
//     NOT in microseconds and NOT in the 64-bit TCA_NETEM_LATENCY64 attribute
//     (that one appeared in Linux 4.15+).
//   * rate uses TCA_NETEM_RATE (bytes/s), TCA_NETEM_RATE64 only above 4 GB/s.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace nre {

constexpr double   kMaxLatencyMs = 60000.0;   // 60 s  (kernel limit is ~275 s)
constexpr double   kMaxRateMbit  = 100000.0;  // 100 Gbit/s
constexpr uint32_t kMinQueue     = 16;        // packets
constexpr uint32_t kMaxQueue     = 10000;     // packets

struct NetemParams {
    double   latency_ms = 0;   // added delay
    double   jitter_ms  = 0;   // +/- delay variation (needs latency > 0)
    double   loss_pct   = 0;   // random packet loss 0..100
    double   rate_mbit  = 0;   // max speed in Mbit/s, 0 = unlimited
    uint32_t queue_pkts = 0;   // netem queue limit, 0 = automatic

    // Returns a copy where NaN/negative values became 0, everything is clamped
    // to the supported range and jitter <= latency.
    NetemParams sanitized() const;
    bool any() const;          // would this change traffic at all?
};

// Values exactly as the 4.14 kernel expects them.
struct NetemWire {
    uint32_t latency = 0;   // psched ticks
    uint32_t jitter  = 0;   // psched ticks
    uint32_t loss    = 0;   // 0 = none, 0xFFFFFFFF = 100 %
    uint32_t limit   = 1000;// packets
    uint64_t rate    = 0;   // bytes per second, 0 = unlimited
};

// Nanoseconds per psched tick, read from /proc/net/psched (64 on Linux 4.14).
uint32_t pschedNsPerTick();
NetemWire encodeNetem(const NetemParams &p, uint32_t nsPerTick);

typedef std::vector<uint8_t> Bytes;

// All methods return 0 on success or a negative errno value.
class Netlink {
public:
    Netlink();
    ~Netlink();
    Netlink(const Netlink &) = delete;
    Netlink &operator=(const Netlink &) = delete;

    bool ok() const { return fd_ >= 0; }

    int setNetem(int ifindex, const NetemWire &w);         // replaces root qdisc
    int clearRoot(int ifindex);
    int setIngressRedirect(int ifindex, int ifbIndex);     // ingress qdisc + u32 + mirred
    int clearIngress(int ifindex);
    int createIfb(const std::string &name, int &ifindex);  // creates and brings up
    int deleteLink(int ifindex);

    // Message builders are public so they can be unit-tested without a kernel.
    static Bytes buildNetem(int ifindex, const NetemWire &w);
    static Bytes buildDelRoot(int ifindex);
    static Bytes buildIngressQdisc(int ifindex);
    static Bytes buildDelIngress(int ifindex);
    static Bytes buildIngressFilter(int ifindex, int ifbIndex);
    static Bytes buildIfbCreate(const char *name);
    static Bytes buildLinkUp(int ifindex);
    static Bytes buildDelLink(int ifindex);

private:
    int request(Bytes msg);
    int fd_ = -1;
    uint32_t seq_ = 0;
};

class LinkListener {
public:
    virtual ~LinkListener() {}
    virtual void onLink(const std::string &name, int ifindex, bool removed) = 0;
};

// Receives RTM_NEWLINK / RTM_DELLINK notifications.
class LinkMonitor {
public:
    LinkMonitor();
    ~LinkMonitor();
    LinkMonitor(const LinkMonitor &) = delete;
    LinkMonitor &operator=(const LinkMonitor &) = delete;

    int fd() const { return fd_; }
    // Returns true if notifications were lost (caller should resynchronise).
    bool dispatch(LinkListener &l);

private:
    int fd_ = -1;
};

} // namespace nre
