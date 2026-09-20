// NREPlatform LiteV - configuration (/etc/config/nreplatform via libuci)
#pragma once

#include "netlink.hpp"

#include <string>
#include <vector>

namespace nre {

enum Direction { DirEgress, DirIngress, DirBoth };

struct Rule {
    std::string section;
    std::string device;
    Direction   dir = DirBoth;
    NetemParams params;      // already sanitized
};

const char *directionName(Direction d);

// Loads all enabled 'port' sections. Invalid values never abort the load: they are
// clamped/zeroed and described in `warnings`. Returns false only if the file itself
// cannot be read (then `err` is set and `out` is left untouched).
bool loadRules(const std::string &package, const std::string &confdir,
               std::vector<Rule> &out, std::vector<std::string> &warnings,
               std::string &err);

} // namespace nre
