# nreplatform-litev

C++17 OpenWrt package: `nreplatformd` + LuCI page (Network -> NREPlatform LiteV).

- Talks rtnetlink directly (no `tc` binary needed): netem qdisc for delay / jitter /
  loss / rate, ifb + ingress redirect for the upload direction.
- Reads /etc/config/nreplatform via libuci, reloads on SIGHUP (procd trigger),
  re-applies rules when an interface reappears, removes everything on stop.
- Status: /var/run/nreplatform.status (shown on the LuCI page).

## Build (OpenWrt buildroot / SDK)

    cp -r nreplatform-litev package/
    make menuconfig        # Network -> nreplatform-litev
    make package/nreplatform-litev/compile V=s

## Build on a PC for testing (needs libuci)

    make -C src CPPFLAGS=-I/usr/local/include LDFLAGS=-L/usr/local/lib
