# nreplatform-litev  (OpenWrt 19.07.10, Linux 4.14.275, mips_24kc, musl, GCC 7.5)

C++17 daemon `nreplatformd` + LuCI page (Network -> NREPlatform LiteV).
Direct rtnetlink (no libnl, no tc binary). Only UAPI present in Linux 4.14 is used.

## Build (buildroot 19.07.10)
    cp -r nreplatform-litev  <buildroot>/package/
    ./scripts/feeds update -a && ./scripts/feeds install -a     # for LuCI in the image
    make menuconfig      # Network -> nreplatform-litev  (selects kmod-netem, kmod-sched, kmod-sched-core, kmod-ifb)
    make package/nreplatform-litev/compile V=s

## Host tests (no kernel needed)
    cd tests && g++ -std=gnu++17 -I../src selftest.cpp ../src/netlink.cpp -o selftest && ./selftest

## On the router
    nreplatformd -n            # dry run: shows ticks / bytes/s that would be sent
    cat /var/run/nreplatform.status
    logread -e nreplatformd
