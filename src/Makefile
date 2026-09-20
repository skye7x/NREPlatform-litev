# Built by the OpenWrt package Makefile (cross) or by hand on a PC (native).
CXX      ?= g++
CXXFLAGS ?= -Os
# GCC 7.5 / C++17, no exceptions and no RTTI to keep the binary small.
override CXXFLAGS += -std=gnu++17 -Wall -Wextra -fno-exceptions -fno-rtti \
                     -ffunction-sections -fdata-sections
override LDFLAGS  += -Wl,--gc-sections
LDLIBS   += -luci

OBJS = main.o config.o netlink.o

nreplatformd: $(OBJS)
	$(CXX) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c -o $@ $<

clean:
	rm -f nreplatformd $(OBJS)

.PHONY: clean
