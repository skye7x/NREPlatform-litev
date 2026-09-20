#
# NREPlatform LiteV - OpenWrt 19.07 package (nreplatformd + LuCI page)
#
include $(TOPDIR)/rules.mk

PKG_NAME:=nreplatform-litev
PKG_VERSION:=1.1.0
PKG_RELEASE:=1

PKG_LICENSE:=Apache-2.0
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/nreplatform-litev
  SECTION:=net
  CATEGORY:=Network
  TITLE:=NREPlatform LiteV - per-port latency, jitter, loss and speed limit
  # Real run-time needs only (checked against the 19.07.10 tree):
  #   libstdcpp        C++ runtime of the daemon
  #   libuci           /etc/config/nreplatform
  #   kmod-sched-core  sch_ingress, cls_u32, act_mirred  (ingress redirect)
  #   kmod-netem       sch_netem (depends on kmod-sched itself)
  #   kmod-ifb         ifb.ko (upload direction)
  # luci-base is intentionally NOT a hard dependency: it lives in the separate
  # "luci" feed, which is what produced the "dependency on 'luci-base', which
  # does not exist" warning. The LuCI page is only static files.
  DEPENDS:=+libstdcpp +libuci +kmod-sched-core +kmod-netem +kmod-ifb
endef

define Package/nreplatform-litev/description
  C++ daemon (nreplatformd) that applies latency, jitter, packet loss and a
  maximum speed to individual interfaces with netem over rtnetlink, plus a
  LuCI page (Network -> NREPlatform LiteV) when LuCI 19.07 is installed.
  Targets Linux 4.14: no libnl, no tc binary, no post-4.14 kernel UAPI.
endef

define Package/nreplatform-litev/conffiles
/etc/config/nreplatform
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		$(TARGET_CONFIGURE_OPTS) \
		CXXFLAGS="$(TARGET_CXXFLAGS)" \
		CPPFLAGS="$(TARGET_CPPFLAGS)" \
		LDFLAGS="$(TARGET_LDFLAGS)"
endef

define Package/nreplatform-litev/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/nreplatformd $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/nreplatform.init $(1)/etc/init.d/nreplatform
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/nreplatform.config $(1)/etc/config/nreplatform
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/90_nreplatform $(1)/etc/uci-defaults/90_nreplatform
	$(INSTALL_DIR) $(1)/usr/share/luci/menu.d
	$(INSTALL_DATA) ./files/menu.json $(1)/usr/share/luci/menu.d/nreplatform-litev.json
	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d
	$(INSTALL_DATA) ./files/acl.json $(1)/usr/share/rpcd/acl.d/nreplatform-litev.json
	$(INSTALL_DIR) $(1)/www/luci-static/resources/view/nreplatform
	$(INSTALL_DATA) ./files/ports.js $(1)/www/luci-static/resources/view/nreplatform/ports.js
endef

$(eval $(call BuildPackage,nreplatform-litev))
