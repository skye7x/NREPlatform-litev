##ROUTER:
``` 
root@SRW-002:~# cat /tmp/sysinfo/model
Linksys WRT160NL
root@SRW-002:~# cat /etc/openwrt_release
DISTRIB_ID='OpenWrt'
DISTRIB_RELEASE='19.07.10'
DISTRIB_REVISION='r11427-9ce6aa9d8d'
DISTRIB_TARGET='ar71xx/generic'
DISTRIB_ARCH='mips_24kc'
DISTRIB_DESCRIPTION='OpenWrt 19.07.10 r11427-9ce6aa9d8d'
DISTRIB_TAINTS=''
root@SRW-002:~# 
``` 

##PC:
``` 
❯ scp -O /home/bartek/Pobrane/openwrt-ar71xx-generic-wrt160nl-squashfs-sysupgrade.bin root@192.168.0.238:/tmp/
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
openwrt-ar71xx-generic-wrt160nl-squashfs-sysupgrade.bin                                         100% 4096KB   1.7MB/s   00:02    
❯ sha256sum /home/bartek/Pobrane/openwrt-ar71xx-generic-wrt160nl-squashfs-sysupgrade.bin
9374de0ff3c9d35c15b82978ccfae2107db89548933e91533438449783a0c70f  /home/bartek/Pobrane/openwrt-ar71xx-generic-wrt160nl-squashfs-sysupgrade.bin
``` 
##ROUTER: (sprawdzenie czy sie nie uszkodzilo)
``` 
sha256sum /tmp/openwrt-ar71xx-generic-wrt160nl-squashfs-sysupgrade.bin 
``` 

##JAK SUMA SIE ZGADZA:
``` 
sysupgrade /tmp/openwrt-ar71xx-generic-wrt160nl-squashfs-sysupgrade.bin
``` 
output:
``` 
Image metadata not found
Saving config files...
Commencing upgrade. Closing all shell sessions.
Connection to 192.168.0.238 closed.

~ 13m 49s
❯ 
``` 
czekamy kilka minut i gdy diodki sie uspokoja:
``` 
   ssh root@xxx.xxx.xxx.xxx
``` 
router juz po wlaczeniu moze jescze wariowac jak pojebany wiec warto poczekac kilka min aby nie rypało sie i nie wypluwał: refused
3. sprawdzamy czy system i moduł działają:
``` 
   cat /etc/openwrt_release
   nreplatformd -n
   cat /var/run/nreplatform.status
   logread -e nreplatformd
``` 
