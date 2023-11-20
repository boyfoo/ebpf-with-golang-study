package nethelper

import (
	"log"
	"net"

	"github.com/vishvananda/netlink"
)

// 获取所有docker创建的veth网卡
func GetVethList() []*net.Interface {
	lists, err := netlink.LinkList()
	if err != nil {
		log.Fatalln(err)
	}
	ret := make([]*net.Interface, 0)
	for _, link := range lists {
		// 此处判断并不严谨
		if link.Type() == "veth" {
			if iface, err := net.InterfaceByName(link.Attrs().Name); err == nil {
				ret = append(ret, iface)
			}
		}
	}
	return ret
}
