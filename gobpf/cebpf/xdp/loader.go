package xdp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
)

type IpData struct {
	Sip   uint32
	Dip   uint32
	PktSz uint32
	III   uint32
	Sport uint16
	Dport uint16
}

func LoadXDP() {
	xdpObj := &myxdpObjects{}
	err := loadMyxdpObjects(xdpObj, nil)
	if err != nil {
		log.Fatalln(err)
	}
	defer xdpObj.Close()

	// 初始化白名单
	initAllowMap(xdpObj.AllowIpsMap)

	iface, err := net.InterfaceByName("docker0")
	if err != nil {
		log.Fatalln(err)
	}
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   xdpObj.MyPass,
		Interface: iface.Index, // 哪个网卡
	})
	if err != nil {
		log.Fatalln(err)
	}
	defer l.Close()
	rd, err := ringbuf.NewReader(xdpObj.IpMap)
	if err != nil {
		log.Fatalln(err)
	}
	defer rd.Close()
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				log.Fatalln("perf reader closed", err)
				return
			}
			log.Fatalln("reading perf event", err)
			continue
		}

		if len(record.RawSample) > 0 {

			data := (*IpData)(unsafe.Pointer(&record.RawSample[0]))
			// sipv4 := net.IPv4(byte(data.Sip), byte(data.Sip>>8), byte(data.Sip>>16), byte(data.Sip>>24))
			// dipv4 := net.IPv4(byte(data.Dip), byte(data.Dip>>8), byte(data.Dip>>16), byte(data.Dip>>24))
			sipv4 := resolveIP(data.Sip, true)
			dipv4 := resolveIP(data.Dip, true)

			fmt.Printf("来源ip是：%s\n", sipv4.String())
			fmt.Printf("目的ip是：%s\n", dipv4.String())
			fmt.Printf("网卡index%d\n", data.III)
			fmt.Printf("来源端口%d\n", data.Sport)
			fmt.Printf("目的端口%d\n", data.Dport)
		}

	}
}

func resolveIP(input_ip uint32, isbig bool) net.IP {
	ipNetworkOrder := make([]byte, 4)
	if isbig {
		binary.BigEndian.PutUint32(ipNetworkOrder, input_ip)
	} else {
		binary.LittleEndian.PutUint32(ipNetworkOrder, input_ip)
	}

	return ipNetworkOrder
}

func initAllowMap(m *ebpf.Map) {
	ip1 := binary.BigEndian.Uint32(net.ParseIP("172.17.0.2").To4())
	// 类型要和bpf.c类型相等
	err := m.Put(ip1 , uint8(1))
	if err != nil {
		fmt.Println("设置白名单错误", err)
	}
}
