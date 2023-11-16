package xdp

import (
	"errors"
	"fmt"
	"log"
	"net"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
)

type IpData struct {
	Sip   uint32
	PktSz uint32
}

func LoadXDP() {
	xdpObj := &myxdpObjects{}
	err := loadMyxdpObjects(xdpObj, nil)
	if err != nil {
		log.Fatalln(err)
	}
	defer xdpObj.Close()
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
			ipv4 := net.IPv4(byte(data.Sip), byte(data.Sip>>8), byte(data.Sip>>16), byte(data.Sip>>24))

			fmt.Println("来源ip是：", ipv4.String())
		}

	}
}
