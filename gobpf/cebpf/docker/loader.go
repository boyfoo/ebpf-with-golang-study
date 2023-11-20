package docker

import (
	"errors"
	"fmt"
	"gobpf/pkg/heloers/nethelper"
	"log"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
)

type IpData struct {
	SIP     uint32
	DIP     uint32
	Sport   uint16
	Dport   uint16
	PayLoad [1024]byte
}

func LoadDockerXdp() {
	obj := &dockerxdpObjects{}
	err := loadDockerxdpObjects(obj, nil)
	if err != nil {
		panic(err)
	}

	defer obj.Close()
	ifaces := nethelper.GetVethList()
	for _, iface := range ifaces {
		l, err := link.AttachXDP(link.XDPOptions{
			Program:   obj.Mydocker,
			Interface: iface.Index,
		})
		if err != nil {
			panic(err)
		}
		defer l.Close()
	}
	rd, err := ringbuf.NewReader(obj.IpMap)
	if err != nil {
		log.Fatalf("creating event reader: %s", err)
	}
	defer rd.Close()

	fmt.Println("开始监听xdp")
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		if len(record.RawSample) > 0 {
			data := (*IpData)(unsafe.Pointer(&record.RawSample[0]))

			ipAddr1 := nethelper.ResolveIP(data.SIP, true)
			ipAddr2 := nethelper.ResolveIP(data.DIP, true)
			fmt.Printf("来源IP:%s---->目标IP:%s\n",
				ipAddr1.To4().String(),
				ipAddr2.To4().String(),
			)
		}
	}
}
