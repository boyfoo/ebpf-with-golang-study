package arp

import (
	"encoding/hex"
	"errors"
	"fmt"
	"gobpf/pkg/heloers/nethelper"
	"log"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
)

type ArpData struct {
	SMAC [6]byte
	SIP  uint32
	DIP  uint32
	OP   uint16
}

func LoadArp() {
	obj := &myarpObjects{}
	err := loadMyarpObjects(obj, nil)
	if err != nil {
		panic(err)
	}

	defer obj.Close()

	go func() {
		set := make(map[string]bool)
		for {
			ifaces := nethelper.GetVethList()
			for _, iface := range ifaces {
				if _, ok := set[iface.Name]; ok {
					continue
				}
				l, err := link.AttachXDP(link.XDPOptions{
					Program:   obj.Myarp,
					Interface: iface.Index,
				})
				if err != nil {
					log.Println(err)
				} else {
					set[iface.Name] = true
				}
				defer l.Close()
			}
			time.Sleep(time.Millisecond * 50)
		}
	}()

	rd, err := ringbuf.NewReader(obj.ArpMap)
	if err != nil {
		log.Fatalf("creating event reader: %s", err)
	}
	defer rd.Close()

	fmt.Println("开始ARP监听")

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
			data := (*ArpData)(unsafe.Pointer(&record.RawSample[0]))
			macStr := hex.EncodeToString(data.SMAC[:])
			sip := nethelper.ResolveIP(data.SIP, true)
			dip := nethelper.ResolveIP(data.DIP, true)
			if data.OP == 1 {
				fmt.Printf("%s(%s)问: 谁是%s?\n",
					sip, macStr, dip,
				)
			} else {
				fmt.Printf("%s回答%s：我是,mac=%s\n",
					sip, dip, macStr,
				)
			}
		}
	}

	// fmt.Println("开始监听")
	// signalChan := make(chan os.Signal, 1)
	// signal.Notify(signalChan, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	// <-signalChan
	// fmt.Println("退出")
}
