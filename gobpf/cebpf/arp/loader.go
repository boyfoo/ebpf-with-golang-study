package arp

import (
	"fmt"
	"gobpf/pkg/heloers/nethelper"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
)

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

	fmt.Println("开始监听")
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	<-signalChan
	fmt.Println("退出")
}
