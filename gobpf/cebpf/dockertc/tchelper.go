package dockertc

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// 加载tc ebpf程序
func MakeTc(ifaceName string) {
	iface, err := netlink.LinkByName(ifaceName)
	if err != nil {
		log.Fatalln(1, err)
	}
	filteratts := netlink.FilterAttrs{
		LinkIndex: iface.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_INGRESS, // 入口
		Handle:    netlink.MakeHandle(0, 1),   //默认交互句柄
		Protocol:  unix.ETH_P_ALL,
		Priority:  1,
	}
	attrs := netlink.QdiscAttrs{
		LinkIndex: iface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT, // ebpf 特殊的 qdisc
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}

	//等同于执行了 tc qdisc add dev docker0 clsact
	if err := netlink.QdiscAdd(qdisc); err != nil {
		log.Fatalln(err)
	}

	defer func() {
		if err := netlink.QdiscDel(qdisc); err != nil {
			fmt.Println("qdiscDel err: ", err.Error())
		}
	}()

	objs := &dockertcObjects{}
	err = loadDockertcObjects(objs, nil)
	if err != nil {
		log.Fatalln(2, err)
	}

	filter := netlink.BpfFilter{
		FilterAttrs:  filteratts,
		Fd:           objs.Mytc.FD(),
		Name:         "mytc",
		DirectAction: true,
	}
	// 等同于 tc filter add dev docker0 ingress bpf direct-action obj dockertc_bpfel_x86_64.o
	if err := netlink.FilterAdd(&filter); err != nil {
		log.Fatalln(2, err)
	}
	defer func() {
		// 等同于 tc qdisc del dev docker0 clsact
		if err := netlink.FilterDel(&filter); err != nil {
			fmt.Println("filterDel err: ", err.Error())
		}
	}()
	fmt.Println("开始监听")
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	<-signalChan
	fmt.Println("退出")
}
