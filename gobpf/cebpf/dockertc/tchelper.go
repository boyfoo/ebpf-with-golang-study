package dockertc

import (
	"errors"
	"fmt"
	"gobpf/pkg/heloers/nethelper"
	"log"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type TcData struct {
	SrcIp uint32
	DstIp uint32
	Sport uint16
	Dport uint16
}

// 加载tc ebpf程序
func MakeTc(ifaceName string) error {
	iface, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return err
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
		return err
	}

	defer func() {
		if err := netlink.QdiscDel(qdisc); err != nil {
			fmt.Println("qdiscDel err: ", err.Error())
		}
	}()

	objs := &dockertcObjects{}
	err = loadDockertcObjects(objs, nil)
	if err != nil {
		return err
	}

	filter := netlink.BpfFilter{
		FilterAttrs:  filteratts,
		Fd:           objs.Mytc.FD(),
		Name:         "mytc",
		DirectAction: true,
	}
	// 等同于 tc filter add dev docker0 ingress bpf direct-action obj dockertc_bpfel_x86_64.o
	if err := netlink.FilterAdd(&filter); err != nil {
		return err
	}
	defer func() {
		// 等同于 tc qdisc del dev docker0 clsact
		if err := netlink.FilterDel(&filter); err != nil {
			fmt.Println("filterDel err: ", err.Error())
		}
	}()

	rd, err := ringbuf.NewReader(objs.TcMap)
	if err != nil {
		return err
	}
	defer rd.Close()

	go func() {
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

				data := (*TcData)(unsafe.Pointer(&record.RawSample[0]))
				ipAddr1 := nethelper.ResolveIP(data.SrcIp, true)
				ipAddr2 := nethelper.ResolveIP(data.DstIp, true)
				fmt.Printf("来源IP:%s:%d---->目标IP:%s:%d\n",
					ipAddr1.To4().String(), data.Sport,
					ipAddr2.To4().String(), data.Dport,
				)
			}
		}
	}()

	fmt.Println("开始监听")
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	<-signalChan
	fmt.Println("退出")
	return nil
}
