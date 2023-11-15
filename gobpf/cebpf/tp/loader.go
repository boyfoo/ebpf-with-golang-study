package tp

import (
	"log"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func LoadTp001() {

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalln("failed to remove memlock rlimit", err)
	}

	tcObj := tp_writeObjects{}
	err := loadTp_writeObjects(&tcObj, nil)
	if err != nil {
		log.Fatalln("failed to load tp_writeObjects", err)
	}
	tp, err := link.Tracepoint("syscalls", "sys_enter_openat", tcObj.HandleTp, nil)
	if err != nil {
		log.Fatalln("opening tracepoint", err)

	}
	defer tp.Close()

	time.Sleep(time.Second * 1000)

}
