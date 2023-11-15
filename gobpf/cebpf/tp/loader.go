package tp

import (
	"errors"
	"log"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
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

	rd, err := perf.NewReader(tcObj.LogMap, os.Getpagesize())
	if err != nil {
		log.Fatalln("opening perf event reader", err)
	}

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

		log.Println("Record:",string(record.RawSample))

	}

}
