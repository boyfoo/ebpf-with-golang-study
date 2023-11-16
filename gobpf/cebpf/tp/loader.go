package tp

import (
	"bytes"
	"errors"
	"log"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// 自定义一个结构体 要和C代码里的结构体字段一样
type MyDataT struct {
	Pid  uint32
	Comm [256]byte
}

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

	rd, err := ringbuf.NewReader(tcObj.LogMap)
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

		if len(record.RawSample) > 0 {
			data := (*MyDataT)(unsafe.Pointer(&record.RawSample[0]))
			b := bytes.TrimRight(data.Comm[:], "\x00")
			str := string(b)
			if str == "testwrite" {
				log.Println("进程名:", str)
			}
		} else {
			log.Println("Record:", string(record.RawSample))
		}
	}

}
