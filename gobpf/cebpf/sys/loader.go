package sys

import (
	"bytes"
	"errors"
	"log"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
)

// 自定义一个结构体 要和C代码里的结构体字段一样
type Proc struct {
	Pid   uint32
	Pname [256]byte
}

func LoadSys() {
	sysObj := sysObjects{}
	err := loadSysObjects(&sysObj, nil)
	if err != nil {
		log.Fatalln("failed to load loadSysObjects", err)
	}
	tp, err := link.Tracepoint("syscalls", "sys_exit_execve", sysObj.Handle, nil)
	if err != nil {
		log.Fatalln("opening tracepoint", err)

	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(sysObj.ProcMap)
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
			data := (*Proc)(unsafe.Pointer(&record.RawSample[0]))
			b := bytes.TrimRight(data.Pname[:], "\x00")
			str := string(b)
			log.Println("进程名:", str, data.Pid)
		} else {
			log.Println("Record:", string(record.RawSample))
		}
	}

}
