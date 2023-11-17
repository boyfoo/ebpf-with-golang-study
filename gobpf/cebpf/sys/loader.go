package sys

import (
	"bytes"
	"errors"
	"log"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
)

// 自定义一个结构体 要和C代码里的结构体字段一样
// 顺序必须和C字段顺序一样
type Proc struct {
	Pid   uint32
	PPid  uint32
	Pname [256]byte
}

func LoadSwich() {
	sysObj := sysObjects{}
	err := loadSysObjects(&sysObj, nil)
	if err != nil {
		log.Fatalln("装载出错", err)
	}
	//通过 cat /sys/kernel/debug/tracing/available_filter_functions| grep finish_task_switch 查看名称
	tp, err := link.Kprobe("finish_task_switch.isra.0", sysObj.FinishTaskSwitch, nil)
	if err != nil {
		log.Fatalln("opening finish_task_switch", err)
	}
	defer tp.Close()

	for {
		time.Sleep(time.Second * 2)
	}
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
			log.Printf(" 进程名: %s, 进程id: %d, 父id: %d \n", str, data.Pid, data.PPid)
		}
	}

}
