package gotools

import (
	"errors"
	"fmt"
	"log"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
)

type MemInfo struct {
	SIZE uint64
}

func LoadGoTool(execPath string) {
	obj := &gotoolObjects{}
	err := loadGotoolObjects(obj, nil)
	if err != nil {
		panic(err)
	}
	ex, err := link.OpenExecutable(execPath)
	if err != nil {
		log.Fatalln("OpenExecutable", err)
	}
	up, err := ex.Uprobe("runtime.mallocgc", obj.UprobeMallocgc, nil)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println("加载eBPF程序")

	defer up.Close()
	rd, err := ringbuf.NewReader(obj.MemMap)
	if err != nil {
		log.Fatalf("creating event reader: %s", err)
	}
	defer rd.Close()

	fmt.Printf("开始监听 %s 进程，请启动该进程", execPath)
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
			data := (*MemInfo)(unsafe.Pointer(&record.RawSample[0]))
			fmt.Printf("分配了 %d 字节内存\n", data.SIZE)
		}
	}
}
