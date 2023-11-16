// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || amd64p32 || arm || arm64 || loong64 || mips64le || mips64p32le || mipsle || ppc64le || riscv64

package xdp

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadMyxdp returns the embedded CollectionSpec for myxdp.
func loadMyxdp() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_MyxdpBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load myxdp: %w", err)
	}

	return spec, err
}

// loadMyxdpObjects loads myxdp and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*myxdpObjects
//	*myxdpPrograms
//	*myxdpMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadMyxdpObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadMyxdp()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// myxdpSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type myxdpSpecs struct {
	myxdpProgramSpecs
	myxdpMapSpecs
}

// myxdpSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type myxdpProgramSpecs struct {
	MyPass *ebpf.ProgramSpec `ebpf:"my_pass"`
}

// myxdpMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type myxdpMapSpecs struct {
	IpMap *ebpf.MapSpec `ebpf:"ip_map"`
}

// myxdpObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadMyxdpObjects or ebpf.CollectionSpec.LoadAndAssign.
type myxdpObjects struct {
	myxdpPrograms
	myxdpMaps
}

func (o *myxdpObjects) Close() error {
	return _MyxdpClose(
		&o.myxdpPrograms,
		&o.myxdpMaps,
	)
}

// myxdpMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadMyxdpObjects or ebpf.CollectionSpec.LoadAndAssign.
type myxdpMaps struct {
	IpMap *ebpf.Map `ebpf:"ip_map"`
}

func (m *myxdpMaps) Close() error {
	return _MyxdpClose(
		m.IpMap,
	)
}

// myxdpPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadMyxdpObjects or ebpf.CollectionSpec.LoadAndAssign.
type myxdpPrograms struct {
	MyPass *ebpf.Program `ebpf:"my_pass"`
}

func (p *myxdpPrograms) Close() error {
	return _MyxdpClose(
		p.MyPass,
	)
}

func _MyxdpClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed myxdp_bpfel.o
var _MyxdpBytes []byte