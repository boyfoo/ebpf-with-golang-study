// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64

package arp

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadMyarp returns the embedded CollectionSpec for myarp.
func loadMyarp() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_MyarpBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load myarp: %w", err)
	}

	return spec, err
}

// loadMyarpObjects loads myarp and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*myarpObjects
//	*myarpPrograms
//	*myarpMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadMyarpObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadMyarp()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// myarpSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type myarpSpecs struct {
	myarpProgramSpecs
	myarpMapSpecs
}

// myarpSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type myarpProgramSpecs struct {
	Myarp *ebpf.ProgramSpec `ebpf:"myarp"`
}

// myarpMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type myarpMapSpecs struct {
	ArpMap *ebpf.MapSpec `ebpf:"arp_map"`
}

// myarpObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadMyarpObjects or ebpf.CollectionSpec.LoadAndAssign.
type myarpObjects struct {
	myarpPrograms
	myarpMaps
}

func (o *myarpObjects) Close() error {
	return _MyarpClose(
		&o.myarpPrograms,
		&o.myarpMaps,
	)
}

// myarpMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadMyarpObjects or ebpf.CollectionSpec.LoadAndAssign.
type myarpMaps struct {
	ArpMap *ebpf.Map `ebpf:"arp_map"`
}

func (m *myarpMaps) Close() error {
	return _MyarpClose(
		m.ArpMap,
	)
}

// myarpPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadMyarpObjects or ebpf.CollectionSpec.LoadAndAssign.
type myarpPrograms struct {
	Myarp *ebpf.Program `ebpf:"myarp"`
}

func (p *myarpPrograms) Close() error {
	return _MyarpClose(
		p.Myarp,
	)
}

func _MyarpClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed myarp_bpfel_x86.o
var _MyarpBytes []byte
