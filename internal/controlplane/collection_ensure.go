package controlplane

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/cat-cc-Lcos/FNCache/internal/datapath"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cilium/ebpf"
)

type collectionHandle interface {
	Unpin() error
	Close() error
}

type collectionOps struct {
	loadCollection func(io.ReaderAt, datapath.CollectionSchema) (*ebpf.CollectionSpec, error)
	loadAndPin     func(*ebpf.CollectionSpec, datapath.CollectionSchema) (collectionHandle, error)
}

type collectionOpsFactory func(string) (collectionOps, error)
type controlInitializer func(context.Context, string) error

type CollectionEnsurer struct {
	elfPath       string
	pinRoot       string
	schema        datapath.CollectionSchema
	newOps        collectionOpsFactory
	initializeCtl controlInitializer
}

func NewCollectionEnsurer(elfPath, pinRoot string) (*CollectionEnsurer, error) {
	return NewCollectionEnsurerWithSchema(elfPath, pinRoot, datapath.V1Schema())
}

func NewCollectionEnsurerWithSchema(elfPath, pinRoot string, schema datapath.CollectionSchema) (*CollectionEnsurer, error) {
	return newCollectionEnsurerWithSchema(elfPath, pinRoot, schema, func(root string) (collectionOps, error) {
		manager, err := datapath.NewManager(root)
		if err != nil {
			return collectionOps{}, err
		}
		return collectionOps{
			loadCollection: manager.LoadCollection,
			loadAndPin: func(spec *ebpf.CollectionSpec, schema datapath.CollectionSchema) (collectionHandle, error) {
				return manager.LoadAndPin(spec, schema)
			},
		}, nil
	}, initializeControlMap)
}

func newCollectionEnsurer(elfPath, pinRoot string, factory collectionOpsFactory, initialize controlInitializer) (*CollectionEnsurer, error) {
	return newCollectionEnsurerWithSchema(elfPath, pinRoot, datapath.V1Schema(), factory, initialize)
}

func newCollectionEnsurerWithSchema(elfPath, pinRoot string, schema datapath.CollectionSchema, factory collectionOpsFactory, initialize controlInitializer) (*CollectionEnsurer, error) {
	if elfPath == "" || !filepath.IsAbs(elfPath) {
		return nil, fmt.Errorf("BPF ELF path must be an absolute file path")
	}
	if pinRoot == "" || !filepath.IsAbs(pinRoot) || filepath.Clean(pinRoot) == string(filepath.Separator) {
		return nil, fmt.Errorf("BPF pin root must be a dedicated absolute directory")
	}
	if factory == nil || initialize == nil {
		return nil, fmt.Errorf("collection dependencies are required")
	}
	return &CollectionEnsurer{elfPath: filepath.Clean(elfPath), pinRoot: filepath.Clean(pinRoot), schema: schema, newOps: factory, initializeCtl: initialize}, nil
}

func (e *CollectionEnsurer) EnsureCollection(ctx context.Context, desired reconcile.DesiredState, actual reconcile.ActualState) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if !desired.Enabled {
		return false, nil
	}
	file, err := os.Open(e.elfPath)
	if err != nil {
		return false, fmt.Errorf("open BPF ELF: %w", err)
	}
	defer file.Close()
	ops, err := e.newOps(e.pinRoot)
	if err != nil {
		return false, fmt.Errorf("create BPF collection manager: %w", err)
	}
	spec, err := ops.loadCollection(file, e.schema)
	if err != nil {
		return false, fmt.Errorf("load BPF collection: %w", err)
	}
	if collectionReadyWithSchema(actual, spec, e.schema) {
		return false, nil
	}
	loaded, err := ops.loadAndPin(spec, e.schema)
	if err != nil {
		return false, fmt.Errorf("pin BPF collection: %w", err)
	}
	if err := e.initializeCtl(ctx, e.pinRoot); err != nil {
		_ = loaded.Unpin()
		_ = loaded.Close()
		return false, fmt.Errorf("initialize control Map: %w", err)
	}
	if err := loaded.Close(); err != nil {
		return false, fmt.Errorf("close BPF collection: %w", err)
	}
	return true, nil
}

func collectionReady(actual reconcile.ActualState, spec *ebpf.CollectionSpec) bool {
	return collectionReadyWithSchema(actual, spec, datapath.V1Schema())
}

func collectionReadyWithSchema(actual reconcile.ActualState, spec *ebpf.CollectionSpec, schema datapath.CollectionSchema) bool {
	if spec == nil {
		return false
	}
	if len(actual.Programs) != len(schema.Programs) || len(actual.Maps) != len(schema.Maps) {
		return false
	}
	for _, name := range schema.Programs {
		program, ok := actual.Programs[name]
		expected, expectedOK := spec.Programs[name]
		if !ok || program.ID == 0 || !expectedOK || expected == nil {
			return false
		}
		if program.Name != "" && program.Name != name {
			return false
		}
		if err := expected.Compatible(&ebpf.ProgramInfo{Tag: program.Tag}); err != nil {
			return false
		}
	}
	for _, expected := range schema.Maps {
		state, ok := actual.Maps[expected.Name]
		if !ok || state.ID == 0 || state.KeySize != expected.KeySize || state.ValueSize != expected.ValueSize || state.MaxEntries != expected.MaxEntries {
			return false
		}
	}
	return true
}

func initializeControlMap(ctx context.Context, pinRoot string) error {
	writer, err := datapath.NewControlWriter(pinRoot)
	if err != nil {
		return err
	}
	return writer.Initialize(ctx)
}
