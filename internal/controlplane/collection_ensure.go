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
	ensureControl  func(context.Context) error
}

type collectionOpsFactory func(string) (collectionOps, error)
type controlInitializer func(context.Context, string) error

type CollectionEnsurer struct {
	elfPath       string
	pinRoot       string
	newOps        collectionOpsFactory
	initializeCtl controlInitializer
}

func NewCollectionEnsurer(elfPath, pinRoot string) (*CollectionEnsurer, error) {
	return newCollectionEnsurer(elfPath, pinRoot, func(root string) (collectionOps, error) {
		manager, err := datapath.NewManager(root)
		if err != nil {
			return collectionOps{}, err
		}
		return collectionOps{
			loadCollection: manager.LoadCollection,
			loadAndPin: func(spec *ebpf.CollectionSpec, schema datapath.CollectionSchema) (collectionHandle, error) {
				return manager.LoadAndPin(spec, schema)
			},
			ensureControl: manager.EnsureControlMap,
		}, nil
	}, initializeControlMap)
}

func newCollectionEnsurer(elfPath, pinRoot string, factory collectionOpsFactory, initialize controlInitializer) (*CollectionEnsurer, error) {
	if elfPath == "" || !filepath.IsAbs(elfPath) {
		return nil, fmt.Errorf("BPF ELF path must be an absolute file path")
	}
	if pinRoot == "" || !filepath.IsAbs(pinRoot) || filepath.Clean(pinRoot) == string(filepath.Separator) {
		return nil, fmt.Errorf("BPF pin root must be a dedicated absolute directory")
	}
	if factory == nil || initialize == nil {
		return nil, fmt.Errorf("collection dependencies are required")
	}
	return &CollectionEnsurer{elfPath: filepath.Clean(elfPath), pinRoot: filepath.Clean(pinRoot), newOps: factory, initializeCtl: initialize}, nil
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
	schema := datapath.V1Schema()
	if partialCollection(actual, schema) {
		if ops.ensureControl == nil {
			return false, fmt.Errorf("partial BPF collection repair is unavailable")
		}
		if err := ops.ensureControl(ctx); err != nil {
			return false, fmt.Errorf("recreate control Map: %w", err)
		}
		if err := e.initializeCtl(ctx, e.pinRoot); err != nil {
			return false, fmt.Errorf("initialize control Map: %w", err)
		}
		return true, nil
	}
	spec, err := ops.loadCollection(file, schema)
	if err != nil {
		return false, fmt.Errorf("load BPF collection: %w", err)
	}
	if collectionReady(actual, spec) {
		return false, nil
	}
	loaded, err := ops.loadAndPin(spec, schema)
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

func partialCollection(actual reconcile.ActualState, schema datapath.CollectionSchema) bool {
	if _, ok := actual.Maps["control_map"]; ok || len(actual.Maps) != len(schema.Maps)-1 || len(actual.Programs) != len(schema.Programs) {
		return false
	}
	for _, name := range schema.Programs {
		if program, ok := actual.Programs[name]; !ok || program.ID == 0 {
			return false
		}
	}
	return true
}

func collectionReady(actual reconcile.ActualState, spec *ebpf.CollectionSpec) bool {
	if spec == nil {
		return false
	}
	schema := datapath.V1Schema()
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
