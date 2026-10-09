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
	removeProgram  func(context.Context, string, uint32) error
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
			ensureControl: manager.EnsureControlMap,
			removeProgram: manager.RemovePinnedProgram,
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
	if partialCollection(actual, e.schema) {
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
	spec, err := ops.loadCollection(file, e.schema)
	if err != nil {
		return false, fmt.Errorf("load BPF collection: %w", err)
	}
	if err := e.recoverPartialProgramPins(ctx, ops, actual, spec); err != nil {
		return false, fmt.Errorf("recover partial BPF program pins: %w", err)
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

func (e *CollectionEnsurer) recoverPartialProgramPins(ctx context.Context, ops collectionOps, actual reconcile.ActualState, spec *ebpf.CollectionSpec) error {
	if !partialProgramCollection(actual, e.schema) {
		return nil
	}
	if spec == nil {
		return fmt.Errorf("BPF collection spec is nil")
	}
	if !actual.Control.Verified || actual.Control.Enabled {
		return fmt.Errorf("control Map is not verified and disabled")
	}
	if len(actual.Attachments) != 0 {
		return fmt.Errorf("partial collection has %d TC attachments", len(actual.Attachments))
	}
	if len(actual.Conflicts) != 0 {
		return fmt.Errorf("partial collection has %d TC conflicts", len(actual.Conflicts))
	}
	if ops.removeProgram == nil {
		return fmt.Errorf("partial program pin recovery is unavailable")
	}
	for _, name := range e.schema.Programs {
		program, ok := actual.Programs[name]
		if !ok {
			continue
		}
		expected, ok := spec.Programs[name]
		if !ok || !programMatchesSpec(name, program, expected) {
			return fmt.Errorf("program %s does not match the current ELF", name)
		}
	}
	for _, name := range e.schema.Programs {
		program, ok := actual.Programs[name]
		if !ok {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := ops.removeProgram(ctx, name, program.ID); err != nil {
			return fmt.Errorf("remove program pin %s: %w", name, err)
		}
	}
	return nil
}

func partialProgramCollection(actual reconcile.ActualState, schema datapath.CollectionSchema) bool {
	if len(actual.Programs) == 0 || len(actual.Programs) >= len(schema.Programs) || len(actual.Maps) != len(schema.Maps) {
		return false
	}
	if _, ok := actual.Maps["control_map"]; !ok {
		return false
	}
	for _, orphan := range actual.Orphans {
		if orphan.Kind == "program-pin" {
			return false
		}
	}
	for _, expected := range schema.Maps {
		state, ok := actual.Maps[expected.Name]
		if !ok || state.ID == 0 || state.KeySize != expected.KeySize || state.ValueSize != expected.ValueSize || state.MaxEntries != expected.MaxEntries {
			return false
		}
	}
	for name, program := range actual.Programs {
		if program.ID == 0 || !containsProgram(schema.Programs, name) {
			return false
		}
	}
	return true
}

func containsProgram(programs []string, name string) bool {
	for _, expected := range programs {
		if expected == name {
			return true
		}
	}
	return false
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
		if !ok || !expectedOK || !programMatchesSpec(name, program, expected) {
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

func programMatchesSpec(name string, program reconcile.ProgramState, expected *ebpf.ProgramSpec) bool {
	if program.ID == 0 || expected == nil {
		return false
	}
	if program.Name != "" && program.Name != name {
		return false
	}
	return expected.Compatible(&ebpf.ProgramInfo{Tag: program.Tag}) == nil
}

func initializeControlMap(ctx context.Context, pinRoot string) error {
	writer, err := datapath.NewControlWriter(pinRoot)
	if err != nil {
		return err
	}
	return writer.Initialize(ctx)
}
