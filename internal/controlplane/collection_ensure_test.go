package controlplane

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/datapath"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

type fakeCollectionHandle struct {
	unpinCalls int
	closeCalls int
}

func (h *fakeCollectionHandle) Unpin() error { h.unpinCalls++; return nil }
func (h *fakeCollectionHandle) Close() error { h.closeCalls++; return nil }

func TestCollectionEnsurerSkipsReadyCollection(t *testing.T) {
	spec := testCollectionSpec()
	assertCollectionReadyNoop(t, spec, readyCollectionState(t, spec))
}

func TestCollectionEnsurerAcceptsSHA256ProgramTags(t *testing.T) {
	spec := testCollectionSpec()
	actual := readyCollectionStateWithHash(t, spec, sha256.New)
	assertCollectionReadyNoop(t, spec, actual)
}

func TestCollectionEnsurerUsesConfiguredMapCapacities(t *testing.T) {
	capacities := datapath.DefaultMapCapacities()
	capacities.IngressCacheMaxEntries = 2048
	capacities.DevMapMaxEntries = 16
	schema := datapath.V1SchemaWithCapacities(capacities)
	spec := testCollectionSpecWithSchema(schema)
	actual := readyCollectionStateWithSchema(t, spec, schema, sha1.New)
	elf := filepath.Join(t.TempDir(), "datapath.o")
	if err := os.WriteFile(elf, []byte("elf"), 0600); err != nil {
		t.Fatal(err)
	}
	ensurer, err := newCollectionEnsurerWithSchema(elf, filepath.Join(t.TempDir(), "bpf"), schema, func(string) (collectionOps, error) {
		return collectionOps{
			loadCollection: func(io.ReaderAt, datapath.CollectionSchema) (*ebpf.CollectionSpec, error) {
				return spec, nil
			},
			loadAndPin: func(*ebpf.CollectionSpec, datapath.CollectionSchema) (collectionHandle, error) {
				return nil, errors.New("configured collection should be ready")
			},
		}, nil
	}, func(context.Context, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := ensurer.EnsureCollection(context.Background(), reconcile.DesiredState{Enabled: true}, actual); err != nil || changed {
		t.Fatalf("configured collection was not treated as ready: changed=%v err=%v", changed, err)
	}
}

func TestCollectionEnsurerDoesNotSkipStaleProgram(t *testing.T) {
	elf := filepath.Join(t.TempDir(), "datapath.o")
	if err := os.WriteFile(elf, []byte("elf"), 0600); err != nil {
		t.Fatal(err)
	}
	spec := testCollectionSpec()
	handle := &fakeCollectionHandle{}
	loaded := false
	ensurer, err := newCollectionEnsurer(elf, filepath.Join(t.TempDir(), "bpf"), func(string) (collectionOps, error) {
		return collectionOps{
			loadCollection: func(io.ReaderAt, datapath.CollectionSchema) (*ebpf.CollectionSpec, error) {
				return spec, nil
			},
			loadAndPin: func(*ebpf.CollectionSpec, datapath.CollectionSchema) (collectionHandle, error) {
				loaded = true
				return handle, nil
			},
		}, nil
	}, func(context.Context, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	actual := readyCollectionState(t, spec)
	staleProgram := actual.Programs["tc_masq"]
	staleProgram.Tag = "stale-program-tag"
	actual.Programs["tc_masq"] = staleProgram
	if changed, err := ensurer.EnsureCollection(context.Background(), reconcile.DesiredState{Enabled: true}, actual); err != nil || !changed || !loaded || handle.closeCalls != 1 {
		t.Fatalf("stale program was incorrectly treated as ready: changed=%v err=%v loaded=%v handle=%+v", changed, err, loaded, handle)
	}
}

func TestCollectionEnsurerLoadsPinsAndInitializesControl(t *testing.T) {
	elf := filepath.Join(t.TempDir(), "datapath.o")
	if err := os.WriteFile(elf, []byte("elf"), 0600); err != nil {
		t.Fatal(err)
	}
	handle := &fakeCollectionHandle{}
	loaded := false
	initialized := false
	ensurer, err := newCollectionEnsurer(elf, filepath.Join(t.TempDir(), "bpf"), func(string) (collectionOps, error) {
		return collectionOps{
			loadCollection: func(io.ReaderAt, datapath.CollectionSchema) (*ebpf.CollectionSpec, error) {
				return &ebpf.CollectionSpec{}, nil
			},
			loadAndPin: func(*ebpf.CollectionSpec, datapath.CollectionSchema) (collectionHandle, error) {
				loaded = true
				return handle, nil
			},
		}, nil
	}, func(context.Context, string) error {
		initialized = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	changed, err := ensurer.EnsureCollection(context.Background(), reconcile.DesiredState{Enabled: true}, reconcile.ActualState{})
	if err != nil || !changed || !loaded || !initialized || handle.closeCalls != 1 || handle.unpinCalls != 0 {
		t.Fatalf("collection was not ensured: changed=%v err=%v loaded=%v initialized=%v handle=%+v", changed, err, loaded, initialized, handle)
	}
}

func TestCollectionEnsurerRollsBackWhenControlInitializationFails(t *testing.T) {
	elf := filepath.Join(t.TempDir(), "datapath.o")
	if err := os.WriteFile(elf, []byte("elf"), 0600); err != nil {
		t.Fatal(err)
	}
	handle := &fakeCollectionHandle{}
	want := errors.New("control init failed")
	ensurer, err := newCollectionEnsurer(elf, filepath.Join(t.TempDir(), "bpf"), func(string) (collectionOps, error) {
		return collectionOps{
			loadCollection: func(io.ReaderAt, datapath.CollectionSchema) (*ebpf.CollectionSpec, error) {
				return &ebpf.CollectionSpec{}, nil
			},
			loadAndPin: func(*ebpf.CollectionSpec, datapath.CollectionSchema) (collectionHandle, error) { return handle, nil },
		}, nil
	}, func(context.Context, string) error { return want })
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := ensurer.EnsureCollection(context.Background(), reconcile.DesiredState{Enabled: true}, reconcile.ActualState{}); err == nil || !errors.Is(err, want) || changed || handle.unpinCalls != 1 || handle.closeCalls != 1 {
		t.Fatalf("control failure was not rolled back: changed=%v err=%v handle=%+v", changed, err, handle)
	}
}

func assertCollectionReadyNoop(t *testing.T, spec *ebpf.CollectionSpec, actual reconcile.ActualState) {
	t.Helper()
	elf := filepath.Join(t.TempDir(), "datapath.o")
	if err := os.WriteFile(elf, []byte("elf"), 0600); err != nil {
		t.Fatal(err)
	}
	loaded := false
	ensurer, err := newCollectionEnsurer(elf, "/sys/fs/bpf/oncache/v1", func(string) (collectionOps, error) {
		return collectionOps{
			loadCollection: func(io.ReaderAt, datapath.CollectionSchema) (*ebpf.CollectionSpec, error) {
				return spec, nil
			},
			loadAndPin: func(*ebpf.CollectionSpec, datapath.CollectionSchema) (collectionHandle, error) {
				loaded = true
				return nil, errors.New("ready collection should not be loaded")
			},
		}, nil
	}, func(context.Context, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := ensurer.EnsureCollection(context.Background(), reconcile.DesiredState{Enabled: true}, actual); err != nil || changed || loaded {
		t.Fatalf("ready collection was not a no-op: changed=%v err=%v loaded=%v", changed, err, loaded)
	}
}

func readyCollectionState(t *testing.T, spec *ebpf.CollectionSpec) reconcile.ActualState {
	return readyCollectionStateWithHash(t, spec, sha1.New)
}

func readyCollectionStateWithHash(t *testing.T, spec *ebpf.CollectionSpec, digest func() hash.Hash) reconcile.ActualState {
	return readyCollectionStateWithSchema(t, spec, datapath.V1Schema(), digest)
}

func readyCollectionStateWithSchema(t *testing.T, spec *ebpf.CollectionSpec, schema datapath.CollectionSchema, digest func() hash.Hash) reconcile.ActualState {
	t.Helper()
	actual := reconcile.ActualState{Programs: make(map[string]reconcile.ProgramState), Maps: make(map[string]reconcile.MapState)}
	for _, name := range schema.Programs {
		program := spec.Programs[name]
		tag := instructionTag(t, program.Instructions, digest)
		actual.Programs[name] = reconcile.ProgramState{ID: 1, Name: name, Tag: tag}
	}
	for _, expected := range schema.Maps {
		actual.Maps[expected.Name] = reconcile.MapState{ID: 1, Name: expected.Name, KeySize: expected.KeySize, ValueSize: expected.ValueSize, MaxEntries: expected.MaxEntries}
	}
	return actual
}

func instructionTag(t *testing.T, instructions asm.Instructions, digest func() hash.Hash) string {
	t.Helper()
	h := digest()
	if err := instructions.Marshal(h, binary.LittleEndian); err != nil {
		t.Fatalf("marshal instructions for tag: %v", err)
	}
	return hex.EncodeToString(h.Sum(nil)[:8])
}

func testCollectionSpec() *ebpf.CollectionSpec {
	return testCollectionSpecWithSchema(datapath.V1Schema())
}

func testCollectionSpecWithSchema(schema datapath.CollectionSchema) *ebpf.CollectionSpec {
	spec := &ebpf.CollectionSpec{Programs: make(map[string]*ebpf.ProgramSpec), Maps: make(map[string]*ebpf.MapSpec)}
	for index, name := range schema.Programs {
		spec.Programs[name] = &ebpf.ProgramSpec{
			Name:         name,
			Instructions: asm.Instructions{asm.LoadImm(asm.R0, int64(index), asm.DWord), asm.Return()},
		}
	}
	for _, expected := range schema.Maps {
		spec.Maps[expected.Name] = &ebpf.MapSpec{
			Name: expected.Name, Type: expected.Type, KeySize: expected.KeySize,
			ValueSize: expected.ValueSize, MaxEntries: expected.MaxEntries, Flags: expected.Flags,
		}
	}
	return spec
}
