package datapath

import (
	"testing"
	"unsafe"
)

func TestControlV1Layout(t *testing.T) {
	var value ControlV1
	fields := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{name: "abi_version", got: unsafe.Offsetof(value.ABIVersion), want: 0},
		{name: "enabled", got: unsafe.Offsetof(value.Enabled), want: 4},
		{name: "generation", got: unsafe.Offsetof(value.Generation), want: 8},
		{name: "heartbeat_ns", got: unsafe.Offsetof(value.HeartbeatNS), want: 16},
		{name: "heartbeat_timeout_ns", got: unsafe.Offsetof(value.HeartbeatTimeoutNS), want: 24},
		{name: "flags", got: unsafe.Offsetof(value.Flags), want: 32},
		{name: "reserved", got: unsafe.Offsetof(value.Reserved), want: 36},
	}
	if got, want := unsafe.Sizeof(value), uintptr(40); got != want {
		t.Fatalf("ControlV1 size = %d, want %d", got, want)
	}
	for _, field := range fields {
		if field.got != field.want {
			t.Errorf("ControlV1 %s offset = %d, want %d", field.name, field.got, field.want)
		}
	}
}
