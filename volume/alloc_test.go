package volume

import (
	"errors"
	"fmt"
	"testing"
)

// Next-fit goes on from the last allocation; first-fit starts at the
// lowest unit; both prefer one run, and split a request only when no run
// is long enough.
func TestAllocator(t *testing.T) {
	next, _ := NewAllocator(2, 20, NextFit)
	first, _ := NewAllocator(2, 20, FirstFit)
	for _, a := range []*Allocator{next, first} {
		r, _ := a.Alloc(4, -1) // 2-5
		a.Alloc(4, -1)         // 6-9
		a.Release(Units(r))
	}
	if r, _ := next.Alloc(2, -1); fmt.Sprint(r) != "[{10 2}]" {
		t.Errorf("next-fit took %v, want the units after the last allocation", r)
	}
	if r, _ := first.Alloc(2, -1); fmt.Sprint(r) != "[{2 2}]" {
		t.Errorf("first-fit took %v, want the lowest free", r)
	}
	if r, _ := first.Alloc(3, 7); fmt.Sprint(r) != "[{10 3}]" {
		t.Errorf("near 7 took %v, want the first run of 3 from there", r)
	}
	// Free now: 4-5, 13-21 for first. A run of 10 does not exist.
	r, err := first.Alloc(10, -1)
	if err != nil || fmt.Sprint(r) != "[{4 2} {13 8}]" {
		t.Errorf("fragmented: %v %v", r, err)
	}
	if _, err := first.Alloc(5, -1); !errors.Is(err, ErrFull) {
		t.Errorf("overfull: %v", err)
	}
	if _, err := NewAllocator(0, 1, "best-fit"); err == nil {
		t.Error("an unknown policy was accepted")
	}
}
