package runinfo

import "testing"

// A stamped version wins over the one the toolchain recorded, because the
// release scripts name their files after it. The revision is not theirs to
// claim, so it keeps coming from the toolchain.
//
// version is written here rather than injected because the linker writes it;
// that is also why this test does not run in parallel with anything.
func TestStampedVersionWins(t *testing.T) {
	wantModule, wantRev, wantModified := recorded()
	t.Cleanup(func() { version = "" })

	version = "v1.2.3"
	module, rev, modified := Build()
	if module != "v1.2.3" {
		t.Errorf("module = %q, want the stamped v1.2.3", module)
	}
	if rev != wantRev || modified != wantModified {
		t.Errorf("revision = %q, %v; want the recorded %q, %v", rev, modified, wantRev, wantModified)
	}

	version = ""
	if module, _, _ = Build(); module != wantModule {
		t.Errorf("module = %q with nothing stamped, want the recorded %q", module, wantModule)
	}
}
