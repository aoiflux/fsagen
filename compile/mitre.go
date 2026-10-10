package compile

import (
	"fmt"
	"regexp"
	"slices"
)

// TechniquePattern is the shape of an ATT&CK technique or sub-technique ID.
// Only the shape is checked: fsagen carries no copy of the ATT&CK catalogue,
// so a well-formed ID that ATT&CK does not define is not caught.
const TechniquePattern = `^T\d{4}(\.\d{3})?$`

var techniqueID = regexp.MustCompile(TechniquePattern)

// checkMitre validates one mitre list as written. A key that is present but
// empty is a mistake, as is the same technique twice in one list.
func checkMitre(ids []string) error {
	if len(ids) == 0 {
		return fmt.Errorf("is empty; list at least one ATT&CK technique ID or leave the key out")
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if !techniqueID.MatchString(id) {
			return fmt.Errorf("%q is not an ATT&CK technique ID (want T1234 or T1234.001)", id)
		}
		if seen[id] {
			return fmt.Errorf("%s is listed twice", id)
		}
		seen[id] = true
	}
	return nil
}

// Techniques returns the ATT&CK techniques the operation exhibits: its own
// and its step's, sorted, each once. Nil when neither says any.
func (op *Op) Techniques() []string {
	if len(op.Mitre) == 0 && len(op.stepMitre) == 0 {
		return nil
	}
	out := slices.Concat(op.stepMitre, op.Mitre)
	slices.Sort(out)
	return slices.Compact(out)
}
