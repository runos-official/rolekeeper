package compile

import "slices"

// Held returns the entries a person holds on the cluster: direct grants,
// and grants to the groups the person is in. groups is the person's group
// membership in the account, read by the issuer at issuance.
func (o Output) Held(person string, groups []string) []Entry {
	var out []Entry
	for _, e := range o.Entries {
		if (e.Person != "" && e.Person == person) || (e.Via != "" && slices.Contains(groups, e.Via)) {
			out = append(out, e)
		}
	}
	return out
}

// ClaimGroups is the sorted runos: group claim for a token that carries
// these entries.
func ClaimGroups(es []Entry) []string {
	var out []string
	for _, e := range es {
		if e.Kind == "Group" {
			out = append(out, e.Subject)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}
