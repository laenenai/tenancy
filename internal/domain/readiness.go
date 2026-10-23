package domain

// Readiness is a stored object's processing lifecycle state.
//
// It is in this module, and in the charter's scope list, for one reason:
// a consumer's authorization caveat has to be able to *name* a readiness
// state ("serve this only once it is ready") without the package that
// names it depending on whatever pipeline eventually implements the
// transitions. `tenancy` owns no pipeline and makes no transition — it
// declares the closed set so that the consumers of a shared tenant model
// agree on the words.
//
// If a second module ever needs to transition between these states, that
// machinery belongs to that module, not here. The enum is the whole of
// this module's interest in readiness.
type Readiness string

const (
	// ReadinessPending is set from creation until processing completes.
	ReadinessPending Readiness = "pending"
	// ReadinessReady means the object has passed processing and is safe
	// to serve.
	ReadinessReady Readiness = "ready"
	// ReadinessQuarantined means processing flagged the object; it is not
	// served without an override permission.
	ReadinessQuarantined Readiness = "quarantined"
	// ReadinessErased means the object's content has been erased; only
	// metadata, if any, remains.
	ReadinessErased Readiness = "erased"
)

// Valid reports whether r is one of the four readiness states.
func (r Readiness) Valid() bool {
	switch r {
	case ReadinessPending, ReadinessReady, ReadinessQuarantined, ReadinessErased:
		return true
	default:
		return false
	}
}
