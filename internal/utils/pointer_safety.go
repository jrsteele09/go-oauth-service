package utils

func Value[T any](v *T) T {
	if v == nil {
		return *new(T)
	}
	return *v
}

func Ptr[T any](v T) *T {
	return &v
}

// SafeDeref safely dereferences a pointer, returning zero value if nil
func SafeDeref[T any](ptr *T) T {
	if ptr == nil {
		var zero T
		return zero
	}
	return *ptr
}
