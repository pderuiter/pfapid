//go:build !openbsd

package sandbox

const Supported = false

func Unveil(string, string) error { return nil }
func Lock() error                 { return nil }
func Pledge(string) error         { return nil }
