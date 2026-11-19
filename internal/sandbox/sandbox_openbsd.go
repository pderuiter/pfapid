//go:build openbsd

// Package sandbox wraps pledge(2) and unveil(2). On other systems the calls
// are no-ops so the code builds and unit-tests anywhere; pfapid itself only
// runs on OpenBSD (main refuses to start the privileged side elsewhere).
package sandbox

import "golang.org/x/sys/unix"

const Supported = true

// Unveil exposes path with perms ("r", "w", "x", "c" combinations).
func Unveil(path, perms string) error { return unix.Unveil(path, perms) }

// Lock forbids further unveil calls.
func Lock() error { return unix.UnveilBlock() }

// Pledge restricts the process to promises. execpromises stay unset, so
// programs it executes (pfctl) are not restricted by this pledge.
func Pledge(promises string) error { return unix.PledgePromises(promises) }
