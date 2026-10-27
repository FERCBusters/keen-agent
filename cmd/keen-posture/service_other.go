//go:build !windows

package main

import "errors"

func service(string) error {
	return errors.New("service command is Windows only; use launchd on macOS")
}
