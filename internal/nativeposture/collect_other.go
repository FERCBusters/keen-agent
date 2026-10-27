//go:build !darwin && !windows

package nativeposture

import (
	"context"
	"errors"
)

func Collect(context.Context, Runner) ([]Observation, error) {
	return nil, errors.New("keen-posture native collector supports macOS and Windows; use keen-agent on Linux")
}
