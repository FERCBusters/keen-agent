package nativeposture

import "context"

func Collect(ctx context.Context, r Runner) ([]Observation, error) { return CollectMac(ctx, r), nil }
