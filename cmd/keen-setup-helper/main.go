package main

import (
	"context"
	"flag"
	"keen-agent/internal/onboarding"
	"os"
	"time"
)

func main() {
	request := flag.String("request", "", "private setup request file")
	flag.Parse()
	if *request == "" {
		os.Exit(onboarding.Invalid)
	}
	f, e := onboarding.OpenRequest(*request)
	if e != nil {
		os.Exit(onboarding.Invalid)
	}
	s, e := f.Stat()
	if e != nil || !s.Mode().IsRegular() || s.Size() > 32768 {
		f.Close()
		os.Exit(onboarding.Invalid)
	}
	r, e := onboarding.Decode(f)
	f.Close()
	if e != nil {
		os.Exit(onboarding.Invalid)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	os.Exit(onboarding.Setup(ctx, r))
}
