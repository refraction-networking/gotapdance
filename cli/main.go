package main

import (
	"github.com/pkg/profile"
	"github.com/sergeyfrolov/gotapdance/tdproxy"
	"os"
)

func main() {
	defer profile.Start().Stop()

	tapdanceProxy := tdproxy.NewTapDanceProxy(10500)
	err := tapdanceProxy.ListenAndServe()
	if err != nil {
		tdproxy.Logger.Errorf("Failed to ListenAndServe(): %v\n", err)
		os.Exit(1)
	}
}
