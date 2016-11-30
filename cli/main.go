package main

import (
	"github.com/SergeyFrolov/gotapdance/tapdance"
)

func main() {
	tapdanceProxy := tapdance.NewTapdanceProxy(10500)
	tapdanceProxy.Listen()
}
