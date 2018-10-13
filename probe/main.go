package main

import (
	"flag"
	"fmt"
	"github.com/sergeyfrolov/gotapdance/tapdance"
	"os"
)

func main() {
	var scan = flag.Bool("scan", false, "Enable scan mode to probe multiple decoys")
	flag.Parse()

	if *scan {
		if flag.NArg() != 1 {
			fmt.Println(os.Args[0], "-scan <file>")
			os.Exit(255)
		}
		_ = flag.Arg(0)

		fmt.Println("To be implemented")
	} else {
		if flag.NArg() != 2 {
			fmt.Println(os.Args[0], "<ip> <sni>")
			os.Exit(255)
		}
		ip := flag.Arg(0)
		sni := flag.Arg(1)

		err := tapdance.ProbeDecoy(ip, sni)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}
}
