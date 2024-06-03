package main

import (
	"os"

	"github.com/honeynet/ja4t"
)

func main() {
	// Parse the command line arguments
	prints, err := ja4t.ParseFile(os.Args[1])
	if err != nil {
		println(err.Error())
		os.Exit(1)
	}
	for _, p := range prints {
		println(p.String())
	}
}
