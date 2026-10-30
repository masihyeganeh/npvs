package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	password := flag.String("password", "", "password for passphrase-protected files")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: npvs [-password <password>] <file.npvt|file.npvs>")
		os.Exit(2)
	}

	b, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		panic(err)
	}

	f, err := Parse(b, *password)
	if err != nil {
		panic(err)
	}

	switch f.Kind {
	case KindNPVT:
		for _, p := range f.Payloads {
			fmt.Println(string(p))
		}
	case KindNPVS:
		if f.NPVS.Body != nil {
			fmt.Println(string(f.NPVS.Body))
		}
		for _, item := range f.NPVS.Items {
			fmt.Println(string(item.Data))
		}
	}
}
