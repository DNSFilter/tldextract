package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/DNSFilter/tldextract"
)

func main() {
	v2 := flag.Bool("v2", false, "use the V2 extraction API instead of the legacy V1 API")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Please provide an fqdn as a cmd line argument.")
		os.Exit(1)
	}

	tldExtract, err := tldextract.New("/tmp/tld.cache", false)
	if err != nil {
		panic(err)
	}

	var res *tldextract.Result
	if *v2 {
		res = tldExtract.ExtractV2(flag.Arg(0))
	} else {
		res = tldExtract.Extract(flag.Arg(0))
	}

	if res.Flag == tldextract.Domain {
		fmt.Printf("%v.%v\n", res.Root, res.Tld)
		fmt.Printf("----\n%+v\n-----\n", res)
	} else {
		fmt.Printf("%+v\n", res)
	}
}
