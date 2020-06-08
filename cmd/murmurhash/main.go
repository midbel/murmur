package main

import (
	"flag"
	"fmt"
	"hash"
	"io"
	"os"

	"github.com/midbel/murmur"
)

func main() {
	method := flag.String("m", "", "algorithm")
	seed := flag.Uint("s", 0, "seed")
	flag.Parse()
	for _, a := range flag.Args() {
		sum := digestFile(a, *method, *seed)
		if sum != nil {
			fmt.Fprintf(os.Stdout, "%x  %s\n", sum, a)
		}
	}
}

func digestFile(file string, alg string, seed uint) []byte {
	r, err := os.Open(file)
	if err != nil {
		return nil
	}
	defer r.Close()

	var sum hash.Hash
	switch alg {
	case "128x64":
		sum = murmur.Murmur128x64v3(uint64(seed))
	case "128x86":
		sum = murmur.Murmur128x86v3(uint32(seed))
	case "32x86", "32", "":
		sum = murmur.Murmur32x86v3(uint32(seed))
	default:
		return nil
	}
	if _, err = io.Copy(sum, r); err != nil {
		return nil
	}
	return sum.Sum(nil)
}
