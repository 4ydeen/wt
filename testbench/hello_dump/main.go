// hello_dump prints the exact TLS ClientHello record that wat.FakeClientHello builds for a comma-separated SNI
// list, as "sni <base64>" lines. testbench/measure.sh feeds this to emulate_dpi.py --fake-hello, so the emulated
// DPI classifies the same bytes the fake-SNI injector emits (including the random-length-dependent record size),
// not a Python re-implementation.
//
//	go run ./testbench/hello_dump -sni www.example.com
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"strings"

	"github.com/JohnWatsoon/WatTunnel/wat"
)

func main() {
	sni := flag.String("sni", "www.example.com", "comma-separated SNI list")
	flag.Parse()
	for _, s := range strings.Split(*sni, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		h := wat.FakeClientHello(s)
		if len(h) == 0 {
			log.Fatalf("hello_dump: empty hello for %q", s)
		}
		fmt.Printf("%s %s\n", s, base64.StdEncoding.EncodeToString(h))
	}
}
