// Command owlsign makes the key a release is signed with and signs the list of hashes of a release.
//
//	owlsign keygen -out signing.key          writes the private key (nobody should read it) and prints the public one
//	owlsign sign -in SHA256SUMS -out SHA256SUMS.sig   signs with the key in the environment variable OWL_SIGN_KEY
//	owlsign verify -pub <key> -in SHA256SUMS -sig SHA256SUMS.sig
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Taminum/Owlery/internal/relsign"
)

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "owlsign: "+format+"\n", a...)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		fail("keygen, sign or verify")
	}
	args := os.Args[2:]
	switch os.Args[1] {
	case "keygen":
		fs := flag.NewFlagSet("keygen", flag.ExitOnError)
		out := fs.String("out", "", "file for the private key")
		_ = fs.Parse(args)
		if *out == "" {
			fail("keygen needs -out")
		}
		pub, priv, err := relsign.GenerateKey()
		if err != nil {
			fail("%v", err)
		}
		f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // never over a key that is there
		if err != nil {
			fail("%v", err)
		}
		if _, err := f.WriteString(priv + "\n"); err != nil {
			fail("%v", err)
		}
		if err := f.Close(); err != nil {
			fail("%v", err)
		}
		fmt.Println("public key:", pub) // the private key is only in the file
	case "sign":
		fs := flag.NewFlagSet("sign", flag.ExitOnError)
		in := fs.String("in", "SHA256SUMS", "the list to sign")
		out := fs.String("out", "SHA256SUMS.sig", "where the signature goes")
		_ = fs.Parse(args)
		key := os.Getenv("OWL_SIGN_KEY")
		if key == "" {
			fail("the key is not in OWL_SIGN_KEY")
		}
		msg, err := os.ReadFile(*in)
		if err != nil {
			fail("%v", err)
		}
		sig, err := relsign.Sign(key, msg)
		if err != nil {
			fail("%v", err)
		}
		if err := os.WriteFile(*out, []byte(sig+"\n"), 0o644); err != nil {
			fail("%v", err)
		}
	case "verify":
		fs := flag.NewFlagSet("verify", flag.ExitOnError)
		pub := fs.String("pub", "", "public key")
		in := fs.String("in", "SHA256SUMS", "the signed list")
		sig := fs.String("sig", "SHA256SUMS.sig", "the signature")
		_ = fs.Parse(args)
		msg, err := os.ReadFile(*in)
		if err != nil {
			fail("%v", err)
		}
		s, err := os.ReadFile(*sig)
		if err != nil {
			fail("%v", err)
		}
		if err := relsign.Verify(*pub, msg, string(s)); err != nil {
			fail("%v", err)
		}
		fmt.Println("signature ok")
	default:
		fail("keygen, sign or verify")
	}
}
