package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"sync"

	"github.com/abdullah2993/go-brute"
)

const refMsg = "testmsg1"

func init() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: pem-cracker private_key public_key\n")
		flag.PrintDefaults()
	}
}

func main() {
	charset := flag.String("charset", "abcdefghijklmnopqrstuvwxyz0123456789", "Character set to use for bruteforce")
	minLen := flag.Int("min", 1, "Minimum length of password phrase")
	maxLen := flag.Int("max", 8, "Maxmimum length of password phrase")
	parallel := flag.Int("parallel", 8, "Numbers of threads to use")

	flag.Parse()

	if *minLen < 1 {
		printErr("min length should be greater than 0")
	}

	if *maxLen < *minLen {
		printErr("max length should be greater than min length")
	}

	if len(*charset) < 1 {
		printErr("charsets should be greater than 0")
	}

	if *parallel < 1 {
		printErr("parallel should be greater than 0")

	}

	if flag.NArg() != 2 {
		flag.Usage()
		os.Exit(1)
	}

	privFile, err := ioutil.ReadFile(flag.Arg(0))
	if err != nil {
		printErr("Unable to read private file[%s]: %v", flag.Arg(0), err)
	}

	pubFile, err := ioutil.ReadFile(flag.Arg(1))
	if err != nil {
		printErr("Unable to read public file[%s]: %v", flag.Arg(1), err)
	}

	encPrivPem, _ := pem.Decode(privFile)
	if encPrivPem == nil {
		printErr("Unable to decode private pem")
	}

	pubPem, _ := pem.Decode(pubFile)
	if pubPem == nil {
		printErr("Unable to decode public pem")
	}

	if !x509.IsEncryptedPEMBlock(encPrivPem) {
		printErr("Private key is not encrypted")
	}

	pubKey, err := x509.ParsePKIXPublicKey(pubPem.Bytes)
	if err != nil {
		printErr("Unable to parse public key: %v", err)
	}

	if _, ok := pubKey.(*rsa.PublicKey); !ok {
		printErr("Only RSA is supported")
	}

	testEncMsg, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey.(*rsa.PublicKey), []byte(refMsg))
	if err != nil {
		printErr("Unable to encrypt refrence message with public key: %v", err)
	}

	gen, closer := brute.Brute([]rune(*charset), *minLen, *maxLen, 1000)
	result := make(chan string, 1)
	wg := new(sync.WaitGroup)
	wg.Add(*parallel)
	for i := 0; i < *parallel; i++ {
		go bruteForce(encPrivPem, testEncMsg, gen, result, wg)
	}

	go func() {
		wg.Wait()
		close(result)
	}()

	res, ok := <-result
	closer()

	if !ok {
		printErr("Unable to find password")
	}

	fmt.Println("Password: ", res)

}

func bruteForce(encPrivPem *pem.Block, testEncMsg []byte, gen <-chan string, result chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	for pass := range gen {
		decPemDate, err := x509.DecryptPEMBlock(encPrivPem, []byte(pass))
		if err != nil {
			continue
		}

		privKey, err := x509.ParsePKCS1PrivateKey(decPemDate)
		if err != nil {
			continue
		}

		decTestMsg, err := rsa.DecryptPKCS1v15(rand.Reader, privKey, testEncMsg)
		if err != nil {
			continue
		}

		if string(decTestMsg) == refMsg {
			result <- pass
			return
		}
	}
}

func printErr(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg, args...)
	fmt.Fprintln(os.Stderr)
	os.Exit(1)
}
