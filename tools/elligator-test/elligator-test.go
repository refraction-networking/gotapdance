// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// package extra25519
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/refraction-networking/conjure/pkg/ed25519/extra25519"
)

func main() {
	var publicKey, representative, privateKey [32]byte

	for {
		rand.Reader.Read(privateKey[:])

		if !extra25519.ScalarBaseMult(&publicKey, &representative, &privateKey) {
			continue
		}
		break

	}

	fmt.Printf("Public key: %s\n", hex.EncodeToString(publicKey[:]))
	fmt.Printf("Representative: %s\n", hex.EncodeToString(representative[:]))

}
