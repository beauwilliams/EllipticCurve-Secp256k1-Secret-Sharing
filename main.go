package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

func main() {
	// Get the secret key, which can be passed in as $1
	pass := "password123"
	mallory := "hackerman"
	argCount := len(os.Args[1:])
	if argCount > 0 {
		pass = os.Args[1]
	}
	// Generate an elliptic curve using secp256k1
	curve := curves.K256()

	// Create our Generator point on the curve
	G := curve.Point.Generator()

	// Create some public and private keys for alice and bob
	a := curve.Scalar.Random(rand.Reader)
	b := curve.Scalar.Random(rand.Reader)
	A := curve.Scalar.Random(rand.Reader)
	B := curve.Scalar.Random(rand.Reader)

	// Create signatures
	sA := a.Add(A)
	sB := b.Add(B)

	// Hash the message
	msg := []byte(pass)
	h := sha256.New()
	h.Write(msg)

	// Hash the malicious message
	malMsg := []byte(mallory)
	hm := sha256.New()
	hm.Write(malMsg)

	// Add the hashes to the message on the curve
	msg1, _ := curve.Scalar.SetBytes(h.Sum(nil))
	malMsg1, _ := curve.Scalar.SetBytes(hm.Sum(nil))
	PE := G.Mul(msg1)
	PEm := G.Mul(malMsg1)

        //Do our ECC math to check if the points are on the curve or not.
	ss_b := PE.Mul(sA).Add(PE.Mul(A.Neg())).Mul(b)
	ss_a := PE.Mul(sB).Add(PE.Mul(B.Neg())).Mul(a)
	ss_c := PEm.Mul(sB).Add(PEm.Mul(B.Neg())).Mul(a)

	// Outputs
	fmt.Printf("\nPassword= %s\n", pass)
	fmt.Printf("\n=== Bob generates ====")
	fmt.Printf("\nb (Bob)= %x\n", b.Bytes())
	fmt.Printf("\nB (Bob)= %x\n", B.Bytes())
	fmt.Printf("\n== Alice generates ===")
	fmt.Printf("\na (Alice)= %x\n", a.Bytes())
	fmt.Printf("\nA (Alice)= %x\n", b.Bytes())
	fmt.Printf("\n== PE of password (SHA256) ==")
	fmt.Printf("\nH(password)= %x\n", msg1.Bytes())
	fmt.Printf("\nPE(password)= %x\n", PE.ToAffineCompressed())
	fmt.Printf("\n=== After key exchange ===")
	fmt.Printf("\nShared Secret (Bob)= %x\n", ss_a.ToAffineCompressed())
	fmt.Printf("\nShared Secret (Alice)= %x\n", ss_b.ToAffineCompressed())
	fmt.Printf("\nShared Secret (Mallory)= %x\n", ss_c.ToAffineCompressed())

	// Verification
	if ss_a.Equal(ss_b) {
		fmt.Printf("Bob and Alice have a shared secret")
		if ss_a.Equal(ss_c) {
			fmt.Printf(" and Mallory has the same shared secret")
		}
		fmt.Printf(" but Mallory does not have the same shared secret")
	} else {
		fmt.Printf("Bob and Alice DO NOT have a shared secret")
	}
}
