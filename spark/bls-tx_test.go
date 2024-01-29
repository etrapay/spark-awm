package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	bls12 "github.com/etrapay/spark-awm/spark/pairing_bls12381"
)

func TestBls12Tx(t *testing.T) {
	assert := test.NewAssert(t)
	publicKeys, bitlist, weights, apkCommitment, privateKeys := generate()

	var msg [32]frontend.Variable
	var x [32]byte

	_, err := rand.Read(x[:])
	if err != nil {
		panic(err)
	}

	for i, v := range x {
		msg[i] = v
	}

	messageHash, err := bls12381.HashToG2(x[:], []byte(DOMAIN_SEPERATOR))
	if err != nil {
		panic(err)
	}

	signedWeight := big.NewInt(0)
	var signature bls12381.G2Affine

	for i := 0; i < len(bitlist); i++ {
		if bitlist[i].Cmp(big.NewInt(0)) == 1 {
			signedWeight.Add(signedWeight, weights[i])
			var S bls12381.G2Affine
			S.ScalarMultiplication(&messageHash, privateKeys[i])
			signature.Add(&signature, &S)
		}
	}

	verifyPairingCheck(publicKeys, bitlist, signature, messageHash)

	assignment := &BLS_BLS12_TX{
		PublicKeys:    bls12.NewG1AffineArray(publicKeys),
		BitList:       bigIntToVariableArray(bitlist),
		Weights:       bigIntToVariableArray(weights),
		Signature:     bls12.NewG2Affine(signature),
		MessageHash:   bls12.NewG2Affine(messageHash),
		ApkCommitment: apkCommitment,
		SignedWeight:  signedWeight,
		MsgBytes:      msg,
	}

	err = test.IsSolved(&BLS_BLS12_TX{}, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
	fmt.Println("Transaction test passed")
	fmt.Println()

}
