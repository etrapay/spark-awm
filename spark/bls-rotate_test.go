package main

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	bls12 "github.com/yelhousni/ZKHackathon/spark/pairing_bls12381"
)

func TestBls12Rotate(t *testing.T) {
	assert := test.NewAssert(t)

	oldPublicKeys, oldBitlist, oldWeights, oldApkCommitment, privateKeys := generate()
	newPublicKeys, newWeights, newBitlist, newApkCommitment, _, newAggregatedSignature, trustedWeight := generateNew(privateKeys, oldPublicKeys, oldWeights, oldBitlist)

	newApkInBytes := newApkCommitment.Bytes()
	var newApkVariable [32]frontend.Variable

	for i, v := range newApkInBytes {
		newApkVariable[i] = v
	}

	msg, err := bls12381.HashToG2(newApkInBytes[:], []byte(DOMAIN_SEPERATOR))
	if err != nil {
		panic(err)
	}

	verifyPairingCheck(newPublicKeys, newBitlist, newAggregatedSignature, msg)

	assignment := &BLS_BLS12_ROTATE{
		OldPublicKeys: bls12.NewG1AffineArray(oldPublicKeys),
		NewPublicKeys: bls12.NewG1AffineArray(newPublicKeys),

		BitList:   bigIntToVariableArray(newBitlist),
		Signature: bls12.NewG2Affine(newAggregatedSignature),

		OldApkCommitment:      oldApkCommitment,
		NewCommitment:         newApkCommitment,
		NewApkCommitmentBytes: newApkVariable,

		OldWeights: bigIntToVariableArray(oldWeights),
		NewWeights: bigIntToVariableArray(newWeights),

		TrustedWeight: frontend.Variable(trustedWeight),
	}

	err = test.IsSolved(&BLS_BLS12_ROTATE{}, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)

	fmt.Println("Rotate test passed")
	fmt.Println()
}
