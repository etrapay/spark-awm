package main

import (
	"github.com/consensys/gnark/frontend"
	bls12 "github.com/yelhousni/ZKHackathon/spark/pairing_bls12381"
)

type BLS_BLS12_ROTATE struct {
	MessageHash bls12.G2Affine `gnark:",public"`

	OldApkCommitment      frontend.Variable     `gnark:",public"`
	NewCommitment         frontend.Variable     `gnark:",public"`
	NewApkCommitmentBytes [32]frontend.Variable `gnark:",public"`

	TrustedWeight frontend.Variable `gnark:",public"`

	OldWeights [10]frontend.Variable
	NewWeights [10]frontend.Variable

	OldPublicKeys [10]bls12.G1Affine
	NewPublicKeys [10]bls12.G1Affine

	BitList [10]frontend.Variable

	Signature bls12.G2Affine
}

func (c *BLS_BLS12_ROTATE) Define(api frontend.API) error {
	bls, err := NewBLS_bls12(api)
	if err != nil {
		panic(err)
	}

	bls.Verify_bls12_Rotate(
		c.OldPublicKeys,
		c.NewPublicKeys,
		c.BitList,
		c.OldWeights,
		c.NewWeights,
		c.Signature,
		c.TrustedWeight,
		c.NewCommitment,
		c.OldApkCommitment,
		c.NewApkCommitmentBytes,
	)

	return nil
}
