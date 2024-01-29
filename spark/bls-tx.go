package main

import (
	"github.com/consensys/gnark/frontend"
	bls12 "github.com/yelhousni/ZKHackathon/spark/pairing_bls12381"
)

type BLS_BLS12_TX struct {
	MessageHash   bls12.G2Affine    `gnark:",public"`
	ApkCommitment frontend.Variable `gnark:",public"`
	SignedWeight  frontend.Variable `gnark:",public"`

	PublicKeys [10]bls12.G1Affine
	Signature  bls12.G2Affine
	BitList    [10]frontend.Variable
	Weights    [10]frontend.Variable
	MsgBytes   [32]frontend.Variable
}

func (c *BLS_BLS12_TX) Define(api frontend.API) error {
	bls, err := NewBLS_bls12(api)
	if err != nil {
		panic(err)
	}

	bls.VerifyBLS_bls12_Tx(
		c.PublicKeys,
		c.BitList,
		c.Weights,
		c.Signature,
		c.MessageHash,
		c.ApkCommitment,
		c.SignedWeight,
		c.MsgBytes,
	)
	return nil
}
