package main

import (
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	bls12 "github.com/etrapay/spark-awm/spark/pairing_bls12381"
)

const DOMAIN_SEPERATOR = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"

const LIMBS_LENGTH = 6

type BLS_bls12 struct {
	pr *bls12.Pairing
}

func NewBLS_bls12(api frontend.API) (*BLS_bls12, error) {
	pairing_bls12, err := bls12.NewPairing(api)
	if err != nil {
		return nil, fmt.Errorf("new pairing: %w", err)
	}
	return &BLS_bls12{
		pr: pairing_bls12,
	}, nil
}

// Transaction
func (bls BLS_bls12) VerifyBLS_bls12_Tx(
	publicKeys [10]bls12.G1Affine,
	bitlist, weights [10]frontend.Variable,
	signature, hash bls12.G2Affine,
	commitment, totalSignedWeight frontend.Variable,
	msg [32]frontend.Variable,
) {
	apk := bls.AggregatePublicKeys(publicKeys, bitlist, weights, totalSignedWeight)
	apkCommitment := bls.ComputeAPKCommitment(publicKeys, weights)
	bls.pr.CommitmentCheck(commitment, apkCommitment)

	_, _, g1, _ := bls12381.Generators()
	g1.Neg(&g1)
	G1neg := bls12.NewG1Affine(g1)

	h := bls.pr.HashToG2(msg)
	bls.pr.PairingCheck([]*bls12.G1Affine{&G1neg, &apk}, []*bls12.G2Affine{&signature, h})
}

// Validator Rotation
func (bls BLS_bls12) Verify_bls12_Rotate(
	oldPublicKeys, newPublicKeys [10]bls12.G1Affine,
	bitlist, oldWeights, newWeights [10]frontend.Variable,
	signature bls12.G2Affine,
	trustedWeight, newCommitment, oldApkCommitment frontend.Variable, newApkCommitmentBytes [32]frontend.Variable,
) {
	trustedWeight_ := bls.pr.CalculateTrustedWeight(oldPublicKeys, newPublicKeys, bitlist, oldWeights)
	bls.pr.CommitmentCheck(trustedWeight, trustedWeight_)

	apkCommitment := bls.ComputeAPKCommitment(oldPublicKeys, oldWeights)
	bls.pr.CommitmentCheck(oldApkCommitment, apkCommitment)

	newApkCommitment := bls.ComputeAPKCommitment(newPublicKeys, newWeights)
	bls.pr.CommitmentCheck(newCommitment, newApkCommitment)

	_, _, g1, _ := bls12381.Generators()
	g1.Neg(&g1)
	G1neg := bls12.NewG1Affine(g1)

	newApk := bls.pr.AggregatePublicKeys_Rotate(newPublicKeys, bitlist)
	apkToG2 := bls.pr.HashToG2(newApkCommitmentBytes)
	bls.pr.PairingCheck([]*bls12.G1Affine{&G1neg, &newApk}, []*bls12.G2Affine{&signature, apkToG2})
}
