package main

import (
	"crypto/rand"
	"fmt"
	"math/big"

	pp "github.com/iden3/go-iden3-crypto/poseidon"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	bls12 "github.com/etrapay/spark-awm/spark/pairing_bls12381"
)

func (bls BLS_bls12) AggregatePublicKeys(
	pubKeys [10]bls12.G1Affine,
	BitList, QuorumWeights [10]frontend.Variable,
	signedWeight frontend.Variable,
) (bls12.G1Affine, bls12.G1Affine) {
	res, fullres := bls.pr.AggregatePublicKeys(pubKeys, BitList, QuorumWeights, signedWeight)
	return res, fullres
}

func (bls BLS_bls12) ComputeAPKCommitment(
	pubKeys [10]bls12.G1Affine,
	quorumW [10]frontend.Variable,
) frontend.Variable {
	m := make([]frontend.Variable, 10)

	for i := 0; i < 10; i++ {
		commX := bls.pr.Poseidon(pubKeys[i].X.Limbs)
		commY := bls.pr.Poseidon(pubKeys[i].Y.Limbs)
		m[i] = bls.pr.Poseidon([]frontend.Variable{commX, commY, quorumW[i]})
	}

	return bls.pr.Poseidon(m)
}

// Test helpers functions
func generate() (
	[]bls12381.G1Affine,
	[]*big.Int,
	[]*big.Int,
	*big.Int,
	[]*big.Int,
) {
	publicKeys := make([]bls12381.G1Affine, 10)
	privateKeys := make([]*big.Int, 10)
	l := 10

	bitlist := genBitlist()
	weights := genWeights()

	for i := 0; i < l; i++ {
		secret := genRandom(230)
		privateKeys[i] = secret
		pk := genPublickey(*secret)
		publicKeys[i] = pk

	}

	commitment := genCommitment(publicKeys, weights)

	return publicKeys, bitlist, weights, commitment, privateKeys
}

func verifyPairingCheck(publicKeys []bls12381.G1Affine, bitlist []*big.Int, signature bls12381.G2Affine, msg bls12381.G2Affine) {
	if len(publicKeys) != len(bitlist) {
		panic("Wrong length")
	}

	var onlySignedApk bls12381.G1Affine
	for i := 0; i < len(publicKeys); i++ {
		if bitlist[i].Int64() == 1 {
			onlySignedApk.Add(&onlySignedApk, &publicKeys[i])
		}
	}

	_, _, g1, _ := bls12381.Generators()
	G1neg := g1.Neg(&g1)

	var zeroG1 bls12381.G1Affine
	zeroG1.X.SetZero()
	zeroG1.Y.SetZero()

	var t bls12381.G1Affine
	t.Add(&onlySignedApk, &zeroG1)

	result, err := bls12381.PairingCheck([]bls12381.G1Affine{*G1neg, t}, []bls12381.G2Affine{signature, msg})
	if err != nil {
		panic(err)
	}

	if !result {
		panic("Pairing check failed")
	} else {
		fmt.Println("! Pairing check passed")
	}
}

func generateNew(
	oldPrivateKeys []*big.Int,
	oldPublicKeys []bls12381.G1Affine,
	weightsOld []*big.Int,
	bitlistOld []*big.Int,
) (
	[]bls12381.G1Affine,
	[]*big.Int,
	[]*big.Int,
	*big.Int,
	bls12381.G2Affine,
	bls12381.G2Affine,
	int,
) {
	weights := make([]*big.Int, len(weightsOld))
	publicKeys := make([]bls12381.G1Affine, len(oldPublicKeys))
	bitlist := make([]*big.Int, len(bitlistOld))
	privateKeys := make([]*big.Int, len(oldPrivateKeys))

	trustedWeight := 0
	totalWeight := 0

	copy(weights, weightsOld)
	copy(publicKeys, oldPublicKeys)
	copy(bitlist, bitlistOld)
	copy(privateKeys, oldPrivateKeys)

	if len(publicKeys) != 10 {
		panic("Wrong public key array length")
	}

	differenceCount := genRandom(2)

	if differenceCount.Int64() == 0 {
		differenceCount = big.NewInt(2)
	}

	m := make(map[int]bool)

	for i := 0; i < int(differenceCount.Int64()); i++ {
		index := big.NewInt(0).Mod(genRandom(4), big.NewInt(10)).Int64()
		if m[int(index)] {
			i--
			continue
		}
		sk := *genRandom(230)
		privateKeys[index] = &sk

		publicKeys[index] = genPublickey(sk)
		m[int(index)] = true
		weights[index] = genRandom(10)
		bitlist[index] = genRandom(1)
	}

	var newAggregatedApk bls12381.G1Affine
	for _, pk := range publicKeys {
		newAggregatedApk.Add(&newAggregatedApk, &pk)
	}

	newApkCommitment := genCommitment(publicKeys, weights)
	newMsg, err := bls12381.HashToG2([]byte(newApkCommitment.Bytes()), []byte(DOMAIN_SEPERATOR))
	if err != nil {
		panic(err)
	}

	var tt []string
	for i := 0; i < len(oldPublicKeys); i++ {
		tt = append(tt, oldPublicKeys[i].X.String())
	}

	var newAggregatedSignature bls12381.G2Affine
	for i := 0; i < len(publicKeys); i++ {
		// if new public key is an element of old public key array
		newPublicKey := publicKeys[i]
		isOld := contains(tt, newPublicKey.X.String())

		// if user signed the message
		if bitlist[i].Int64() == 1 {
			var S bls12381.G2Affine
			S.ScalarMultiplication(&newMsg, privateKeys[i])
			newAggregatedSignature.Add(&newAggregatedSignature, &S)
			totalWeight += int(weights[i].Int64())
		}

		if isOld && bitlist[i].Int64() == 1 {
			trustedWeight += int(weights[i].Int64())
		}

	}

	return publicKeys, weights, bitlist, newApkCommitment, newMsg, newAggregatedSignature, trustedWeight
}

func genRandom(exp int64) *big.Int {
	secret, err := rand.Int(rand.Reader, big.NewInt(0).Exp(big.NewInt(2), big.NewInt(exp), nil))
	if err != nil {
		panic(err)
	}
	return secret
}

func genBitlist() []*big.Int {
	var bits []*big.Int
	for i := 0; i < 10; i++ {
		bits = append(bits, genRandom(1))
	}
	return bits
}

func genWeights() []*big.Int {
	var weights []*big.Int
	for i := 0; i < 10; i++ {
		weights = append(weights, genRandom(10))
	}
	return weights
}

func genCommitment(publicKeys []bls12381.G1Affine, weights []*big.Int) *big.Int {
	c := make([]*big.Int, 10)
	for i := 0; i < 10; i++ {
		pp := bls12.NewG1Affine(publicKeys[i])
		if len(pp.X.Limbs) != LIMBS_LENGTH {
			panic("Wrong limbs length")
		}

		arrX := make([]*big.Int, LIMBS_LENGTH)
		arrY := make([]*big.Int, LIMBS_LENGTH)

		for j := 0; j < LIMBS_LENGTH; j++ {
			arrX[j] = pp.X.Limbs[j].(*big.Int)
			arrY[j] = pp.Y.Limbs[j].(*big.Int)
		}

		cmX := PoseidonHash(arrX)
		cmY := PoseidonHash(arrY)
		c[i] = PoseidonHash([]*big.Int{cmX, cmY, weights[i]})
	}

	return PoseidonHash(c)
}

func genPublickey(secret big.Int) bls12381.G1Affine {
	var PK bls12381.G1Affine
	PK.ScalarMultiplicationBase(&secret)
	return PK
}

func bigIntToVariableArray(p []*big.Int) [10]frontend.Variable {
	var r [10]frontend.Variable

	for i := 0; i < 10; i++ {
		r[i] = frontend.Variable(p[i])
	}

	return r
}

func contains(arr []string, val string) bool {
	for _, v := range arr {
		if v == val {
			return true
		}
	}
	return false
}

func PoseidonHash(inputs []*big.Int) *big.Int {
	out, err := pp.Hash(inputs)
	if err != nil {
		panic(err)
	}
	return out
}
