package pairing_bls12381

import (
	"log"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

type G2Affine struct {
	X, Y E2
}

type G2Jacobian struct {
	X, Y, Z E2
}

func NewG2Affine(v bls12381.G2Affine) G2Affine {
	return G2Affine{
		X: E2{
			A0: emulated.ValueOf[emulated.BLS12381Fp](v.X.A0),
			A1: emulated.ValueOf[emulated.BLS12381Fp](v.X.A1),
		},
		Y: E2{
			A0: emulated.ValueOf[emulated.BLS12381Fp](v.Y.A0),
			A1: emulated.ValueOf[emulated.BLS12381Fp](v.Y.A1),
		},
	}
}

func G2JacobianDouble(api frontend.API, p G2Jacobian) G2Jacobian {
	// ba, err := emulated.NewField[BLS12381Fp](api)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	et2 := NewExt2(api)
	XX := et2.Square(&p.X)
	YY := et2.Square(&p.Y)
	YYYY := et2.Square(YY)
	ZZ := et2.Square(&p.Z)
	S := et2.Add(&p.X, YY)
	S = et2.Square(S)
	S = et2.Sub(S, XX)
	S = et2.Sub(S, YYYY)
	S = et2.Double(S)
	M := et2.Double(XX)
	M = et2.Add(M, XX)
	p.Z = *et2.Add(&p.Z, &p.Y)
	p.Z = *et2.Square(&p.Z)
	p.Z = *et2.Sub(&p.Z, YY)
	p.Z = *et2.Sub(&p.Z, ZZ)
	T := *et2.Square(M)
	p.X = T
	T = *et2.Double(S)
	p.X = *et2.Sub(&p.X, &T)
	p.Y = *et2.Sub(S, &p.X)
	p.Y = *et2.Mul(&p.Y, M)
	YYYY = et2.Double(YYYY)
	YYYY = et2.Double(YYYY)
	YYYY = et2.Double(YYYY)
	p.Y = *et2.Sub(&p.Y, YYYY)

	return p
}

func G2JacobianConstScalarMul(api frontend.API, a G2Jacobian) G2Jacobian {
	var table [2]G2Jacobian
	var res G2Jacobian

	table[0] = a
	table[1] = G2JacobianDouble(api, table[0])
	res = G2JacobianAddAssign(api, table[1], table[0])

	for j := 1; j < 32; j++ {
		res = G2JacobianDouble(api, res)
		res = G2JacobianDouble(api, res)

		if j == 1 {
			res = G2JacobianAddAssign(api, res, table[0])
		} else if j == 3 {
			res = G2JacobianAddAssign(api, res, table[1])
		} else if j == 7 {
			res = G2JacobianAddAssign(api, res, table[0])
		} else if j == 23 {
			res = G2JacobianAddAssign(api, res, table[0])
		}
	}
	return res
}

func G1NotZero(api frontend.API, x BaseEl) frontend.Variable {
	ba, err := emulated.NewField[emulated.BLS12381Fp](api)
	if err != nil {
		log.Fatal(err)
	}
	x = *ba.Reduce(&x)
	bs := ba.ToBits(&x)
	var isNotZero frontend.Variable
	isNotZero = 0
	for _, b := range bs {
		isNotZero = api.Or(isNotZero, b)
	}
	return isNotZero
}

func E2NotZero(api frontend.API, x E2) frontend.Variable {
	a0NotZero := G1NotZero(api, x.A0)
	a1NotZero := G1NotZero(api, x.A1)
	return api.Or(a0NotZero, a1NotZero)
}

func G1NotEqual(api frontend.API, x, y BaseEl) frontend.Variable {
	ba, err := emulated.NewField[emulated.BLS12381Fp](api)
	if err != nil {
		log.Fatal(err)
	}
	x = *ba.Reduce(&x)
	y = *ba.Reduce(&y)
	xBits := ba.ToBits(&x)
	yBits := ba.ToBits(&y)

	var notEqual frontend.Variable
	notEqual = 0
	for i, b := range xBits {
		notEqual = api.Or(notEqual, api.Xor(b, yBits[i]))
	}

	return notEqual
}

func E2NotEqual(api frontend.API, x, y E2) frontend.Variable {
	var a0NotEqual, a1NotEqual frontend.Variable
	a0NotEqual = G1NotEqual(api, x.A0, y.A0)
	a1NotEqual = G1NotEqual(api, x.A1, y.A1)
	return api.Or(a0NotEqual, a1NotEqual)
}

// G2Affine
func G2JacobianAddAssign(api frontend.API, p, a G2Jacobian) G2Jacobian {
	// ba, err := emulated.NewField[BLS12381Fp](api)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	et2 := NewExt2(api)

	pZNotZero := E2NotZero(api, p.Z)
	res1 := a
	aZNotZero := E2NotZero(api, a.Z)
	res2 := p

	Z1Z1 := et2.Square(&a.Z)
	Z2Z2 := et2.Square(&p.Z)
	U1 := et2.Mul(&a.X, Z2Z2)
	U2 := et2.Mul(&p.X, Z1Z1)
	S1 := et2.Mul(&a.Y, &p.Z)
	S1 = et2.Mul(S1, Z2Z2)
	S2 := et2.Mul(&p.Y, &a.Z)
	S2 = et2.Mul(S2, Z1Z1)

	U1NotEqualU2 := E2NotEqual(api, *U1, *U2)
	S1NotEqualS2 := E2NotEqual(api, *S1, *S2)
	pNotEqualA := api.Or(U1NotEqualU2, S1NotEqualS2)
	res3 := G2JacobianDouble(api, p)

	H := et2.Sub(U2, U1)
	I := et2.Double(H)
	I = et2.Square(I)
	J := et2.Mul(H, I)
	r := et2.Sub(S2, S1)
	r = et2.Double(r)
	V := et2.Mul(U1, I)
	p.X = *et2.Square(r)
	p.X = *et2.Sub(&p.X, J)
	p.X = *et2.Sub(&p.X, V)
	p.X = *et2.Sub(&p.X, V)
	p.Y = *et2.Sub(V, &p.X)
	p.Y = *et2.Mul(&p.Y, r)
	S1 = et2.Mul(S1, J)
	S1 = et2.Double(S1)
	p.Y = *et2.Sub(&p.Y, S1)
	p.Z = *et2.Add(&p.Z, &a.Z)
	p.Z = *et2.Square(&p.Z)
	p.Z = *et2.Sub(&p.Z, Z1Z1)
	p.Z = *et2.Sub(&p.Z, Z2Z2)
	p.Z = *et2.Mul(&p.Z, H)

	res := p

	res.X = *et2.Select(pNotEqualA, &res.X, &res3.X)
	res.Y = *et2.Select(pNotEqualA, &res.Y, &res3.Y)
	res.Z = *et2.Select(pNotEqualA, &res.Z, &res3.Z)

	res.X = *et2.Select(aZNotZero, &res.X, &res2.X)
	res.Y = *et2.Select(aZNotZero, &res.Y, &res2.Y)
	res.Z = *et2.Select(aZNotZero, &res.Z, &res2.Z)

	res.X = *et2.Select(pZNotZero, &res.X, &res1.X)
	res.Y = *et2.Select(pZNotZero, &res.Y, &res1.Y)
	res.Z = *et2.Select(pZNotZero, &res.Z, &res1.Z)

	return res
}

func G2JacobianNeg(api frontend.API, p G2Jacobian) G2Jacobian {
	// ba, err := emulated.NewField[emulated.BLS12381Fp](api)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	et2 := NewExt2(api)
	p.Y = *et2.Neg(&p.Y)
	return p
}

// p - p1
func G2JacobianSubAssign(api frontend.API, p, p1 G2Jacobian) G2Jacobian {
	// ba, err := emulated.NewField[BLS12381Fp](api)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	et2 := NewExt2(api)

	p1.Y = *et2.Neg(&p1.Y)
	return G2JacobianAddAssign(api, p, p1)
}

func G2JacobianPsi(api frontend.API, a G2Jacobian) G2Jacobian {
	// ba, err := emulated.NewField[BLS12381Fp](api)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	et2 := NewExt2(api)

	var uA0, uA1, vA0, vA1 fp.Element

	uA0.SetString("0")
	uA1.SetString("4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939437")
	vA0.SetString("2973677408986561043442465346520108879172042883009249989176415018091420807192182638567116318576472649347015917690530")
	vA1.SetString("1028732146235106349975324479215795277384839936929757896155643118032610843298655225875571310552543014690878354869257")
	u := E2{
		A0: emulated.ValueOf[emulated.BLS12381Fp](uA0),
		A1: emulated.ValueOf[emulated.BLS12381Fp](uA1),
	}
	v := E2{
		A0: emulated.ValueOf[emulated.BLS12381Fp](vA0),
		A1: emulated.ValueOf[emulated.BLS12381Fp](vA1),
	}

	var p G2Jacobian
	p.X = a.X
	p.Y = a.Y
	p.Z = a.Z
	p.X = *et2.Conjugate(&p.X)
	p.X = *et2.Mul(&p.X, &u)
	p.Y = *et2.Conjugate(&p.Y)
	p.Y = *et2.Mul(&p.Y, &v)
	p.Z = *et2.Conjugate(&p.Z)
	return p
}

// ClearCofactor maps a point in curve to r-torsion
func G2ClearCofactor(api frontend.API, a G2Affine) *G2Affine {
	var res *G2Affine
	// ba, err := emulated.NewField[BLS12381Fp](api)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	et2 := NewExt2(api)
	// https://eprint.iacr.org/2017/419.pdf, 4.1

	// use jac
	_a := GetG2JacFromG2Affine(api, &a)
	_xg := G2JacobianConstScalarMul(api, *_a)
	_xg = G2JacobianNeg(api, _xg)
	_xxg := G2JacobianConstScalarMul(api, _xg)
	_xxg = G2JacobianNeg(api, _xxg)
	xg := GetG2AffineFromG2Jac(api, &_xg)
	xxg := GetG2AffineFromG2Jac(api, &_xxg)

	// use 377 method
	/*xg := G2ConstScalarMul(api, a)
	xg = G2Neg(api, *xg)
	xxg := G2ConstScalarMul(api, *xg)
	xxg = G2Neg(api, *xxg)*/

	// use g2Affine
	/*xg := G2ConstScalarMulV2(api, a)
	xg = *G2Neg(api, xg)
	xxg := G2ConstScalarMulV2(api, xg)
	xxg = *G2Neg(api, xxg)*/

	res = G2SubAssign(api, *xxg, *xg)
	res = G2SubAssign(api, *res, a)

	t := G2SubAssign(api, *xg, a)
	t = G2Psi(api, *t)

	res = G2AddAssign(api, *res, *t)
	t = G2Double(api, a)

	var thirdRootOneG1 fp.Element
	thirdRootOneG1.SetString("4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939436")

	trog1 := emulated.ValueOf[emulated.BLS12381Fp](thirdRootOneG1)
	t.X = *et2.MulByElement(&t.X, &trog1)
	res = G2SubAssign(api, *res, *t)

	return res
}

func GetG2JacFromG2Affine(api frontend.API, Q *G2Affine) *G2Jacobian {
	// ba, err := emulated.NewField[BLS12381Fp](api)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	et2 := NewExt2(api)
	g2NotInfinity := G2AffineNotInfinity(api, Q)

	z := *et2.Select(g2NotInfinity, et2.One(), et2.Zero())
	x := *et2.Select(g2NotInfinity, &Q.X, et2.One())
	y := *et2.Select(g2NotInfinity, &Q.Y, et2.One())

	return &G2Jacobian{
		X: x,
		Y: y,
		Z: z,
	}
}

func G2AffineNotInfinity(api frontend.API, a *G2Affine) frontend.Variable {
	xNotZero := E2NotZero(api, a.X)
	yNotZero := E2NotZero(api, a.Y)
	return api.Or(xNotZero, yNotZero)
}

func GetG2AffineFromG2Jac(api frontend.API, Q *G2Jacobian) *G2Affine {
	// ba, err := emulated.NewField[BLS12381Fp](api)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	et2 := NewExt2(api)

	res1 := &G2Affine{
		X: *et2.Zero(),
		Y: *et2.Zero(),
	}
	a := et2.Inverse(&Q.Z)
	b := et2.Square(a)
	res2 := &G2Affine{}
	res2.X = *et2.Mul(&Q.X, b)
	res2.Y = *et2.Mul(&Q.Y, b)
	res2.Y = *et2.Mul(&res2.Y, a)
	jacZNotZero := E2NotZero(api, Q.Z)

	final := &G2Affine{}
	final.X = *et2.Select(jacZNotZero, &res2.X, &res1.X)
	final.Y = *et2.Select(jacZNotZero, &res2.Y, &res1.Y)
	return final
}

// p - p1
func G2SubAssign(api frontend.API, p, p1 G2Affine) *G2Affine {
	// ba, err := emulated.NewField[BLS12381Fp](api)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	et2 := NewExt2(api)

	p1.Y = *et2.Neg(&p1.Y)
	return G2AddAssign(api, p, p1)
}

// Affine
// AddAssign add p1 to p and return p
func G2AddAssign(api frontend.API, p, p1 G2Affine) *G2Affine {
	// ba, err := emulated.NewField[BLS12381Fp](api)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	et2 := NewExt2(api)

	n := et2.Sub(&p1.Y, &p.Y)
	d := et2.Sub(&p1.X, &p.X)

	// TODO use hint?
	l := et2.DivUnchecked(n, d)
	xr := et2.Square(l)
	xr = et2.Sub(xr, &p1.X)
	xr = et2.Sub(xr, &p.X)

	yr := et2.Sub(&p.X, xr)
	yr = et2.Mul(l, yr)
	yr = et2.Sub(yr, &p.Y)

	return &G2Affine{
		X: *xr,
		Y: *yr,
	}
}

func G2Psi(api frontend.API, a G2Affine) *G2Affine {
	// ba, err := emulated.NewField[BLS12381Fp](api)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	et2 := NewExt2(api)

	var uA0, uA1, vA0, vA1 fp.Element

	uA0.SetString("0")
	uA1.SetString("4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939437")
	vA0.SetString("2973677408986561043442465346520108879172042883009249989176415018091420807192182638567116318576472649347015917690530")
	vA1.SetString("1028732146235106349975324479215795277384839936929757896155643118032610843298655225875571310552543014690878354869257")
	u := E2{
		A0: emulated.ValueOf[emulated.BLS12381Fp](uA0),
		A1: emulated.ValueOf[emulated.BLS12381Fp](uA1),
	}
	v := E2{
		A0: emulated.ValueOf[emulated.BLS12381Fp](vA0),
		A1: emulated.ValueOf[emulated.BLS12381Fp](vA1),
	}

	var p G2Affine
	p.X = a.X
	p.Y = a.Y
	p.X = *et2.Conjugate(&p.X)
	p.X = *et2.Mul(&p.X, &u)
	p.Y = *et2.Conjugate(&p.Y)
	p.Y = *et2.Mul(&p.Y, &v)
	return &p
}

// Double compute 2*p1, assign the result to p and return it
// Only for curve with j invariant 0 (a=0).
func G2Double(api frontend.API, p1 G2Affine) *G2Affine {
	// ba, err := emulated.NewField[BLS12381Fp](api)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	et2 := NewExt2(api)

	n := et2.Square(&p1.X)
	nP := emulated.ValueOf[emulated.BLS12381Fp](new(big.Int).SetUint64(3))
	n = et2.MulByElement(n, &nP)

	t := emulated.ValueOf[emulated.BLS12381Fp](new(big.Int).SetUint64(2))
	d := et2.MulByElement(&p1.Y, &t)

	// !!!
	l := et2.DivUnchecked(n, d)

	xr := et2.Square(l)
	xr = et2.Sub(xr, &p1.X)
	xr = et2.Sub(xr, &p1.X)

	yr := et2.Sub(&p1.X, xr)
	yr = et2.Mul(l, yr)
	yr = et2.Sub(yr, &p1.Y)

	return &G2Affine{
		X: *xr,
		Y: *yr,
	}
}
