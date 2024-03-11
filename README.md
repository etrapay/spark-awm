![sparky](https://github.com/etrapay/spark-awm/assets/69128891/dd8cb6e3-e9f2-41c6-b193-652c349cd4d0)
# Spark for AWM

Spark is an extension to the Avalanche Warp Messaging (AWM) protocol, utilizing zero-knowledge proofs (zk-SNARKs) for more independent subnet communication. It aims to eliminate the need for an external ledger to collect validator public keys (P-chain), allowing subnet validators to verify cross-chain transactions with just SNARK proofs. Spark addresses the challenge of frequent and unpredictable validator set changes by enabling new validator sets to sign their own commitments, which relayers use to construct SNARK proofs for validator set rotations. 

For more details, you can visit the provided link:

https://leeward-weaver-c7c.notion.site/Spark-87367b4980c449cea7005762f949075d

## Getting Started

### Prerequisites

You need following dependencies for setup:

- `Golang >= 1.21.x `

### Installation

1. Clone the repo
   ```sh
   git clone git@github.com:etrapay/spark-awm.git
   ```
2. Install golang packages

   ```sh
   go get .
   ```



### Run Tests

Circuit tests:

```
cd spark/ && go test
```

## Specifications

All tests are conducted on a Macbook Pro (M1 Pro CPU), using Gnark with Groth16 over BN254.
Both circuits are designed for 10 validators, but this can be modified easily.

- Number of constraints:

  -   Transaction circuit: 4887411
  -   Rotate circuit: 5933281 

- Generate Proof:

  -   Transaction circuit: 23.66s (0.39m)
  -   Rotate circuit: 28.72s (0.47s)


- One-time Setup (pk,vk):

  -   Transaction circuit: 492.42s (8.21m)
  -   Rotate circuit: 527.14s (8.78m)