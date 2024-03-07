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

All tests are done on AWS EC2 c6a.8xlarge (32vCPU 64GiB Ram) instance using gnark library with Groth16 over BN254 curve.
Both circuits are tested for 10 validators.

- Number of constraints:

  -   Transaction circuit: 4887411
  -   Rotate circuit: 5933281
    
- Generate witness:

  -   Transaction circuit: -
  -   Rotate circuit: 328.979µs

- Generate Proof:

  -   Transaction circuit: -
  -   Rotate circuit: 118.88ms 


- One-time Setup (pk,vk):

  -   Transaction circuit: - 
  -   Rotate circuit: 289.32s (4.82m)
