# Design decisions

## Stage 1

### 1. Leaf vs internal domain separation
Choice:
Why:

### 2. Odd node counts (duplicate last / promote / pad to power of two)
Choice:
Why (see CVE-2012-2459):

### 3. Empty-tree root
Choice:
Why:

### 4. Index argument vs per-step direction bit in Proof
Choice:
What a malicious prover gains from the rejected option:

### 5. Is `Hasher` generality worth it, given the MPT hardcodes Keccak-256?
Argument:

## prove_absence failure analysis
Where it breaks:
What an adversarial prover can do that an honest one cannot:
