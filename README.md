# Twisted ElGamal Non-Interactive Schnorr Chaum-Pedersen protocol implementation.

Using Twisted ElGamal encryption, this library implements a Non-Interactive version of the Chaum-Pedersen protocol using Fiat-Shamir Heuristics for Zero Knowledge, over an abstract cyclic group (G,+) using Ristretto Group with Curve25519. The library used in this implementation for the construction of the Ristretto Group is curve25519-dalek.

## The problem

### Twisted ElGamal Non-Interactive Chaum/Pedersen protocol
Consider cyclic Group $(\mathcal{G}, +)$ of prime order q with generator $G$ and $H$ with fixed and secret domain separator (hidden dependence).\
For Key Generation $x \xleftarrow{\\$} \mathbb{Z}_q, Y = x G$,

With message in scalar form m, it encodes $M = m G \in \mathcal{G}$.

### Encryption is as follows:
$k \xleftarrow{\\$} Z_q$,\
$`C_1 = k G, C_2 = M + k Y`$ \
Ciphertext $CT = (C_1, C_2)$

### Decryption
Compute $`S' = x C_1 = x k G = k x G = k Y`$\
$`C_2 - S' = M + k Y - k Y = M = m G`$\
Then solves the discrete logarithm (theoretical) of $M = m G$ to recover $m$

### Goal
Given a Public Key $(Y)$, a Commitment $(C_m)$ and a Ciphertext $(C_1, C_2)$ prove that there exists scalars $m$, $r$ and $k$ such that:\
$`C_m = m G + r H`$\
$`C_1 = k G`$\
$`C_2 = M + k Y`$\
This statement hides $M = m G$ with domain separated $H$ and randomly generated $r$, while encrypting the same original $m$ of the message.
 
### Statement and witnesses:
Public: $`G, H, Y, C_m, C_1, C_2`$\
Witnesses: $`m, r, k \in Z_q`$

$`C_m = m G + r H`$\
$`C_1 = k G`$\
$`C_2 = M + k Y`$

### Multi-relation Sigma Protocol (P, V):
Prover P chooses random $`\alpha, \beta, \gamma \xleftarrow{\tiny \$} Z_q`$\
and defines:\
$`T_1 = \gamma G`$\
$`T_2 = \alpha G + \gamma Y`$\
$`T_3 = \alpha G + \beta H`$

Computes Fiat-Shamir challenge for the Non-Interactive construction:\
$`e = Hash(G, H, Y, C_m, C_1, C_2, T_1, T_2, T_3)`$
 
and responds with scalars:\
$`s_m = \alpha + e m, s_r = \beta + e r, s_k = \gamma + e k`$
 
Validator V checks:\
$`s_k G \stackrel{\text{\tiny ?}}{=} T_1 + e C_1`$\
$`s_m G + s_kY \stackrel{\text{\tiny ?}}{=} T_2 + e C_2`$\
$`s_m G + S_rH \stackrel{\text{\tiny ?}}{=} T_3 + e C_m`$

and accepts if they all hold, otherwise it rejects

### Properties:

- Completeness: For mathematical proof, replace with generic variables
- Special soundness: Two accepting transcripts with same initial $T_1, T_2, T_3$ and different challenges extracts the openings $(m, r, k)$
- Honest validator zero-knowledge (HVZK): From an accepting transcript, we can simulate $T_1, T_2, T_3$ from totally random $s_m, s_r, s_k \xleftarrow{\\$} Z_q$ and post hoc $e$, proving no aditional information is leaked.
- Non-Interactive zero-knowledge (NIZK): Given by HVZK and the Fiat-Shamir heuristics.

### Sigma Protocol (P,V) for Verifiable Decryption (Chaum-Pedersen):
 Proves that $log_G(C1) = log_Y(C2 - M)$
 
- Prover P choose $`t \xleftarrow{\tiny \$} Z_q`$ and sends:

$`A = t G, B = t Y`$

- Validator V sends a challenge $`e \xleftarrow{\tiny \$} Z_q`$

- Prover finally sends:

$`z = t + e k`$

- V verifies:

$`z G \stackrel{\text{\tiny ?}}{=} A + e C_1`$\
$`z Y \stackrel{\text{\tiny ?}}{=} B + (C_2 - M)`$

If both conditions hold, accepts, otherwise rejects.

 Completeness, special soundness, HVZK and NIZK given by the Multi-relation Sigma Protocol with Fiat-Shamir heuristics.
