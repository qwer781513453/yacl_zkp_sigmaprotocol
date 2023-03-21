# Introduction

The resource implements the struct of **Non-interactive Sigma Protocol** in SigmaProtocol.h, which includes five main part:

- SigmaProtocolCommonInput: consists of public parameters used in the protocol
- SigmaProtocolResponseMsgShort & SigmaProtocolResponseMsgBatch:  the two correspond to two different implementation ways of sigma protocol
- SigmaProtocolProver:  SigmaProtocolProverShort & SigmaProtocolProverBatch
- SigmaProtocolVerifier:  SigmaProtocolVerifierShort & SigmaProtocolVerifierBatch

- function SigmaProtocolGetchallenge: used to compute the challenge message in SigmaProtocol

The resource implements four sigma protocols:

- Schnorr protocol:  proving knowledge of the discrete logarithm $w$ of a point $Y$ in base $G$
- DlogEquality protocol: proving equality of the known discrete logarithm $w$ of $Y_1$ in base $G$ and $Y_2$
- PedersenCommitmentOpen: proving knowledge of a valid opening of a Pedersen commitment
- Diffie-Hellman triple Protocol: proving knowledge of the exponents of a valid Diffie-Hellman triple