#pragma once
#include "public_header.h"
double proof_gen(Proof *p, MyFile f, Challenge chall, pairing_t pairing);
double liu_proof_gen(LiuProof *p, MyFile f, element_t d_fu, element_t h_fu, Challenge chall, pairing_t pairing);