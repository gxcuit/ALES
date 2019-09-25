#pragma once
double chall_gen(Challenge *chall, int random_seeds, pairing_t pairing);
double my_proof_verify(Challenge chall, Proof p, const char * file_id, element_t pk, element_t pk_uf, pairing_t pairing);
double liu_proof_verify(Challenge chall, LiuProof p, const char * file_id, element_t pk, element_t xu, pairing_t pairing);
double my_proof_batch_auditing(Challenge chall, Proof p, const char * file_id, element_t* pk, element_t* pk_uf, pairing_t pairing, int n);