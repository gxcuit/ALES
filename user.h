#pragma once
#include "public_header.h"
double my_auth_gen(MyFile *f, element_t sk, pairing_t pairing);
double my_tagkey_gen(element_t sk_f, element_t pk_f, const char * file_id, pairing_t pairing);
double my_rekey_gen(element_t rekey, element_t pk_f, element_t sk, pairing_t pairing);

double liu_tagkey_gen(element_t kf, const char * file_id);
double liu__rekey_gen(element_t d_uf, element_t h_uf, element_t sk, element_t kf, element_t xu, pairing_t pairing);
