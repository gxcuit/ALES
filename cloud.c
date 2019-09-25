#include "cloud.h"

double proof_gen(Proof *p, MyFile f, Challenge chall,pairing_t pairing) {
	double t1= pbc_get_time();

	element_t vi_mi, sigi_vi;
	element_init_Zr(vi_mi, pairing);
	element_init_G1(sigi_vi, pairing);
	element_init_Zr(p->agg_data, pairing);
	element_init_G1(p->agg_auth, pairing);

	for (size_t i = 0; i < C; i++)
	{
		int index = chall.i[i];
		element_mul(vi_mi, chall.vi[i], f.data[index]);
		element_add(p->agg_data, p->agg_data, vi_mi);
		element_pow_zn(sigi_vi, f.authenticator[index], chall.vi[i]);
		element_mul(p->agg_auth, p->agg_auth, sigi_vi);
	}
	//clear
	element_clear(vi_mi);
	element_clear(sigi_vi);

	double t2 = pbc_get_time();
	return t2 - t1;
}

double liu_proof_gen(LiuProof *p, MyFile f,element_t d_fu,element_t h_fu, Challenge chall, pairing_t pairing) {
	double t1 = pbc_get_time();

	element_t vi_mi, sigi_vi,dv,hv,sigi1_vi;
	element_init_Zr(vi_mi, pairing);
	element_init_Zr(dv, pairing);
	element_init_Zr(hv, pairing);
	element_init_G1(sigi_vi, pairing);
	element_init_G1(sigi1_vi, pairing);
	element_init_Zr(p->agg_data, pairing);
	element_init_G1(p->agg_auth1, pairing);
	element_init_G1(p->agg_auth2, pairing);


	for (size_t i = 0; i < C; i++)
	{
		int index = chall.i[i];
		element_mul(vi_mi, chall.vi[i], f.data[index]);
		element_add(p->agg_data, p->agg_data, vi_mi);
		element_mul(dv, d_fu, chall.vi[i]);
		element_pow_zn(sigi_vi, f.authenticator[index], dv);
		element_mul(p->agg_auth1, p->agg_auth1, sigi_vi);

		element_mul(hv, h_fu, chall.vi[i]);
		element_pow_zn(sigi1_vi, f.authenticator[index], hv);
		element_mul(p->agg_auth2, p->agg_auth2, sigi1_vi);
	}
	//clear
	element_clear(vi_mi);
	element_clear(sigi_vi);
	element_clear(dv);
	element_clear(hv);
	element_clear(sigi1_vi);

	double t2 = pbc_get_time();
	return t2 - t1;
}