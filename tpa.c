#include "public_header.h"

double chall_gen(Challenge *chall, int random_seeds,pairing_t pairing) {
	double t1 = pbc_get_time();

	srand(random_seeds);
	for (size_t i = 0; i < C; i++)
	{
		chall->i[i] = rand() % N;
		element_init_Zr(chall->vi[i], pairing);
		//myprintf(chall.vi[i]);
		element_set_si(chall->vi[i], rand());
		//printf("%d ",chall.i[i]);
	}
	double t2 = pbc_get_time();

	return t2 - t1;
}

double my_proof_verify(Challenge chall, Proof p, const char * file_id, element_t pk, element_t pk_uf,pairing_t pairing) {
	double t1 = pbc_get_time();
	element_t agg_hash;
	element_init_G1(agg_hash, pairing);

	element_t h_vi;
	element_init_G1(h_vi, pairing);

	element_t temp1, temp2;

	element_init_GT(temp1, pairing);//用来计算e比较的，等式有左边
	element_init_GT(temp2, pairing);//等式右边

	element_t u_m;
	element_init_G1(u_m, pairing);

	for (size_t i = 0; i < C; i++)
	{
		int index = chall.i[i];
		char str_hash[1100] = { '\0' };
		char buf[1100] = { '\0' };
		//_itoa(index, buf, 10);
		sprintf(buf, "%d", index);
		strcat(buf, "||");
		strcat(buf, file_id);
		element_from_hash(h, (char *)buf, sizeof(buf));
		element_pow_zn(h_vi, h, chall.vi[i]);
		element_mul(agg_hash, agg_hash, h_vi);
	}
	pairing_apply(temp1, p.agg_auth, pk_uf, pairing);
	element_pow_zn(u_m, u, p.agg_data);
	element_mul(agg_hash, agg_hash, u_m);
	pairing_apply(temp2, agg_hash, pk, pairing);
	if (!element_cmp(temp1, temp2))
	{
	}
	else {
		return -1;
	}

	//clear
	element_clear(agg_hash);
	element_clear(h_vi);
	element_clear(temp1);
	element_clear(temp2);
	element_clear(u_m);

	double t2 = pbc_get_time();
	return t2 - t1;
}

double my_proof_batch_auditing(Challenge chall, Proof p, const char * file_id, element_t* pk, element_t* pk_uf, pairing_t pairing,int n) {
	double t1 = pbc_get_time();
	element_t agg_hash;
	element_init_G1(agg_hash, pairing);

	element_t h_vi;
	element_init_G1(h_vi, pairing);

	element_t temp1, temp2;

	element_init_GT(temp1, pairing);//用来计算e比较的，等式有左边
	element_init_GT(temp2, pairing);//等式右边

	element_t u_m;
	element_init_G1(u_m, pairing);

	element_t agg_pk, agg_pkf;
	element_init_G1(agg_pk, pairing);//用来计算e比较的，等式有左边
	element_init_G1(agg_pkf, pairing);

	for (size_t i = 0; i <n; i++)
	{
		element_mul(agg_pk, agg_pk, pk[i]);
		element_mul(agg_pkf, agg_pkf, pk_uf[i]);
	}



	for (size_t i = 0; i < C; i++)
	{
		int index = chall.i[i];
		char str_hash[1100] = { '\0' };
		char buf[1100] = { '\0' };
		//_itoa(index, buf, 10);
		sprintf(buf, "%d", index);
		strcat(buf, "||");
		strcat(buf, file_id);
		element_from_hash(h, (char *)buf, sizeof(buf));
		element_pow_zn(h_vi, h, chall.vi[i]);
		element_mul(agg_hash, agg_hash, h_vi);
	}
	pairing_apply(temp1, p.agg_auth, agg_pkf, pairing);
	element_pow_zn(u_m, u, p.agg_data);
	element_mul(agg_hash, agg_hash, u_m);
	pairing_apply(temp2, agg_hash, agg_pk, pairing);
	if (!element_cmp(temp1, temp2))
	{
	}
	else {
		return -1;
	}

	//clear
	element_clear(agg_hash);
	element_clear(h_vi);
	element_clear(temp1);
	element_clear(temp2);
	element_clear(u_m);

	double t2 = pbc_get_time();
	return t2 - t1;
}

double liu_proof_verify(Challenge chall, LiuProof p, const char * file_id, element_t pk, element_t xu, pairing_t pairing) {

	double t1 = pbc_get_time();
	element_invert(xu, xu);
	element_pow_zn(p.agg_auth2, p.agg_auth2, xu);
	element_t agg_hash;
	element_init_G1(agg_hash, pairing);

	element_t h_vi;
	element_init_G1(h_vi, pairing);

	element_t temp1, temp2;

	element_init_GT(temp1, pairing);//用来计算e比较的，等式有左边
	element_init_GT(temp2, pairing);//等式右边

	element_t u_m;
	element_init_G1(u_m, pairing);

	for (size_t i = 0; i < C; i++)
	{
		int index = chall.i[i];
		char str_hash[1100] = { '\0' };
		char buf[1100] = { '\0' };
		//_itoa(index, buf, 10);
		sprintf(buf, "%d", index);
		strcat(buf, "||");
		strcat(buf, file_id);
		element_from_hash(h, (char *)buf, sizeof(buf));
		element_pow_zn(h_vi, h, chall.vi[i]);
		element_mul(agg_hash, agg_hash, h_vi);
	}
	element_div(p.agg_auth1, p.agg_auth1, p.agg_auth2);
	pairing_apply(temp1, p.agg_auth1, g, pairing);
	element_pow_zn(u_m, u, p.agg_data);
	element_mul(agg_hash, agg_hash, u_m);
	pairing_apply(temp2, agg_hash, pk, pairing);
	if (!element_cmp(temp1, temp2))
	{
	}
	else {

		return -1;
	}

	//clear
	element_clear(agg_hash);
	element_clear(h_vi);
	element_clear(temp1);
	element_clear(temp2);
	element_clear(u_m);

	double t2 = pbc_get_time();
	return t2 - t1;
}