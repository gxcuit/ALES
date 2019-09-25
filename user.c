#include "user.h"

/*
随机生成文件block，用sk生成标签authenticator，保存在f中，
*/
double my_auth_gen(MyFile *f,element_t sk, pairing_t pairing) {
	double t1 = pbc_get_time();

	f->id = "file's ID";//模拟文件的id，这一步对整体影响不大
	element_t h, u_m;
	element_init_G1(h, pairing);
	element_init_G1(u_m, pairing);
	for (int i = 0; i < N; i++)
	{
		//生成文件
		element_init_Zr(f->data[i], pairing);
		element_random(f->data[i]);
		//生成认证器
		element_init_G1(f->authenticator[i], pairing);
		//算hash（id||i）
		char str_hash[1100] = { '\0' };
		char buf[1100] = { '\0' };
		//_itoa(i, buf, 10);
		sprintf(buf, "%d", i);
		strcat(buf, "||");
		strcat(buf, f->id);
		element_from_hash(h, (char *)buf, sizeof(buf));
		element_pow_zn(u_m, u, f->data[i]);//u^m
		element_mul(h, h, u_m);//hash()*u^m
		element_pow_zn(f->authenticator[i], h, sk);//[]^sk =>signature
	}
	//clear
	element_clear(h);
	element_clear(u_m);
	double t2= pbc_get_time();
	return t2 - t1;
}


double my_tagkey_gen(element_t sk_f, element_t pk_f, const char * file_id, pairing_t pairing) {
	double t1 = pbc_get_time();

	//生成tag的私钥
	element_t r,h_z,sk_f_invert;
	element_init_Zr(r, pairing);
	element_init_Zr(sk_f_invert, pairing);
	element_init_Zr(h_z, pairing);
	element_from_hash(h_z, (char *)file_id, sizeof(file_id));
	element_random(r);//随机选r
	element_mul(sk_f, r, h_z);//sk_f=r*h_Z() 即为tag私钥
	
	element_invert(sk_f_invert, sk_f);//sk_f=sk_f^-1
	element_pow_zn(pk_f, g, sk_f_invert);

	element_clear(r);
	element_clear(h_z);
	element_clear(sk_f_invert);

	double t2 = pbc_get_time();
	return t2 - t1;
}

double liu_tagkey_gen(element_t kf, const char * file_id) {
	double t1 = pbc_get_time();

	element_from_hash(kf, (char *)file_id, sizeof(file_id));
	element_t temp;
	element_init_G1(temp, pairing);
	element_pow_zn(temp, g, kf);

	double t2 = pbc_get_time();
	return t2 - t1;
}

double my_rekey_gen(element_t rekey, element_t pk_f, element_t sk, pairing_t pairing) {
	double t1 = pbc_get_time();
	element_pow_zn(rekey, pk_f, sk);
	double t2 = pbc_get_time();
	return t2 - t1;
}

double liu__rekey_gen(element_t d_uf, element_t h_uf, element_t sk, element_t kf, element_t xu, pairing_t pairing) {
	double t1 = pbc_get_time();

	element_t kf_invert,r_uf;
	element_init_Zr(kf_invert,pairing);
	element_init_Zr(r_uf, pairing);
	element_random(r_uf);

	element_invert(kf_invert, kf);
	element_mul(d_uf, sk, kf_invert);
	element_add(d_uf, d_uf, r_uf);

	element_mul(h_uf, r_uf, xu);

	element_clear(kf_invert);
	element_clear(r_uf);

	double t2 = pbc_get_time();
	return t2 - t1;
}