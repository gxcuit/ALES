// pbcTest.cpp : 定义控制台应用程序的入口点。
#include "tool.h"
#include "public_header.h"
#include "user.h"
#include "tpa.h"
#include "cloud.h"









void init(int argc, char **argv) {
	pbc_demo_pairing_init(pairing, argc, argv);
	printf("pairing_length_in_bytes_Zr:%d ;G1:%d ;G2:%d ;GT:%d\n", pairing_length_in_bytes_Zr(pairing), pairing_length_in_bytes_G1(pairing), pairing_length_in_bytes_G2(pairing), pairing_length_in_bytes_GT(pairing));
	//初始化public_header中的公共参数
	element_init_G1(h, pairing);
	element_init_G1(u, pairing);
	element_init_G2(g, pairing);
	element_init_Zr(sk, pairing);
	element_init_G2(pk, pairing);
	element_random(g);
	element_random(u);
	//计算用户的私钥sk公钥pk
	element_random(sk);
	element_pow_zn(pk, g, sk);//公钥
}

void clear() {
	element_clear(h);
	element_clear(u);
	element_clear(g);
	element_clear(sk);
	element_clear(pk);
	pairing_clear(pairing);
	
}

int my_scheme(int argc, char **argv) {

	init(argc, argv);
	double tt = 0, tt2 = 0;

	//文件操作
	FILE *fp = fopen("log_my_scheme.txt", "a+");
	//获取当前时间，便于打印log
	time_t t;
	time(&t);
	char des[100] = { '\0' };
	char *ti = ctime(&t);
	strncpy(des, ti, strlen(ti) - 1);
	//打印log时间信息
	fprintf(fp, "INFO(%s) :\n", des);
	printf("INFO(%s) :\n", des);

	//自己协议中用到的sk_f,pk_f,pk_uf
	element_t pk_uf, sk_f, pk_f;
	element_init_Zr(sk_f, pairing);
	element_init_G1(pk_uf, pairing);
	element_init_G1(pk_f, pairing);

	//---生成文件---
	MyFile f;
	f.id = "file's ID";//模拟文件的id，这一步对整体影响不大

	//tag key gen
	tt=my_tagkey_gen(sk_f, pk_f, f.id, pairing);
	//打印 tag key 生成时间
	fprintf(fp, "(1)tag_key__gen_time is %f\n", tt);
	printf("(1)tag_key__gen_time is %f\n", tt);
	tt = -1000;

	//re key gen
	tt=my_rekey_gen(pk_uf, pk_f, sk, pairing);
	//打印 tag key 生成时间
	fprintf(fp, "(2)re_key__gen_time is %f\n", tt);
	printf("(2)re_key__gen_time is %f\n", tt);
	tt = -1000;

	//生成标签
	tt = my_auth_gen(&f, sk_f, pairing);
	//打印 tag 生成时间
	fprintf(fp, "(3)auth_gen_time for %d blocks is %f\n", N, tt);
	printf("(3)auth_gen_time for %d blocks is %f\n", N, tt);
	tt = -1000;

	//---生成challenge---
	//这里只生成seeds
	srand(time(NULL));
	int seeds = rand();
	Challenge chall;


	//生成proof，要先根据seeds生成chall
	Proof p;
	tt = chall_gen(&chall, seeds, pairing);
	tt2 = proof_gen(&p, f, chall, pairing);
	//打印 proof 生成时间
	fprintf(fp, "(4)proof_gen_time for %d checking-blocks is %f\n", C, tt2 );
	printf("(4)proof_gen_time for %d checking-blocks is %f\n", C, tt2);
	tt = -1000;
	tt2 = -1000;

	//验证proof，要先根据seeds生成chall
	memset(&chall, 0, sizeof(chall));
	tt = chall_gen(&chall, seeds, pairing);
	tt2 = my_proof_verify(chall, p, f.id, pk, pk_uf, pairing);
	if (tt2 == -1) {
		//验证失败
		fprintf(fp, "not valid!\n-----failed!-----\n");
		printf("not valid!\n-----failed-----\n");
		return -1;
	}
	//打印 proof 验证时间
	fprintf(fp, "(5)proof_verifacation_time for %d cheching-blocks is %f\n-----individual auditing valid!-----\n", C, tt + tt2);
	printf("(5)proof_verifacation_time for %d checking-blocks is %f\n-----individual auditing valid-----\n", C, tt + tt2);
	tt = -1000;
	tt2 = -1000;

	//batch auditing
	memset(&chall, 0, sizeof(chall));
	tt2 = chall_gen(&chall, seeds, pairing);
	element_t sk_set[TASK],pk_set[TASK],pk_uf_set[TASK];
	for (size_t i = 0; i < TASK; i++)
	{
		element_init_Zr(sk_set[i], pairing);
		element_init_G1(pk_set[i], pairing);
		element_init_G1(pk_uf_set[i], pairing);

		element_random(sk_set[i]);
		element_pow_zn(pk_set[i], g, sk_set[i]);
		element_pow_zn(pk_uf_set[i], pk_f, sk_set[i]);
	}
	tt = my_proof_batch_auditing(chall, p, f.id, pk_set, pk_uf_set, pairing, TASK);
	if (tt == -1) {
		//验证失败
		fprintf(fp, "not valid!\n-----failed!-----\n");
		printf("not valid!\n-----failed-----\n");
		return -1;
	}
	fprintf(fp, "(6)batch auditing time for %d TASK is %f\n-----batch auditing valid!-----\n", TASK, tt+tt2 );
	printf("(6)batch auditing time for %d TASK is %f\n-----batch auditing valid!-----\n", TASK, tt+tt2 );
	tt = -1000;
	tt2 = -1000;

	//自己协议自定义clear
	element_clear(pk_uf);
	element_clear(sk_f);
	element_clear(pk_f);
	//file 和challclear
	for (size_t i = 0; i < N; i++)
	{
		element_clear(f.data[i]);
		element_clear(f.authenticator[i]);
	}
	for (size_t i = 0; i < C; i++)
	{
		element_clear(chall.vi[i]);
	}
	//公共参数clear
	clear();
	fclose(fp);
	return 0;
}

int liu_scheme(int argc, char **argv) {
	init(argc, argv);
	double tt = -500, tt2 = 0;

	//文件操作
	FILE *fp = fopen("log_liu_scheme.txt", "a+");
	//获取当前时间，便于打印log
	time_t t;
	time(&t);
	char des[100] = { '\0' };
	char *ti = ctime(&t);
	strncpy(des, ti, strlen(ti) - 1);
	//打印log时间信息
	fprintf(fp, "INFO(%s) :\n", des);
	printf("INFO(%s) :\n", des);

	element_t kf ,d_uf,  h_uf,xu;

	element_init_Zr(kf, pairing);
	element_init_Zr(d_uf, pairing);
	element_init_Zr(h_uf, pairing);
	element_init_Zr(xu, pairing);
	element_random(xu);
	//---生成文件---
	MyFile f;
	f.id = "file's ID";//模拟文件的id，这一步对整体影响不大

	
	tt=liu_tagkey_gen(kf, f.id);
	fprintf(fp, "(1)liu_tagkey_gen time is %f\n",  tt );
	printf("(1)liu_tagkey_gen  time is %f\n", tt );
	tt = -1000;

	tt=liu__rekey_gen(d_uf, h_uf, sk, kf, xu, pairing);
	fprintf(fp, "(2)liu__rekey_gen time is %f\n", tt);
	printf("(2)liu__rekey_gen  timeis %f\n", tt);
	tt = -1000;


	tt=my_auth_gen(&f, kf, pairing);
	fprintf(fp, "(3)auth_gen_time for %d blocks is %f\n", N, tt);
	printf("(3)auth_gen_time for %d blocks is %f\n", N, tt);
	tt = -1000;

	srand(time(NULL));
	int seeds = rand();
	Challenge chall;
	chall_gen(&chall, seeds, pairing);

	LiuProof p;
	tt=liu_proof_gen(&p, f, d_uf, h_uf, chall, pairing);
	fprintf(fp, "(4)liu_proof_gen time for %d checking-blocks is %f\n", C, tt );
	printf("(4)liu_proof_gen time for %d checking-blocks is %f\n", C, tt );

	tt =liu_proof_verify(chall, p, f.id, pk, xu, pairing);
	if (tt == -1) {
		//验证失败
		fprintf(fp, "not valid!\n-----failed!-----\n");
		printf("not valid!\n-----failed-----\n");
		return -1;
	}
	//打印 proof 验证时间
	fprintf(fp, "(5)liu_proof_verify_time for %d cheching-blocks is %f\n-----valid!-----\n", C, tt );
	printf("(5)liu_proof_verify_time for %d checking-blocks is %f\n-----valid-----\n", C, tt );
	tt = -1000;

	element_clear(kf);
	element_clear(d_uf);
	element_clear(h_uf);
	element_clear(xu);

	clear();
	fclose(fp);
	return 0;
}







/*
带验证的
*/
//int filebls(int argc, char **argv) {
//
//	pairing_t pairing;
//	pbc_demo_pairing_init(pairing, argc, argv);
//	element_t g, h, sk, pk, sig, temp1, temp2, m, u_m, u, agg_data, agg_auth,agg_hash;
//	element_init_G1(sig, pairing);
//	element_init_G1(h, pairing);
//	element_init_G1(u, pairing);
//	element_init_G1(u_m, pairing);
//	element_init_G2(g, pairing);
//	element_init_Zr(sk, pairing);
//
//	//element_init_Zr(m, pairing);
//	element_init_G2(pk, pairing);
//	element_init_GT(temp1, pairing);//用来计算e比较的，等式有左边
//	element_init_GT(temp2, pairing);//等式右边
//	element_random(sk);
//	element_random(g);
//	element_random(u);
//	//element_random(m);
//
//	element_pow_zn(pk, g, sk);//公钥
//
//	//---生成文件---
//
//	MyFile f;
//	f.id = "file's ID";//模拟文件的id，这一步对整体影响不大
//
//	for (size_t i = 0; i < N; i++)
//	{
//		//生成文件
//		element_init_Zr(f.data[i], pairing);
//		element_random(f.data[i]);
//
//		//生成认证器
//		element_init_G1(f.authenticator[i], pairing);
//		//算hash（id||i）
//		char str_hash[1100] = { '\0' };
//		char buf[1100] = {'\0'};
//		_itoa(i, buf, 10);
//		strcat(buf, "||");
//		strcat(buf, f.id);
//		element_from_hash(h, (char *)buf, sizeof(buf));
//		//myprintf(h);
//		element_pow_zn(u_m, u, f.data[i]);//u^m
//		element_mul(h, h, u_m);//hash()*u^m
//		element_pow_zn(f.authenticator[i], h, sk);//[]^sk =>signature
//
//	}
//
//	//---生成challenge---
//	srand(time(NULL));
//	int seeds = rand();
//	srand(seeds);
//	Challenge chall;
//	for (size_t i = 0; i < C; i++)
//	{
//		chall.i[i] = rand() % N;
//		element_init_Zr(chall.vi[i], pairing);
//		//myprintf(chall.vi[i]);
//		element_set_si(chall.vi[i], rand());
//		//printf("%d ",chall.i[i]);
//
//	}
//	//---计算叠加---
//	element_init_Zr(agg_data, pairing);
//	element_init_G1(agg_auth, pairing);
//	element_init_G1(agg_hash, pairing);
//
//	//临时变量存放vi*mi、sigi^vi、h^vi
//	element_t vi_mi,sigi_vi,h_vi;
//	element_init_Zr(vi_mi, pairing);
//	element_init_G1(sigi_vi, pairing);
//	element_init_G1(h_vi, pairing);
//	for (size_t i = 0; i < C; i++)
//	{
//		int index = chall.i[i];
//		element_mul(vi_mi, chall.vi[i], f.data[index]);
//		element_add(agg_data, agg_data, vi_mi);
//
//		element_pow_zn(sigi_vi, f.authenticator[index], chall.vi[i]);
//		element_mul(agg_auth, agg_auth, sigi_vi);
//		char str_hash[1100] = { '\0' };
//		char buf[1100] = { '\0' };
//		_itoa(index, buf, 10);
//		strcat(buf, "||");
//		strcat(buf, f.id);
//		element_from_hash(h, (char *)buf, sizeof(buf));
//		element_pow_zn(h_vi, h, chall.vi[i]);
//		//myprintf(h);
//		element_mul(agg_hash, agg_hash, h_vi);
//	}
//
//	//---验证---
//	pairing_apply(temp1, agg_auth, g, pairing);
//	element_pow_zn(u_m, u, agg_data);
//	element_mul(agg_hash, agg_hash, u_m);
//	pairing_apply(temp2, agg_hash, pk, pairing);
//	printf("%d   ", element_cmp(temp1, temp2));
//
//	return 0;
//}


/*
传统的bls
*/
//int bls(int argc, char **argv) {
//	pairing_t pairing;
//	pbc_demo_pairing_init(pairing, argc, argv);
//	element_t g, h, sk, pk, sig, temp1, temp2, m, u_m, u;
//	element_init_G1(sig, pairing);
//	element_init_G1(h, pairing);
//	element_init_G1(u, pairing);
//	element_init_G1(u_m, pairing);
//	element_init_G2(g, pairing);
//	element_init_Zr(sk, pairing);
//	element_init_Zr(m, pairing);
//	element_init_G2(pk, pairing);
//	element_init_GT(temp1, pairing);//用来计算e比较的，等式有左边
//	element_init_GT(temp2, pairing);//等式右边
//	element_random(sk);
//	element_random(g);
//	element_random(u);
//	element_random(m);
//
//	element_pow_zn(pk, g, sk);//公钥
//
//	element_from_hash(h, (char *)"id || i", sizeof("id||i"));//hash()
//	element_pow_zn(u_m, u, m);//u^m
//	element_mul(h, h, u_m);//hash()*u^m
//	element_pow_zn(sig, h, sk);//[]^sk =>signature
//	char ch_h[1100] = { '\0' };
//	element_snprint(ch_h, sizeof(ch_h), h);
//	element_printf("%B\n", h);
//	printf("%s\n", ch_h);
//	double t1 = pbc_get_time();
//	pairing_apply(temp1, sig, g, pairing);
//	element_from_hash(h, (char *)"id || i", sizeof("id||i"));
//	element_mul(h, h, u_m);
//
//	pairing_apply(temp2, h, pk, pairing);
//	printf("%d   ", element_cmp(temp1, temp2));
//	double t2 = pbc_get_time();
//	printf("time=%f", t2 - t1);
//	return 0;
//}


int main(int argc, char **argv)
{
	//time(NULL);
	//bls(argc, argv);
	//pbc_param_t param;
	//FILE *file_pm;
	//file_pm = fopen("my_param.txt", "w+");
	//pbc_param_init_a_gen(param, 160, 512);
	//pbc_param_out_str(file_pm, param);
	//fclose(file_pm);
	//pairing_init_pbc_param(pairing, param);
	//
	//printf("pairing_length_in_bytes_Zr:%d ;G1:%d ;G2:%d ;GT:%d\n", pairing_length_in_bytes_Zr(pairing), pairing_length_in_bytes_G1(pairing), pairing_length_in_bytes_G2(pairing), pairing_length_in_bytes_GT(pairing));

	for (size_t i = 0; i < 5; i++)
	{
		//算5次
		my_scheme(argc, argv);
		//liu_scheme(argc, argv);
	}

	
	//pbc_param_clear(param);



	//system("pause");

	//pairing_t pairing;
	//pbc_demo_pairing_init(pairing, argc, argv);
	//if (!pairing_is_symmetric(pairing)) pbc_die("pairing must be symmetric");
	//element_t P, Ppub, x, S, H, t1, t2, t3, t4;
	//element_init_Zr(x, pairing);
	//element_init_Zr(H, pairing);
	//element_init_Zr(t1, pairing);

	//element_init_G1(S, pairing);
	//element_init_G1(P, pairing);
	//element_init_G1(Ppub, pairing);
	//element_init_G1(t2, pairing);

	//element_init_GT(t3, pairing);
	//element_init_GT(t4, pairing);

	//printf("ZSS short signature schema\n");
	//printf("KEYGEN\n");
	//element_random(x);
	//element_random(P);
	//element_mul_zn(Ppub, P, x);
	//element_printf("P = %B\n", P);
	//element_printf("x = %B\n", x);
	//element_printf("Ppub = %B\n", Ppub);

	//printf("SIGN\n");
	//element_from_hash(H, (char*)"Message", 7);
	//element_add(t1, H, x);
	//element_invert(t1, t1);
	//element_mul_zn(S, P, t1);
	//printf("Signature of message \"Message\" is:\n");
	//element_printf("S = %B\n", S);

	//printf("VERIFY\n");
	//element_from_hash(H, (char*)"Message", 7);
	//element_mul_zn(t2, P, H);
	//element_add(t2, t2, Ppub);
	//element_pairing(t3, t2, S);
	//element_pairing(t4, P, P);
	//element_printf("e(H(m)P + Ppub, S) = %B\n", t3);
	//element_printf("e(P, P) = %B\n", t4);
	//if (!element_cmp(t3, t4)) printf("Signature is valid\n");
	//else printf("Signature is invalid\n");
	//element_clear(P);
	//element_clear(Ppub);
	//element_clear(x);
	//element_clear(S);
	//element_clear(H);
	//element_clear(t1);
	//element_clear(t2);
	//element_clear(t3);
	//element_clear(t4);
	//pairing_clear(pairing);

	//printf("Have a good day!\n");
	//std::cin.get();
	//return 0;
}
