#include <bits/stdc++.h>
#include "seal/seal.h"
#include "examples.h"
#include <iostream>
#include <fstream>
#include <vector>

using namespace std;
using namespace seal;

int main()
{	
	//构建参数容器 parms
	EncryptionParameters parms(scheme_type::ckks);
	
	/*CKKS参数：
	1.poly_module_degree(多项式模数)
	2.coeff_modulus（参数模数）
	3.scale（规模）
	*/
	size_t poly_modulus_degree = 8192;
	parms.set_poly_modulus_degree(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

	//选用2^40进行编码
	double scale = pow(2.0, 40);
	
	////用参数生成CKKS框架context
	SEALContext context(parms);

	//构建各模块
	//首先构建keygenerator，生成公钥、私钥和重线性化密钥
	KeyGenerator keygen(context);
	auto secret_key = keygen.secret_key();

	PublicKey public_key;
    keygen.create_public_key(public_key);

    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);




	//构建编码器，加密模块、运算器和解密模块
	//注意加密需要公钥pk；解密需要私钥sk；编码器需要scale
	Encryptor encryptor(context, public_key);
	Evaluator evaluator(context);
	Decryptor decryptor(context, secret_key);

	CKKSEncoder encoder(context);

	vector<double> x, y, z;
		x = { 1.0, 2.0, 3.0 };
		y = { 2.0, 3.0, 4.0 };
		z = { 3.0, 4.0, 5.0 };

	//对向量x、y、z进行编码
	Plaintext xp, yp, zp;
	encoder.encode(x, scale, xp);
	encoder.encode(y, scale, yp);
	encoder.encode(z, scale, zp);

	//对明文xp、yp、zp进行加密
	Ciphertext xc, yc, zc;
	encryptor.encrypt(xp, xc);
	encryptor.encrypt(yp, yc);
	encryptor.encrypt(zp, zc);

	/*
	对密文进行计算，要说明的原则是：
	1.加法可以连续运算，但乘法不能连续运算
	2.密文乘法后要进行relinearize操作
	3.执行乘法后要进行rescaling操作
	4.进行运算的密文必需执行过相同次数的rescaling（位于相同level）
	基于上述原则进行运算
	*/

	//中间变量
	Ciphertext temp;
	Ciphertext result_c;

	//计算x*y，密文相乘，要进行relinearize和rescaling操作
	evaluator.multiply(xc,yc,temp);
	evaluator.relinearize_inplace(temp, relin_keys);
	evaluator.rescale_to_next_inplace(temp);

	//在计算x*y * z之前，z没有进行过rescaling操作，所以需要对z进行一次乘法和rescaling操作，目的是 make x*y and z at the same level
	Plaintext wt;
	encoder.encode(1.0, scale, wt);

	//执行乘法和rescaling操作：
	evaluator.multiply_plain_inplace(zc, wt);
	evaluator.rescale_to_next_inplace(zc);

	//最后执行temp（x*y）* zc（z*1.0）
	evaluator.multiply_inplace(temp, zc);
	evaluator.relinearize_inplace(temp,relin_keys);
	evaluator.rescale_to_next(temp, result_c);


	//解密和解码
	Plaintext result_p;
	decryptor.decrypt(result_c, result_p);
	//注意要解码到一个向量上
	vector<double> result;
	encoder.decode(result_p, result);

	cout << "Result：" << endl;
	print_vector(result,3,3);
	return 0;
}