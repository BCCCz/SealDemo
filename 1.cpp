#include <bits/stdc++.h>
#include "seal/seal.h"
#include "examples.h"
#include <iostream>
#include <fstream>
#include "time.h"

using namespace std;
using namespace seal;

size_t number_n; // 有效数目个数

vector<uint64_t> get_input(size_t slot_count) 
{
    vector<uint64_t> input(slot_count, 0ULL);
    ifstream in("input.txt", ios::in);
    number_n = 0;
    if (in.is_open()) 
    {
        string str;
        auto it = input.begin();
        while (getline(in, str)) 
        {
            stringstream input_txt(str);
            string str_result;
            while (input_txt >> str_result) 
            {
                (*it) = atof(str_result.c_str());
                it++;
                number_n++; 
            }
        }
        in.close();
    }
    
    return input;
}

vector<vector<uint64_t>> get_database(size_t slot_count) 
{
    vector<vector<uint64_t>> E_matrix;
    ifstream in("database.txt", ios::in);
    if (in.is_open()) 
    {
        string str;

        while (getline(in, str)) 
        {
            stringstream input_txt(str);
            string str_result;
            vector<uint64_t> input(slot_count,0ULL);
            auto it = input.begin();
            while (input_txt >> str_result) 
            {
                (*it) = atof(str_result.c_str());
                it++;
            }
            E_matrix.push_back(input);
        }
        in.close();
    }
    return E_matrix;
}

Ciphertext get_encrypt_probe(BatchEncoder&batch_encoder,Encryptor&encryptor,vector<uint64_t>v_input) 
{
    Plaintext v_plaintext;
    //BatchEncoder
    batch_encoder.encode(v_input, v_plaintext);
    Ciphertext probe_p;
    //加密
    encryptor.encrypt(v_plaintext, probe_p);
    return probe_p;
}

vector<Ciphertext> get_encrypt_E_matrix(BatchEncoder&batch_encoder, Encryptor& encryptor, vector<vector<uint64_t>>E_matrix) 
{
    vector<Ciphertext> encrypt_E_matrix;
    for (auto it = E_matrix.begin(); it != E_matrix.end(); it++) 
    {
        Plaintext plain_E_ci;
        Ciphertext encrypt_E_ci;
        batch_encoder.encode(*it, plain_E_ci);
        encryptor.encrypt(plain_E_ci, encrypt_E_ci);
        encrypt_E_matrix.push_back(encrypt_E_ci);
    }
    return encrypt_E_matrix;
}

vector<Ciphertext> dot_product(BatchEncoder& batch_encoder,Evaluator & evaluator,Decryptor & decryptor,vector<Ciphertext> encrypt_E_matrix, Ciphertext probe_p,RelinKeys & relin_keys) 
{
    vector<Ciphertext> encrypt_R_matrix;
    for (auto it = encrypt_E_matrix.begin(); it != encrypt_E_matrix.end(); it++) 
    {
        Plaintext plain_cheng_cache, plain_mult_cache;  
        Ciphertext encrypt_cheng_cache, encrypt_multiply_cache;
        vector<uint64_t>result_cheng_cache, result_mult_cache;
        evaluator.multiply(probe_p, (*it), encrypt_cheng_cache);    
        decryptor.decrypt(encrypt_cheng_cache, plain_cheng_cache);
        batch_encoder.decode(plain_cheng_cache, result_cheng_cache);
        //cout << "multiply: " << endl;
        //print_vector(result_cheng_cache);
        evaluator.relinearize_inplace(encrypt_cheng_cache, relin_keys);
        
        encrypt_R_matrix.push_back(encrypt_cheng_cache);


    }
    return encrypt_R_matrix;
}

vector<Ciphertext> get_sum_rotate(SEALContext &context,BatchEncoder& batch_encoder, Evaluator& evaluator,Encryptor &encryptor ,Decryptor& decryptor, vector<Ciphertext>encrypt_R_matrix,GaloisKeys & galois_keys,RelinKeys & relin_keys) 
{
    //print_line(__LINE__);
    vector<Ciphertext> encrypt_RR_matrix;
    /*
    * get encryptor of vector K{1,0,0,....0}
    * begin
    */
    size_t slot_count = batch_encoder.slot_count();
    vector<uint64_t>vector_k(slot_count, 0ULL);
    vector_k[0] = 0ULL;
    //print_vector(vector_k, 3, 13);

    Plaintext plain_vector_k;
    Ciphertext encrypt_vector_k;
    batch_encoder.encode(vector_k, plain_vector_k);
    encryptor.encrypt(plain_vector_k, encrypt_vector_k);
    evaluator.mod_switch_to_next_inplace(encrypt_vector_k);

   
    for (auto it = encrypt_R_matrix.begin(); it != encrypt_R_matrix.end(); it++) {

        Plaintext plain_rotated_cache, plain_sum_cache;
        Ciphertext encrypt_rotated_cache, encrypt_sum_cache;
        vector<uint64_t>result_rotated_cache, result_sum_cache;

        encrypt_sum_cache = (*it);

        /*
        * rotated & add to get sum of them
        */
        for (auto i = 0; i < number_n - 1; i++) 
        {
            evaluator.rotate_rows(encrypt_sum_cache, 1, galois_keys, encrypt_rotated_cache);
            encrypt_sum_cache = encrypt_rotated_cache;
            evaluator.add_inplace(encrypt_sum_cache,(*it) );    
        
        //evaluator.multiply_inplace(encrypt_sum_cache, encrypt_vector_k);
        }
        evaluator.relinearize_inplace(encrypt_sum_cache, relin_keys);
        
        //evaluator.rescale_to_next_inplace(encrypt_sum_cache);
        //cout << "    + Scale of encrypt_sum_cache after rescale: " << log2(encrypt_sum_cache.scale()) << endl;
        
        
        // output test 
        decryptor.decrypt(encrypt_sum_cache, plain_sum_cache);
        batch_encoder.decode(plain_sum_cache, result_sum_cache);
        cout<<"Dot"<<endl;
        print_vector(result_sum_cache);
        
        encrypt_RR_matrix.push_back(encrypt_sum_cache);
        /*
        *  output test begin
        */
        }
    /*
    *  Calculate end;
    */

    //print_line(__LINE__);
    //cout << "------get_sum_rotate() end------" << endl;
    return encrypt_RR_matrix;
    
}

vector<Ciphertext> get_dist(SEALContext& context,BatchEncoder&batch_encoder, Evaluator& evaluator, vector<Ciphertext> encrypt_E_matrix, Ciphertext probe_p,Encryptor & encryptor ,Decryptor& decryptor, RelinKeys& relin_keys,  GaloisKeys& galois_keys) 
{
    vector<Ciphertext> encrypt_R_matrix;
    vector<Ciphertext> encrypt_R_matrix_cache = dot_product(batch_encoder, evaluator, decryptor,encrypt_E_matrix,probe_p, relin_keys);
    encrypt_R_matrix = get_sum_rotate(context,batch_encoder,evaluator,encryptor, decryptor, encrypt_R_matrix_cache,galois_keys,relin_keys);
    return encrypt_R_matrix;
}




int main()
{
    clock_t start,finish;
    double duration;
    EncryptionParameters parms(scheme_type::bfv); //声明HE 使用的模式
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20)); 

    //创建一个context
    SEALContext context(parms);

    KeyGenerator keygen(context); // 密钥类
    SecretKey secret_key = keygen.secret_key(); // 创建私钥
    PublicKey public_key;
    keygen.create_public_key(public_key); // 创建公钥
    
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);
    
    Encryptor encryptor(context, public_key);// 加密类,只需要公钥即可;
    Evaluator evaluator(context); // 评估计算类
    Decryptor decryptor(context, secret_key);  // 解密类
    BatchEncoder batch_encoder(context);//编码类
    size_t slot_count = batch_encoder.slot_count();
    

    vector<uint64_t> v_input = get_input(slot_count);
    /*
    cout << "Search v:" << endl;
    print_vector(v_input);
    */
    vector<vector<uint64_t>> E_matrix = get_database(slot_count);  
    /*
    cout << "Data E:" << endl;
    for(int i = 0 ; i< 10 ; i++)
        print_vector(E_matrix[i]);
    */
    Ciphertext encrypt_probe_p = get_encrypt_probe(batch_encoder,encryptor,v_input);
    vector<Ciphertext> encrypt_E_matrix = get_encrypt_E_matrix(batch_encoder, encryptor, E_matrix);

    start = clock();
    vector<Ciphertext>encrypt_R_matrix = get_dist(context,batch_encoder,evaluator,encrypt_E_matrix,encrypt_probe_p,encryptor,decryptor,relin_keys,galois_keys);
    finish = clock();

    duration = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("Time : %.3fs\n",duration);
    return 0;
}



