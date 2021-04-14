#include <bits/stdc++.h>
#include "seal/seal.h"
#include "examples.h"
#include <iostream>
#include <fstream>
#include "time.h"
#include <sstream>

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

Ciphertext get_sum_rotate(SEALContext &context,BatchEncoder& batch_encoder, Evaluator& evaluator,Encryptor &encryptor ,Decryptor& decryptor, vector<Ciphertext>encrypt_R_matrix,GaloisKeys & galois_keys,RelinKeys & relin_keys) {

    size_t slot_count = batch_encoder.slot_count();
    vector<uint64_t>vector_k(slot_count, 0ULL);
    vector<uint64_t>result_sum_cache;
    //print_vector(vector_k);

    Plaintext plain_vector_k;
    Ciphertext encrypt_vector_k;
    batch_encoder.encode(vector_k, plain_vector_k);
    encryptor.encrypt(plain_vector_k, encrypt_vector_k);
   
    for (auto it = encrypt_R_matrix.begin(); it != encrypt_R_matrix.end(); it++) 
    {

        Plaintext  plain_sum_cache;
        Ciphertext  encrypt_sum_cache;
        vector<uint64_t> result_sum_cache;
        evaluator.add_inplace(encrypt_vector_k,(*it) ); 
        evaluator.relinearize_inplace(encrypt_vector_k, relin_keys);
    }  
    


    decryptor.decrypt(encrypt_vector_k, plain_vector_k);
    batch_encoder.decode(plain_vector_k, result_sum_cache);
    cout<<"result:"<<endl;
    print_vector(result_sum_cache,13);
        
    return encrypt_vector_k;
}

Ciphertext get_dist(SEALContext& context,BatchEncoder&batch_encoder, Evaluator& evaluator, vector<Ciphertext> encrypt_E_matrix, Ciphertext probe_p,Encryptor & encryptor ,Decryptor& decryptor, RelinKeys& relin_keys,  GaloisKeys& galois_keys) 
{
    Ciphertext encrypt_R_matrix;
    vector<Ciphertext> encrypt_R_matrix_cache = dot_product(batch_encoder, evaluator, decryptor,encrypt_E_matrix,probe_p, relin_keys);
    encrypt_R_matrix = get_sum_rotate(context,batch_encoder,evaluator,encryptor, decryptor, encrypt_R_matrix_cache,galois_keys,relin_keys);
    return encrypt_R_matrix;
}


void saveCiphertext(string filename,vector<Ciphertext> abc)    // 3.12
{
  string name = filename;
  
  for(int i=0;i<abc.size();i++)
  {
      ofstream ct;
      filename.append(to_string(i));
      ct.open(filename, ios::binary);
      abc[i].save(ct);
      filename = name ;
  }  
  
}

void saveKeys(string filename1, string filename2,RelinKeys& relin_keys,  GaloisKeys& galois_keys)    
// 3.12 保存密钥
{ 
    ofstream rkey,gkey;
    rkey.open(filename1, ios::binary);
    relin_keys.save(rkey);
    rkey.close();
    gkey.open(filename2, ios::binary);
    galois_keys.save(gkey);
    gkey.close();
}  
  

RelinKeys loadRkeys(SEALContext& context,string filename)    
// 3.12 读取relin_keys
{ 
    
    ifstream rkey;
    rkey.open(filename, ios::binary);
    RelinKeys r;
    r.unsafe_load(context,rkey);
    return r;
} 

GaloisKeys loadGkeys(SEALContext& context,string filename)    
// 3.12 读取golois_keys
{ 
    
    ifstream gkey;
    gkey.open(filename, ios::binary);
    GaloisKeys g;
    g.load(context,gkey);
    return g;
} 

Ciphertext unsafe_loadCiphertext(SEALContext& context,string filename) // 3.12
{
  ifstream ct;
  ct.open(filename, ios::binary);
  Ciphertext result;
  result.unsafe_load(context,ct);
  return result;
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
    saveKeys("rkey","gkey",relin_keys,galois_keys);   // 3.12 保存密钥
    relin_keys = loadRkeys(context,"rkey");           // 3.12 读取relin_keys
    galois_keys = loadGkeys(context,"gkey");          // 3.12 读取galois_keys
    
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
    
    //saveCiphertext("save",encrypt_E_matrix); //3.12 加密矩阵保存到文件
    //3.12 读取文件
    //Ciphertext erow1 = unsafe_loadCiphertext(context,"save0");
    //Plaintext prow1;
    //vector<uint64_t> row1;
    //decryptor.decrypt(erow1,prow1);
    //batch_encoder.decode(prow1, row1);
    //print_vector(row1);
    
    start = clock();
    Ciphertext encrypt_R_matrix = get_dist(context,batch_encoder,evaluator,encrypt_E_matrix,encrypt_probe_p,encryptor,decryptor,relin_keys,galois_keys);
    finish = clock();

    duration = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("Time : %.3fs\n",duration);
    return 0;
}