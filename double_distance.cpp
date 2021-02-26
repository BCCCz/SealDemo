#include <bits/stdc++.h>
#include "seal/seal.h"
#include "examples.h"
#include <iostream>
#include <fstream>


using namespace std;
using namespace seal;

size_t number_n; // 有效数目个数
const double scale = pow(2.0, 40);// 放大因子


vector<double> get_input(size_t slot_count) {
  
    vector<double> input(slot_count, 0ULL);
    //input.reserve(slot_count); // 申请空间

    ifstream in("input.txt", ios::in);
    number_n = 0;
    if (in.is_open()) {
        string str;
        auto it = input.begin();
        while (getline(in, str)) {
            stringstream input_txt(str);
            string str_result;
            while (input_txt >> str_result) {
                (*it) = atof(str_result.c_str());
                it++;
                number_n++; // 统计有效数目个数
                //input.push_back(atof(str_result.c_str())); // string -> double;       
            }
        }
        in.close();
    }
    
    //cout << "Search V: " << endl;
    //print_vector(input); // 前5 后5 项

    return input;
}

vector<vector<double>> get_database(size_t slot_count) {
    vector<vector<double>> E_matrix;
    ifstream in("database.txt", ios::in);
    if (in.is_open()) {
        string str;

        while (getline(in, str)) {
            stringstream input_txt(str);
            string str_result;
            vector<double> input(slot_count,0ULL);
            auto it = input.begin();
            while (input_txt >> str_result) {
                (*it) = atof(str_result.c_str());
                it++;
            }
            E_matrix.push_back(input);
        }
        in.close();
    }

    //cout << "Data E:" << endl;
    // get database output test
    //for(int i = 0 ; i< 10 ; i++)
    //    print_vector(E_matrix[i]);
    return E_matrix;
}



//* ejcrypt get probe_p;
Ciphertext get_encrypt_probe(CKKSEncoder& ckks_encoder,Encryptor & encryptor, vector<double>v_input) {
    //cout << "V Encrypt" << endl;
    //cout << "Done" << endl;

    //* 加密获得probe_p;
    Plaintext v_plaintext;
    // v编码
    ckks_encoder.encode(v_input, scale, v_plaintext);
    Ciphertext probe_p;
    // 加密
    encryptor.encrypt(v_plaintext, probe_p);
    return probe_p;
}



//encrypt get enceypt_E_matrix
vector<Ciphertext> get_encrypt_E_matrix(CKKSEncoder& ckks_encoder, Encryptor& encryptor, vector<vector<double>>E_matrix) {
    //cout << "E_matrix Encrypt" << endl;
    //cout << "Done" << endl;
    
    vector<Ciphertext> encrypt_E_matrix;
    for (auto it = E_matrix.begin(); it != E_matrix.end(); it++) {
        Plaintext plain_E_ci;
        Ciphertext encrypt_E_ci;
        ckks_encoder.encode(*it, scale, plain_E_ci);
        encryptor.encrypt(plain_E_ci, encrypt_E_ci);
        encrypt_E_matrix.push_back(encrypt_E_ci);
    }
    return encrypt_E_matrix;
}


/*
 get (Ci - Pi)^2
*/
vector<Ciphertext> get_sub_square(CKKSEncoder& ckks_encoder,Evaluator & evaluator,Decryptor & decryptor,vector<Ciphertext> encrypt_E_matrix, Ciphertext probe_p,RelinKeys & relin_keys) {

    vector<Ciphertext> encrypt_R_matrix;
    for (auto it = encrypt_E_matrix.begin(); it != encrypt_E_matrix.end(); it++) {

        /*
        *  Calculate begin
        */
        Plaintext plain_sub_cache, plain_mult_cache;
        Ciphertext encrypt_sub_cache, encrypt_multiply_cache;
        vector<double>result_sub_cache, result_mult_cache;

        evaluator.sub(probe_p, (*it), encrypt_sub_cache);
        //evaluator.relinearize_inplace(encrypt_sub_cache, relin_keys);
        /*
        *  output test begin
        */
        
        decryptor.decrypt(encrypt_sub_cache, plain_sub_cache);
        ckks_encoder.decode(plain_sub_cache, result_sub_cache);
        //cout << "sub: " << endl;
        //print_vector(result_sub_cache,5,13);

        /*
        *  output test begin
        */
       
        evaluator.square(encrypt_sub_cache, encrypt_multiply_cache);
        evaluator.relinearize_inplace(encrypt_multiply_cache, relin_keys);
         //cout << "    + Scale of encrypt_multiply_cache before rescale: " << log2(encrypt_multiply_cache.scale()) << " bits" << endl;
        evaluator.rescale_to_next_inplace(encrypt_multiply_cache);
         //cout << "    + Scale of encrypt_multiply_cache: " << log2(encrypt_multiply_cache.scale()) << " bits" << endl;
         
        encrypt_R_matrix.push_back(encrypt_multiply_cache);

        /*
        *  output test begin
        */
        
        decryptor.decrypt(encrypt_multiply_cache, plain_mult_cache);
        ckks_encoder.decode(plain_mult_cache, result_mult_cache);
        
        //cout << "mult: " << endl;
        //print_vector(result_mult_cache,5,13);
    
        /*
        double sum = 0;
        std::cout << std::fixed << std::setprecision(13); // 设置输出保留位数
        for (int i = 0; i < 10; i++)
        {
            sum += result_mult_cache[i];
            cout << result_mult_cache[i] << " ";
        }
        cout << endl;
        print_line(__LINE__);
        cout <<"true of sum is : "<< sum <<endl;
        */

        /*
        *  output test begin
        */

    }
    //print_line(__LINE__);
    return encrypt_R_matrix;
}

/*
* squared Euclidean distance: Sum of (Ci - Pi)^2
* Afterwards, the sum of elements is present in the first element of the vector.
* The other elements of the vector are now irrelevant and are cleaned by multiplying with 0.
* k = {1,0, . . .0}
*/
vector<Ciphertext> get_sum_rotate(SEALContext &context,CKKSEncoder& ckks_encoder, Evaluator& evaluator,Encryptor &encryptor ,Decryptor& decryptor, vector<Ciphertext>encrypt_R_matrix,GaloisKeys & galois_keys,RelinKeys & relin_keys) {
    //print_line(__LINE__);
    vector<Ciphertext> encrypt_RR_matrix;
    /*
    * get encryptor of vector K{1,0,0,....0}
    * begin
    */
    size_t slot_count = ckks_encoder.slot_count();
    vector<double>vector_k(slot_count, 0ULL);
    vector_k[0] = 1ULL;
    //print_vector(vector_k, 3, 13);

    Plaintext plain_vector_k;
    Ciphertext encrypt_vector_k;
    ckks_encoder.encode(vector_k, pow(2.0, 40), plain_vector_k);
    encryptor.encrypt(plain_vector_k, encrypt_vector_k);
    evaluator.mod_switch_to_next_inplace(encrypt_vector_k);

    //end

    /*
    *  Calculate begin
    */
    for (auto it = encrypt_R_matrix.begin(); it != encrypt_R_matrix.end(); it++) {

        Plaintext plain_rotated_cache, plain_sum_cache;
        Ciphertext encrypt_rotated_cache, encrypt_sum_cache;
        vector<double>result_rotated_cache, result_sum_cache;

        encrypt_sum_cache = (*it);
        /*
        * rotated & add to get sum of them
        */
        for (auto i = 0; i < number_n - 1; i++) {
            evaluator.rotate_vector(encrypt_sum_cache, 1, galois_keys, encrypt_rotated_cache);
            encrypt_sum_cache = encrypt_rotated_cache;
            evaluator.add_inplace(encrypt_sum_cache,(*it) );
            //evaluator.relinearize_inplace(encrypt_sum_cache, relin_keys);
            
            /*
            decryptor.decrypt(encrypt_rotated_cache, plain_rotated_cache);
            ckks_encoder.decode(plain_rotated_cache, result_rotated_cache);
            cout << "rotated 1: " << endl;
            print_vector(result_rotated_cache, 5, 13);
            
            
            /*
            cout << "    + Scale of encrypt_sum_cache before rescale: " << log2(encrypt_sum_cache.scale()) << endl;
            
            cout << "    + Scale of it before rescale: " << log2(encrypt_sum_cache.scale()) << endl;
            cout << "    + Modulus chain index for encrypted of dist: "
                << context.get_context_data(encrypt_sum_cache.parms_id())->chain_index() << endl;
                */
            
            /*
            decryptor.decrypt(encrypt_sum_cache, plain_sum_cache);
            ckks_encoder.decode(plain_sum_cache, result_sum_cache);
            
            cout << "rotated 1 & add : " << endl;
            print_vector(result_sum_cache, 5, 13);
            */
        }

        /*
        cout << "    + Modulus chain index for encrypted of dist: "
            << context.get_context_data(encrypt_sum_cache.parms_id())->chain_index() << endl;
        cout << "    + Modulus chain index for encrypted of k: "
            << context.get_context_data(encrypt_vector_k.parms_id())->chain_index() << endl;
        */
     
        //cout << "    + Scale of encrypt_sum_cache before rescale: " << log2(encrypt_sum_cache.scale()) << endl;
        //cout << "    + Scale of encrypt_vector_k before rescale: " << log2(encrypt_vector_k.scale()) << endl;
        evaluator.multiply_inplace(encrypt_sum_cache, encrypt_vector_k);
        evaluator.relinearize_inplace(encrypt_sum_cache, relin_keys);
        evaluator.rescale_to_next_inplace(encrypt_sum_cache);
        //cout << "    + Scale of encrypt_sum_cache after rescale: " << log2(encrypt_sum_cache.scale()) << endl;
        
        
        // output test 
        decryptor.decrypt(encrypt_sum_cache, plain_sum_cache);
        ckks_encoder.decode(plain_sum_cache, result_sum_cache);
        print_vector(result_sum_cache, 5, 13);
        
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

vector<Ciphertext> get_dist(SEALContext& context,CKKSEncoder& ckks_encoder, Evaluator& evaluator, vector<Ciphertext> encrypt_E_matrix, Ciphertext probe_p,Encryptor & encryptor ,Decryptor& decryptor, RelinKeys& relin_keys,  GaloisKeys& galois_keys) {
    //print_line(__LINE__);
    vector<Ciphertext> encrypt_R_matrix;

    /*
    * get (Ci - Pi)^2
    */
   
    //cout << "sub & square && stored in encrypt_R_matrix: " << endl;
    vector<Ciphertext> encrypt_R_matrix_cache = get_sub_square(ckks_encoder, evaluator, decryptor,encrypt_E_matrix,probe_p, relin_keys);
    /*
    * get sum
    */
    encrypt_R_matrix = get_sum_rotate(context,ckks_encoder,evaluator,encryptor, decryptor, encrypt_R_matrix_cache,galois_keys,relin_keys);

    //print_line(__LINE__);
    return encrypt_R_matrix;
}

int main(){
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 50,30,30,30,60 }));


    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    // 密钥
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);

    //加密器
    Encryptor encryptor(context, public_key);
    //计算器
    Evaluator evaluator(context);
    //解密器
    Decryptor decryptor(context, secret_key);

    CKKSEncoder ckks_encoder(context);
    

    
    size_t slot_count = ckks_encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    double curr_point = 0;
    double step_size = 1.0 / (static_cast<double>(slot_count) - 1); // 
    //create_database(slot_count);

    vector<double> v_input = get_input(slot_count);
    vector<vector<double>> E_matrix = get_database(slot_count);
    
    /*
    * 加密获得probe_p;
    */
    Ciphertext encrypt_probe_p = get_encrypt_probe(ckks_encoder, encryptor, v_input);

    /*
    * 加密 获得 enceypt_E_matrix
    */ 
    vector<Ciphertext> encrypt_E_matrix = get_encrypt_E_matrix(ckks_encoder, encryptor, E_matrix);


    /*
    * Sum of (Ci - Pi)^2
    * Core
    */
    vector<Ciphertext>encrypt_R_matrix = get_dist(context,ckks_encoder,evaluator,encrypt_E_matrix,encrypt_probe_p,encryptor,decryptor,relin_keys,galois_keys);


    return 0;
}
