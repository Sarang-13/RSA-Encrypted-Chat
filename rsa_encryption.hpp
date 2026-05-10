#ifndef RSA_ENCRYPTION_HPP
#define RSA_ENCRYPTION_HPP

#include <string>
#include <vector>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <nlohmann/json.hpp>
#include <stdexcept>

using json = nlohmann::json;

class RSAEncryption {
public:
    // Generate RSA key pair (2048-bit)
    static std::pair<std::string, std::string> generate_key_pair() {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (!ctx) throw std::runtime_error("Failed to create EVP_PKEY_CTX");
        
        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize keygen");
        }
        
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to set key size");
        }
        
        EVP_PKEY *pkey = nullptr;
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to generate key pair");
        }
        EVP_PKEY_CTX_free(ctx);
        
        // Serialize private key
        BIO *priv_bio = BIO_new(BIO_s_mem());
        if (!PEM_write_bio_PrivateKey(priv_bio, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
            BIO_free(priv_bio);
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to serialize private key");
        }
        
        BUF_MEM *priv_mem = nullptr;
        BIO_get_mem_ptr(priv_bio, &priv_mem);
        std::string private_pem(priv_mem->data, priv_mem->length);
        BIO_free(priv_bio);
        
        // Serialize public key
        BIO *pub_bio = BIO_new(BIO_s_mem());
        if (!PEM_write_bio_PUBKEY(pub_bio, pkey)) {
            BIO_free(pub_bio);
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to serialize public key");
        }
        
        BUF_MEM *pub_mem = nullptr;
        BIO_get_mem_ptr(pub_bio, &pub_mem);
        std::string public_pem(pub_mem->data, pub_mem->length);
        BIO_free(pub_bio);
        
        EVP_PKEY_free(pkey);
        
        return {private_pem, public_pem};
    }
    
    // Encrypt message with public key, return as hex-encoded JSON array
    static json encrypt_message(const std::string& msg, const std::string& public_key_pem) {
        BIO *bio = BIO_new_mem_buf((void*)public_key_pem.c_str(), -1);
        EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        
        if (!pkey) throw std::runtime_error("Failed to load public key");
        
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, nullptr);
        if (!ctx) {
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to create encryption context");
        }
        
        if (EVP_PKEY_encrypt_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to initialize encryption");
        }
        
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to set padding");
        }
        
        // Get max plaintext size (2048-bit key: 190 bytes max with OAEP)
        size_t chunk_size = 190;
        size_t msg_len = msg.length();
        size_t out_len = 0;
        
        json encrypted_chunks = json::array();
        
        // Encrypt in chunks
        for (size_t i = 0; i < msg_len; i += chunk_size) {
            size_t current_chunk_size = std::min(chunk_size, msg_len - i);
            
            // Get output buffer size
            if (EVP_PKEY_encrypt(ctx, nullptr, &out_len, 
                                 (const unsigned char*)msg.c_str() + i, 
                                 current_chunk_size) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                EVP_PKEY_free(pkey);
                throw std::runtime_error("Failed to get encryption output size");
            }
            
            std::vector<unsigned char> enc_data(out_len);
            
            if (EVP_PKEY_encrypt(ctx, enc_data.data(), &out_len,
                                (const unsigned char*)msg.c_str() + i,
                                current_chunk_size) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                EVP_PKEY_free(pkey);
                throw std::runtime_error("Encryption failed");
            }
            
            // Convert to hex string
            std::string hex_chunk = to_hex(enc_data);
            encrypted_chunks.push_back(hex_chunk);
        }
        
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        
        return encrypted_chunks;
    }
    
    // Decrypt message with private key
    static std::string decrypt_message(const json& encrypted_json, const std::string& private_key_pem) {
        try {
            BIO *bio = BIO_new_mem_buf((void*)private_key_pem.c_str(), -1);
            EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
            
            if (!pkey) throw std::runtime_error("Failed to load private key");
            
            EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, nullptr);
            if (!ctx) {
                EVP_PKEY_free(pkey);
                throw std::runtime_error("Failed to create decryption context");
            }
            
            if (EVP_PKEY_decrypt_init(ctx) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                EVP_PKEY_free(pkey);
                throw std::runtime_error("Failed to initialize decryption");
            }
            
            if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                EVP_PKEY_free(pkey);
                throw std::runtime_error("Failed to set padding");
            }
            
            std::string decrypted_msg;
            
            // Decrypt each chunk
            for (const auto& hex_chunk : encrypted_json) {
                std::vector<unsigned char> enc_data = from_hex(hex_chunk.get<std::string>());
                size_t out_len = 0;
                
                if (EVP_PKEY_decrypt(ctx, nullptr, &out_len, enc_data.data(), enc_data.size()) <= 0) {
                    EVP_PKEY_CTX_free(ctx);
                    EVP_PKEY_free(pkey);
                    throw std::runtime_error("Failed to get decryption output size");
                }
                
                std::vector<unsigned char> dec_data(out_len);
                
                if (EVP_PKEY_decrypt(ctx, dec_data.data(), &out_len, 
                                     enc_data.data(), enc_data.size()) <= 0) {
                    EVP_PKEY_CTX_free(ctx);
                    EVP_PKEY_free(pkey);
                    throw std::runtime_error("Decryption failed");
                }
                
                decrypted_msg.append(dec_data.begin(), dec_data.end());
            }
            
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            
            return decrypted_msg;
        } catch (const std::exception& e) {
            return std::string("[Decryption error: ") + e.what() + "]";
        }
    }
    
private:
    static std::string to_hex(const std::vector<unsigned char>& data) {
        std::string hex;
        for (unsigned char byte : data) {
            char buf[3];
            snprintf(buf, 3, "%02x", byte);
            hex += buf;
        }
        return hex;
    }
    
    static std::vector<unsigned char> from_hex(const std::string& hex) {
        std::vector<unsigned char> data;
        for (size_t i = 0; i < hex.length(); i += 2) {
            std::string byte_str = hex.substr(i, 2);
            unsigned char byte = (unsigned char) strtol(byte_str.c_str(), nullptr, 16);
            data.push_back(byte);
        }
        return data;
    }
};

#endif // RSA_ENCRYPTION_HPP
