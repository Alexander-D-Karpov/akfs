#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <crypto/aead.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include "vtfs.h"

int vtfs_crypto_init(struct vtfs_sb_info *sbi)
{
    struct crypto_aead *aead;
    int ret;

    aead = crypto_alloc_aead("gcm(aes)", 0, 0);
    if (IS_ERR(aead)) {
        VTFS_ERR("Failed to allocate AES-GCM cipher: %ld", PTR_ERR(aead));
        return PTR_ERR(aead);
    }

    ret = crypto_aead_setkey(aead, sbi->enc_key, VTFS_KEY_SIZE);
    if (ret) {
        VTFS_ERR("Failed to set AES key: %d", ret);
        crypto_free_aead(aead);
        return ret;
    }

    ret = crypto_aead_setauthsize(aead, VTFS_TAG_SIZE);
    if (ret) {
        VTFS_ERR("Failed to set auth tag size: %d", ret);
        crypto_free_aead(aead);
        return ret;
    }

    sbi->aead = aead;
    sbi->encrypted = true;
    VTFS_LOG("AES-GCM encryption initialized");
    return 0;
}

void vtfs_crypto_cleanup(struct vtfs_sb_info *sbi)
{
    if (sbi->aead) {
        crypto_free_aead(sbi->aead);
        sbi->aead = NULL;
    }
    sbi->encrypted = false;
}

int vtfs_encrypt(struct vtfs_sb_info *sbi, const u8 *plain, size_t plain_len,
                 u8 *cipher, size_t *cipher_len)
{
    struct aead_request *req = NULL;
    struct scatterlist sg_plain, sg_cipher;
    u8 *nonce;
    u8 *temp_buf = NULL;
    int ret;
    size_t out_len;

    if (!sbi->aead || !sbi->encrypted) {
        memcpy(cipher, plain, plain_len);
        *cipher_len = plain_len;
        return 0;
    }

    out_len = VTFS_NONCE_SIZE + plain_len + VTFS_TAG_SIZE;
    
    nonce = cipher;
    get_random_bytes(nonce, VTFS_NONCE_SIZE);

    temp_buf = kmalloc(plain_len + VTFS_TAG_SIZE, GFP_KERNEL);
    if (!temp_buf)
        return -ENOMEM;

    memcpy(temp_buf, plain, plain_len);

    req = aead_request_alloc(sbi->aead, GFP_KERNEL);
    if (!req) {
        kfree(temp_buf);
        return -ENOMEM;
    }

    sg_init_one(&sg_plain, temp_buf, plain_len + VTFS_TAG_SIZE);
    sg_init_one(&sg_cipher, temp_buf, plain_len + VTFS_TAG_SIZE);

    aead_request_set_crypt(req, &sg_plain, &sg_cipher, plain_len, nonce);
    aead_request_set_ad(req, 0);

    ret = crypto_aead_encrypt(req);
    if (ret) {
        VTFS_ERR("Encryption failed: %d", ret);
        goto out;
    }

    memcpy(cipher + VTFS_NONCE_SIZE, temp_buf, plain_len + VTFS_TAG_SIZE);
    *cipher_len = out_len;

out:
    aead_request_free(req);
    kfree(temp_buf);
    return ret;
}

int vtfs_decrypt(struct vtfs_sb_info *sbi, const u8 *cipher, size_t cipher_len,
                 u8 *plain, size_t *plain_len)
{
    struct aead_request *req = NULL;
    struct scatterlist sg_cipher, sg_plain;
    const u8 *nonce;
    u8 *temp_buf = NULL;
    int ret;
    size_t data_len;

    if (!sbi->aead || !sbi->encrypted) {
        memcpy(plain, cipher, cipher_len);
        *plain_len = cipher_len;
        return 0;
    }

    if (cipher_len < VTFS_NONCE_SIZE + VTFS_TAG_SIZE)
        return -EINVAL;

    nonce = cipher;
    data_len = cipher_len - VTFS_NONCE_SIZE;

    temp_buf = kmalloc(data_len, GFP_KERNEL);
    if (!temp_buf)
        return -ENOMEM;

    memcpy(temp_buf, cipher + VTFS_NONCE_SIZE, data_len);

    req = aead_request_alloc(sbi->aead, GFP_KERNEL);
    if (!req) {
        kfree(temp_buf);
        return -ENOMEM;
    }

    sg_init_one(&sg_cipher, temp_buf, data_len);
    sg_init_one(&sg_plain, temp_buf, data_len);

    aead_request_set_crypt(req, &sg_cipher, &sg_plain, data_len, (u8 *)nonce);
    aead_request_set_ad(req, 0);

    ret = crypto_aead_decrypt(req);
    if (ret) {
        VTFS_ERR("Decryption failed: %d", ret);
        goto out;
    }

    *plain_len = data_len - VTFS_TAG_SIZE;
    memcpy(plain, temp_buf, *plain_len);

out:
    aead_request_free(req);
    kfree(temp_buf);
    return ret;
}

void vtfs_derive_key(const char *password, u8 *key)
{
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    int ret;

    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm)) {
        memset(key, 0, VTFS_KEY_SIZE);
        strncpy((char *)key, password, VTFS_KEY_SIZE);
        return;
    }

    desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) {
        crypto_free_shash(tfm);
        memset(key, 0, VTFS_KEY_SIZE);
        strncpy((char *)key, password, VTFS_KEY_SIZE);
        return;
    }

    desc->tfm = tfm;

    ret = crypto_shash_digest(desc, password, strlen(password), key);
    if (ret) {
        memset(key, 0, VTFS_KEY_SIZE);
        strncpy((char *)key, password, VTFS_KEY_SIZE);
    }

    kfree(desc);
    crypto_free_shash(tfm);
}
