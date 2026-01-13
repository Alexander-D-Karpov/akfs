#ifndef _VTFS_H
#define _VTFS_H

#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/net.h>
#include <crypto/aead.h>
#include "vtfs_compat.h"

#define VTFS_MAGIC       0x56544653
#define VTFS_ROOT_INO    1
#define VTFS_NAME_MAX    255
#define VTFS_BLOCK_SIZE  4096
#define VTFS_MAX_FILESIZE (100 * 1024 * 1024)
#define VTFS_TOKEN_MAX   256
#define VTFS_KEY_SIZE    32
#define VTFS_NONCE_SIZE  12
#define VTFS_TAG_SIZE    16

#define VTFS_HEADER_SIZE 24
#define VTFS_MAX_MSG     (16 * 1024 * 1024)

#define VTFS_OP_INIT     0x01
#define VTFS_OP_DESTROY  0x02
#define VTFS_OP_LOOKUP   0x10
#define VTFS_OP_GETATTR  0x11
#define VTFS_OP_READDIR  0x20
#define VTFS_OP_CREATE   0x30
#define VTFS_OP_MKDIR    0x31
#define VTFS_OP_UNLINK   0x32
#define VTFS_OP_RMDIR    0x33
#define VTFS_OP_LINK     0x34
#define VTFS_OP_READ     0x40
#define VTFS_OP_WRITE    0x41
#define VTFS_OP_TRUNCATE 0x42
#define VTFS_OP_WATCH    0x50
#define VTFS_OP_UNWATCH  0x51
#define VTFS_OP_NOTIFY   0x52

#define VTFS_FLAG_ENCRYPTED 0x0001
#define VTFS_FLAG_RESPONSE  0x8000

#define VTFS_LOG(fmt, ...) \
    printk(KERN_INFO "[vtfs] " fmt "\n", ##__VA_ARGS__)
#define VTFS_ERR(fmt, ...) \
    printk(KERN_ERR "[vtfs] ERROR: " fmt "\n", ##__VA_ARGS__)
#define VTFS_DBG(fmt, ...) \
    printk(KERN_DEBUG "[vtfs] " fmt "\n", ##__VA_ARGS__)

struct vtfs_msg_header {
    __le32 length;
    __le16 opcode;
    __le16 flags;
    __le64 txn_id;
    __le64 node_id;
} __packed;

struct vtfs_inode_info {
    struct inode vfs_inode;
    u64 backend_ino;
    u64 cached_size;
};

struct vtfs_sb_info {
    char server_host[128];
    int server_port;
    char token[VTFS_TOKEN_MAX];
    u8 enc_key[VTFS_KEY_SIZE];
    bool readonly;
    bool encrypted;
    struct mutex net_lock;
    struct socket *sock;
    struct crypto_aead *aead;
    u64 txn_counter;
};

static inline struct vtfs_inode_info *VTFS_I(struct inode *inode)
{
    return container_of(inode, struct vtfs_inode_info, vfs_inode);
}

static inline struct vtfs_sb_info *VTFS_SB(struct super_block *sb)
{
    return sb->s_fs_info;
}

extern const struct inode_operations vtfs_dir_inode_ops;
extern const struct inode_operations vtfs_file_inode_ops;
extern const struct file_operations vtfs_dir_ops;
extern const struct file_operations vtfs_file_ops;
extern const struct super_operations vtfs_super_ops;

struct inode *vtfs_iget(struct super_block *sb, u64 backend_ino, umode_t mode,
                        loff_t size, unsigned int nlink);

int vtfs_fill_super(struct super_block *sb, struct fs_context *fc);
int vtfs_init_fs_context(struct fs_context *fc);
void vtfs_kill_sb(struct super_block *sb);

int vtfs_init_inode_cache(void);
void vtfs_destroy_inode_cache(void);

int vtfs_net_connect(struct vtfs_sb_info *sbi);
void vtfs_net_disconnect(struct vtfs_sb_info *sbi);
int vtfs_net_init(struct vtfs_sb_info *sbi);
int vtfs_net_send(struct vtfs_sb_info *sbi, void *buf, size_t len);
int vtfs_net_recv(struct vtfs_sb_info *sbi, void *buf, size_t len);

int vtfs_crypto_init(struct vtfs_sb_info *sbi);
void vtfs_crypto_cleanup(struct vtfs_sb_info *sbi);
int vtfs_encrypt(struct vtfs_sb_info *sbi, const u8 *plain, size_t plain_len,
                 u8 *cipher, size_t *cipher_len);
int vtfs_decrypt(struct vtfs_sb_info *sbi, const u8 *cipher, size_t cipher_len,
                 u8 *plain, size_t *plain_len);

int vtfs_proto_lookup(struct vtfs_sb_info *sbi, u64 parent_ino, const char *name,
                      u64 *out_ino, umode_t *out_mode, loff_t *out_size,
                      unsigned int *out_nlink);
int vtfs_proto_getattr(struct vtfs_sb_info *sbi, u64 ino, umode_t *out_mode,
                       loff_t *out_size, unsigned int *out_nlink);
int vtfs_proto_readdir(struct vtfs_sb_info *sbi, u64 dir_ino,
                       int (*callback)(void *ctx, const char *name, u64 ino, umode_t mode),
                       void *ctx);
int vtfs_proto_create(struct vtfs_sb_info *sbi, u64 parent_ino, const char *name,
                      umode_t mode, u64 *out_ino);
int vtfs_proto_mkdir(struct vtfs_sb_info *sbi, u64 parent_ino, const char *name,
                     umode_t mode, u64 *out_ino);
int vtfs_proto_unlink(struct vtfs_sb_info *sbi, u64 parent_ino, const char *name);
int vtfs_proto_rmdir(struct vtfs_sb_info *sbi, u64 parent_ino, const char *name);
int vtfs_proto_link(struct vtfs_sb_info *sbi, u64 ino, u64 new_parent_ino,
                    const char *new_name);
int vtfs_proto_truncate(struct vtfs_sb_info *sbi, u64 ino, loff_t size);
ssize_t vtfs_proto_read(struct vtfs_sb_info *sbi, u64 ino, char *buf,
                        size_t len, loff_t offset);
ssize_t vtfs_proto_write(struct vtfs_sb_info *sbi, u64 ino, const char *buf,
                         size_t len, loff_t offset, loff_t *new_size);

#endif
