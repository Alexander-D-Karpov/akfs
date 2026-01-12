#ifndef _VTFS_H
#define _VTFS_H

#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include "vtfs_compat.h"

#define VTFS_MAGIC       0x56544653
#define VTFS_ROOT_INO    1
#define VTFS_NAME_MAX    255
#define VTFS_BLOCK_SIZE  4096
#define VTFS_MAX_FILESIZE (1024 * 1024 * 100)
#define VTFS_TOKEN_MAX   256

#define VTFS_LOG(fmt, ...) \
    printk(KERN_INFO "[vtfs] " fmt "\n", ##__VA_ARGS__)
#define VTFS_ERR(fmt, ...) \
    printk(KERN_ERR "[vtfs] ERROR: " fmt "\n", ##__VA_ARGS__)

struct vtfs_inode_info {
    struct inode vfs_inode;
    u64 backend_ino;
};

struct vtfs_sb_info {
    char server_url[256];
    char token[VTFS_TOKEN_MAX];
    bool readonly;
    struct mutex http_lock;
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

int vtfs_http_lookup(struct vtfs_sb_info *sbi, u64 parent_ino, const char *name,
                     u64 *out_ino, umode_t *out_mode, loff_t *out_size,
                     unsigned int *out_nlink);
int vtfs_http_list(struct vtfs_sb_info *sbi, u64 parent_ino,
                   int (*callback)(void *ctx, const char *name, u64 ino, umode_t mode),
                   void *ctx);
int vtfs_http_create(struct vtfs_sb_info *sbi, u64 parent_ino, const char *name,
                     umode_t mode, u64 *out_ino);
int vtfs_http_mkdir(struct vtfs_sb_info *sbi, u64 parent_ino, const char *name,
                    umode_t mode, u64 *out_ino);
int vtfs_http_unlink(struct vtfs_sb_info *sbi, u64 parent_ino, const char *name);
int vtfs_http_rmdir(struct vtfs_sb_info *sbi, u64 parent_ino, const char *name);
int vtfs_http_link(struct vtfs_sb_info *sbi, u64 ino, u64 new_parent_ino,
                   const char *new_name);
ssize_t vtfs_http_read(struct vtfs_sb_info *sbi, u64 ino, char *buf, size_t len,
                       loff_t offset);
ssize_t vtfs_http_write(struct vtfs_sb_info *sbi, u64 ino, const char *buf,
                        size_t len, loff_t offset, loff_t *new_size);

#endif