#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/slab.h>
#include <linux/statfs.h>
#include "vtfs.h"

enum vtfs_param {
    Opt_host,
    Opt_port,
    Opt_token,
    Opt_key,
};

static const struct fs_parameter_spec vtfs_fs_parameters[] = {
    fsparam_string("host",  Opt_host),
    fsparam_u32("port",     Opt_port),
    fsparam_string("token", Opt_token),
    fsparam_string("key",   Opt_key),
    {}
};

struct vtfs_fs_context {
    char *host;
    int port;
    char *token;
    char *key;
};

static int vtfs_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
    struct vtfs_fs_context *ctx = fc->fs_private;
    struct fs_parse_result result;
    int opt;

    opt = fs_parse(fc, vtfs_fs_parameters, param, &result);
    if (opt < 0)
        return opt;

    switch (opt) {
    case Opt_host:
        kfree(ctx->host);
        ctx->host = kstrdup(param->string, GFP_KERNEL);
        if (!ctx->host)
            return -ENOMEM;
        break;
    case Opt_port:
        ctx->port = result.uint_32;
        break;
    case Opt_token:
        kfree(ctx->token);
        ctx->token = kstrdup(param->string, GFP_KERNEL);
        if (!ctx->token)
            return -ENOMEM;
        break;
    case Opt_key:
        kfree(ctx->key);
        ctx->key = kstrdup(param->string, GFP_KERNEL);
        if (!ctx->key)
            return -ENOMEM;
        break;
    default:
        return -EINVAL;
    }

    return 0;
}

static int vtfs_get_tree(struct fs_context *fc)
{
    return get_tree_nodev(fc, vtfs_fill_super);
}

static void vtfs_free_fc(struct fs_context *fc)
{
    struct vtfs_fs_context *ctx = fc->fs_private;

    if (ctx) {
        kfree(ctx->host);
        kfree(ctx->token);
        kfree(ctx->key);
        kfree(ctx);
    }
}

static const struct fs_context_operations vtfs_context_ops = {
    .parse_param = vtfs_parse_param,
    .get_tree    = vtfs_get_tree,
    .free        = vtfs_free_fc,
};

int vtfs_init_fs_context(struct fs_context *fc)
{
    struct vtfs_fs_context *ctx;

    ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
    if (!ctx)
        return -ENOMEM;

    ctx->host = kstrdup("127.0.0.1", GFP_KERNEL);
    ctx->port = 9000;
    ctx->token = NULL;
    ctx->key = kstrdup("default-encryption-key-32bytes!", GFP_KERNEL);

    if (!ctx->host || !ctx->key) {
        kfree(ctx->host);
        kfree(ctx->key);
        kfree(ctx);
        return -ENOMEM;
    }

    fc->fs_private = ctx;
    fc->ops = &vtfs_context_ops;
    return 0;
}

static struct kmem_cache *vtfs_inode_cache;

static void vtfs_inode_init_once(void *obj)
{
    struct vtfs_inode_info *vi = obj;
    inode_init_once(&vi->vfs_inode);
}

static struct inode *vtfs_alloc_inode(struct super_block *sb)
{
    struct vtfs_inode_info *vi;

    vi = kmem_cache_alloc(vtfs_inode_cache, GFP_KERNEL);
    if (!vi)
        return NULL;

    vi->backend_ino = 0;
    vi->cached_size = 0;
    return &vi->vfs_inode;
}

static void vtfs_free_inode(struct inode *inode)
{
    kmem_cache_free(vtfs_inode_cache, VTFS_I(inode));
}

static void vtfs_put_super(struct super_block *sb)
{
    struct vtfs_sb_info *sbi = VTFS_SB(sb);

    if (sbi) {
        vtfs_net_disconnect(sbi);
        vtfs_crypto_cleanup(sbi);
        kfree(sbi);
        sb->s_fs_info = NULL;
    }
}

static int vtfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
    buf->f_type = VTFS_MAGIC;
    buf->f_bsize = VTFS_BLOCK_SIZE;
    buf->f_blocks = 1024 * 1024;
    buf->f_bfree = 512 * 1024;
    buf->f_bavail = 512 * 1024;
    buf->f_files = 0;
    buf->f_ffree = 0;
    buf->f_namelen = VTFS_NAME_MAX;
    return 0;
}

const struct super_operations vtfs_super_ops = {
    .alloc_inode = vtfs_alloc_inode,
    .free_inode  = vtfs_free_inode,
    .put_super   = vtfs_put_super,
    .statfs      = vtfs_statfs,
};

extern void vtfs_derive_key(const char *password, u8 *key);

int vtfs_fill_super(struct super_block *sb, struct fs_context *fc)
{
    struct vtfs_fs_context *ctx = fc->fs_private;
    struct vtfs_sb_info *sbi;
    struct inode *root_inode;
    int ret;

    sbi = kzalloc(sizeof(*sbi), GFP_KERNEL);
    if (!sbi)
        return -ENOMEM;

    strncpy(sbi->server_host, ctx->host, sizeof(sbi->server_host) - 1);
    sbi->server_port = ctx->port;

    if (ctx->token) {
        strncpy(sbi->token, ctx->token, sizeof(sbi->token) - 1);
        sbi->readonly = false;
    } else {
        sbi->readonly = true;
    }

    vtfs_derive_key(ctx->key, sbi->enc_key);
    mutex_init(&sbi->net_lock);
    sbi->txn_counter = 0;

    ret = vtfs_crypto_init(sbi);
    if (ret < 0) {
        VTFS_ERR("Failed to initialize crypto: %d", ret);
        kfree(sbi);
        return ret;
    }

    sb->s_fs_info = sbi;
    sb->s_magic = VTFS_MAGIC;
    sb->s_op = &vtfs_super_ops;
    sb->s_maxbytes = VTFS_MAX_FILESIZE;
    sb->s_blocksize = VTFS_BLOCK_SIZE;
    sb->s_blocksize_bits = 12;
    sb->s_time_gran = 1;

    ret = vtfs_net_init(sbi);
    if (ret < 0) {
        VTFS_ERR("Failed to connect to server: %d", ret);
        vtfs_crypto_cleanup(sbi);
        kfree(sbi);
        sb->s_fs_info = NULL;
        return ret;
    }

    root_inode = vtfs_iget(sb, VTFS_ROOT_INO, S_IFDIR | 0777, 0, 2);
    if (IS_ERR(root_inode)) {
        ret = PTR_ERR(root_inode);
        VTFS_ERR("Failed to create root inode: %d", ret);
        vtfs_net_disconnect(sbi);
        vtfs_crypto_cleanup(sbi);
        kfree(sbi);
        sb->s_fs_info = NULL;
        return ret;
    }

    sb->s_root = d_make_root(root_inode);
    if (!sb->s_root) {
        VTFS_ERR("Failed to create root dentry");
        vtfs_net_disconnect(sbi);
        vtfs_crypto_cleanup(sbi);
        kfree(sbi);
        sb->s_fs_info = NULL;
        return -ENOMEM;
    }

    VTFS_LOG("Mounted filesystem from %s:%d (readonly=%d)",
             sbi->server_host, sbi->server_port, sbi->readonly);
    return 0;
}

void vtfs_kill_sb(struct super_block *sb)
{
    VTFS_LOG("Unmounting filesystem");
    kill_anon_super(sb);
}

int __init vtfs_init_inode_cache(void)
{
    vtfs_inode_cache = kmem_cache_create("vtfs_inode_cache",
                                         sizeof(struct vtfs_inode_info),
                                         0,
                                         SLAB_RECLAIM_ACCOUNT | SLAB_ACCOUNT,
                                         vtfs_inode_init_once);
    if (!vtfs_inode_cache)
        return -ENOMEM;
    return 0;
}

void vtfs_destroy_inode_cache(void)
{
    rcu_barrier();
    kmem_cache_destroy(vtfs_inode_cache);
}