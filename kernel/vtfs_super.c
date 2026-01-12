#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "vtfs.h"

struct vtfs_fs_context {
    char *server_url;
    char *token;
};

enum vtfs_param {
    Opt_token,
};

static const struct fs_parameter_spec vtfs_fs_parameters[] = {
    fsparam_string("token", Opt_token),
    {}
};

int vtfs_fill_super(struct super_block *sb, struct fs_context *fc)
{
    struct vtfs_fs_context *ctx = fc->fs_private;
    struct vtfs_sb_info *sbi;
    struct inode *root_inode;

    sbi = kzalloc(sizeof(*sbi), GFP_KERNEL);
    if (!sbi)
        return -ENOMEM;

    if (ctx->server_url && strlen(ctx->server_url) > 0) {
        strncpy(sbi->server_url, ctx->server_url, sizeof(sbi->server_url) - 1);
    } else if (fc->source && strlen(fc->source) > 0) {
        strncpy(sbi->server_url, fc->source, sizeof(sbi->server_url) - 1);
    } else {
        strncpy(sbi->server_url, "http://localhost:8080", sizeof(sbi->server_url) - 1);
    }
    sbi->server_url[sizeof(sbi->server_url) - 1] = '\0';

    if (ctx->token && strlen(ctx->token) > 0) {
        strncpy(sbi->token, ctx->token, sizeof(sbi->token) - 1);
        sbi->token[sizeof(sbi->token) - 1] = '\0';
        sbi->readonly = false;
        VTFS_LOG("Mounting with write access (token provided)");
    } else {
        sbi->token[0] = '\0';
        sbi->readonly = true;
        VTFS_LOG("Mounting read-only (no token)");
    }

    mutex_init(&sbi->http_lock);

    sb->s_fs_info = sbi;
    sb->s_magic = VTFS_MAGIC;
    sb->s_op = &vtfs_super_ops;
    sb->s_maxbytes = VTFS_MAX_FILESIZE;
    sb->s_blocksize = VTFS_BLOCK_SIZE;
    sb->s_blocksize_bits = 12;
    sb->s_time_gran = 1;

    if (sbi->readonly)
        sb->s_flags |= SB_RDONLY;

    root_inode = vtfs_iget(sb, VTFS_ROOT_INO, S_IFDIR | 0777, 0, 2);
    if (IS_ERR(root_inode)) {
        VTFS_ERR("Failed to get root inode");
        kfree(sbi);
        return PTR_ERR(root_inode);
    }

    sb->s_root = d_make_root(root_inode);
    if (!sb->s_root) {
        VTFS_ERR("Failed to create root dentry");
        kfree(sbi);
        return -ENOMEM;
    }

    VTFS_LOG("Superblock initialized, server: %s", sbi->server_url);
    return 0;
}

static int vtfs_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
    struct vtfs_fs_context *ctx = fc->fs_private;
    struct fs_parse_result result;
    int opt;

    opt = fs_parse(fc, vtfs_fs_parameters, param, &result);
    if (opt < 0)
        return opt;

    switch (opt) {
    case Opt_token:
        kfree(ctx->token);
        ctx->token = kstrdup(param->string, GFP_KERNEL);
        if (!ctx->token)
            return -ENOMEM;
        break;
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
        kfree(ctx->server_url);
        kfree(ctx->token);
        kfree(ctx);
    }
}

static const struct fs_context_operations vtfs_context_ops = {
    .parse_param    = vtfs_parse_param,
    .get_tree       = vtfs_get_tree,
    .free           = vtfs_free_fc,
};

int vtfs_init_fs_context(struct fs_context *fc)
{
    struct vtfs_fs_context *ctx;

    ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
    if (!ctx)
        return -ENOMEM;

    fc->fs_private = ctx;
    fc->ops = &vtfs_context_ops;
    return 0;
}

void vtfs_kill_sb(struct super_block *sb)
{
    struct vtfs_sb_info *sbi = VTFS_SB(sb);

    VTFS_LOG("Destroying superblock");
    kill_anon_super(sb);

    if (sbi) {
        mutex_destroy(&sbi->http_lock);
        kfree(sbi);
    }

    VTFS_LOG("VTFS unmounted");
}