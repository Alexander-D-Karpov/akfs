#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/fs_context.h>
#include "vtfs.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alexander Karpov");
MODULE_DESCRIPTION("VTFS - Virtual Token File System with HTTP Backend");
MODULE_VERSION("1.0");

static struct kmem_cache *vtfs_inode_cache;

static struct inode *vtfs_alloc_inode(struct super_block *sb)
{
    struct vtfs_inode_info *vi;

    vi = kmem_cache_alloc(vtfs_inode_cache, GFP_KERNEL);
    if (!vi)
        return NULL;

    vi->backend_ino = 0;
    return &vi->vfs_inode;
}

static void vtfs_free_inode(struct inode *inode)
{
    kmem_cache_free(vtfs_inode_cache, VTFS_I(inode));
}

const struct super_operations vtfs_super_ops = {
    .alloc_inode    = vtfs_alloc_inode,
    .free_inode     = vtfs_free_inode,
    .statfs         = simple_statfs,
};

static void vtfs_inode_init_once(void *obj)
{
    struct vtfs_inode_info *vi = obj;
    inode_init_once(&vi->vfs_inode);
}

static struct file_system_type vtfs_fs_type = {
    .owner              = THIS_MODULE,
    .name               = "vtfs",
    .init_fs_context    = vtfs_init_fs_context,
    .kill_sb            = vtfs_kill_sb,
    .fs_flags           = 0,
};

static int __init vtfs_init(void)
{
    int ret;

    vtfs_inode_cache = kmem_cache_create("vtfs_inode_cache",
                                          sizeof(struct vtfs_inode_info),
                                          0,
                                          SLAB_RECLAIM_ACCOUNT | SLAB_ACCOUNT,
                                          vtfs_inode_init_once);
    if (!vtfs_inode_cache) {
        VTFS_ERR("Failed to create inode cache");
        return -ENOMEM;
    }

    ret = register_filesystem(&vtfs_fs_type);
    if (ret) {
        VTFS_ERR("Failed to register filesystem: %d", ret);
        kmem_cache_destroy(vtfs_inode_cache);
        return ret;
    }

    VTFS_LOG("VTFS module loaded successfully");
    return 0;
}

static void __exit vtfs_exit(void)
{
    unregister_filesystem(&vtfs_fs_type);
    rcu_barrier();
    kmem_cache_destroy(vtfs_inode_cache);
    VTFS_LOG("VTFS module unloaded");
}

module_init(vtfs_init);
module_exit(vtfs_exit);