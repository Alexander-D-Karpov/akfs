#include <linux/module.h>
#include <linux/fs.h>
#include <linux/init.h>
#include "vtfs.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alexander Karpov");
MODULE_DESCRIPTION("Virtual Filesystem with TCP backend");
MODULE_VERSION("2.0");

extern int vtfs_init_inode_cache(void);
extern void vtfs_destroy_inode_cache(void);

static struct file_system_type vtfs_fs_type = {
    .owner          = THIS_MODULE,
    .name           = "vtfs",
    .init_fs_context = vtfs_init_fs_context,
    .kill_sb        = vtfs_kill_sb,
    .fs_flags       = 0,
};

static int __init vtfs_init(void)
{
    int ret;

    VTFS_LOG("Initializing VTFS module v2.0");

    ret = vtfs_init_inode_cache();
    if (ret) {
        VTFS_ERR("Failed to initialize inode cache: %d", ret);
        return ret;
    }

    ret = register_filesystem(&vtfs_fs_type);
    if (ret) {
        VTFS_ERR("Failed to register filesystem: %d", ret);
        vtfs_destroy_inode_cache();
        return ret;
    }

    VTFS_LOG("VTFS module loaded successfully");
    return 0;
}

static void __exit vtfs_exit(void)
{
    VTFS_LOG("Unloading VTFS module");

    unregister_filesystem(&vtfs_fs_type);
    vtfs_destroy_inode_cache();

    VTFS_LOG("VTFS module unloaded");
}

module_init(vtfs_init);
module_exit(vtfs_exit);
