#ifndef _VTFS_COMPAT_H
#define _VTFS_COMPAT_H

#include <linux/version.h>
#include <linux/fs.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
    #include <linux/mnt_idmapping.h>
    #define VTFS_IDMAP_TYPE struct mnt_idmap *
    #define VTFS_NOP_IDMAP &nop_mnt_idmap
    #define vtfs_inode_init_owner(idmap, inode, dir, mode) \
        inode_init_owner(idmap, inode, dir, mode)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
    #define VTFS_IDMAP_TYPE struct user_namespace *
    #define VTFS_NOP_IDMAP &init_user_ns
    #define vtfs_inode_init_owner(userns, inode, dir, mode) \
        inode_init_owner(userns, inode, dir, mode)
#else
    #define VTFS_IDMAP_TYPE void *
    #define VTFS_NOP_IDMAP NULL
    #define vtfs_inode_init_owner(unused, inode, dir, mode) \
        inode_init_owner(inode, dir, mode)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
    #define VTFS_DIR_ITERATE .iterate_shared
#else
    #define VTFS_DIR_ITERATE .iterate_shared
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0)
    #define VTFS_MKDIR_RETTYPE struct dentry *
    #define VTFS_MKDIR_RET_OK NULL
    #define VTFS_MKDIR_RET_ERR(e) ERR_PTR(e)
#else
    #define VTFS_MKDIR_RETTYPE int
    #define VTFS_MKDIR_RET_OK 0
    #define VTFS_MKDIR_RET_ERR(e) (e)
#endif

#endif