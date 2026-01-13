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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
    #define VTFS_GETATTR_ARGS VTFS_IDMAP_TYPE idmap, const struct path *path, \
                              struct kstat *stat, u32 request_mask, \
                              unsigned int query_flags
    #define VTFS_GETATTR_INODE d_inode(path->dentry)
#else
    #define VTFS_GETATTR_ARGS struct vfsmount *mnt, struct dentry *dentry, \
                              struct kstat *stat
    #define VTFS_GETATTR_INODE d_inode(dentry)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    #define VTFS_USE_PROC_OPS 1
#endif

/* generic_fillattr changed signature in newer kernels */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
#define vtfs_generic_fillattr(idmap, request_mask, inode, stat) \
    generic_fillattr((idmap), (request_mask), (inode), (stat))
#else
#define vtfs_generic_fillattr(idmap, request_mask, inode, stat) \
    generic_fillattr((idmap), (inode), (stat))
#endif


/* Timestamp helpers */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 7, 0)
    /* Newer kernels: don't assign inode->i_atime/i_mtime directly */
    #define vtfs_set_time(inode) simple_inode_init_ts(inode)
    #define vtfs_update_time(inode) \
        inode_set_mtime_to_ts((inode), inode_set_ctime_current((inode)))
#else
    #define vtfs_set_time(inode) do { \
        (inode)->i_atime = (inode)->i_mtime = (inode)->i_ctime = current_time((inode)); \
    } while (0)

    #define vtfs_update_time(inode) do { \
        (inode)->i_mtime = (inode)->i_ctime = current_time((inode)); \
    } while (0)
#endif

#endif
