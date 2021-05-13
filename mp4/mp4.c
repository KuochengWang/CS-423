#define pr_fmt(fmt) "cs423_mp4: " fmt

#include <linux/lsm_hooks.h>
#include <linux/security.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/binfmts.h>
#include "mp4_given.h"

/**
 * get_inode_sid - Get the inode mp4 security label id
 *
 * @inode: the input inode
 *
 * @return the inode's security id if found.
 *
 */
static int get_inode_sid(struct inode *inode)
{
	/*
	 * Add your code here
	 * ...
	 */
	int sid;
	char * path;
	struct dentry *dentry;
	int ret; 
	int len;

	if (!inode || !inode->i_op || !inode->i_op->getxattr) {
        return -ENOMEM;
    }

	dentry = d_find_alias(inode);
	if (!dentry) {
		return -EFAULT;
	}

	len = 100;
	path = kmalloc(len, GFP_KERNEL);
	if (!path) {
		dput(dentry);
		return -ENOMEM;
	}

	memset(path, 0, len);
	ret = inode->i_op->getxattr(dentry, XATTR_NAME_MP4, path, len);

	if (ret == -ERANGE) 
	{
	    ret = inode->i_op->getxattr(dentry, XATTR_NAME_MP4, NULL, 0);
	    if (ret < 0) 
		{
			dput(dentry);
			return ret;
	    }

	    len = ret;
	    path = kmalloc(len + 1, GFP_NOFS);
	    if (!path) {
			dput(dentry);
			return -ENOMEM;
	    }
	    path[len] = 0;
	    ret = inode->i_op->getxattr(dentry, XATTR_NAME_MP4, path, len);
	}

	dput(dentry);

	if (ret < 0) 
	{	
		kfree(path);
			return ret;
    } else 
	{
	    sid = __cred_ctx_to_sid(path);
	    ret = sid;
	}

	kfree(path);
	return ret;
}


static int mp4_bprm_set_creds(struct linux_binprm *bprm)
{
    /*
     * Add your code here
     * ...
    */
    int sid; 
    struct inode *inode;
    struct mp4_security *security_label;

    // need to check whether the pointers are null
    if (!bprm || !bprm->file)
        return -ENOMEM;
    
    inode = bprm->file->f_inode;
    if (!inode)
        return -ENOMEM;

    sid = get_inode_sid(inode);

    if (sid == MP4_TARGET_SID)
    {
        if (!bprm->cred)
            return -ENOMEM;
        security_label = bprm->cred->security; // should i check it inside when sid==MP4_TARGET_SID
        if (!security_label)
            return -ENOMEM;
        security_label->mp4_flags = MP4_TARGET_SID;
    }
    return 0;
}

/**
 * mp4_cred_alloc_blank - Allocate a blank mp4 security label
 *
 * @cred: the new credentials
 * @gfp: the atomicity of the memory allocation
 *
 */
static int mp4_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
    /*
     * Add your code here
     * ...
     */

     // ?
    struct mp4_security *security_label;

    if (!cred)
    {   
        return -ENOMEM;
    }

    security_label = kmalloc(sizeof(struct mp4_security), gfp);
    if (!security_label)
        return -ENOMEM;
    security_label->mp4_flags = MP4_NO_ACCESS;
    cred->security = security_label;
    
    return 0;
}

/**
 * mp4_cred_free - Free a created security label
 *
 * @cred: the credentials struct
 *
 */
static void mp4_cred_free(struct cred *cred)
{
    /*
     * Add your code here
     * ...
     */
     struct mp4_security *security_label;
     if (!cred)
        return;

    security_label = cred->security;
    if (security_label)
    {
        kfree(security_label);
        security_label = NULL;
    }
}

/**
 * mp4_cred_prepare - Prepare new credentials for modification
 *
 * @new: the new credentials
 * @old: the old credentials
 * @gfp: the atomicity of the memory allocation
 *
 */  
 
static int mp4_cred_prepare(struct cred *new, const struct cred *old,
                gfp_t gfp)
{
    const struct mp4_security *old_tsec;
    struct mp4_security *new_tsec;
    int ret;

    old_tsec = old->security;

    if (!new)
        goto out;
    
    if (!old || !old_tsec)
    {
        new_tsec = kmalloc(sizeof(struct mp4_security), gfp);
        if (!new_tsec)
        {
            goto out;
        }
        new_tsec->mp4_flags = MP4_NO_ACCESS;
        
    } else
    {
        new_tsec = kmemdup(old_tsec, sizeof(struct mp4_security), gfp);
        if (!new_tsec)
            goto out;
        // are we going to copy from old blob?
    }  
    new->security = new_tsec;
    return 0;

out:
    ret = -ENOMEM;
    return ret;
    
}

/**
 * mp4_inode_init_security - Set the security attribute of a newly created inode
 *
 * @inode: the newly created inode
 * @dir: the containing directory
 * @qstr: unused
 * @name: where to put the attribute name
 * @value: where to put the attribute value
 * @len: where to put the length of the attribute
 *
 * returns 0 if all goes well, -ENOMEM if no memory, -EOPNOTSUPP to skip
 *
 */
 // only be called when we are creating or writing a program
static int mp4_inode_init_security(struct inode *inode, struct inode *dir,
                   const struct qstr *qstr,
                   const char **name, void **value, size_t *len)
{
    /*
     * Add your code here
     * ...
     */
    int sid;
    int rc;
    struct mp4_security *security_label;
    char* value_str;
    char* name_str;

    if (!current_cred() || !inode || !dir || !current_cred()->security)
    {
        return -EOPNOTSUPP;
    }
    
    security_label = current_cred()->security;
    
    if (name)
    {
        name_str = kstrdup(XATTR_MP4_SUFFIX, GFP_KERNEL);
        if(!name_str) {
		    return -ENOMEM;
	    }
        *name = name_str;
    }
        
        
    sid = security_label->mp4_flags;  // should use current_secury
    if (sid == MP4_TARGET_SID)
    {
        if (value && len)
        {
            value_str = kstrdup("read-write", GFP_KERNEL);
            if (!value_str) {
                return -ENOMEM;
            }
            *value = value_str;
            *len = 11;  /// might be 10
        }
    } else
        return -EOPNOTSUPP; 
    return 0;
}

static int mp4_has_permission(int ssid, int osid, int mask)
{
	/*
	 * Add your code here
	 * ...
	 */
	if (osid == MP4_NO_ACCESS)
	{
		if (ssid == MP4_TARGET_SID)
		{
			return -EACCES;
		}
		else
			return 0;
	}

	if (osid == MP4_READ_OBJ)
	{
		if ((mask & MAY_WRITE) > 0 || (mask & MAY_APPEND) > 0 || (mask & MAY_EXEC) > 0)
			return -EACCES;
	}
	else if (osid == MP4_READ_WRITE)
	{
		if (ssid == MP4_TARGET_SID)
		{
			if ((mask & MAY_EXEC) > 0)
				return -EACCES;
		}
		else
		{
			if ((mask & MAY_EXEC) > 0 || (mask & MAY_APPEND) || (mask & MAY_WRITE))
				return -EACCES;
		}
	}
	else if (osid == MP4_WRITE_OBJ)
	{
		if (ssid == MP4_TARGET_SID)
		{
			if ((mask & MAY_READ) > 0 || (mask & MAY_EXEC) > 0)
				return -EACCES;
		}
		else
		{
			if ((mask & MAY_EXEC) > 0 || (mask & MAY_APPEND) || (mask & MAY_WRITE))
				return -EACCES;
		}
	}
	else if (osid == MP4_EXEC_OBJ)
	{
		if ((mask & MAY_WRITE) > 0 || (mask & MAY_APPEND) > 0)
			return -EACCES;
	}
	else if (ssid == MP4_TARGET_SID)
	{
		if (osid == MP4_READ_DIR)
		{
			// exe: am I allowed to list the content of the dir
			if ((mask & MAY_WRITE) > 0)
				return -EACCES;
		}
		else if (osid == MP4_RW_DIR)
		{
			return 0;
		}
	}

	return 0;
}

/**
 * mp4_inode_permission - Check permission for an inode being opened
 *
 * @inode: the inode in question
 * @mask: the access requested
 *
 * This is the important access check hook
 *
 * returns 0 if access is granted, -EACCES otherwise
 *
 */
static int mp4_inode_permission(struct inode *inode, int mask)
{
	/*
	 * Add your code here
	 * ...
	 */
	char *path;
	char *buffer;
	struct dentry *dentry;
	struct mp4_security *security;
	struct cred *cred;
	int ret;
	int ssid;
	int osid;

	if (!mask) {
		return 0;
	}

	if (!inode) {
		if (printk_ratelimit())
			pr_info("inode failed\n");
		return -EACCES;
	}

	dentry = d_find_alias(inode);
	if (!dentry) {
		if (printk_ratelimit())
			pr_info("dentry failed\n");
		return -EACCES;
	}

	buffer = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buffer) {
		if (printk_ratelimit())
			pr_info("buffer failed\n");
		dput(dentry);
		return -EACCES;
	}

	path = dentry_path_raw(dentry, buffer, PATH_MAX);

	if (!path) {
		if (printk_ratelimit())
			pr_info("path failed\n");
		kfree(buffer);
		dput(dentry);
		return -EACCES;
	}

	if (mp4_should_skip_path(path)) {
		dput(dentry);
		kfree(buffer);
		return 0;
	}

	cred = current_cred();
	if (!cred || !cred->security) {  // ssid
		kfree(buffer);
		dput(dentry);
		return -EACCES;
	}

	security = cred->security;
	ssid = security->mp4_flags;
	osid = get_inode_sid(inode);
	if (osid < 0)
		osid = MP4_NO_ACCESS;
	if (ssid == MP4_TARGET_SID || (ssid != MP4_TARGET_SID && !S_ISDIR(inode->i_mode)))
	{
		ret = mp4_has_permission(ssid, osid, mask);
	}
	else
	{
		ret = 0;
	}

	if (printk_ratelimit())
	{
		if (ret == 0)
		{
		//	pr_info("path allowed %s, ssid: %d, osid:%d\n", path, ssid, osid);
		}
		else
		{
			pr_info("path denied %s\n", path);
		}
	}

	dput(dentry);
	kfree(buffer);
	return ret;
}


/*
 * This is the list of hooks that we will using for our security module.
 */
static struct security_hook_list mp4_hooks[] = {
	/*
	 * inode function to assign a label and to check permission
	 */
	LSM_HOOK_INIT(inode_init_security, mp4_inode_init_security),
	LSM_HOOK_INIT(inode_permission, mp4_inode_permission),

	/*
	 * setting the credentials subjective security label when laucnhing a
	 * binary
	 */
	LSM_HOOK_INIT(bprm_set_creds, mp4_bprm_set_creds),

	/* credentials handling and preparation */
	LSM_HOOK_INIT(cred_alloc_blank, mp4_cred_alloc_blank),
	LSM_HOOK_INIT(cred_free, mp4_cred_free),
	LSM_HOOK_INIT(cred_prepare, mp4_cred_prepare)
};

static __init int mp4_init(void)
{
	/*
	 * check if mp4 lsm is enabled with boot parameters
	 */
	if (!security_module_enable("mp4"))
		return 0;

	pr_info("mp4 LSM initializing..");

	/*
	 * Register the mp4 hooks with lsm
	 */
	security_add_hooks(mp4_hooks, ARRAY_SIZE(mp4_hooks));

	return 0;
}

/*
 * early registration with the kernel
 */
security_initcall(mp4_init);

