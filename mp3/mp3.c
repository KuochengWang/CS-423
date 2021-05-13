#define LINUX

#include <asm/uaccess.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/page-flags.h>
#include <linux/pid.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/threads.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <linux/vmalloc.h>
#include "mp3_given.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kuocheng");
MODULE_DESCRIPTION("CS-423 MP3");

#define DIRECTORY "mp3"
#define STATUS_FILE "status"
#define READ_BUF_LEN 1000
#define TIMEOUT 5000
#define PAGE_NUM 128
#define MAX_DEV 1
#define INTERVAL 50

struct mutex etx_mutex;

static struct proc_dir_entry *mp3_dir, *mp3_entry;
static struct kmem_cache *mp3_task_struct_cache;
static char kernel_buf[READ_BUF_LEN];

static void work_handler(struct work_struct *w);
static DECLARE_DELAYED_WORK(mp3_work, work_handler);
static struct workqueue_struct *wkqueue;
static struct cdev mp3_cdev;
static int dev_major = 0;

unsigned long *profile;
int profile_index;
dev_t mp3_dev = 0;

LIST_HEAD(task_list);

struct mp3_task_struct 
{
    struct task_struct *linux_task;
    struct list_head task_node;
    pid_t pid;
};


static ssize_t mp3_read(struct file *file, char __user *buffer, size_t size, loff_t *offset)
{
   int copied = 0;
   struct mp3_task_struct *temp;
   
   mutex_lock_interruptible(&etx_mutex); 
   list_for_each_entry(temp, &task_list, task_node) 
   {
        copied += sprintf(kernel_buf + copied, "%u\n", temp->pid);
   }
   mutex_unlock(&etx_mutex);
   if (copied > READ_BUF_LEN) 
   {
      copied = READ_BUF_LEN;
   }
   
   return simple_read_from_buffer(buffer, size, offset, kernel_buf, copied);
}

static void work_handler(struct work_struct *w)
{
    unsigned long min_falt;
    unsigned long maj_falt;
    unsigned long total_min_falt;
    unsigned long total_maj_falt;
    unsigned long ut;
    unsigned long st;
    unsigned long total_ut;
    unsigned long total_st;
    struct mp3_task_struct *temp;

    total_maj_falt = 0;
    total_min_falt = 0;
    total_st = 0;
    total_ut = 0;
    ut = 0;
    st = 0;
    
    mutex_lock_interruptible(&etx_mutex); 
    list_for_each_entry(temp, &task_list, task_node) 
    {
            get_cpu_use(temp->pid, &min_falt, &maj_falt, &ut, &st);
            total_st += st;
            total_ut += ut;
            total_maj_falt += maj_falt;
            total_min_falt += min_falt;
    }

    profile[profile_index++] =  jiffies;    
    profile[profile_index++] = total_min_falt;   
    profile[profile_index++] = total_maj_falt;   
    profile[profile_index++] = total_st + total_ut;
    mutex_unlock(&etx_mutex);

    queue_delayed_work(wkqueue, &mp3_work, msecs_to_jiffies(INTERVAL));
}

void register_pid(pid_t pid)
{
    struct mp3_task_struct *task;
    task = kmem_cache_alloc(mp3_task_struct_cache, GFP_KERNEL);
    INIT_LIST_HEAD(&(task->task_node));
    
    task->pid = pid;
    task->linux_task = find_task_by_pid(pid);
    
    printk(KERN_INFO "pid: %d\n", pid);
   
    mutex_lock_interruptible(&etx_mutex);
    if (list_empty(&task_list))
    {
        
        queue_delayed_work(wkqueue, &mp3_work, msecs_to_jiffies(INTERVAL));
    }  
    
    list_add(&(task->task_node), &task_list);
    mutex_unlock(&etx_mutex);  
}

void deregistration(pid_t pid)
{
    struct mp3_task_struct *cursor, *temp;

    mutex_lock_interruptible(&etx_mutex);
    list_for_each_entry_safe(cursor, temp, &task_list, task_node)
    {
        if (cursor->pid == pid)
        {
            list_del(&cursor->task_node);   
            kmem_cache_free(mp3_task_struct_cache, cursor);    
        }  
    } 

    if (list_empty(&task_list))   
    {
        cancel_work_sync(&mp3_work);
        flush_workqueue(wkqueue);
    }  
    mutex_unlock(&etx_mutex);
}

static ssize_t mp3_write(struct file *file, const char __user *buf, size_t size, loff_t *offset)
{
    char *user_content;
    char *token;
    char *end;
    pid_t pid; 
 
    user_content = (char*) kzalloc((size + 1), GFP_KERNEL);
    if (!user_content)
    {
        return -ENOMEM;
    }
    copy_from_user(user_content, buf, size); 
    user_content[size] = '\0';
    pid = -1;
    token = user_content;
    end = user_content;
    while (token != NULL)
    {
        strsep(&end, " ");
        sscanf(token, "%d", &pid);
        token = end;  
    }

    if (user_content[0] == 'U')
    {
      deregistration(pid);
      printk(KERN_INFO "unregister");
    }
    if (user_content[0] == 'R')
    {
        register_pid(pid);
    }  

    kfree(user_content);
    return size;
}

static const struct file_operations fops = {
    .owner = THIS_MODULE,
    .read = mp3_read,
    .write = mp3_write
};

static int device_open(struct inode *inode, struct file *file)
{
    return 0;
}

static int device_close(struct inode *inode, struct file *file)
{
    return 0;
}

static int device_map(struct file *file, struct vm_area_struct * vma)
{
    int counter;
    int ret;
    struct page *page;
    unsigned long size;
    unsigned long pfn;
    char *profile_ptr = (char *)profile;

    ret = 0;
    page = NULL;
    size = (unsigned long)(vma->vm_end - vma->vm_start);
    if (size > PAGE_NUM * PAGE_SIZE) {
        ret = -EINVAL;
        return ret; 
    } 
   
    mutex_lock_interruptible(&etx_mutex);
    for(counter = 0; counter < PAGE_NUM * PAGE_SIZE; counter += PAGE_SIZE)
    {
        if (size <= 0)
        {
            return 0;
        } 
        pfn = vmalloc_to_pfn(profile_ptr + counter);   
        ret = remap_pfn_range(vma, vma->vm_start + counter, pfn, PAGE_SIZE, PAGE_SHARED);  
        size -= PAGE_SIZE;
    } 
    mutex_unlock(&etx_mutex);

    if (ret != 0) {
        return ret;
    }   
    return 0;
}

static struct file_operations dops =
{
    .owner = THIS_MODULE,
    .open  = device_open,
    .release = device_close,
    .mmap = device_map
};

int __init mp3_init(void) 
{
    printk(KERN_ALERT "MP3 MODULE LOADING\n");
    int counter;
    int err;
    dev_t dev;
    mp3_dir = proc_mkdir(DIRECTORY, NULL);
    mp3_task_struct_cache = kmem_cache_create("mp3_task_struct", sizeof(struct mp3_task_struct),0, SLAB_HWCACHE_ALIGN|SLAB_POISON|SLAB_RED_ZONE, NULL);
   
    if (mp3_dir == NULL) 
    {
        printk(KERN_ALERT "FAILED TO  CREATE MP3 DIR\n");
        return -ENOMEM;
    } 

    mp3_entry = proc_create(STATUS_FILE, 0666, mp3_dir, &fops);
    if (mp3_entry == NULL)
    {   
        printk(KERN_ALERT "ERROR proc_create\n");
        remove_proc_entry(DIRECTORY, NULL);
        return -ENOMEM;
    }

    mutex_init(&etx_mutex);
    wkqueue = create_workqueue("work_queue");
    
    profile = vmalloc(PAGE_NUM * PAGE_SIZE);
    if (!profile)
        return profile;

    for(counter = 0; counter < PAGE_NUM * PAGE_SIZE; counter += PAGE_SIZE)
    {
        SetPageReserved(vmalloc_to_page(((unsigned long)profile) + counter));  
    } 
    
    err = alloc_chrdev_region(&dev, 0, MAX_DEV, "mp3");  
    dev_major = MAJOR(dev);
    cdev_init(&mp3_cdev, &dops);
    cdev_add(&mp3_cdev, MKDEV(dev_major, 0), 1);  
    profile_index = 0;
    return 0;     
}

void __exit mp3_exit(void)
{
    struct mp3_task_struct *cursor, *temp;
    int counter;
    printk(KERN_ALERT "MP3 MODULE UNLOADING\n");
    
    remove_proc_entry(STATUS_FILE, mp3_dir);
    remove_proc_entry(DIRECTORY, NULL); 
    cdev_del(&mp3_cdev);
    unregister_chrdev_region(MKDEV(dev_major, 0), 1); 
    list_for_each_entry_safe(cursor, temp, &task_list, task_node)
    {
        list_del(&cursor->task_node);
        kmem_cache_free(mp3_task_struct_cache, cursor);  
    } 

    cancel_work_sync(&mp3_work);
    flush_workqueue(wkqueue);
    destroy_workqueue(wkqueue);
    printk(KERN_ALERT "MP3 MODULE UNLOADED\n");

    for(counter = 0; counter < PAGE_NUM * PAGE_SIZE; counter += PAGE_SIZE)
    {
        ClearPageReserved(vmalloc_to_page(((unsigned long)profile) + counter));  // ??? cause error
    } 
    vfree(profile);
}

// Register init and exit funtions
module_init(mp3_init);
module_exit(mp3_exit);