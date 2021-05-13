#define LINUX

#include <asm/uaccess.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include "mp1_given.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Group_ID");
MODULE_DESCRIPTION("CS-423 MP1");

#define DEBUG 1
#define DIRECTORY "mp1"
#define STATUS_FILE "status"
#define TIMEOUT 5000
#define READ_BUF_LEN 1000 

spinlock_t lock;

static struct proc_dir_entry *mp1_dir, *mp1_entry; 
struct workqueue_struct *wkqueue;
struct work_data *w_data;
static char kernel_buf[READ_BUF_LEN];

struct cpu
{
   unsigned long time;
   int pid;
   struct list_head head;   
};

struct work_data 
{
   struct work_struct work;
   int data;
};

static struct timer_list etx_timer;

LIST_HEAD(cpu_list);

// Delete the pid if it does not exist.
// Update the time if it exists 
static void work_handler(struct work_struct *work)
{
   unsigned long flags;
   struct cpu *cursor, *temp;
   spin_lock_irqsave(&lock, flags);

   list_for_each_entry_safe(cursor, temp, &cpu_list, head)
   {  
      if(get_cpu_use(cursor->pid, &cursor->time) == -1)
      { 
         list_del(&cursor->head);
         kfree(cursor);
         printk(KERN_ALERT "deleted\n");
      }
   }

   spin_unlock_irqrestore(&lock, flags);   
}

// Botom part of the timer interrupt.
// repeat work every 5 ms 
void timer_callback(unsigned long data)
{
   queue_work(wkqueue, &w_data->work);
   mod_timer(&etx_timer, jiffies + msecs_to_jiffies(TIMEOUT));
}

static ssize_t mp1_write(struct file *file, const char __user *buf, size_t size, loff_t *offset)
{
   struct cpu *cur_cpu = kmalloc(sizeof(struct cpu), GFP_KERNEL);
   unsigned long flags;
   char *user_content = (char*) kzalloc((size + 1), GFP_KERNEL);

   INIT_LIST_HEAD(&(cur_cpu->head));

   if (!user_content)
   {
      return -ENOMEM;
   }
   cur_cpu->time = 0;
   
   copy_from_user(user_content, buf, size);
   user_content[size] = '\0';
   sscanf(user_content, "%u", &cur_cpu->pid); 
   printk(KERN_INFO "write: %d\n", cur_cpu->pid);
   
   printk(KERN_INFO "inside write\n");
   cur_cpu->time = 0;   
   spin_lock_irqsave(&lock, flags); 
   list_add(&(cur_cpu->head), &cpu_list);
   spin_unlock_irqrestore(&lock, flags);
   kfree(user_content); 
   return size;
}

static ssize_t mp1_read(struct file *file, char __user *buffer, size_t size, loff_t *offset)
{
   unsigned long flags;
   // char* temp_buf;
   int copied = 0;
   struct cpu *temp;
   
   spin_lock_irqsave(&lock, flags);
   list_for_each_entry(temp, &cpu_list, head) {
   copied += sprintf(kernel_buf + copied, "%u:%u\n", temp->pid, temp->time);
   }
   if (copied > READ_BUF_LEN) {
      copied = READ_BUF_LEN;
   }
   printk(KERN_INFO "read: %s:", kernel_buf); 
   spin_unlock_irqrestore(&lock, flags);
   return simple_read_from_buffer(buffer, size, offset, kernel_buf, copied);
}

// owner refers to the file owner
static const struct file_operations fops = {
  .owner = THIS_MODULE,
  .read = mp1_read,
  .write = mp1_write
};

// mp1_init - Called when module is loaded
int __init mp1_init(void)
{
   #ifdef DEBUG
   printk(KERN_ALERT "MP1 MODULE LOADING\n");
   #endif
   // Insert your code here ...
   
   mp1_dir = proc_mkdir(DIRECTORY, NULL);
   if (mp1_dir == NULL) 
   {
      printk(KERN_ALERT "FAILED TO  CREATE MP1 DIR\n");
      return -ENOMEM;
   } 
  
   mp1_entry = proc_create(STATUS_FILE, 0666, mp1_dir, &fops);
   if (mp1_entry == NULL)
   {   
      printk(KERN_ALERT "ERROR proc_create\n");
      remove_proc_entry(DIRECTORY, NULL);
      return -ENOMEM;
   } 

   spin_lock_init(&lock);
   wkqueue = create_workqueue("work_queue");
   w_data = kmalloc(sizeof(struct work_data), GFP_KERNEL);
   INIT_WORK(&w_data->work, work_handler);

   setup_timer(&etx_timer, timer_callback, 0);
   mod_timer(&etx_timer, jiffies + msecs_to_jiffies(TIMEOUT));
   
   return 0;   
}

// mp1_exit - Called when module is unloaded
void __exit mp1_exit(void)
{
   #ifdef DEBUG
   printk(KERN_ALERT "MP1 MODULE UNLOADING\n");
   #endif
   // Insert your code here ...   
   struct cpu *cursor, *temp;
   remove_proc_entry(STATUS_FILE, mp1_dir);
   remove_proc_entry(DIRECTORY, NULL);
   
   list_for_each_entry_safe(cursor, temp, &cpu_list, head)
   {
      list_del(&cursor->head);
      kfree(cursor);  
   }

   del_timer(&etx_timer);
   flush_workqueue(wkqueue);
   destroy_workqueue(wkqueue);
   kfree(w_data);  
   printk(KERN_ALERT "MP1 MODULE UNLOADED\n");
}

// Register init and exit funtions
module_init(mp1_init);
module_exit(mp1_exit);
