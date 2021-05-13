#define LINUX

#include <asm/uaccess.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/pid.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/threads.h>
#include <linux/workqueue.h>
#include "mp2_given.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kuocheng");
MODULE_DESCRIPTION("CS-423 MP2");

#define DIRECTORY "mp2"
#define STATUS_FILE "status"
#define READ_BUF_LEN 1000
#define TIMEOUT 5000

static struct proc_dir_entry *mp2_dir, *mp2_entry;
static char kernel_buf[READ_BUF_LEN];
static struct kmem_cache *mp2_task_struct_cache;
static struct task_struct *dispatch_task;

spinlock_t lock;
enum task_states{sleep, ready, running};
int wake_up_time;

struct mp2_task_struct 
{
    struct task_struct *linux_task;
    struct list_head task_node;
    struct timer_list wakeup_timer;
    pid_t pid;
    unsigned int period_ms;
    unsigned int compute_time_ms;
    unsigned long deadline_jiff;
    int task_state;
};

LIST_HEAD(task_list);
struct mp2_task_struct *running_task;

void set_priority(int priority_value, struct task_struct *task, int sched_type)
{
    struct sched_param sparam;
    sparam.sched_priority = priority_value;
    sched_setscheduler(task, sched_type, &sparam);
}

void wake_up_dispatch_thread(void)
{
    wake_up_process(dispatch_task);
}

struct mp2_task_struct* find_task_by_id(int pid)
{
    struct mp2_task_struct *cursor, *temp, *task_selected;
    unsigned long flags;
    
    task_selected = NULL;
    spin_lock_irqsave(&lock, flags); 
    list_for_each_entry_safe(cursor, temp, &task_list, task_node)
    {
        if (cursor->pid == pid)
        {
            task_selected = cursor; 
        }  
    } 
    spin_unlock_irqrestore(&lock, flags);
    return task_selected;
}

void timer_callback(int pid)
{
    unsigned long flags; 
    struct mp2_task_struct* task = find_task_by_id(pid);
    if (task != NULL)
    {
        spin_lock_irqsave(&lock, flags); 
        task->task_state = ready; 
        spin_unlock_irqrestore(&lock, flags);
    } 
    printk(KERN_INFO "timer caller back");
    wake_up_dispatch_thread();
}

int admission_control(pid_t pid, int period, int process_time)
{
    unsigned long flags;
    int sum;
    int scale;
    int threashold;
    struct mp2_task_struct *cursor, *temp;
  
    sum = 0;
    scale = 100000;
    threashold = 69300;
    spin_lock_irqsave(&lock, flags); 
    list_for_each_entry_safe(cursor, temp, &task_list, task_node)
    {
        sum += cursor->compute_time_ms*scale / cursor->period_ms;        
    } 
    spin_unlock_irqrestore(&lock, flags);
    sum += (process_time*scale) / period;
  
    printk(KERN_INFO "sum %d", sum);
    if (sum <= threashold)
    {
        return 1;
    }
    return 0;
}

void register_pid(pid_t pid, unsigned int period, unsigned int process_time)
{
    unsigned long flags;
    struct mp2_task_struct *task;

         
    if (!admission_control(pid, period, process_time))
    {
        printk(KERN_INFO "not admitted");
        return;
    }

    INIT_LIST_HEAD(&(task->task_node));
    task = kmem_cache_alloc(mp2_task_struct_cache, GFP_KERNEL);
   // task->task_state = sleep; do i  
    task->period_ms = period;
    task->pid = pid;
    task->compute_time_ms = process_time;
    task->deadline_jiff = 0;
    task->linux_task = find_task_by_pid(pid);
    
    setup_timer(&task->wakeup_timer, timer_callback, pid);

    spin_lock_irqsave(&lock, flags); 
    list_add(&(task->task_node), &task_list);
    spin_unlock_irqrestore(&lock, flags);
}

void deregistration(pid_t pid)
{
    unsigned long flags;
    struct mp2_task_struct *cursor, *temp;

    spin_lock_irqsave(&lock, flags); 
    list_for_each_entry_safe(cursor, temp, &task_list, task_node)
    {
        if (cursor->pid == pid)
        {
            // check if the current task is the deregister task
            if (cursor == running_task)
            {
                running_task = NULL;  
                wake_up_dispatch_thread();  // find the next running task
            }
            list_del(&cursor->task_node);
            kmem_cache_free(mp2_task_struct_cache, cursor);    
        }  
    } 
    spin_unlock_irqrestore(&lock, flags);
}

void pid_yield(int pid)
{
    struct mp2_task_struct* task;
    int should_sleep;
    unsigned long flags;

    task = find_task_by_id(pid);
    if (task == NULL)
    {
        return;
    }

    should_sleep = 1;

    if (task->deadline_jiff == 0)
    {
        printk(KERN_INFO "dealine: %d\n", task->period_ms);
        task->deadline_jiff = jiffies + msecs_to_jiffies(task->period_ms);
    }
    else
    {
        task->deadline_jiff +=  msecs_to_jiffies(task->period_ms);
        should_sleep = task->deadline_jiff > jiffies? 1 : 0; 
        
    }
    printk(KERN_INFO "should_sleep: %d\n", should_sleep);
    if (!should_sleep)
        return;
    printk(KERN_INFO "dealine: %d\n", jiffies_to_msecs(task->deadline_jiff));
    task->task_state = sleep;
    mod_timer(&task->wakeup_timer, task->deadline_jiff);

    spin_lock_irqsave(&lock, flags); 
    running_task = NULL;
    spin_unlock_irqrestore(&lock, flags);
    
    wake_up_dispatch_thread();  // find the new running task

    set_task_state(task->linux_task, TASK_UNINTERRUPTIBLE);  // force to sleep until next period
    schedule(); 
}

static ssize_t mp2_write(struct file *file, const char __user *buf, size_t size, loff_t *offset)
{
    unsigned int period;
    unsigned int process_time;
    char *user_content;
    char *token;
    char *end;
    pid_t pid; 
    int index;
    
    user_content = (char*) kzalloc((size + 1), GFP_KERNEL);
    if (!user_content)
    {
        return -ENOMEM;
    }
    copy_from_user(user_content, buf, size); 
    user_content[size] = '\0';
    index = 0;
    pid = -1;
    period = -1;
    process_time = -1;
    token = user_content;
    end = user_content;
    while (token != NULL)
    {
        index++;
        strsep(&end, ",");
        switch (index)
        {
            case 2:
                sscanf(token, "%d", &pid);
                break;
            case 3:
                sscanf(token, "%d", &period);
                break;
            case 4:
                sscanf(token, "%d", &process_time);
                break;
        }
        if (user_content[0] == 'Y' || user_content[0] == 'D')
        {
            if (index == 2)
                break;
        }
        token = end;  
    }

    if (user_content[0] == 'Y')
    {
        pid_yield(pid);
    }
    if (user_content[0] == 'D')
    {
        deregistration(pid);
    }
    if (user_content[0] == 'R')
    {
        printk(KERN_INFO "pid: %d, period: %d, process %d\n", pid, period, process_time);
        register_pid(pid, period, process_time);
    }  

    kfree(user_content);
    return size;
}

static ssize_t mp2_read(struct file *file, char __user *buffer, size_t size, loff_t *offset)
{
   unsigned long flags;
   int copied = 0;
   struct mp2_task_struct *temp;
   
   spin_lock_irqsave(&lock, flags);
   list_for_each_entry(temp, &task_list, task_node) 
   {
        copied += sprintf(kernel_buf + copied, "%u: %d, %d\n", temp->pid, temp->period_ms, temp->compute_time_ms);
   }
   spin_unlock_irqrestore(&lock, flags);
   if (copied > READ_BUF_LEN) 
   {
      copied = READ_BUF_LEN;
   }
   
   return simple_read_from_buffer(buffer, size, offset, kernel_buf, copied);
}

static const struct file_operations fops = {
    .owner = THIS_MODULE,
    .read = mp2_read,
    .write = mp2_write
};

static int task_handler(void *arguments)
{
    struct mp2_task_struct *cursor, *temp, *shortest_task;
    unsigned long flags;
    
    allow_signal(SIGKILL);
    while(!kthread_should_stop())
    {
        shortest_task = NULL;
        spin_lock_irqsave(&lock, flags);  
        list_for_each_entry_safe(cursor, temp, &task_list, task_node)
        {
            if (shortest_task == NULL || cursor->period_ms < shortest_task->period_ms)
            {
                if (cursor->task_state == ready)
                {
                    shortest_task = cursor;
                }
                
            }
        }

        // preempt current task
        if (running_task != NULL)
        {
            set_priority(0, running_task->linux_task, SCHED_NORMAL);
            if (running_task->task_state == running)
            {
                running_task->task_state = ready;
            }
        }
        if (shortest_task != NULL)
        {
            
            running_task = shortest_task;
            printk(KERN_INFO "pid %d:", running_task->pid);
            wake_up_process(running_task->linux_task);
            // context switch to chosen task (another way to do context switch)
            set_priority(99, running_task->linux_task, SCHED_FIFO);
            running_task->task_state = running;
        } 
        spin_unlock_irqrestore(&lock, flags);

        // context switch
        set_current_state(TASK_INTERRUPTIBLE);
        schedule();
    }

    do_exit(0);
    return 0;
}

void create_dispatch_thread(void)
{
    int cpu;
    dispatch_task = kthread_create(task_handler,
            (void*)NULL,"dispatch_thread");
    if (!dispatch_task) 
    {
        printk(KERN_INFO "can't create dispatch thread");
    }
}

int __init mp2_init(void) 
{
    printk(KERN_ALERT "MP2 MODULE LOADING\n");

    mp2_dir = proc_mkdir(DIRECTORY, NULL);
    running_task = NULL;
    if (mp2_dir == NULL) 
    {
        printk(KERN_ALERT "FAILED TO  CREATE MP2 DIR\n");
        return -ENOMEM;
    } 

    mp2_entry = proc_create(STATUS_FILE, 0666, mp2_dir, &fops);
    if (mp2_entry == NULL)
    {   
        printk(KERN_ALERT "ERROR proc_create\n");
        remove_proc_entry(DIRECTORY, NULL);
        return -ENOMEM;
    }

    spin_lock_init(&lock);
    mp2_task_struct_cache = kmem_cache_create("mp2_task_struct", sizeof(struct mp2_task_struct),0, SLAB_HWCACHE_ALIGN|SLAB_POISON|SLAB_RED_ZONE, NULL);
    create_dispatch_thread();
    
    return 0;     
}

void __exit mp2_exit(void)
{
    printk(KERN_ALERT "MP2 MODULE UNLOADING\n");
    
    struct mp2_task_struct *cursor, *temp;

    list_for_each_entry_safe(cursor, temp, &task_list, task_node)
    {
        del_timer(&cursor->wakeup_timer);  
        list_del(&cursor->task_node);
        kmem_cache_free(mp2_task_struct_cache, cursor);  
    } 
    remove_proc_entry(STATUS_FILE, mp2_dir);
    remove_proc_entry(DIRECTORY, NULL); 
    kthread_stop(dispatch_task);
}

// Register init and exit funtions
module_init(mp2_init);
module_exit(mp2_exit);



