#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>

#define BUFFER_LEN 1000
#define PID_NUM 1000
#define PID_FILE "/proc/mp2/status"

void register_pid(pid_t pid, unsigned long period, unsigned long process_time)
{
    char command[100];
    sprintf(command, "echo R, %d, %d, %d > /proc/mp2/status", pid, period, process_time);
    system(command);
}

void yield_pid(pid_t pid)
{
    char command[100];
    sprintf(command, "echo Y, %d > /proc/mp2/status", pid);
    system(command);
}

void deregister_pid(pid_t pid)
{
    char command[100];
    sprintf(command, "echo D, %d > /proc/mp2/status", pid);
    system(command);
}

int *read_status()
{
    char buff[BUFFER_LEN] = "";
    char *token = NULL;
    const char *delim = ":(,)\n";
    FILE *file = fopen(PID_FILE, "r"); 
    static int pids[PID_NUM]; 
    int pid_index = 0;
    if (!file) 
    {    
        perror ("file open failed");
        return 1;
    }

    for (int i = 0; i < PID_NUM; i++)
    {
        pids[i] = -1;
    }

    while(fgets(buff, BUFFER_LEN, file) != NULL) 
    {
        size_t len = strlen (buff);
        if (len == BUFFER_LEN - 1 && buff[len - 1] != '\n') 
        {
            fputs ("error: line too long.\n", stderr);
        }

        token = strtok(buff, delim);
        
        pids[pid_index] = atoi(token);
      //  printf ("%d\n", pids[pid_index]);
        pid_index++;
    }

    fclose (file);
    return pids;
}

int convert_to_ms(struct timespec t)
{
    return (t.tv_sec) * 1000 + (t.tv_nsec) / 1000000; 
}

void do_job(int time)
{
    //float time_sec = time / 1000;
    usleep(time * 1000);
   // printf("do time time %d, ", time * 1000);
}

int main(int argc, char* argv[])
{
    int period;
    int process_time;
    int pid = getpid();
  //  int pid = 23;
    int pid_admission = 0;
    struct timespec t0, t1, t2;
    int t0_msec;
    int wakeup_time;
    int actual_process_time;
    int job_amount;
    time_t t;
    
    if (argc != 4)
    {
        printf("enter period， process time and number of jobs (3 param)\n");
        return 0;
    }
    period = atoi(argv[1]);
    process_time = atoi(argv[2]);
    job_amount = atoi(argv[3]);

    register_pid(pid, period, process_time);
    int *pids = read_status();

    for (int i = 0; i < PID_NUM; i++)
    {
        if (pids[i] == pid)
        {
            pid_admission = 1;
        }
    } 

    if (pid_admission == 0)
    {
        printf("pid: %d not is not admitted \n", pid);
        return 1;
    }

    if(clock_gettime(CLOCK_REALTIME, &t0) == -1 ) 
    {
        perror( "clock gettime" );
        exit( EXIT_FAILURE );
    }
    t0_msec = convert_to_ms(t0);  

    yield_pid(pid);
  
    for (int i = 0; i < job_amount; i++)   
    {
        clock_gettime(CLOCK_REALTIME, &t1);
        wakeup_time = convert_to_ms(t1);

        do_job(process_time);
        clock_gettime(CLOCK_REALTIME, &t2);
        actual_process_time = convert_to_ms(t2) - wakeup_time;
        printf("wakeup: %d, process: %d\n", wakeup_time, actual_process_time);
        yield_pid(pid);
    }

    deregister_pid(pid);
    return 0;
}


