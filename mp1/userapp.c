#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include "userapp.h"

int main(int argc, char* argv[])
{
   char command1[100];
   unsigned int pid = getpid();
   sprintf(command1, "echo %u > /proc/mp1/status", pid);
   system(command1);

   int f1 = 0;
   int f2 = 1;
   int next = 0;
   int n = 10000;
   char command2[100];
   sprintf(command2, "cat /proc/mp1/status");
   for (int i = 0; i < n; i++) 
   {
      f1 = f2;
      f2 = next;
      next = f1 + f2;
      system(command2);
   }
   return 0;
}
