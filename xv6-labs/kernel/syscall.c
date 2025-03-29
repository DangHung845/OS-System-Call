#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "syscall.h"
#include "defs.h"


static char *syscall_names[] = {
    "fork", "exit", "wait", "pipe", "read", "kill", "exec", "fstat", "chdir", 
    "dup", "getpid", "sbrk", "sleep", "uptime", "open", "write", "mknod", "unlink", 
    "link", "mkdir", "close", "trace", "sysinfo"
};

// Fetch the uint64 at addr from the current process.
int
fetchaddr(uint64 addr, uint64 *ip)
{
  struct proc *p = myproc();
  if(addr >= p->sz || addr+sizeof(uint64) > p->sz) // both tests needed, in case of overflow
    return -1;
  if(copyin(p->pagetable, (char *)ip, addr, sizeof(*ip)) != 0)
    return -1;
  return 0;
}

// Fetch the nul-terminated string at addr from the current process.
// Returns length of string, not including nul, or -1 for error.
int
fetchstr(uint64 addr, char *buf, int max)
{
  struct proc *p = myproc();
  if(copyinstr(p->pagetable, buf, addr, max) < 0)
    return -1;
  return strlen(buf);
}

static uint64
argraw(int n)
{
  struct proc *p = myproc();
  switch (n) {
  case 0:
    return p->trapframe->a0;
  case 1:
    return p->trapframe->a1;
  case 2:
    return p->trapframe->a2;
  case 3:
    return p->trapframe->a3;
  case 4:
    return p->trapframe->a4;
  case 5:
    return p->trapframe->a5;
  }
  panic("argraw");
  return -1;
}

// Fetch the nth 32-bit system call argument.
void
argint(int n, int *ip)
{
  *ip = argraw(n);
}

// Retrieve an argument as a pointer.
// Doesn't check for legality, since
// copyin/copyout will do that.
void
argaddr(int n, uint64 *ip)
{
  *ip = argraw(n);
}

// Fetch the nth word-sized system call argument as a null-terminated string.
// Copies into buf, at most max.
// Returns string length if OK (including nul), -1 if error.
int
argstr(int n, char *buf, int max)
{
  uint64 addr;
  argaddr(n, &addr);
  return fetchstr(addr, buf, max);
}

// Prototypes for the functions that handle system calls.
extern uint64 sys_fork(void);
extern uint64 sys_exit(void);
extern uint64 sys_wait(void);
extern uint64 sys_pipe(void);
extern uint64 sys_read(void);
extern uint64 sys_kill(void);
extern uint64 sys_exec(void);
extern uint64 sys_fstat(void);
extern uint64 sys_chdir(void);
extern uint64 sys_dup(void);
extern uint64 sys_getpid(void);
extern uint64 sys_sbrk(void);
extern uint64 sys_sleep(void);
extern uint64 sys_uptime(void);
extern uint64 sys_open(void);
extern uint64 sys_write(void);
extern uint64 sys_mknod(void);
extern uint64 sys_unlink(void);
extern uint64 sys_link(void);
extern uint64 sys_mkdir(void);
extern uint64 sys_close(void);
extern uint64 sys_trace(void);
extern uint64 sys_sysinfo(void);
// An array mapping syscall numbers from syscall.h
// to the function that handles the system call.
static uint64 (*syscalls[])(void) = {
[SYS_fork]     sys_fork,
[SYS_exit]     sys_exit,
[SYS_wait]     sys_wait,
[SYS_pipe]     sys_pipe,
[SYS_read]     sys_read,
[SYS_kill]     sys_kill,
[SYS_exec]     sys_exec,
[SYS_fstat]    sys_fstat,
[SYS_chdir]    sys_chdir,
[SYS_dup]      sys_dup,
[SYS_getpid]   sys_getpid,
[SYS_sbrk]     sys_sbrk,
[SYS_sleep]    sys_sleep,
[SYS_uptime]   sys_uptime,
[SYS_open]     sys_open,
[SYS_write]    sys_write,
[SYS_mknod]    sys_mknod,
[SYS_unlink]   sys_unlink,
[SYS_link]     sys_link,
[SYS_mkdir]    sys_mkdir,
[SYS_close]    sys_close,
[SYS_trace]    sys_trace,
[SYS_sysinfo]  sys_sysinfo,
};

int syscall_arg_count[] = {
  [SYS_fork]    = 0, //       No arguments
  [SYS_exit]    = 1, // int   [status] x
  [SYS_wait]    = 1, // int*  [wstatus]x
  [SYS_pipe]    = 1, // int*  [pipefd]x
  [SYS_read]    = 3, // int   [fd], void*  [buf], int  [count]x
  [SYS_kill]    = 1, // int   [pid] x
  [SYS_exec]    = 2, // char* [path], char** [argv]x
  [SYS_fstat]   = 2, // int   [fd], struct stat* [statbuf]x
  [SYS_chdir]   = 1, // char* [path]x
  [SYS_dup]     = 1, // int   [fd]x
  [SYS_getpid]  = 0, //       No arguments
  [SYS_sbrk]    = 1, // int   [increment]x
  [SYS_sleep]   = 1, // int   [seconds]x
  [SYS_uptime]  = 0, //       No arguments
  [SYS_open]    = 2, // char* [pathname], int [flags]x
  [SYS_write]   = 3, // int   [fd], void*  [buf], int  [count]x
  [SYS_mknod]   = 3, // char* [path], int [mode], int [dev]x
  [SYS_unlink]  = 1, // char* [pathname]x
  [SYS_link]    = 2, // char* [oldpath], char* [newpath]x
  [SYS_mkdir]   = 1, // char* [pathname]x
  [SYS_close]   = 1, // int   [fd]x
  [SYS_trace]   = 1, // int   [mask]x
  [SYS_sysinfo] = 0  //       No arguments
}; 

void
syscall(void)
{
  int num;
  struct proc *p = myproc();

  uint64 args_list[] = {
    p->trapframe->a0, p->trapframe->a1, p->trapframe->a2, 
    p->trapframe->a3, p->trapframe->a4, p->trapframe->a5
  };

  num = p->trapframe->a7;

  if(num > 0 && num < NELEM(syscalls) && syscalls[num]) { // num is a valid syscall number
    int return_val = syscalls[num]();
    // Use num to lookup the system call function for num, call it,
    // and store its return value in p->trapframe->a0
    if(p->trace_mask & (1 << num)) {
      printf("%d: syscall %s(", p->pid, syscall_names[num - 1]);
      switch (num) {
        case SYS_exit:
        case SYS_kill:
        case SYS_dup:
        case SYS_sbrk:
        case SYS_sleep:
        case SYS_close:
        case SYS_trace:
          printf("%lu", args_list[0]);
          break;
        case SYS_wait:
        case SYS_pipe:
          printf("%p", (int*)args_list[0]);
          break;
        case SYS_read:
        case SYS_write:
          printf("%lu, %p, %lu", args_list[0], (char*)args_list[1], args_list[2]);
          break;
        case SYS_exec:
          char* path_exec = (char*)args_list[0];
          if(!path_exec) {
            printf("NULL, ");
          } else {
            printf("%p, ", (void*)args_list[0]);
          }
          char** argv = (char**)args_list[1];
          if(!argv) {
            printf("NULL,");
          } else {
            printf("%p", (void*)args_list[1]);
          }
          break;
        case SYS_fstat:
          printf("%lu, %p", args_list[0], (struct stat*)args_list[1]);
          break;
        case SYS_chdir:
        case SYS_unlink:
        case SYS_mkdir:
          printf("%s", (char*)args_list[0]);
          break;
        case SYS_open:
          char* path_open = (char*)args_list[0];
          if(!path_open) {
            printf("NULL, %lu", args_list[1]);
          } else {
            printf("%p, %lu", (void*)args_list[0], args_list[1]);
          }
          break;
        case SYS_mknod:
          printf("%s, %lu, %lu", (char*)args_list[0], args_list[1], args_list[2]);
          break;
        case SYS_link:
          printf("%s, %s", (char*)args_list[0], (char*)args_list[1]);
          break;
        default: // fork, getpid, uptime
          break;
      }
      printf(") -> %d\n", return_val);
    }
    p->trapframe->a0 = return_val;
  } else { // num is not a valid syscall number
    printf("%d %s: unknown sys call %d\n", p->pid, p->name, num);
    p->trapframe->a0 = -1;
  }
}
