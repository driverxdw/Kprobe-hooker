# Kprobe-hooker
Use kprobe capture common kernel events and can also use for hids agent（kernel module）
## Compatibility
- Kernel == 4.15.0（The project selects relatively stable kprobe points to hook, and the compatibility will be testd after the framework is completed）



## Execve Event
```
{
  'evt':'execve',
  'pid':7477,
  'exe':/bin/bash,
  'cmdline':rmmod Kprobe_hooker ,
  'cwd':/usr/local/Kprobe-hooker,
  'ppid':2142,
  'pexe':/bin/bash,
  'pcomm':bash,
  'uid':0,
  'comm':rmmod,
  'pid_tree':1(systemd)->1223(sshd)->2061(sshd)->2142(bash)->7477(rmmod),
  'tty':pts1,
  'stdin':/dev/pts/1,
  'stdout':/dev/pts/1
}
```

## How To Use
```
root@eBPF:/usr/local/Kprobe-hooker# make # compile
rm -f *.o *.ko Module.markers Module.symvers w_plus_x*.mod.c modules.order
make -C /lib/modules/4.15.0-20-generic/build M=/usr/local/Kprobe-hooker modules
make[1]: Entering directory '/usr/src/linux-headers-4.15.0-20-generic'
  CC [M]  /usr/local/Kprobe-hooker/Kprobe-hooker.o
  Building modules, stage 2.
  MODPOST 1 modules
  CC      /usr/local/Kprobe-hooker/Kprobe-hooker.mod.o
  LD [M]  /usr/local/Kprobe-hooker/Kprobe-hooker.ko
make[1]: Leaving directory '/usr/src/linux-headers-4.15.0-20-generic'

root@eBPF:/usr/local/Kprobe-hooker# insmod Kprobe-hooker.ko # install lkm

root@eBPF:/usr/local/Kprobe-hooker# rmmod Kprobe_hooker # uninstall lkm

root@eBPF:/usr/local/Kprobe-hooker# dmesg # event show
[ 1193.260895] planted return probe at sys_execve: 00000000200bdbd7
[  621.256485] event_info:
               {
               	'evt':'execve',
               	'pid':7477,
               	'exe':/bin/bash,
               	'cmdline':rmmod Kprobe_hooker ,
               	'cwd':/usr/local/Kprobe-hooker,
               	'ppid':2142,
               	'pexe':/bin/bash,
               	'pcomm':bash,
               	'uid':0,
               	'comm':rmmod,
               	'pid_tree':1(systemd)->1223(sshd)->2061(sshd)->2142(bash)->7477(rmmod),
               	'tty':pts1,
               	'stdin':/dev/pts/1,
               	'stdout':/dev/pts/1
               }
```

## Todo
- Multiple Common Events (ing)
- Memory Map (ring buffer)
- Intrusion detection (reverse shell & web rce & etc.)
- Combine With Common Data Streaming Platform (kafka & es & etc.) 
- todo.

## Reference
https://github.com/EBWi11/AgentSmith-HIDS