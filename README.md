# Kprobe-hooker
Use kprobe capture common kernel events and can also use for hids agent（kernel module）
## Compatibility
- Kernel == 4.15.0（The project selects relatively stable kprobe points to hook, and the compatibility will be testd after the framework is completed）



## Execve Event
```
{
    'evt':'execve',
    'pid':'8736',
    'exe':'/usr/bin/awk',
    'cmdline':'awk',
    'cwd':'/root/Kprobe-hooker',
    'ppid':'19255',
    'pexe':'8734',
    'pcmdline':'awk',
    'uid':'0',
    'pname':'bash',
    'pid_tree':'1(systemd)->1244(sshd)->1453(sshd)->1611(bash)->8733(bash)->8734(bash)->8736(awk)',
    'stdin':'/dev/pts/3',
    'stdout':'/dev/pts/3',
    'srcip':'10.211.55.2',
    'dstip':'10.211.55.21',
    'srcport':'62589',
    'dstport':'22',
    'tty':'pts3',
    'unixtime':'0'
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
[ 1193.262248] event_info:
               {
               'evt':'execve',
               'pid':6761,
               'exe':/bin/date,
               'cmdline':date +%s ,
               'cwd':/root/Kprobe-hooker,
               'ppid':6760,
               'uid':0,
               'comm':date,
               'pid_tree':1(systemd)->1221(sshd)->2121(sshd)->2202(bash)->6760(bash)->6761(date),
               'tty':pts2
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