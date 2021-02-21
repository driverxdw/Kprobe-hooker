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
<<<<<<< HEAD
    'srcip':'',
    'dstip':'',
    'srcport':'',
    'dstport':'',
=======
    'srcip':'10.211.55.2',
    'dstip':'10.211.55.21',
    'srcport':'62589',
    'dstport':'22',
>>>>>>> bc5cd5e... kprobe-hooker第一次上传
    'tty':'pts3',
    'unixtime':'0'
}
```

## Reference
https://github.com/EBWi11/AgentSmith-HIDS
