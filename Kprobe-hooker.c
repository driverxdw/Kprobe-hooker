#include "Kprobe-hooker.h"

char *argv_res = NULL;

char *str_replace(char *orig, char *rep, char *with) {
    char *result, *ins, *tmp;
    int len_rep, len_with, len_front, count;
    if (!orig || !rep)
        return NULL;
    len_rep = strlen(rep);
    if (len_rep == 0)
        return NULL;
    if (!with)
        with = "";
    len_with = strlen(with);
    ins = orig;
    for (count = 0; (tmp = strstr(ins, rep)); ++count)
        ins = tmp + len_rep;
    tmp = result = kzalloc(strlen(orig) + (len_with - len_rep) * count + 1, GFP_ATOMIC);
    if (unlikely(!result))
        return NULL;
    while (count--) {
        ins = strstr(orig, rep);
        len_front = ins - orig;
        tmp = strncpy(tmp, orig, len_front) + len_front;
        tmp = strcpy(tmp, with) + len_with;
        orig += len_front + len_rep;
    }
    strcpy(tmp, orig);
    return result;
}

char *get_pid_tree(void){
    int data_len;
    int comm_free = 0;
    int limit_index = 0;
    char *comm = NULL;
    char *res = NULL;
    char *tmp_data = NULL;
    char pid[sizeof(size_t)];
    struct task_struct *task;

    task = current;
    if(strlen(task->comm)>0){
        comm = str_replace(current->comm,"\n"," ");
        if(likely(comm))
            comm_free = 1;
        else 
            comm = "";
    }else
        comm = "";
    snprintf(pid,sizeof(size_t),"%d",task->pid);
    tmp_data = kzalloc(4096,GFP_ATOMIC);
    strcat(tmp_data,pid);
    strcat(tmp_data,"(");
    strcat(tmp_data,comm);
    strcat(tmp_data,")");
    if(likely(comm_free == 1))
        kfree(comm);
    while(task->pid != 1){
        comm_free = 0;
        limit_index = limit_index + 1;
        if(limit_index > PID_TREE_LIMIT)
            break;
        task = task->parent;
        data_len = strlen(task->comm) + sizeof(size_t) + 8;
        if(data_len > sizeof(size_t) + 8){
            comm = str_replace(task->comm,"\n"," ");
            if(likely(comm))
                comm_free = 1;
            else 
                comm = "";
        } else comm = "";
        res = kzalloc(data_len + strlen(tmp_data),GFP_ATOMIC);
        snprintf(pid,sizeof(size_t),"%d",task->pid);
        strcat(res,pid);
        strcat(res,"(");
        strcat(res,comm);
        strcat(res,")->");
        strcat(res,tmp_data);
        strcpy(tmp_data,res);
        kfree(res);
    }
    // pr_info("pid_tree:%s\n",tmp_data);
    return tmp_data;
}

char *get_exe_file(struct task_struct *task, char *buffer, int size) {
    char *exe_file_str = NULL;
    if (unlikely(!buffer)) {
        exe_file_str = "-1";
        return exe_file_str;
    }
    if (likely(task->mm)) {
        if (likely(task->mm->exe_file)) {
            char pathname[PATH_MAX];
            memset(pathname, 0, PATH_MAX);
            exe_file_str = d_path(&task->mm->exe_file->f_path, buffer, size);
        }
    }
    if (unlikely(IS_ERR(exe_file_str))) {
        exe_file_str = "-1";
    }
    return exe_file_str;
}

char *get_cwd(void){
    char *cwd;
    char *pname_buf = NULL;
    struct path pwd;
    pwd = current->fs->pwd;
    path_get(&pwd);
    pname_buf = kzalloc(PATH_MAX,GFP_ATOMIC);
    if (unlikely(!pname_buf))
        return "-1";
    cwd = kzalloc(PATH_MAX,GFP_ATOMIC);
    cwd = d_path(&pwd,pname_buf,PATH_MAX);
    kfree(pname_buf);
    return cwd;
}

const char __user *get_user_arg_ptr(const char **argv_ptr, int nr)
{
    const char __user *native;
    if (get_user(native, argv_ptr + nr))
        return ERR_PTR(-EFAULT);

    return native;
}

int count(const char **argv_ptr, int max)
{
    int i = 0;
    if (argv_ptr != NULL) {
        for (;;) {
            const char __user *p = get_user_arg_ptr(argv_ptr, i);
            if (!p)
                break;
            if (IS_ERR(p))
                return -EFAULT;
            if (i >= max)
                return -E2BIG;
            ++i;
            if (fatal_signal_pending(current))
                return -ERESTARTNOHAND;
        }
    }
    return i;
}

static void evt_fmt(char *result_str){
    pr_info("event_info:%s\n",result_str);
}

static int entry_handler(struct kretprobe_instance *ri,struct pt_regs *regs){
    const char *argv_ptr;
    const char ** argv_ptr2;
    // char *argv_res = NULL;
    char *native = NULL;
    int argv_len = 0,argv_res_len = 0,i = 0, len = 0,offset = 0;
    argv_ptr = kzalloc(255,GFP_ATOMIC);
    copy_from_user((void *)argv_ptr,(const char **)regs->di,255);
    argv_ptr2 = (const char **)regs->si;
    argv_len = count(argv_ptr2, MAX_ARG_STRINGS);
    argv_res_len = 128 * (argv_len + 2);
    
    if(likely(argv_len > 0)) {
        argv_res = kzalloc(argv_res_len + 1, GFP_ATOMIC);
        if(unlikely(!argv_res))
            argv_res = NULL;
        else {
            for (i = 0; i < argv_len; i++) {
                native = (char*)get_user_arg_ptr(argv_ptr2, i);
                if (unlikely(IS_ERR(native)))
                    break;
                len = strnlen_user(native, MAX_ARG_STRLEN);
                if (unlikely(!len))
                    break;
                if (offset + len > argv_res_len - 1)
                    break;
                if (unlikely(copy_from_user(argv_res + offset, native, len)))
                    break;
                offset += len - 1;
                *(argv_res + offset) = ' ';
                offset += 1;
            }
        }
    }
    return 0;
}

char *get_p_exe_file(struct task_struct *task, char *buffer, int size) {
    char *exe_file_str = NULL;
    if (unlikely(!buffer)) {
        exe_file_str = "-1";
        return exe_file_str;
    }
    if (likely(task->mm)) {
        if (likely(task->parent->mm->exe_file)) {
            char pathname[PATH_MAX];
            memset(pathname, 0, PATH_MAX);
            exe_file_str = d_path(&task->parent->mm->exe_file->f_path, buffer, size);
        }
    }
    if (unlikely(IS_ERR(exe_file_str))) {
        exe_file_str = "-1";
    }
    return exe_file_str;
}

static int ret_handler(struct kretprobe_instance *ri,struct pt_regs *regs){
    int uid,pid,ppid,result_str_len=0;
    char *cwd = NULL;
    char *comm = NULL;
    struct tty_struct *tty;
    char *tty_name = "-1";
    char *buffer = NULL;
    // char *buffer_2 = NULL;
    char *abs_path = NULL;
    struct task_struct *task;
    char *result_str = NULL;
    char *pid_tree = "-1";
    char *stdin = "-1";
    char *stdout = "-1";
    char *pexe = NULL;
    char *pcomm = NULL;
    char *ret_buffer = "-1";
    struct fdtable *files;

    task = current;
    comm = str_replace(current->comm,"\n"," ");
    // pr_info("comm:%s\n",comm);
    tty = get_current_tty();
    if(likely(tty)){
        if(likely(tty->name)){
            int tty_name_len = strlen(tty->name);
            if(tty_name_len == 0)
                tty_name = "-1";
            else
                tty_name = tty->name;
        }else
            tty_name = "-1";
    }
    // pr_info("tty:%s\n",tty_name);
    pid_tree = get_pid_tree();
    buffer = kzalloc(PATH_MAX, GFP_ATOMIC);
    if (unlikely(!buffer))
        abs_path = "-2";
    else
        abs_path = get_exe_file(task, buffer, PATH_MAX);
    // pr_info("exe:%s\n",abs_path);
    uid = current->real_cred->uid.val;
    // pr_info("uid:%d\n",uid);
    pid = current->pid;
    // pr_info("pid:%d\n",pid);
    ppid = current->real_parent->pid;
    // pr_info("ppid:%d\n",ppid);
    pcomm = str_replace(current->real_parent->comm,"\n"," ");
    // pr_info("ppid:%s?\n",pcomm);
    // buffer_2 = kzalloc(PATH_MAX, GFP_ATOMIC);
    pexe = get_p_exe_file(task,buffer,PATH_MAX);
    // pr_info("exe:%s?\n",pexe);
    ret_buffer = kzalloc(PATH_MAX,GFP_ATOMIC);
    files = files_fdtable(task->files);
    // ret_buffer = kzalloc(PATH_MAX,GFP_ATOMIC);
    stdin = kzalloc(PATH_MAX,GFP_ATOMIC);
    stdin = d_path(&(files->fd[0]->f_path),ret_buffer,PATH_MAX);
    stdout = kzalloc(PATH_MAX,GFP_ATOMIC);
    stdout = d_path(&(files->fd[1]->f_path),ret_buffer,PATH_MAX);
    // pr_info("stdin:%s stdout:%s\n",stdin,stdout);
    cwd = get_cwd();
    // pr_info("cwd:%s\n",cwd);
    result_str_len = strlen(argv_res) + strlen(comm) + strlen(abs_path) + strlen(pid_tree) + strlen(cwd) + strlen(tty_name) +strlen(pcomm) 
    + strlen(pexe) + strlen(stdin) + strlen(stdout) + 256;
    // pr_info("test_len:%d\n",result_str_len);
    result_str = kzalloc(result_str_len, GFP_ATOMIC);
    snprintf(result_str,result_str_len,"\n{\n\t'evt':'execve',\n\t'pid':%d,\n\t'exe':%s,\n\t'cmdline':%s,\n\t'cwd':%s,\n\t'ppid':%d,\n\t\
'pexe':%s,\n\t'pcomm':%s,\n\t'uid':%d,\n\t'comm':%s,\n\t'pid_tree':%s,\n\t'tty':%s,\n\t'stdin':%s,\n\t'stdout':%s\n}\n",pid,\
abs_path,argv_res,cwd,ppid,pexe,pcomm,uid,comm,pid_tree,tty_name,stdin,stdout);
    evt_fmt(result_str);
    // if(likely(buffer))
    //     kfree(buffer);
    // if(likely(abs_path))
    //     kfree(abs_path);
    // if(likely(result_str))
    //     kfree(result_str);
    // if(likely(pid_tree))
    //     kfree(pid_tree);
    // if(likely(stdin))
    //     kfree(stdin);
    // if(likely(stdout))
    //     kfree(stdout);
    // if(likely(pexe))
    //     kfree(pexe);
    // if(likely(pcomm))
    //     kfree(pcomm);
    return 0;
}

static struct kretprobe rp = {
    .kp.symbol_name = "sys_execve",
    .entry_handler = entry_handler,
    .handler = ret_handler,
    .maxactive = 20
};

static int __init kretprobe_init(void){
    int ret;
    ret = register_kretprobe(&rp);
    if(ret < 0){
        pr_info("register kretprobe failed, ret is %d\n",ret);
    }
    pr_info("planted return probe at %s: %p\n",rp.kp.symbol_name,rp.kp.addr);
    return 0;
};

static void __exit kretprobe_exit(void){
    unregister_kretprobe(&rp);
    pr_info("kretprobe at %s: %p unregistered\n",rp.kp.symbol_name,rp.kp.addr);
};

module_init(kretprobe_init)
module_exit(kretprobe_exit)

MODULE_DESCRIPTION("Kprobe-hooker Demo");
MODULE_AUTHOR("driverxdw");
MODULE_LICENSE("GPL");
