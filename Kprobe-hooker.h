#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/fs_struct.h>
#include <linux/uaccess.h>
#include <linux/tty.h>
#include <linux/binfmts.h>
#define PID_TREE_LIMIT 7