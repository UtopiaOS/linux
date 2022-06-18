#ifndef _MACHO_DEBUG_H
#define _MACHO_DEBUG_H

#include <linux/kernel.h>

#define mch_print_debug(x, args...) \
    printk(KERN_DEBUG "binfmt_mach-o: " x, ##args)

#endif