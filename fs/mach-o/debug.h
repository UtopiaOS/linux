#ifndef _MACHO_DEBUG_H
#define _MACHO_DEBUG_H

#include <linux/kernel.h>

#define debug_msg(x, args...) \
    printk(KERN_DEBUG "binfmt_mach-o: " x, ##args)

#endif