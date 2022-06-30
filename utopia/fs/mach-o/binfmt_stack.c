/*
 * Darling Mach Linux Kernel Module
 * Copyright (C) 2017 Lubos Dolezel
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

// TODO: Decide if this is useless or not, since we don't really have the commpage feature!
#if defined(GEN_64BIT)
#define FUNCTION_NAME setup_stack64
#define macho_addr_t unsigned long
#elif defined(GEN_32BIT)
#define FUNCTION_NAME setup_stack32
#define macho_addr_t unsigned int
#else
#error See above
#endif

#define STACK_ALLOC(sp, len) ({sp -= len; sp; })

int FUNCTION_NAME(struct linux_binprm *bprm, struct load_results *lr)
{
	int err = 0;
	// unsigned char rand_bytes[16];
	char *executable_path, *executable_buf;
	macho_addr_t __user *argv;
	macho_addr_t __user *envp;
	macho_addr_t __user *sp;
	macho_addr_t __user *u_rand_bytes;
	macho_addr_t __user *utopiap;
	char *env_value = NULL;
	unsigned char k_rand_bytes[16];
	char __user *exepath_user;
	size_t exepath_len;
	char __user *kernfd_user;
	char kernfd[12];
	char __user *utopia_pointer_contents[3];

	executable_buf = kmalloc(4096, GFP_KERNEL);

	executable_path = d_path(&bprm->file->f_path, executable_buf, 4095);
	if (IS_ERR(executable_path))
	{
		err = -ENAMETOOLONG;
		goto out;
	}

	exepath_len = strlen(executable_path);

	memmove(executable_buf, executable_path, exepath_len + 1);

	executable_path = executable_buf;

	// The size, changed, as we copied the buffer
	exepath_len = strlen(executable_path);
	mch_print_debug("Stack top: %p\n", bprm->p);
	sp = (macho_addr_t *)(bprm->p & ~(sizeof(macho_addr_t) - 1));
	sp -= bprm->argc + bprm->envc + 6 + exepath_len + sizeof(kernfd)/4;
	exepath_user = (char __user *)bprm->p - exepath_len - sizeof(EXECUTABLE_PATH);
	
	if (!find_extend_vma(current->mm, (unsigned long)sp))
	{
		err = -EFAULT;
		goto out;
	}

	snprintf(kernfd, sizeof(kernfd), "kernfd=%d", lr->kernfd);
	kernfd_user = exepath_user - sizeof(kernfd);

	if (copy_to_user(kernfd_user, kernfd, sizeof(kernfd)))
	{
		err = -EFAULT;
		goto out;
	}

	if (copy_to_user(exepath_user, EXECUTABLE_PATH, sizeof(EXECUTABLE_PATH) - 1))
	{
		err = -EFAULT;
		goto out;
	}

	if (copy_to_user(exepath_user + sizeof(EXECUTABLE_PATH) - 1, executable_buf, exepath_len + 1))
	{
		err = -EFAULT;
		goto out;
	}

	utopia_pointer_contents[0] = exepath_user;
	utopia_pointer_contents[1] = kernfd_user;
	utopia_pointer_contents[2] = NULL;

	bprm->p = (unsigned long)sp;

	unsigned long p = current->mm->arg_start;
	int argc = bprm->argc;

	argv = sp;
	envp = argv + argc + 1;

	// Fill in argv pointers
	while (argc--)
	{
		if (__put_user((macho_addr_t)p, argv++))
		{
			err = -EFAULT;
			goto out;
		}

		size_t len = strnlen_user((void __user *)p, MAX_ARG_STRLEN);
		if (!len || len > MAX_ARG_STRLEN)
		{
			err = -EINVAL;
			goto out;
		}

		p += len;
	}
	if (__put_user((macho_addr_t)0, argv++))
	{
		err = -EFAULT;
		goto out;
	}
	current->mm->arg_end = current->mm->env_start = p;

	// Fill in envp pointers
	int envc = bprm->envc;
	env_value = (char *)kmalloc(MAX_ARG_STRLEN, GFP_KERNEL);

	while (envc--)
	{
		size_t len = strnlen_user((void __user *)p, MAX_ARG_STRLEN);
		if (!len || len > MAX_ARG_STRLEN)
		{
			err = -EINVAL;
			goto out;
		}

		if (copy_from_user(env_value, (void __user *)p, len) == 0)
		{
			// Don't pass this special env var down the the userland
			if (strncmp(env_value, "__mldr_bprefs=", 14) == 0)
			{
				p += len;
				continue;
			}
		}

		if (__put_user((macho_addr_t)p, envp++))
		{
			err = -EFAULT;
			goto out;
		}

		p += len;
	}
	if (__put_user((macho_addr_t)0, envp++))
	{
		err = -EFAULT;
		goto out;
	}
	current->mm->env_end = p;
	utopiap = envp;

	int i;
	for (i = 0; i < sizeof(utopia_pointer_contents) / sizeof(utopia_pointer_contents[0]); i++)
	{
		mch_print_debug("utopia_pointer_contents[%d]: %s\n", i, utopia_pointer_contents[i]);
		if (__put_user((macho_addr_t)(unsigned long)utopia_pointer_contents[i], utopiap++))
		{
			err = -EFAULT;
			goto out;
		}
	}

	get_random_bytes(k_rand_bytes, sizeof(k_rand_bytes));
	u_rand_bytes = (macho_addr_t __user *)STACK_ALLOC(p, sizeof(k_rand_bytes));

	if (copy_to_user(u_rand_bytes, k_rand_bytes, sizeof(k_rand_bytes)))
		return -EFAULT;

	// TODO: produce stack_guard, e.g. stack_guard=0xcdd5c48c061b00fd (must contain 00 somewhere!)
	// TODO: produce malloc_entropy, e.g. malloc_entropy=0x9536cc569d9595cf,0x831942e402da316b
	// TODO: produce main_stack?

out:
	if (env_value)
		kfree(env_value);
	return err;
}

#undef FUNCTION_NAME
#undef macho_addr_t