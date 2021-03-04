#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>

MODULE_DESCRIPTION("Display the memory areas of the current process");
MODULE_AUTHOR("Teodor Dutu");
MODULE_LICENSE("GPL");

static int mem_info_init(void)
{
	int i;
	struct mm_struct *mem = current->mm;
	struct vm_area_struct *areas = mem->mmap;

	for (i = 0; i != mem->map_count; ++i)
		pr_info("Memory area: [0x%08lX, 0x%08lX]",
			areas[i].vm_start, areas[i].vm_end);

	return 0;
}

static void mem_info_exit(void)
{
	pr_info("Removed mem info module");
}

module_init(mem_info_init);
module_exit(mem_info_exit);
