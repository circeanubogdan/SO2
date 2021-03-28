/*
 * SO2 - Lab 6 - Deferred Work
 *
 * Exercise #6: kernel thread
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <asm/atomic.h>
#include <linux/kthread.h>

MODULE_DESCRIPTION("Simple kernel thread");
MODULE_AUTHOR("SO2");
MODULE_LICENSE("GPL");

wait_queue_head_t wq_stop_thread;
atomic_t flag_stop_thread;
wait_queue_head_t wq_thread_terminated;
atomic_t flag_thread_terminated;

int my_thread_f(void *data)
{
	pr_info("[my_thread_f] Current process id is %d (%s)\n",
		current->pid, current->comm);
	/* TODO: Wait for command to remove module on wq_stop_thread queue. */
	wait_event(wq_stop_thread, atomic_cmpxchg(&flag_stop_thread, 1, 0));

	/* TODO: set flag to mark kernel thread termination */
	atomic_set(&flag_thread_terminated, 1);
	/* TODO: notify the unload process that we have exited */
	wake_up(&wq_thread_terminated);

	pr_info("[my_thread_f] Exiting\n");
	do_exit(0);
}

static int __init kthread_init(void)
{
	pr_info("[kthread_init] Init module\n");

	/* TODO: init the waitqueues and flags */
	init_waitqueue_head(&wq_stop_thread);
	init_waitqueue_head(&wq_thread_terminated);

	atomic_set(&flag_stop_thread, 0);
	atomic_set(&flag_thread_terminated, 0);

	/* TODO: create and start the kernel thread */
	kthread_run(my_thread_f, NULL, "Thread de manele!!!");

	return 0;
}

static void __exit kthread_exit(void)
{
	/* TODO: notify the kernel thread that its time to exit */
	atomic_set(&flag_stop_thread, 1);
	wake_up(&wq_stop_thread);

	/* TODO: wait for the kernel thread to exit */
	wait_event(
		wq_thread_terminated,
		atomic_cmpxchg(&flag_thread_terminated, 1, 0)
	);

	pr_info("[kthread_exit] Exit module\n");
}

module_init(kthread_init);
module_exit(kthread_exit);
