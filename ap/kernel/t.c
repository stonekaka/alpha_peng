
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/timer.h>
#include <linux/jiffies.h>

struct timer_list mytimer;

struct mdata {
	struct mdata *next;
	struct timer_list timer;	
};

static void timer_handler(unsigned long arg)
{
	unsigned long now, next;
	char *s = (char *)arg;
	printk("In timer, arg=%s\n", s);	
	now = jiffies;
	next = jiffies + 5 * HZ;
	mod_timer(&mytimer, next);

}

static int __init reverse_init(void)
{
	printk(KERN_INFO "reverse device has been registered\n");
	char *str;

	str = (char *)kmalloc(3, GFP_KERNEL);
	memset(str, 0, 3);
	memcpy(str, "ok", 2);

//	mytimer = (struct timer_list *)kmalloc(sizeof(struct timer_list), GFP_KERNEL);

	setup_timer(&mytimer, timer_handler, (unsigned long)str);
	//init_timer_on_stack(&mytimer);
	mytimer.expires = jiffies + 5*HZ;
	//mytimer.data = (unsigned long)str;
	//mytimer.function = timer_handler;

	add_timer(&mytimer);

	

	return 0;
}
 
static void __exit reverse_exit(void)
{
	printk(KERN_INFO "reverse device has been unregistered\n");
}
  
module_init(reverse_init);
module_exit(reverse_exit);

