/* 
 * pfw.c - Personal Fire-Wall code 
 * Author: Jignesh Patel <Jignesh.Patel@umkc.edu>
 */

#define __KERNEL_
#define MODULE

#include "pfw.h"

MODULE_DESCRIPTION("Personal Fire-Wall Kernel Module");
MODULE_AUTHOR("Jignesh, Harshil, Mitul");
MODULE_LICENSE("GPL");
MODULE_SUPPORTED_DEVICE("pfw");

MODULE_PARM(CONFIG_FILE,"s");

MODULE_PARM_DESC(CONFIG_FILE,"Fire-Wall Config File e.g. /etc/pfw.conf");

wait_queue_head_t wq;
wait_queue_head_t pq;
static char *CONFIG_FILE="/etc/pfw.conf";
static struct sk_buff *sock_buff_in;
static struct sk_buff *sock_buff_out;
static alert_t *alerts;
static int cur=0,tail=0;

/* Fire-Wall rule structures */
static pfw_in_rule_t *rules_in;//[MAXINRULES];
static pfw_out_rule_t *rules_out;//[MAXOUTRULES];
static int in_count =0; // number of in rules
static int out_count=0; // number of out rules

/* pfw device VFS interface functions */
int pfw_open(struct inode *, struct file *);
int pfw_release(struct inode *, struct file *);
int pfw_read(struct file *, char *,size_t,loff_t *);
int pfw_ioctl(struct inode *,struct file *,unsigned int cmd,unsigned long arg);

/* pfw device file operations */
struct file_operations pfw_fops = {
  .owner=      THIS_MODULE,
  .read=       pfw_read,
  .ioctl=      pfw_ioctl, 
  .open=       pfw_open,
  .release=    pfw_release 
};

/* to access the system call table */
extern void *sys_call_table[];

/* pointer to original system call */
asmlinkage long (*original_sys_socketcall)(int call, unsigned long *args);

/* hook to the sys_socketcall system call */
asmlinkage long hook_sys_socketcall(int call, unsigned long *args);

/* structures to register our hooks to netfilter */
static struct nf_hook_ops pfw_inops; // to intercept incoming packets
static struct nf_hook_ops pfw_outops; // to intercept outgoing packets

/* utility function to copy from kernel to user */
int bytecopy(unsigned char *dest, unsigned char *src,int len)
{
	int j=0,k=0;
	int ret=0;
	
	for(j=len-1,k=0;k<len;k++,j--){
		put_user(*(src++),dest++);
	}	
	
	return ret;
}

/* a hook function to process the incoming packets */
unsigned int in_hook_func(unsigned int hooknum, struct sk_buff **skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn) (struct sk_buff *)){

	int i=0;
	char *da;
	sock_buff_in = *skb;

	if(!sock_buff_in) return NF_ACCEPT;
	if(!sock_buff_in->nh.iph) return NF_ACCEPT;	
	if(!sock_buff_in->h.raw) return NF_ACCEPT;

	for(i=0; i< in_count; i++){
		printk(" searching rules... \n");
		if(rules_in[i].srcip.s_addr == sock_buff_in->nh.iph->saddr
				&& rules_in[i].destport == 
				sock_buff_in->h.th->dest){

			return rules_in[i].action;
		}
	}
	
	lock_kernel();
	/* insert a new alert for user */
	alerts[cur].type = INCOMING;
	//da = (char *) &sock_buff_in->nh.iph->saddr;
	//printk("\n%s is trying to send packets on port %u.%u.%u.%u\n",da[0],da[1],da[2],da[3],sock_buff_in->h.th->dest);
//	sprintf((char *)alerts[cur].message,"%s is trying to send packets on port %u.%u.%u.%u",da[0],da[1],da[2],da[3],sock_buff_in->h.th->dest);
//	printk("PWF debug: %s ",alerts[cur].message);
	unlock_kernel();

	if ( cur == MAXALERTS-1){
		printk("pwf panic: memory overflow\n");
		cur=0;
		return -1;
	}
	else 
		cur++;
//	wake_up_interruptible(&wq);
	//cur++;
	return NF_ACCEPT;//NF_REPEAT; // or NF_STOLEN ?
		
	//if(sock_buff_in->nh.iph->protocol == IPPROTO_ICMP)
	//	return NF_DROP;
	
	//return NF_ACCEPT;
}

/* a hook function to process the outgoing packets */
unsigned int out_hook_func(unsigned int hooknum, struct sk_buff **skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn) (struct sk_buff *)){

	int i=0;
	sock_buff_out = *skb;

	if(!sock_buff_out) return NF_ACCEPT;
	if(!sock_buff_out->nh.iph) return NF_ACCEPT;	
	/* nothing much to do so just accept the packets ;)
	for(i=0; i< in_count; i++){
		if(rules_in[i]. == sock_buff_in->nh.iph->saddr
				&& rules_in[i].destport == 
				sock_buff_in->h.th->dest){

			return rules_in[i].action;
		}
		else {
			// insert a new alert for user to read
			return NF_REPEAT; // or NF_STOLEN ?
		}	
	}*/	
	
	return NF_ACCEPT;
}

/* hook to the sys_socketcall system call */
asmlinkage long hook_sys_socketcall(int call, unsigned long *args){

	int i=0;
	switch(call){
		case SYS_SOCKET:
			break;
		case SYS_BIND:
			break;
		case SYS_CONNECT:
//printk("Process %s is trying to connect to the network.\n",current->comm);
repeat1:
			for(i=0; i< out_count; i++){
				if(strcmp(rules_out[i].process,current->comm)){
				  if(rules_out[i].action==ALLOW){
					  goto allow;
				  }
				  else{
					  return -1;
				  }
				}
			}
			// insert a new alert for user to read
			// move this call to waiting 
		       	interruptible_sleep_on(&pq);
			goto repeat1;
			// or better stop this process 
			//kill_proc(current->pid,SIGSTOP,1);
			//return 0;
			// return NF_REPEAT; // or NF_STOLEN ?
			break;
		case SYS_ACCEPT:
			break;
		case SYS_SENDTO: goto allow;
//printk("Process %s is trying to send information to the internet.\n",current->comm);
repeat2:
			for(i=0; i< out_count; i++){
				if(strcmp(rules_out[i].process,current->comm))
				  if(rules_out[i].action==ALLOW){
						goto allow;
				  }
				  else {
					  return -1;
				  }
			}			
			// insert a new alert for user to read
			// move this call to waiting 
		       	interruptible_sleep_on(&pq);
			goto repeat2;
			// or better stop this process 
			//kill_proc(current->pid,SIGSTOP,1);
			//return 0;
			// return NF_REPEAT; // or NF_STOLEN ?
			break;
		case SYS_RECVFROM:
			break;
		default:
			break;
	};
allow:
	return original_sys_socketcall(call,args);
}

/* pfw device open function */
int pfw_open(struct inode *ino, struct file *filp){

	printk("Opening Personal Fire-Wall device\n");
	
//	MOD_INC_USE_COUNT;
	return 0;
}

/* pfw device close function */
int pfw_release(struct inode *ino, struct file *filp){
	
	printk("Closing Personal Fire-Wall device\n");
	
//	MOD_DEC_USE_COUNT;
	return 0;	
}

/* pfw device read function */
int pfw_read(struct file *filp, char *buff,size_t len,loff_t *n){
	

	return 0;
}

/* pfw device ioctl function */
int pfw_ioctl(struct inode *ino,struct file *filp,unsigned int cmd, \
		unsigned long arg){
	
	return 0;
}

/* module initialization */
int init_module(){
	
	/* register the sniff device driver as character driver */
	if( register_chrdev(PFW_MAJOR,PFW_NAME,&pfw_fops)< 0 ){
		printk("Error registering pfw device\n");
		return 1;
	}
	
	/* filling our hook structure for incoming packets */
	pfw_inops.hook = in_hook_func; /* handler function */
	pfw_inops.hooknum = NF_IP_LOCAL_IN; /* first hook number */
	pfw_inops.pf = PF_INET; 
	pfw_inops.priority = NF_IP_PRI_FIRST; /* set our function first */

	/* filling our hook structure for outgoing packets */
	pfw_outops.hook = out_hook_func; /* handler function */
	pfw_outops.hooknum = NF_IP_LOCAL_OUT; /* first hook number */
	pfw_outops.pf = PF_INET; 
	pfw_outops.priority = NF_IP_PRI_FIRST; /* set our function first */
	
	/* registering the hooks! */
	nf_register_hook(&pfw_inops);
	nf_register_hook(&pfw_outops);

	/* install the sys_socketcall hook */
	original_sys_socketcall = sys_call_table[__NR_socketcall];
	sys_call_table[__NR_socketcall] = hook_sys_socketcall;
	
	init_waitqueue_head(&wq);
	init_waitqueue_head(&pq);
	
	if((rules_in=(pfw_in_rule_t *)vmalloc(sizeof(pfw_in_rule_t)*MAXINRULES))
			==NULL){
		printk("Unable to allocate memory to alerts");
		return -1;
	}
	if((rules_out=(pfw_out_rule_t *)vmalloc( \
			sizeof(pfw_out_rule_t)*MAXOUTRULES))==NULL){
		printk("Unable to allocate memory to alerts");
		return -1;
	}
	if((alerts=(alert_t *)kmalloc(sizeof(alert_t)*MAXALERTS,\
					GFP_KERNEL))==NULL){
		printk("Unable to allocate memory to alerts");
		return -1;
	}

	printk("Personal Fire-Wall Module Loaded :) \n");
	printk("The Major number of the device is %d.\n",PFW_MAJOR);
	printk("Please make sure to create a device file. \n");
	printk("e.g.: mknod /dev/%s c %d 0\n",PFW_NAME,PFW_MAJOR);
	printk("Personal Fire-Wall Protection is On! \n");
	
  return 0;
}

/* module cleanup */
void cleanup_module(){
	
	/* unregister the device driver */
	if(unregister_chrdev(PFW_MAJOR,PFW_NAME)< 0 )
	       printk("Error in unregister_chrdev\n");

	/* unregister the netfilter hooks */
	nf_unregister_hook(&pfw_inops);
	nf_unregister_hook(&pfw_outops);
	
	/* uninstall the sys_socketcall hook */
	sys_call_table[__NR_socketcall] = original_sys_socketcall;
	
	vfree(rules_in);
	vfree(rules_out);
	kfree(alerts);	

	printk("Personal Fire-Wall Module successfully unloaded\n");
}

