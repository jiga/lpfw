/* 
 * pfw.h - Personal Fire-Wall Header file
 * Author: Jignesh Patel <Jignesh.Patel@umkc.edu>
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/net.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <sys/syscall.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/wrapper.h>
#include <linux/wait.h>
#include <asm/uaccess.h>
#include <linux/smp_lock.h>
#include <asm/atomic.h>

#define PFW_MAJOR	222	// device major number
#define PFW_NAME	"pfw"	// device name
#define MAXINRULES	100	
#define MAXOUTRULES	100
#define MAXALERTS	100

typedef enum {
	DENY = 0,
	ALLOW = 1
}action_t;

/* rule data structure for incoming packets */
typedef struct __pfw_in_rule{
	int action; 		// allow or deny
	struct in_addr srcip; 	// source ip address
	__u16	destport;	// destination port number	
}pfw_in_rule_t;

/* rule data structure for outgoing packets */
typedef struct __pfw_out_rule{ 
	int action; 		// allow or deny
	char process[16]; 	// process name
}pfw_out_rule_t;

typedef enum {
	INCOMING = 0,
	OUTGOING = 1,
}alerttype_t;
/* alert structure for prompting user */
typedef struct __alert_s {
	int type;		// alert for incoming or outgoing traffic
	char message[100];
}alert_t;

