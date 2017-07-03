/*
 * ss.c		"sockstat", socket statistics
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <fnmatch.h>
#include <getopt.h>
#include <stdbool.h>
#include <limits.h>

#include "utils.h"
#include "rt_names.h"
#include "ll_map.h"
#include "libnetlink.h"
#include "namespace.h"
#include "SNAPSHOT.h"

#include <linux/tcp.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <linux/unix_diag.h>
#include <linux/netdevice.h>	/* for MAX_ADDR_LEN */
#include <linux/filter.h>
#include <linux/packet_diag.h>
#include <linux/netlink_diag.h>
#include <linux/sctp.h>

#define MAGIC_SEQ 123456

#define DIAG_REQUEST(_req, _r)						    \
	struct {							    \
		struct nlmsghdr nlh;					    \
		_r;							    \
	} _req = {							    \
		.nlh = {						    \
			.nlmsg_type = SOCK_DIAG_BY_FAMILY,		    \
			.nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST,\
			.nlmsg_seq = MAGIC_SEQ,				    \
			.nlmsg_len = sizeof(_req),			    \
		},							    \
	}

#if HAVE_SELINUX
#include <selinux/selinux.h>
#else
/* Stubs for SELinux functions */
static int is_selinux_enabled(void)
{
	return -1;
}

static int getpidcon(pid_t pid, char **context)
{
	*context = NULL;
	return -1;
}

static int getfilecon(char *path, char **context)
{
	*context = NULL;
	return -1;
}

static int security_get_initial_context(char *name,  char **context)
{
	*context = NULL;
	return -1;
}
#endif

int resolve_hosts;
int resolve_services = 1;
int preferred_family = AF_UNSPEC;
int show_options;
int show_details;
int show_users;
int show_mem;
int show_tcpinfo;
int show_bpf;
int show_proc_ctx;
int show_sock_ctx;
int show_header = 1;
int follow_events;
int sctp_ino;

int netid_width;
int state_width;
int addr_width;
int serv_width;

static const char *TCP_PROTO = "tcp";
static const char *UDP_PROTO = "udp";
static const char *RAW_PROTO = "raw";
static const char *dg_proto;

enum {
	TCP_DB,
	DCCP_DB,
	UDP_DB,
	RAW_DB,
	UNIX_DG_DB,
	UNIX_ST_DB,
	UNIX_SQ_DB,
	PACKET_DG_DB,
	PACKET_R_DB,
	NETLINK_DB,
	SCTP_DB,
	MAX_DB
};

#define PACKET_DBM ((1<<PACKET_DG_DB)|(1<<PACKET_R_DB))
#define UNIX_DBM ((1<<UNIX_DG_DB)|(1<<UNIX_ST_DB)|(1<<UNIX_SQ_DB))
#define ALL_DB ((1<<MAX_DB)-1)
#define INET_L4_DBM ((1<<TCP_DB)|(1<<UDP_DB)|(1<<DCCP_DB)|(1<<SCTP_DB))
#define INET_DBM (INET_L4_DBM | (1<<RAW_DB))

enum {
	SS_UNKNOWN,
	SS_ESTABLISHED,
	SS_SYN_SENT,
	SS_SYN_RECV,
	SS_FIN_WAIT1,
	SS_FIN_WAIT2,
	SS_TIME_WAIT,
	SS_CLOSE,
	SS_CLOSE_WAIT,
	SS_LAST_ACK,
	SS_LISTEN,
	SS_CLOSING,
	SS_MAX
};

enum {
	SCTP_STATE_CLOSED		= 0,
	SCTP_STATE_COOKIE_WAIT		= 1,
	SCTP_STATE_COOKIE_ECHOED	= 2,
	SCTP_STATE_ESTABLISHED		= 3,
	SCTP_STATE_SHUTDOWN_PENDING	= 4,
	SCTP_STATE_SHUTDOWN_SENT	= 5,
	SCTP_STATE_SHUTDOWN_RECEIVED	= 6,
	SCTP_STATE_SHUTDOWN_ACK_SENT	= 7,
};

#define SS_ALL ((1 << SS_MAX) - 1)
#define SS_CONN (SS_ALL & ~((1<<SS_LISTEN)|(1<<SS_CLOSE)|(1<<SS_TIME_WAIT)|(1<<SS_SYN_RECV)))

#include "ssfilter.h"

struct filter {
	int dbs;
	int states;
	int families;
	struct ssfilter *f;
	bool kill;
};

static const struct filter default_dbs[MAX_DB] = {
	[TCP_DB] = {
		.states   = SS_CONN,
		.families = (1 << AF_INET) | (1 << AF_INET6),
	},
	[DCCP_DB] = {
		.states   = SS_CONN,
		.families = (1 << AF_INET) | (1 << AF_INET6),
	},
	[UDP_DB] = {
		.states   = (1 << SS_ESTABLISHED),
		.families = (1 << AF_INET) | (1 << AF_INET6),
	},
	[RAW_DB] = {
		.states   = (1 << SS_ESTABLISHED),
		.families = (1 << AF_INET) | (1 << AF_INET6),
	},
	[UNIX_DG_DB] = {
		.states   = (1 << SS_CLOSE),
		.families = (1 << AF_UNIX),
	},
	[UNIX_ST_DB] = {
		.states   = SS_CONN,
		.families = (1 << AF_UNIX),
	},
	[UNIX_SQ_DB] = {
		.states   = SS_CONN,
		.families = (1 << AF_UNIX),
	},
	[PACKET_DG_DB] = {
		.states   = (1 << SS_CLOSE),
		.families = (1 << AF_PACKET),
	},
	[PACKET_R_DB] = {
		.states   = (1 << SS_CLOSE),
		.families = (1 << AF_PACKET),
	},
	[NETLINK_DB] = {
		.states   = (1 << SS_CLOSE),
		.families = (1 << AF_NETLINK),
	},
	[SCTP_DB] = {
		.states   = SS_CONN,
		.families = (1 << AF_INET) | (1 << AF_INET6),
	},
};

static const struct filter default_afs[AF_MAX] = {
	[AF_INET] = {
		.dbs    = INET_DBM,
		.states = SS_CONN,
	},
	[AF_INET6] = {
		.dbs    = INET_DBM,
		.states = SS_CONN,
	},
	[AF_UNIX] = {
		.dbs    = UNIX_DBM,
		.states = SS_CONN,
	},
	[AF_PACKET] = {
		.dbs    = PACKET_DBM,
		.states = (1 << SS_CLOSE),
	},
	[AF_NETLINK] = {
		.dbs    = (1 << NETLINK_DB),
		.states = (1 << SS_CLOSE),
	},
};

static int do_default = 1;
static struct filter current_filter;

static void filter_db_set(struct filter *f, int db)
{
	f->states   |= default_dbs[db].states;
	f->dbs	    |= 1 << db;
	do_default   = 0;
}

static void filter_af_set(struct filter *f, int af)
{
	f->states	   |= default_afs[af].states;
	f->families	   |= 1 << af;
	do_default	    = 0;
	preferred_family    = af;
}

static void filter_default_dbs(struct filter *f)
{
	filter_db_set(f, UDP_DB);
	filter_db_set(f, DCCP_DB);
	filter_db_set(f, TCP_DB);
	filter_db_set(f, RAW_DB);
	filter_db_set(f, UNIX_ST_DB);
	filter_db_set(f, UNIX_DG_DB);
	filter_db_set(f, UNIX_SQ_DB);
	filter_db_set(f, PACKET_R_DB);
	filter_db_set(f, PACKET_DG_DB);
	filter_db_set(f, NETLINK_DB);
	filter_db_set(f, SCTP_DB);
}

static void filter_states_set(struct filter *f, int states)
{
	if (states)
		f->states = states;
}

static void filter_merge_defaults(struct filter *f)
{
	int db;
	int af;

	for (db = 0; db < MAX_DB; db++) {
		if (!(f->dbs & (1 << db)))
			continue;

		if (!(default_dbs[db].families & f->families))
			f->families |= default_dbs[db].families;
	}
	for (af = 0; af < AF_MAX; af++) {
		if (!(f->families & (1 << af)))
			continue;

		if (!(default_afs[af].dbs & f->dbs))
			f->dbs |= default_afs[af].dbs;
	}
}

static void sock_addr_print_width(int addr_len, const char *addr, char *delim,
                int port_len, const char *port, const char *ifname)
{
        if (ifname) {
                printf("%*s%%%s%s%-*s ", addr_len, addr, ifname, delim,
                                port_len, port);
        } else {
                printf("%*s%s%-*s ", addr_len, addr, delim, port_len, port);
        }
}



static FILE *generic_proc_open(const char *env, const char *name)
{
	const char *p = getenv(env);
	char store[128];

	if (!p) {
		p = getenv("PROC_ROOT") ? : "/proc";
		snprintf(store, sizeof(store)-1, "%s/%s", p, name);
		p = store;
	}

	return fopen(p, "r");
}
#define net_tcp_open()		generic_proc_open("PROC_NET_TCP", "net/tcp")
#define net_tcp6_open()		generic_proc_open("PROC_NET_TCP6", "net/tcp6")
#define net_udp_open()		generic_proc_open("PROC_NET_UDP", "net/udp")
#define net_udp6_open()		generic_proc_open("PROC_NET_UDP6", "net/udp6")
#define net_raw_open()		generic_proc_open("PROC_NET_RAW", "net/raw")
#define net_raw6_open()		generic_proc_open("PROC_NET_RAW6", "net/raw6")
#define net_unix_open()		generic_proc_open("PROC_NET_UNIX", "net/unix")
#define net_packet_open()	generic_proc_open("PROC_NET_PACKET", \
							"net/packet")
#define net_netlink_open()	generic_proc_open("PROC_NET_NETLINK", \
							"net/netlink")
#define slabinfo_open()		generic_proc_open("PROC_SLABINFO", "slabinfo")
#define net_sockstat_open()	generic_proc_open("PROC_NET_SOCKSTAT", \
							"net/sockstat")
#define net_sockstat6_open()	generic_proc_open("PROC_NET_SOCKSTAT6", \
							"net/sockstat6")
#define net_snmp_open()		generic_proc_open("PROC_NET_SNMP", "net/snmp")
#define ephemeral_ports_open()	generic_proc_open("PROC_IP_LOCAL_PORT_RANGE", \
					"sys/net/ipv4/ip_local_port_range")

struct user_ent {
	struct user_ent	*next;
	unsigned int	ino;
	int		pid;
	int		fd;
	char		*process;
	char		*process_ctx;
	char		*socket_ctx;
};

#define USER_ENT_HASH_SIZE	256
struct user_ent *user_ent_hash[USER_ENT_HASH_SIZE];

static int user_ent_hashfn(unsigned int ino)
{
	int val = (ino >> 24) ^ (ino >> 16) ^ (ino >> 8) ^ ino;

	return val & (USER_ENT_HASH_SIZE - 1);
}

enum entry_types {
	USERS,
	PROC_CTX,
	PROC_SOCK_CTX
};

#define ENTRY_BUF_SIZE 512
static int find_entry(unsigned int ino, char **buf, int type)
{
	struct user_ent *p;
	int cnt = 0;
	char *ptr;
	char *new_buf;
	int len, new_buf_len;
	int buf_used = 0;
	int buf_len = 0;

	if (!ino)
		return 0;

	p = user_ent_hash[user_ent_hashfn(ino)];
	ptr = *buf = NULL;
	while (p) {
		if (p->ino != ino)
			goto next;

		while (1) {
			ptr = *buf + buf_used;
			switch (type) {
			case USERS:
				len = snprintf(ptr, buf_len - buf_used,
					"(\"%s\",pid=%d,fd=%d),",
					p->process, p->pid, p->fd);
				break;
			case PROC_CTX:
				len = snprintf(ptr, buf_len - buf_used,
					"(\"%s\",pid=%d,proc_ctx=%s,fd=%d),",
					p->process, p->pid,
					p->process_ctx, p->fd);
				break;
			case PROC_SOCK_CTX:
				len = snprintf(ptr, buf_len - buf_used,
					"(\"%s\",pid=%d,proc_ctx=%s,fd=%d,sock_ctx=%s),",
					p->process, p->pid,
					p->process_ctx, p->fd,
					p->socket_ctx);
				break;
			default:
				fprintf(stderr, "ss: invalid type: %d\n", type);
				abort();
			}

			if (len < 0 || len >= buf_len - buf_used) {
				new_buf_len = buf_len + ENTRY_BUF_SIZE;
				new_buf = realloc(*buf, new_buf_len);
				if (!new_buf) {
					fprintf(stderr, "ss: failed to malloc buffer\n");
					abort();
				}
				*buf = new_buf;
				buf_len = new_buf_len;
				continue;
			} else {
				buf_used += len;
				break;
			}
		}
		cnt++;
next:
		p = p->next;
	}
	if (buf_used) {
		ptr = *buf + buf_used;
		ptr[-1] = '\0';
	}
	return cnt;
}

static unsigned long long cookie_sk_get(const uint32_t *cookie)
{
	return (((unsigned long long)cookie[1] << 31) << 1) | cookie[0];
}

static const char *sctp_sstate_name[] = {
	[SCTP_STATE_CLOSED] = "CLOSED",
	[SCTP_STATE_COOKIE_WAIT] = "COOKIE_WAIT",
	[SCTP_STATE_COOKIE_ECHOED] = "COOKIE_ECHOED",
	[SCTP_STATE_ESTABLISHED] = "ESTAB",
	[SCTP_STATE_SHUTDOWN_PENDING] = "SHUTDOWN_PENDING",
	[SCTP_STATE_SHUTDOWN_SENT] = "SHUTDOWN_SENT",
	[SCTP_STATE_SHUTDOWN_RECEIVED] = "SHUTDOWN_RECEIVED",
	[SCTP_STATE_SHUTDOWN_ACK_SENT] = "ACK_SENT",
};

struct sockstat {
	struct sockstat	   *next;
	unsigned int	    type;
	uint16_t	    prot;
	uint16_t	    raw_prot;
	inet_prefix	    local;
	inet_prefix	    remote;
	int		    lport;
	int		    rport;
	int		    state;
	int		    rq, wq;
	unsigned int ino;
	unsigned int uid;
	int		    refcnt;
	unsigned int	    iface;
	unsigned long long  sk;
	char *name;
	char *peer_name;
	__u32		    mark;
};

struct dctcpstat {
	unsigned int	ce_state;
	unsigned int	alpha;
	unsigned int	ab_ecn;
	unsigned int	ab_tot;
	bool		enabled;
};

struct tcpstat {
	struct sockstat	    ss;
	int		    timer;
	int		    timeout;
	int		    probes;
	char		    cong_alg[16];
	double		    rto, ato, rtt, rttvar;
	int		    qack, ssthresh, backoff;
	double		    send_bps;
	int		    snd_wscale;
	int		    rcv_wscale;
	int		    mss;
	unsigned int	    cwnd;
	unsigned int	    lastsnd;
	unsigned int	    lastrcv;
	unsigned int	    lastack;
	double		    pacing_rate;
	double		    pacing_rate_max;
	double		    delivery_rate;
	unsigned long long  bytes_acked;
	unsigned long long  bytes_received;
	unsigned int	    segs_out;
	unsigned int	    segs_in;
	unsigned int	    data_segs_out;
	unsigned int	    data_segs_in;
	unsigned int	    unacked;
	unsigned int	    retrans;
	unsigned int	    retrans_total;
	unsigned int	    lost;
	unsigned int	    sacked;
	unsigned int	    fackets;
	unsigned int	    reordering;
	unsigned int	    not_sent;
	double		    rcv_rtt;
	double		    min_rtt;
	int		    rcv_space;
	unsigned long long  busy_time;
	unsigned long long  rwnd_limited;
	unsigned long long  sndbuf_limited;
	bool		    has_ts_opt;
	bool		    has_sack_opt;
	bool		    has_ecn_opt;
	bool		    has_ecnseen_opt;
	bool		    has_fastopen_opt;
	bool		    has_wscale_opt;
	bool		    app_limited;
	struct dctcpstat    *dctcp;
	struct tcp_bbr_info *bbr_info;
};

/* SCTP assocs share the same inode number with their parent endpoint. So if we
 * have seen the inode number before, it must be an assoc instead of the next
 * endpoint. */
static bool is_sctp_assoc(struct sockstat *s, const char *sock_name)
{
	if (strcmp(sock_name, "sctp"))
		return false;
	if (!sctp_ino || sctp_ino != s->ino)
		return false;
	return true;
}

static const char *unix_netid_name(int type)
{
	switch (type) {
	case SOCK_STREAM:
		return "u_str";
	case SOCK_SEQPACKET:
		return "u_seq";
	case SOCK_DGRAM:
	default:
		return "u_dgr";
	}
}

static const char *proto_name(int protocol)
{
	switch (protocol) {
	case 0:
		return "raw";
	case IPPROTO_UDP:
		return "udp";
	case IPPROTO_TCP:
		return "tcp";
	case IPPROTO_SCTP:
		return "sctp";
	case IPPROTO_DCCP:
		return "dccp";
	}

	return "???";
}

static void sock_state_print(struct sockstat *s)
{
	const char *sock_name;
	static const char * const sstate_name[] = {
		"UNKNOWN",
		[SS_ESTABLISHED] = "ESTAB",
		[SS_SYN_SENT] = "SYN-SENT",
		[SS_SYN_RECV] = "SYN-RECV",
		[SS_FIN_WAIT1] = "FIN-WAIT-1",
		[SS_FIN_WAIT2] = "FIN-WAIT-2",
		[SS_TIME_WAIT] = "TIME-WAIT",
		[SS_CLOSE] = "UNCONN",
		[SS_CLOSE_WAIT] = "CLOSE-WAIT",
		[SS_LAST_ACK] = "LAST-ACK",
		[SS_LISTEN] =	"LISTEN",
		[SS_CLOSING] = "CLOSING",
	};

	switch (s->local.family) {
	case AF_UNIX:
		sock_name = unix_netid_name(s->type);
		break;
	case AF_INET:
	case AF_INET6:
		sock_name = proto_name(s->type);
		break;
	case AF_PACKET:
		sock_name = s->type == SOCK_RAW ? "p_raw" : "p_dgr";
		break;
	case AF_NETLINK:
		sock_name = "nl";
		break;
	default:
		sock_name = "unknown";
	}

	if (netid_width)
		printf("%-*s ", netid_width,
		       is_sctp_assoc(s, sock_name) ? "" : sock_name);
	if (state_width) {
		if (is_sctp_assoc(s, sock_name))
			printf("`- %-*s ", state_width - 3,
			       sctp_sstate_name[s->state]);
		else
			printf("%-*s ", state_width, sstate_name[s->state]);
	}

	printf("%-6d %-6d ", s->rq, s->wq);
}

static void sock_details_print(struct sockstat *s)
{
	if (s->uid)
		printf(" uid:%u", s->uid);

	printf(" ino:%u", s->ino);
	printf(" sk:%llx", s->sk);

	if (s->mark)
		printf(" fwmark:0x%x", s->mark);
}

static const char *print_ms_timer(int timeout)
{
	static char buf[64];
	int secs, msecs, minutes;

	if (timeout < 0)
		timeout = 0;
	secs = timeout/1000;
	minutes = secs/60;
	secs = secs%60;
	msecs = timeout%1000;
	buf[0] = 0;
	if (minutes) {
		msecs = 0;
		snprintf(buf, sizeof(buf)-16, "%dmin", minutes);
		if (minutes > 9)
			secs = 0;
	}
	if (secs) {
		if (secs > 9)
			msecs = 0;
		sprintf(buf+strlen(buf), "%d%s", secs, msecs ? "." : "sec");
	}
	if (msecs)
		sprintf(buf+strlen(buf), "%03dms", msecs);
	return buf;
}

struct scache {
	struct scache *next;
	int port;
	char *name;
	const char *proto;
};

struct scache *rlist;

/* Even do not try default linux ephemeral port ranges:
 * default /etc/services contains so much of useless crap
 * wouldbe "allocated" to this area that resolution
 * is really harmful. I shrug each time when seeing
 * "socks" or "cfinger" in dumps.
 */
static int is_ephemeral(int port)
{
	static int min = 0, max;

	if (!min) {
		FILE *f = ephemeral_ports_open();

		if (!f || fscanf(f, "%d %d", &min, &max) < 2) {
			min = 1024;
			max = 4999;
		}
		if (f)
			fclose(f);
	}
	return port >= min && port <= max;
}


static const char *__resolve_service(int port)
{
	struct scache *c;

	for (c = rlist; c; c = c->next) {
		if (c->port == port && c->proto == dg_proto)
			return c->name;
	}

	if (!is_ephemeral(port)) {
		static int notfirst;
		struct servent *se;

		if (!notfirst) {
			setservent(1);
			notfirst = 1;
		}
		se = getservbyport(htons(port), dg_proto);
		if (se)
			return se->s_name;
	}

	return NULL;
}

#define SCACHE_BUCKETS 1024
static struct scache *cache_htab[SCACHE_BUCKETS];

static const char *resolve_service(int port)
{
	static char buf[128];
	struct scache *c;
	const char *res;
	int hash;

	if (port == 0) {
		buf[0] = '*';
		buf[1] = 0;
		return buf;
	}

	if (!resolve_services)
		goto do_numeric;

	if (dg_proto == RAW_PROTO)
		return inet_proto_n2a(port, buf, sizeof(buf));


	hash = (port^(((unsigned long)dg_proto)>>2)) % SCACHE_BUCKETS;

	for (c = cache_htab[hash]; c; c = c->next) {
		if (c->port == port && c->proto == dg_proto)
			goto do_cache;
	}

	c = malloc(sizeof(*c));
	if (!c)
		goto do_numeric;
	res = __resolve_service(port);
	c->port = port;
	c->name = res ? strdup(res) : NULL;
	c->proto = dg_proto;
	c->next = cache_htab[hash];
	cache_htab[hash] = c;

do_cache:
	if (c->name)
		return c->name;

do_numeric:
	sprintf(buf, "%u", port);
	return buf;
}

static void inet_addr_print(const inet_prefix *a, int port, unsigned int ifindex)
{
	char buf[1024];
	const char *ap = buf;
	int est_len = addr_width;
	const char *ifname = NULL;

	if (a->family == AF_INET) {
		if (a->data[0] == 0) {
			buf[0] = '*';
			buf[1] = 0;
		} else {
			ap = format_host(AF_INET, 4, a->data);
		}
	} else {
		ap = format_host(a->family, 16, a->data);
		est_len = strlen(ap);
		if (est_len <= addr_width)
			est_len = addr_width;
		else
			est_len = addr_width + ((est_len-addr_width+3)/4)*4;
	}

	if (ifindex) {
		ifname   = ll_index_to_name(ifindex);
		est_len -= strlen(ifname) + 1;  /* +1 for percent char */
		if (est_len < 0)
			est_len = 0;
	}

	sock_addr_print_width(est_len, ap, ":", serv_width, resolve_service(port),
			ifname);
}

struct aafilter {
	inet_prefix	addr;
	int		port;
	unsigned int	iface;
	__u32		mark;
	__u32		mask;
	struct aafilter *next;
};

static int inet2_addr_match(const inet_prefix *a, const inet_prefix *p,
			    int plen)
{
	if (!inet_addr_match(a, p, plen))
		return 0;

	/* Cursed "v4 mapped" addresses: v4 mapped socket matches
	 * pure IPv4 rule, but v4-mapped rule selects only v4-mapped
	 * sockets. Fair? */
	if (p->family == AF_INET && a->family == AF_INET6) {
		if (a->data[0] == 0 && a->data[1] == 0 &&
		    a->data[2] == htonl(0xffff)) {
			inet_prefix tmp = *a;

			tmp.data[0] = a->data[3];
			return inet_addr_match(&tmp, p, plen);
		}
	}
	return 1;
}

static int unix_match(const inet_prefix *a, const inet_prefix *p)
{
	char *addr, *pattern;

	memcpy(&addr, a->data, sizeof(addr));
	memcpy(&pattern, p->data, sizeof(pattern));
	if (pattern == NULL)
		return 1;
	if (addr == NULL)
		addr = "";
	return !fnmatch(pattern, addr, 0);
}

static int run_ssfilter(struct ssfilter *f, struct sockstat *s)
{
	switch (f->type) {
		case SSF_S_AUTO:
	{
		if (s->local.family == AF_UNIX) {
			char *p;

			memcpy(&p, s->local.data, sizeof(p));
			return p == NULL || (p[0] == '@' && strlen(p) == 6 &&
					     strspn(p+1, "0123456789abcdef") == 5);
		}
		if (s->local.family == AF_PACKET)
			return s->lport == 0 && s->local.data[0] == 0;
		if (s->local.family == AF_NETLINK)
			return s->lport < 0;

		return is_ephemeral(s->lport);
	}
		case SSF_DCOND:
	{
		struct aafilter *a = (void *)f->pred;

		if (a->addr.family == AF_UNIX)
			return unix_match(&s->remote, &a->addr);
		if (a->port != -1 && a->port != s->rport)
			return 0;
		if (a->addr.bitlen) {
			do {
				if (!inet2_addr_match(&s->remote, &a->addr, a->addr.bitlen))
					return 1;
			} while ((a = a->next) != NULL);
			return 0;
		}
		return 1;
	}
		case SSF_SCOND:
	{
		struct aafilter *a = (void *)f->pred;

		if (a->addr.family == AF_UNIX)
			return unix_match(&s->local, &a->addr);
		if (a->port != -1 && a->port != s->lport)
			return 0;
		if (a->addr.bitlen) {
			do {
				if (!inet2_addr_match(&s->local, &a->addr, a->addr.bitlen))
					return 1;
			} while ((a = a->next) != NULL);
			return 0;
		}
		return 1;
	}
		case SSF_D_GE:
	{
		struct aafilter *a = (void *)f->pred;

		return s->rport >= a->port;
	}
		case SSF_D_LE:
	{
		struct aafilter *a = (void *)f->pred;

		return s->rport <= a->port;
	}
		case SSF_S_GE:
	{
		struct aafilter *a = (void *)f->pred;

		return s->lport >= a->port;
	}
		case SSF_S_LE:
	{
		struct aafilter *a = (void *)f->pred;

		return s->lport <= a->port;
	}
		case SSF_DEVCOND:
	{
		struct aafilter *a = (void *)f->pred;

		return s->iface == a->iface;
	}
		case SSF_MARKMASK:
	{
		struct aafilter *a = (void *)f->pred;

		return (s->mark & a->mask) == a->mark;
	}
		/* Yup. It is recursion. Sorry. */
		case SSF_AND:
		return run_ssfilter(f->pred, s) && run_ssfilter(f->post, s);
		case SSF_OR:
		return run_ssfilter(f->pred, s) || run_ssfilter(f->post, s);
		case SSF_NOT:
		return !run_ssfilter(f->pred, s);
		default:
		abort();
	}
}

/* Relocate external jumps by reloc. */
static int remember_he(struct aafilter *a, struct hostent *he)
{
	char **ptr = he->h_addr_list;
	int cnt = 0;
	int len;

	if (he->h_addrtype == AF_INET)
		len = 4;
	else if (he->h_addrtype == AF_INET6)
		len = 16;
	else
		return 0;

	while (*ptr) {
		struct aafilter *b = a;

		if (a->addr.bitlen) {
			if ((b = malloc(sizeof(*b))) == NULL)
				return cnt;
			*b = *a;
			b->next = a->next;
			a->next = b;
		}
		memcpy(b->addr.data, *ptr, len);
		b->addr.bytelen = len;
		b->addr.bitlen = len*8;
		b->addr.family = he->h_addrtype;
		ptr++;
		cnt++;
	}
	return cnt;
}

static int get_dns_host(struct aafilter *a, const char *addr, int fam)
{
	static int notfirst;
	int cnt = 0;
	struct hostent *he;

	a->addr.bitlen = 0;
	if (!notfirst) {
		sethostent(1);
		notfirst = 1;
	}
	he = gethostbyname2(addr, fam == AF_UNSPEC ? AF_INET : fam);
	if (he)
		cnt = remember_he(a, he);
	if (fam == AF_UNSPEC) {
		he = gethostbyname2(addr, AF_INET6);
		if (he)
			cnt += remember_he(a, he);
	}
	return !cnt;
}

static int xll_initted;

static void xll_init(void)
{
	struct rtnl_handle rth;

	if (rtnl_open(&rth, 0) < 0)
		exit(1);

	ll_init_map(&rth);
	rtnl_close(&rth);
	xll_initted = 1;
}

static int xll_name_to_index(const char *dev)
{
	if (!xll_initted)
		xll_init();
	return ll_name_to_index(dev);
}

void *parse_devcond(char *name)
{
	struct aafilter a = { .iface = 0 };
	struct aafilter *res;

	a.iface = xll_name_to_index(name);
	if (a.iface == 0) {
		char *end;
		unsigned long n;

		n = strtoul(name, &end, 0);
		if (!end || end == name || *end || n > UINT_MAX)
			return NULL;

		a.iface = n;
	}

	res = malloc(sizeof(*res));
	*res = a;

	return res;
}

void *parse_hostcond(char *addr, bool is_port)
{
	char *port = NULL;
	struct aafilter a = { .port = -1 };
	struct aafilter *res;
	int fam = preferred_family;
	struct filter *f = &current_filter;

	if (fam == AF_UNIX || strncmp(addr, "unix:", 5) == 0) {
		char *p;

		a.addr.family = AF_UNIX;
		if (strncmp(addr, "unix:", 5) == 0)
			addr += 5;
		p = strdup(addr);
		a.addr.bitlen = 8*strlen(p);
		memcpy(a.addr.data, &p, sizeof(p));
		fam = AF_UNIX;
		goto out;
	}

	if (fam == AF_PACKET || strncmp(addr, "link:", 5) == 0) {
		a.addr.family = AF_PACKET;
		a.addr.bitlen = 0;
		if (strncmp(addr, "link:", 5) == 0)
			addr += 5;
		port = strchr(addr, ':');
		if (port) {
			*port = 0;
			if (port[1] && strcmp(port+1, "*")) {
				if (get_integer(&a.port, port+1, 0)) {
					if ((a.port = xll_name_to_index(port+1)) <= 0)
						return NULL;
				}
			}
		}
		if (addr[0] && strcmp(addr, "*")) {
			unsigned short tmp;

			a.addr.bitlen = 32;
			if (ll_proto_a2n(&tmp, addr))
				return NULL;
			a.addr.data[0] = ntohs(tmp);
		}
		fam = AF_PACKET;
		goto out;
	}

	if (fam == AF_NETLINK || strncmp(addr, "netlink:", 8) == 0) {
		a.addr.family = AF_NETLINK;
		a.addr.bitlen = 0;
		if (strncmp(addr, "netlink:", 8) == 0)
			addr += 8;
		port = strchr(addr, ':');
		if (port) {
			*port = 0;
			if (port[1] && strcmp(port+1, "*")) {
				if (get_integer(&a.port, port+1, 0)) {
					if (strcmp(port+1, "kernel") == 0)
						a.port = 0;
					else
						return NULL;
				}
			}
		}
		if (addr[0] && strcmp(addr, "*")) {
			a.addr.bitlen = 32;
			if (nl_proto_a2n(&a.addr.data[0], addr) == -1)
				return NULL;
		}
		fam = AF_NETLINK;
		goto out;
	}

	if (fam == AF_INET || !strncmp(addr, "inet:", 5)) {
		fam = AF_INET;
		if (!strncmp(addr, "inet:", 5))
			addr += 5;
	} else if (fam == AF_INET6 || !strncmp(addr, "inet6:", 6)) {
		fam = AF_INET6;
		if (!strncmp(addr, "inet6:", 6))
			addr += 6;
	}

	/* URL-like literal [] */
	if (addr[0] == '[') {
		addr++;
		if ((port = strchr(addr, ']')) == NULL)
			return NULL;
		*port++ = 0;
	} else if (addr[0] == '*') {
		port = addr+1;
	} else {
		port = strrchr(strchr(addr, '/') ? : addr, ':');
	}

	if (is_port)
		port = addr;

	if (port && *port) {
		if (*port == ':')
			*port++ = 0;

		if (*port && *port != '*') {
			if (get_integer(&a.port, port, 0)) {
				struct servent *se1 = NULL;
				struct servent *se2 = NULL;

				if (current_filter.dbs&(1<<UDP_DB))
					se1 = getservbyname(port, UDP_PROTO);
				if (current_filter.dbs&(1<<TCP_DB))
					se2 = getservbyname(port, TCP_PROTO);
				if (se1 && se2 && se1->s_port != se2->s_port) {
					fprintf(stderr, "Error: ambiguous port \"%s\".\n", port);
					return NULL;
				}
				if (!se1)
					se1 = se2;
				if (se1) {
					a.port = ntohs(se1->s_port);
				} else {
					struct scache *s;

					for (s = rlist; s; s = s->next) {
						if ((s->proto == UDP_PROTO &&
						     (current_filter.dbs&(1<<UDP_DB))) ||
						    (s->proto == TCP_PROTO &&
						     (current_filter.dbs&(1<<TCP_DB)))) {
							if (s->name && strcmp(s->name, port) == 0) {
								if (a.port > 0 && a.port != s->port) {
									fprintf(stderr, "Error: ambiguous port \"%s\".\n", port);
									return NULL;
								}
								a.port = s->port;
							}
						}
					}
					if (a.port <= 0) {
						fprintf(stderr, "Error: \"%s\" does not look like a port.\n", port);
						return NULL;
					}
				}
			}
		}
	}
	if (!is_port && addr && *addr && *addr != '*') {
		if (get_prefix_1(&a.addr, addr, fam)) {
			if (get_dns_host(&a, addr, fam)) {
				fprintf(stderr, "Error: an inet prefix is expected rather than \"%s\".\n", addr);
				return NULL;
			}
		}
	}

out:
	if (fam != AF_UNSPEC) {
		int states = f->states;
		f->families = 0;
		filter_af_set(f, fam);
		filter_states_set(f, states);
	}

	res = malloc(sizeof(*res));
	if (res)
		memcpy(res, &a, sizeof(a));
	return res;
}

void *parse_markmask(const char *markmask)
{
	struct aafilter a, *res;

	if (strchr(markmask, '/')) {
		if (sscanf(markmask, "%i/%i", &a.mark, &a.mask) != 2)
			return NULL;
	} else {
		a.mask = 0xffffffff;
		if (sscanf(markmask, "%i", &a.mark) != 1)
			return NULL;
	}

	res = malloc(sizeof(*res));
	if (res)
		memcpy(res, &a, sizeof(a));
	return res;
}

static void proc_ctx_print(struct sockstat *s)
{
	char *buf;

	if (show_proc_ctx || show_sock_ctx) {
		if (find_entry(s->ino, &buf,
				(show_proc_ctx & show_sock_ctx) ?
				PROC_SOCK_CTX : PROC_CTX) > 0) {
			printf(" users:(%s)", buf);
			free(buf);
		}
	} else if (show_users) {
		if (find_entry(s->ino, &buf, USERS) > 0) {
			printf(" users:(%s)", buf);
			free(buf);
		}
	}
}

static void inet_stats_print(struct sockstat *s)
{
	sock_state_print(s);

	inet_addr_print(&s->local, s->lport, s->iface);
	inet_addr_print(&s->remote, s->rport, 0);

	proc_ctx_print(s);
}

static char *sprint_bw(char *buf, double bw)
{
	if (bw > 1000000.)
		sprintf(buf, "%.1fM", bw / 1000000.);
	else if (bw > 1000.)
		sprintf(buf, "%.1fK", bw / 1000.);
	else
		sprintf(buf, "%g", bw);

	return buf;
}

static void sctp_stats_print(struct sctp_info *s)
{
	if (s->sctpi_tag)
		printf(" tag:%x", s->sctpi_tag);
	if (s->sctpi_state)
		printf(" state:%s", sctp_sstate_name[s->sctpi_state]);
	if (s->sctpi_rwnd)
		printf(" rwnd:%d", s->sctpi_rwnd);
	if (s->sctpi_unackdata)
		printf(" unackdata:%d", s->sctpi_unackdata);
	if (s->sctpi_penddata)
		printf(" penddata:%d", s->sctpi_penddata);
	if (s->sctpi_instrms)
		printf(" instrms:%d", s->sctpi_instrms);
	if (s->sctpi_outstrms)
		printf(" outstrms:%d", s->sctpi_outstrms);
	if (s->sctpi_inqueue)
		printf(" inqueue:%d", s->sctpi_inqueue);
	if (s->sctpi_outqueue)
		printf(" outqueue:%d", s->sctpi_outqueue);
	if (s->sctpi_overall_error)
		printf(" overerr:%d", s->sctpi_overall_error);
	if (s->sctpi_max_burst)
		printf(" maxburst:%d", s->sctpi_max_burst);
	if (s->sctpi_maxseg)
		printf(" maxseg:%d", s->sctpi_maxseg);
	if (s->sctpi_peer_rwnd)
		printf(" prwnd:%d", s->sctpi_peer_rwnd);
	if (s->sctpi_peer_tag)
		printf(" ptag:%x", s->sctpi_peer_tag);
	if (s->sctpi_peer_capable)
		printf(" pcapable:%d", s->sctpi_peer_capable);
	if (s->sctpi_peer_sack)
		printf(" psack:%d", s->sctpi_peer_sack);
	if (s->sctpi_s_autoclose)
		printf(" autoclose:%d", s->sctpi_s_autoclose);
	if (s->sctpi_s_adaptation_ind)
		printf(" adapind:%d", s->sctpi_s_adaptation_ind);
	if (s->sctpi_s_pd_point)
		printf(" pdpoint:%d", s->sctpi_s_pd_point);
	if (s->sctpi_s_nodelay)
		printf(" nodealy:%d", s->sctpi_s_nodelay);
	if (s->sctpi_s_disable_fragments)
		printf(" nofrag:%d", s->sctpi_s_disable_fragments);
	if (s->sctpi_s_v4mapped)
		printf(" v4mapped:%d", s->sctpi_s_v4mapped);
	if (s->sctpi_s_frag_interleave)
		printf(" fraginl:%d", s->sctpi_s_frag_interleave);
}

static void tcp_stats_print(struct tcpstat *s)
{
	char b1[64];

	if (s->has_ts_opt)
		printf(" ts");
	if (s->has_sack_opt)
		printf(" sack");
	if (s->has_ecn_opt)
		printf(" ecn");
	if (s->has_ecnseen_opt)
		printf(" ecnseen");
	if (s->has_fastopen_opt)
		printf(" fastopen");
	if (s->cong_alg[0])
		printf(" %s", s->cong_alg);
	if (s->has_wscale_opt)
		printf(" wscale:%d,%d", s->snd_wscale, s->rcv_wscale);
	if (s->rto)
		printf(" rto:%g", s->rto);
	if (s->backoff)
		printf(" backoff:%u", s->backoff);
	if (s->rtt)
		printf(" rtt:%g/%g", s->rtt, s->rttvar);
	if (s->ato)
		printf(" ato:%g", s->ato);

	if (s->qack)
		printf(" qack:%d", s->qack);
	if (s->qack & 1)
		printf(" bidir");

	if (s->mss)
		printf(" mss:%d", s->mss);
	if (s->cwnd)
		printf(" cwnd:%u", s->cwnd);
	if (s->ssthresh)
		printf(" ssthresh:%d", s->ssthresh);

	if (s->bytes_acked)
		printf(" bytes_acked:%llu", s->bytes_acked);
	if (s->bytes_received)
		printf(" bytes_received:%llu", s->bytes_received);
	if (s->segs_out)
		printf(" segs_out:%u", s->segs_out);
	if (s->segs_in)
		printf(" segs_in:%u", s->segs_in);
	if (s->data_segs_out)
		printf(" data_segs_out:%u", s->data_segs_out);
	if (s->data_segs_in)
		printf(" data_segs_in:%u", s->data_segs_in);

	if (s->dctcp && s->dctcp->enabled) {
		struct dctcpstat *dctcp = s->dctcp;

		printf(" dctcp:(ce_state:%u,alpha:%u,ab_ecn:%u,ab_tot:%u)",
				dctcp->ce_state, dctcp->alpha, dctcp->ab_ecn,
				dctcp->ab_tot);
	} else if (s->dctcp) {
		printf(" dctcp:fallback_mode");
	}

	if (s->bbr_info) {
		__u64 bw;

		bw = s->bbr_info->bbr_bw_hi;
		bw <<= 32;
		bw |= s->bbr_info->bbr_bw_lo;

		printf(" bbr:(bw:%sbps,mrtt:%g",
		       sprint_bw(b1, bw * 8.0),
		       (double)s->bbr_info->bbr_min_rtt / 1000.0);
		if (s->bbr_info->bbr_pacing_gain)
			printf(",pacing_gain:%g",
			       (double)s->bbr_info->bbr_pacing_gain / 256.0);
		if (s->bbr_info->bbr_cwnd_gain)
			printf(",cwnd_gain:%g",
			       (double)s->bbr_info->bbr_cwnd_gain / 256.0);
		printf(")");
	}

	if (s->send_bps)
		printf(" send %sbps", sprint_bw(b1, s->send_bps));
	if (s->lastsnd)
		printf(" lastsnd:%u", s->lastsnd);
	if (s->lastrcv)
		printf(" lastrcv:%u", s->lastrcv);
	if (s->lastack)
		printf(" lastack:%u", s->lastack);

	if (s->pacing_rate) {
		printf(" pacing_rate %sbps", sprint_bw(b1, s->pacing_rate));
		if (s->pacing_rate_max)
				printf("/%sbps", sprint_bw(b1,
							s->pacing_rate_max));
	}

	if (s->delivery_rate)
		printf(" delivery_rate %sbps", sprint_bw(b1, s->delivery_rate));
	if (s->app_limited)
		printf(" app_limited");

	if (s->busy_time) {
		printf(" busy:%llums", s->busy_time / 1000);
		if (s->rwnd_limited)
			printf(" rwnd_limited:%llums(%.1f%%)",
			       s->rwnd_limited / 1000,
			       100.0 * s->rwnd_limited / s->busy_time);
		if (s->sndbuf_limited)
			printf(" sndbuf_limited:%llums(%.1f%%)",
			       s->sndbuf_limited / 1000,
			       100.0 * s->sndbuf_limited / s->busy_time);
	}

	if (s->unacked)
		printf(" unacked:%u", s->unacked);
	if (s->retrans || s->retrans_total)
		printf(" retrans:%u/%u", s->retrans, s->retrans_total);
	if (s->lost)
		printf(" lost:%u", s->lost);
	if (s->sacked && s->ss.state != SS_LISTEN)
		printf(" sacked:%u", s->sacked);
	if (s->fackets)
		printf(" fackets:%u", s->fackets);
	if (s->reordering != 3)
		printf(" reordering:%d", s->reordering);
	if (s->rcv_rtt)
		printf(" rcv_rtt:%g", s->rcv_rtt);
	if (s->rcv_space)
		printf(" rcv_space:%d", s->rcv_space);
	if (s->not_sent)
		printf(" notsent:%u", s->not_sent);
	if (s->min_rtt)
		printf(" minrtt:%g", s->min_rtt);
}

static void tcp_timer_print(struct tcpstat *s)
{
	static const char * const tmr_name[] = {
		"off",
		"on",
		"keepalive",
		"timewait",
		"persist",
		"unknown"
	};

	if (s->timer) {
		if (s->timer > 4)
			s->timer = 5;
		printf(" timer:(%s,%s,%d)",
				tmr_name[s->timer],
				print_ms_timer(s->timeout),
				s->retrans);
	}
}

static void sctp_timer_print(struct tcpstat *s)
{
	if (s->timer)
		printf(" timer:(T3_RTX,%s,%d)",
		       print_ms_timer(s->timeout), s->retrans);
}

static void print_skmeminfo(struct rtattr *tb[], int attrtype)
{
	const __u32 *skmeminfo;

	if (!tb[attrtype]) {
		if (attrtype == INET_DIAG_SKMEMINFO) {
			if (!tb[INET_DIAG_MEMINFO])
				return;

			const struct inet_diag_meminfo *minfo =
				RTA_DATA(tb[INET_DIAG_MEMINFO]);

			printf(" mem:(r%u,w%u,f%u,t%u)",
					minfo->idiag_rmem,
					minfo->idiag_wmem,
					minfo->idiag_fmem,
					minfo->idiag_tmem);
		}
		return;
	}

	skmeminfo = RTA_DATA(tb[attrtype]);

	printf(" skmem:(r%u,rb%u,t%u,tb%u,f%u,w%u,o%u",
	       skmeminfo[SK_MEMINFO_RMEM_ALLOC],
	       skmeminfo[SK_MEMINFO_RCVBUF],
	       skmeminfo[SK_MEMINFO_WMEM_ALLOC],
	       skmeminfo[SK_MEMINFO_SNDBUF],
	       skmeminfo[SK_MEMINFO_FWD_ALLOC],
	       skmeminfo[SK_MEMINFO_WMEM_QUEUED],
	       skmeminfo[SK_MEMINFO_OPTMEM]);

	if (RTA_PAYLOAD(tb[attrtype]) >=
		(SK_MEMINFO_BACKLOG + 1) * sizeof(__u32))
		printf(",bl%u", skmeminfo[SK_MEMINFO_BACKLOG]);

	if (RTA_PAYLOAD(tb[attrtype]) >=
		(SK_MEMINFO_DROPS + 1) * sizeof(__u32))
		printf(",d%u", skmeminfo[SK_MEMINFO_DROPS]);

	printf(")");
}

#define TCPI_HAS_OPT(info, opt) !!(info->tcpi_options & (opt))

static void tcp_show_info(const struct nlmsghdr *nlh, struct inet_diag_msg *r,
		struct rtattr *tb[])
{
	double rtt = 0;
	struct tcpstat s = {};

	s.ss.state = r->idiag_state;

	print_skmeminfo(tb, INET_DIAG_SKMEMINFO);

	if (tb[INET_DIAG_INFO]) {
		struct tcp_info *info;
		int len = RTA_PAYLOAD(tb[INET_DIAG_INFO]);

		/* workaround for older kernels with less fields */
		if (len < sizeof(*info)) {
			info = alloca(sizeof(*info));
			memcpy(info, RTA_DATA(tb[INET_DIAG_INFO]), len);
			memset((char *)info + len, 0, sizeof(*info) - len);
		} else
			info = RTA_DATA(tb[INET_DIAG_INFO]);

		if (show_options) {
			s.has_ts_opt	   = TCPI_HAS_OPT(info, TCPI_OPT_TIMESTAMPS);
			s.has_sack_opt	   = TCPI_HAS_OPT(info, TCPI_OPT_SACK);
			s.has_ecn_opt	   = TCPI_HAS_OPT(info, TCPI_OPT_ECN);
			s.has_ecnseen_opt  = TCPI_HAS_OPT(info, TCPI_OPT_ECN_SEEN);
			s.has_fastopen_opt = TCPI_HAS_OPT(info, TCPI_OPT_SYN_DATA);
		}

		if (tb[INET_DIAG_CONG])
			strncpy(s.cong_alg,
				rta_getattr_str(tb[INET_DIAG_CONG]),
				sizeof(s.cong_alg) - 1);

		if (TCPI_HAS_OPT(info, TCPI_OPT_WSCALE)) {
			s.has_wscale_opt  = true;
			s.snd_wscale	  = info->tcpi_snd_wscale;
			s.rcv_wscale	  = info->tcpi_rcv_wscale;
		}

		if (info->tcpi_rto && info->tcpi_rto != 3000000)
			s.rto = (double)info->tcpi_rto / 1000;

		s.backoff	 = info->tcpi_backoff;
		s.rtt		 = (double)info->tcpi_rtt / 1000;
		s.rttvar	 = (double)info->tcpi_rttvar / 1000;
		s.ato		 = (double)info->tcpi_ato / 1000;
		s.mss		 = info->tcpi_snd_mss;
		s.rcv_space	 = info->tcpi_rcv_space;
		s.rcv_rtt	 = (double)info->tcpi_rcv_rtt / 1000;
		s.lastsnd	 = info->tcpi_last_data_sent;
		s.lastrcv	 = info->tcpi_last_data_recv;
		s.lastack	 = info->tcpi_last_ack_recv;
		s.unacked	 = info->tcpi_unacked;
		s.retrans	 = info->tcpi_retrans;
		s.retrans_total  = info->tcpi_total_retrans;
		s.lost		 = info->tcpi_lost;
		s.sacked	 = info->tcpi_sacked;
		s.reordering	 = info->tcpi_reordering;
		s.rcv_space	 = info->tcpi_rcv_space;
		s.cwnd		 = info->tcpi_snd_cwnd;

		if (info->tcpi_snd_ssthresh < 0xFFFF)
			s.ssthresh = info->tcpi_snd_ssthresh;

		rtt = (double) info->tcpi_rtt;
		if (tb[INET_DIAG_VEGASINFO]) {
			const struct tcpvegas_info *vinfo
				= RTA_DATA(tb[INET_DIAG_VEGASINFO]);

			if (vinfo->tcpv_enabled &&
					vinfo->tcpv_rtt && vinfo->tcpv_rtt != 0x7fffffff)
				rtt =  vinfo->tcpv_rtt;
		}

		if (tb[INET_DIAG_DCTCPINFO]) {
			struct dctcpstat *dctcp = malloc(sizeof(struct
						dctcpstat));

			const struct tcp_dctcp_info *dinfo
				= RTA_DATA(tb[INET_DIAG_DCTCPINFO]);

			dctcp->enabled	= !!dinfo->dctcp_enabled;
			dctcp->ce_state = dinfo->dctcp_ce_state;
			dctcp->alpha	= dinfo->dctcp_alpha;
			dctcp->ab_ecn	= dinfo->dctcp_ab_ecn;
			dctcp->ab_tot	= dinfo->dctcp_ab_tot;
			s.dctcp		= dctcp;
		}

		if (tb[INET_DIAG_BBRINFO]) {
			const void *bbr_info = RTA_DATA(tb[INET_DIAG_BBRINFO]);
			int len = min(RTA_PAYLOAD(tb[INET_DIAG_BBRINFO]),
				      sizeof(*s.bbr_info));

			s.bbr_info = calloc(1, sizeof(*s.bbr_info));
			if (s.bbr_info && bbr_info)
				memcpy(s.bbr_info, bbr_info, len);
		}

		if (rtt > 0 && info->tcpi_snd_mss && info->tcpi_snd_cwnd) {
			s.send_bps = (double) info->tcpi_snd_cwnd *
				(double)info->tcpi_snd_mss * 8000000. / rtt;
		}

		if (info->tcpi_pacing_rate &&
				info->tcpi_pacing_rate != ~0ULL) {
			s.pacing_rate = info->tcpi_pacing_rate * 8.;

			if (info->tcpi_max_pacing_rate &&
					info->tcpi_max_pacing_rate != ~0ULL)
				s.pacing_rate_max = info->tcpi_max_pacing_rate * 8.;
		}
		s.bytes_acked = info->tcpi_bytes_acked;
		s.bytes_received = info->tcpi_bytes_received;
		s.segs_out = info->tcpi_segs_out;
		s.segs_in = info->tcpi_segs_in;
		s.data_segs_out = info->tcpi_data_segs_out;
		s.data_segs_in = info->tcpi_data_segs_in;
		s.not_sent = info->tcpi_notsent_bytes;
		if (info->tcpi_min_rtt && info->tcpi_min_rtt != ~0U)
			s.min_rtt = (double) info->tcpi_min_rtt / 1000;
		s.delivery_rate = info->tcpi_delivery_rate * 8.;
		s.app_limited = info->tcpi_delivery_rate_app_limited;
		s.busy_time = info->tcpi_busy_time;
		s.rwnd_limited = info->tcpi_rwnd_limited;
		s.sndbuf_limited = info->tcpi_sndbuf_limited;
                if (s.rtt > 50.0 || s.retrans > 2)
		  tcp_stats_print(&s);
		free(s.dctcp);
		free(s.bbr_info);
	}
}

static const char *format_host_sa(struct sockaddr_storage *sa)
{
	union {
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} *saddr = (void *)sa;

	switch (sa->ss_family) {
	case AF_INET:
		return format_host(AF_INET, 4, &saddr->sin.sin_addr);
	case AF_INET6:
		return format_host(AF_INET6, 16, &saddr->sin6.sin6_addr);
	default:
		return "";
	}
}

static void sctp_show_info(const struct nlmsghdr *nlh, struct inet_diag_msg *r,
		struct rtattr *tb[])
{
	struct sockaddr_storage *sa;
	int len;

	print_skmeminfo(tb, INET_DIAG_SKMEMINFO);

	if (tb[INET_DIAG_LOCALS]) {
		len = RTA_PAYLOAD(tb[INET_DIAG_LOCALS]);
		sa = RTA_DATA(tb[INET_DIAG_LOCALS]);

		printf("locals:%s", format_host_sa(sa));
		for (sa++, len -= sizeof(*sa); len > 0; sa++, len -= sizeof(*sa))
			printf(",%s", format_host_sa(sa));

	}
	if (tb[INET_DIAG_PEERS]) {
		len = RTA_PAYLOAD(tb[INET_DIAG_PEERS]);
		sa = RTA_DATA(tb[INET_DIAG_PEERS]);

		printf(" peers:%s", format_host_sa(sa));
		for (sa++, len -= sizeof(*sa); len > 0; sa++, len -= sizeof(*sa))
			printf(",%s", format_host_sa(sa));
	}
	if (tb[INET_DIAG_INFO]) {
		struct sctp_info *info;
		len = RTA_PAYLOAD(tb[INET_DIAG_INFO]);

		/* workaround for older kernels with less fields */
		if (len < sizeof(*info)) {
			info = alloca(sizeof(*info));
			memcpy(info, RTA_DATA(tb[INET_DIAG_INFO]), len);
			memset((char *)info + len, 0, sizeof(*info) - len);
		} else
			info = RTA_DATA(tb[INET_DIAG_INFO]);

		sctp_stats_print(info);
	}
}

static void parse_diag_msg(struct nlmsghdr *nlh, struct sockstat *s)
{
	struct rtattr *tb[INET_DIAG_MAX+1];
	struct inet_diag_msg *r = NLMSG_DATA(nlh);

	parse_rtattr(tb, INET_DIAG_MAX, (struct rtattr *)(r+1),
		     nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*r)));

	s->state	= r->idiag_state;
	s->local.family	= s->remote.family = r->idiag_family;
	s->lport	= ntohs(r->id.idiag_sport);
	s->rport	= ntohs(r->id.idiag_dport);
	s->wq		= r->idiag_wqueue;
	s->rq		= r->idiag_rqueue;
	s->ino		= r->idiag_inode;
	s->uid		= r->idiag_uid;
	s->iface	= r->id.idiag_if;
	s->sk		= cookie_sk_get(&r->id.idiag_cookie[0]);

	s->mark = 0;
	if (tb[INET_DIAG_MARK])
		s->mark = *(__u32 *) RTA_DATA(tb[INET_DIAG_MARK]);
	if (tb[INET_DIAG_PROTOCOL])
		s->raw_prot = *(__u8 *)RTA_DATA(tb[INET_DIAG_PROTOCOL]);
	else
		s->raw_prot = 0;

	if (s->local.family == AF_INET)
		s->local.bytelen = s->remote.bytelen = 4;
	else
		s->local.bytelen = s->remote.bytelen = 16;

	memcpy(s->local.data, r->id.idiag_src, s->local.bytelen);
	memcpy(s->remote.data, r->id.idiag_dst, s->local.bytelen);
}

static int inet_show_sock(struct nlmsghdr *nlh,
			  struct sockstat *s)
{
	struct rtattr *tb[INET_DIAG_MAX+1];
	struct inet_diag_msg *r = NLMSG_DATA(nlh);

	parse_rtattr(tb, INET_DIAG_MAX, (struct rtattr *)(r+1),
		     nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*r)));

	if (tb[INET_DIAG_PROTOCOL])
		s->type = *(__u8 *)RTA_DATA(tb[INET_DIAG_PROTOCOL]);

	inet_stats_print(s);

	if (show_options) {
		struct tcpstat t = {};

		t.timer = r->idiag_timer;
		t.timeout = r->idiag_expires;
		t.retrans = r->idiag_retrans;
		if (s->type == IPPROTO_SCTP)
			sctp_timer_print(&t);
		else
			tcp_timer_print(&t);
	}

	if (show_details) {
		sock_details_print(s);
		if (s->local.family == AF_INET6 && tb[INET_DIAG_SKV6ONLY]) {
			unsigned char v6only;

			v6only = *(__u8 *)RTA_DATA(tb[INET_DIAG_SKV6ONLY]);
			printf(" v6only:%u", v6only);
		}
		if (tb[INET_DIAG_SHUTDOWN]) {
			unsigned char mask;

			mask = *(__u8 *)RTA_DATA(tb[INET_DIAG_SHUTDOWN]);
			printf(" %c-%c", mask & 1 ? '-' : '<', mask & 2 ? '-' : '>');
		}
	}

	if (show_mem || (show_tcpinfo && s->type != IPPROTO_UDP)) {
		printf("\n\t");
		if (s->type == IPPROTO_SCTP)
			sctp_show_info(nlh, r, tb);
		else
			tcp_show_info(nlh, r, tb);
	}
	sctp_ino = s->ino;

	printf("\n");
	return 0;
}

struct inet_diag_arg {
	struct filter *f;
	int protocol;
	struct rtnl_handle *rth;
};

static int kill_inet_sock(struct nlmsghdr *h, void *arg, struct sockstat *s)
{
	struct inet_diag_msg *d = NLMSG_DATA(h);
	struct inet_diag_arg *diag_arg = arg;
	struct rtnl_handle *rth = diag_arg->rth;

	DIAG_REQUEST(req, struct inet_diag_req_v2 r);

	req.nlh.nlmsg_type = SOCK_DESTROY;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nlh.nlmsg_seq = ++rth->seq;
	req.r.sdiag_family = d->idiag_family;
	req.r.sdiag_protocol = diag_arg->protocol;
	req.r.id = d->id;

	if (diag_arg->protocol == IPPROTO_RAW) {
		struct inet_diag_req_raw *raw = (void *)&req.r;

		BUILD_BUG_ON(sizeof(req.r) != sizeof(*raw));
		raw->sdiag_raw_protocol = s->raw_prot;
	}

	return rtnl_talk(rth, &req.nlh, NULL, 0);
}

static int show_one_inet_sock(const struct sockaddr_nl *addr,
		struct nlmsghdr *h, void *arg)
{
	int err;
	struct inet_diag_arg *diag_arg = arg;
	struct inet_diag_msg *r = NLMSG_DATA(h);
	struct sockstat s = {};

	if (!(diag_arg->f->families & (1 << r->idiag_family)))
		return 0;

	parse_diag_msg(h, &s);
	s.type = diag_arg->protocol;

	if (diag_arg->f->f && run_ssfilter(diag_arg->f->f, &s) == 0)
		return 0;

	if (diag_arg->f->kill && kill_inet_sock(h, arg, &s) != 0) {
		if (errno == EOPNOTSUPP || errno == ENOENT) {
			/* Socket can't be closed, or is already closed. */
			return 0;
		} else {
			perror("SOCK_DESTROY answers");
			return -1;
		}
	}

	err = inet_show_sock(h, &s);
	if (err < 0)
		return err;

	return 0;
}

#define MAX_UNIX_REMEMBER (1024*1024/sizeof(struct sockstat))

struct sock_diag_msg {
	__u8 sdiag_family;
};

static int generic_show_sock(const struct sockaddr_nl *addr,
		struct nlmsghdr *nlh, void *arg)
{
	struct sock_diag_msg *r = NLMSG_DATA(nlh);
	struct inet_diag_arg inet_arg = { .f = arg, .protocol = IPPROTO_MAX };

	switch (r->sdiag_family) {
	case AF_INET:
	case AF_INET6:
		return show_one_inet_sock(addr, nlh, &inet_arg);
	case AF_UNIX:
		//return unix_show_sock(addr, nlh, arg);
	case AF_PACKET:
		//return packet_show_sock(addr, nlh, arg);
	case AF_NETLINK:
		//return netlink_show_sock(addr, nlh, arg);
	default:
		return -1;
	}
}

static int handle_follow_request(struct filter *f)
{
	int ret = 0;
	int groups = 0;
	struct rtnl_handle rth;

	if (f->families & (1 << AF_INET) && f->dbs & (1 << TCP_DB))
		groups |= 1 << (SKNLGRP_INET_TCP_DESTROY - 1);
	if (f->families & (1 << AF_INET) && f->dbs & (1 << UDP_DB))
		groups |= 1 << (SKNLGRP_INET_UDP_DESTROY - 1);
	if (f->families & (1 << AF_INET6) && f->dbs & (1 << TCP_DB))
		groups |= 1 << (SKNLGRP_INET6_TCP_DESTROY - 1);
	if (f->families & (1 << AF_INET6) && f->dbs & (1 << UDP_DB))
		groups |= 1 << (SKNLGRP_INET6_UDP_DESTROY - 1);

	if (groups == 0)
		return -1;

	if (rtnl_open_byproto(&rth, groups, NETLINK_SOCK_DIAG))
		return -1;

	rth.dump = 0;
	rth.local.nl_pid = 0;

	if (rtnl_dump_filter(&rth, generic_show_sock, f))
		ret = -1;

	rtnl_close(&rth);
	return ret;
}

/* Get stats from sockstat */

struct ssummary {
	int socks;
	int tcp_mem;
	int tcp_total;
	int tcp_orphans;
	int tcp_tws;
	int tcp4_hashed;
	int udp4;
	int raw4;
	int frag4;
	int frag4_mem;
	int tcp6_hashed;
	int udp6;
	int raw6;
	int frag6;
	int frag6_mem;
};

static void _usage(FILE *dest)
{
	fprintf(dest,
"Usage: ss [ OPTIONS ]\n"
"       ss [ OPTIONS ] [ FILTER ]\n"
"   -h, --help          this message\n"
"   -V, --version       output version information\n"
"   -n, --numeric       don't resolve service names\n"
"   -r, --resolve       resolve host names\n"
"   -a, --all           display all sockets\n"
"   -l, --listening     display listening sockets\n"
"   -o, --options       show timer information\n"
"   -e, --extended      show detailed socket information\n"
"   -m, --memory        show socket memory usage\n"
"   -p, --processes     show process using socket\n"
"   -i, --info          show internal TCP information\n"
"   -s, --summary       show socket usage summary\n"
"   -b, --bpf           show bpf filter socket information\n"
"   -E, --events        continually display sockets as they are destroyed\n"
"   -Z, --context       display process SELinux security contexts\n"
"   -z, --contexts      display process and socket SELinux security contexts\n"
"   -N, --net           switch to the specified network namespace name\n"
"\n"
"   -4, --ipv4          display only IP version 4 sockets\n"
"   -6, --ipv6          display only IP version 6 sockets\n"
"   -0, --packet        display PACKET sockets\n"
"   -t, --tcp           display only TCP sockets\n"
"   -S, --sctp          display only SCTP sockets\n"
"   -u, --udp           display only UDP sockets\n"
"   -d, --dccp          display only DCCP sockets\n"
"   -w, --raw           display only RAW sockets\n"
"   -x, --unix          display only Unix domain sockets\n"
"   -f, --family=FAMILY display sockets of type FAMILY\n"
"       FAMILY := {inet|inet6|link|unix|netlink|help}\n"
"\n"
"   -K, --kill          forcibly close sockets, display what was closed\n"
"   -H, --no-header     Suppress header line\n"
"\n"
"   -A, --query=QUERY, --socket=QUERY\n"
"       QUERY := {all|inet|tcp|udp|raw|unix|unix_dgram|unix_stream|unix_seqpacket|packet|netlink}[,QUERY]\n"
"\n"
"   -D, --diag=FILE     Dump raw information about TCP sockets to FILE\n"
"   -F, --filter=FILE   read filter information from FILE\n"
"       FILTER := [ state STATE-FILTER ] [ EXPRESSION ]\n"
"       STATE-FILTER := {all|connected|synchronized|bucket|big|TCP-STATES}\n"
"         TCP-STATES := {established|syn-sent|syn-recv|fin-wait-{1,2}|time-wait|closed|close-wait|last-ack|listen|closing}\n"
"          connected := {established|syn-sent|syn-recv|fin-wait-{1,2}|time-wait|close-wait|last-ack|closing}\n"
"       synchronized := {established|syn-recv|fin-wait-{1,2}|time-wait|close-wait|last-ack|closing}\n"
"             bucket := {syn-recv|time-wait}\n"
"                big := {established|syn-sent|fin-wait-{1,2}|closed|close-wait|last-ack|listen|closing}\n"
		);
}

static void help(void) __attribute__((noreturn));
static void help(void)
{
	_usage(stdout);
	exit(0);
}

static void usage(void) __attribute__((noreturn));
static void usage(void)
{
	_usage(stderr);
	exit(-1);
}


static const struct option long_opts[] = {
	{ "numeric", 0, 0, 'n' },
	{ "resolve", 0, 0, 'r' },
	{ "options", 0, 0, 'o' },
	{ "extended", 0, 0, 'e' },
	{ "memory", 0, 0, 'm' },
	{ "info", 0, 0, 'i' },
	{ "processes", 0, 0, 'p' },
	{ "bpf", 0, 0, 'b' },
	{ "events", 0, 0, 'E' },
	{ "dccp", 0, 0, 'd' },
	{ "tcp", 0, 0, 't' },
	{ "sctp", 0, 0, 'S' },
	{ "udp", 0, 0, 'u' },
	{ "raw", 0, 0, 'w' },
	{ "unix", 0, 0, 'x' },
	{ "all", 0, 0, 'a' },
	{ "listening", 0, 0, 'l' },
	{ "ipv4", 0, 0, '4' },
	{ "ipv6", 0, 0, '6' },
	{ "packet", 0, 0, '0' },
	{ "family", 1, 0, 'f' },
	{ "socket", 1, 0, 'A' },
	{ "query", 1, 0, 'A' },
	{ "summary", 0, 0, 's' },
	{ "diag", 1, 0, 'D' },
	{ "filter", 1, 0, 'F' },
	{ "version", 0, 0, 'V' },
	{ "help", 0, 0, 'h' },
	{ "context", 0, 0, 'Z' },
	{ "contexts", 0, 0, 'z' },
	{ "net", 1, 0, 'N' },
	{ "kill", 0, 0, 'K' },
	{ "no-header", 0, 0, 'H' },
	{ 0 }

};

int main(int argc, char *argv[])
{
	int state_filter = 0;
	int addrp_width, screen_width = 80;

	// option "-tniE"
	resolve_services = 0;
	show_tcpinfo = 1;
	follow_events = 1;
	filter_db_set(&current_filter, TCP_DB);
        if (do_default) {
                state_filter = state_filter ? state_filter : SS_CONN;
                filter_default_dbs(&current_filter);
        }

        filter_states_set(&current_filter, state_filter);
        filter_merge_defaults(&current_filter);

	state_width = 0;
	if (current_filter.states&(current_filter.states-1))
		state_width = 10;

	if (isatty(STDOUT_FILENO)) {
		struct winsize w;

		if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) != -1) {
			if (w.ws_col > 0)
				screen_width = w.ws_col;
		}
	}

	addrp_width = screen_width;
	addrp_width -= netid_width+1;
	addrp_width -= state_width+1;
	addrp_width -= 14;

	if (addrp_width&1) {
		if (netid_width)
			netid_width++;
		else if (state_width)
			state_width++;
	}

	addrp_width /= 2;
	addrp_width--;

	serv_width = resolve_services ? 7 : 5;

	if (addrp_width < 15+serv_width+1)
		addrp_width = 15+serv_width+1;

	addr_width = addrp_width - serv_width - 1;

	if (show_header) {
		if (netid_width)
			printf("%-*s ", netid_width, "Netid");
		if (state_width)
			printf("%-*s ", state_width, "State");
		printf("%-6s %-6s ", "Recv-Q", "Send-Q");
	}

	/* Make enough space for the local/remote port field */
	addr_width -= 13;
	serv_width += 13;

	if (show_header) {
		printf("%*s:%-*s %*s:%-*s\n",
		       addr_width, "Local Address", serv_width, "Port",
		       addr_width, "Peer Address", serv_width, "Port");
	}

	fflush(stdout);

	return handle_follow_request(&current_filter);
}
