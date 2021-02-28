/* linAUDIT 0.5 - Replacement of auditd for multi-core AWS EC2 instances.
   Uses multi-threaded event processor.
   (C)2021 Jakub Jozwicki
*/
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <linux/netlink.h>
#include <linux/audit.h>
#include <pthread.h>
#include <string.h>
#include <poll.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <syslog.h>
#include "syscall64.h"
#include "audit.h"

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

#ifndef AUDIT_NLGRP_READLOG
#define AUDIT_NLGRP_READLOG 1
#endif

#ifdef DEBUG
#define dprintf(arg1,arg2) printf(arg1,arg2)
#else
#define dprintf(arg1,arg2) ;
#endif

struct managed_buffer {
  void *addr;
  struct managed_buffer *next;
  struct managed_buffer *link;
};

#define MAX_BUFFERS 256
#define BUFFER_SIZE 8192
#define MAX_ACTIVE_JOBS 8

struct managed_buffer* free_buffers_head = NULL;
struct managed_buffer* free_buffers_tail = NULL;
int allocated_buffer_cnt = 0;
pthread_mutex_t buff_lock = PTHREAD_MUTEX_INITIALIZER;

struct managed_buffer *work_buffers_head = NULL;
struct managed_buffer *work_buffers_tail = NULL;
pthread_mutex_t work_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_t processors[MAX_ACTIVE_JOBS];
pthread_cond_t work_ready;
pthread_cond_t buffer_freed;
int running = 1;
int free_buffers = 0;
int work_buffers = 0;

#define EXIT_ON_ERROR(op, msg) do { int res=op; if (res!=0) { if (errno==0) errno=EINVAL; perror(msg); exit(-1); } } while(0)

void release_buffer(struct managed_buffer* mb, int tid) {
  EXIT_ON_ERROR(pthread_mutex_lock(&buff_lock), "release_buffer[+]");
  if (free_buffers_tail==NULL) {
    free_buffers_head = free_buffers_tail = mb;
  }
  else {
    free_buffers_tail->next = mb;
    free_buffers_tail = mb;
  }
  mb->next = NULL;
  free_buffers++;
  dprintf("Free buffer count is %d\n",free_buffers);
  if (free_buffers==1) {
    pthread_cond_signal(&buffer_freed);
  }
  EXIT_ON_ERROR(pthread_mutex_unlock(&buff_lock), "release_buffer[-]");
}

void push_work_buffer(struct managed_buffer* mb) {
  EXIT_ON_ERROR(pthread_mutex_lock(&work_lock), "push_work_buffer[+]");
  if (work_buffers_tail==NULL) {
    work_buffers_head = work_buffers_tail = mb;
  }
  else {
    work_buffers_tail->next = mb;
    work_buffers_tail = mb;
  }
  mb->next = NULL;
  work_buffers++;
  dprintf("Work buffer count is %d\n",work_buffers);
  if (work_buffers==1) {
    pthread_cond_signal(&work_ready);
  }
  EXIT_ON_ERROR(pthread_mutex_unlock(&work_lock), "push_work_buffer[-]");
}

struct managed_buffer* acquire_buffer() {
  int must_block = allocated_buffer_cnt >= MAX_BUFFERS ? 1 : 0;
  while(1) {
    EXIT_ON_ERROR(pthread_mutex_lock(&buff_lock), "acquire_buffer[+]");
    if (free_buffers==0 && free_buffers_head==NULL && must_block) {
      dprintf("Waiting for freed buffer on %x\n", &buff_lock);
      pthread_cond_wait(&buffer_freed, &buff_lock);
      dprintf("Waiting for freed buffer on %x completed\n", &buff_lock);
    }
    if (free_buffers_head) {
      struct managed_buffer* taken = free_buffers_head;
      free_buffers_head = free_buffers_head->next;
      free_buffers--;
      if (free_buffers_head==NULL) {
        free_buffers_tail = NULL;
      }
      EXIT_ON_ERROR(pthread_mutex_unlock(&buff_lock), "acquire_buffer[--]");
      memset(taken->addr, 0, BUFFER_SIZE);
      taken->next=NULL;
      taken->link=NULL;
      return taken;
    }
    EXIT_ON_ERROR(pthread_mutex_unlock(&buff_lock), "acquire_buffer[-]");
    if (must_block==0) {
      struct managed_buffer* allocated = (struct managed_buffer*)malloc(sizeof(struct managed_buffer));
      if (allocated==NULL) {
        perror("malloc managed_buffer");
        exit(-1);
      }
      allocated->addr = (void*)malloc(BUFFER_SIZE);
      if (allocated->addr==NULL) {
        perror("malloc managed buffer");
        exit(-1);
      }
      memset(allocated->addr, 0, BUFFER_SIZE);
      allocated->next = NULL;
      allocated->link = NULL;
      allocated_buffer_cnt++;
      return allocated;
    }
    dprintf("Expected free buffers, but none there, free buffers=%d\n", free_buffers);
  }
}

struct managed_buffer* pull_work_buffer(int tid) {
  while(1) {
    EXIT_ON_ERROR(pthread_mutex_lock(&work_lock), "pull_work_buffer[+]");
    if (work_buffers==0) {
      dprintf("Processor thread %d waiting on work ready condition\n", tid);
      pthread_cond_wait(&work_ready, &work_lock);
    }
    if (work_buffers_head) {
      struct managed_buffer* taken = work_buffers_head;
      work_buffers_head = work_buffers_head->next;
      if (work_buffers_head==NULL) {
        work_buffers_tail = NULL;
      }
      work_buffers--;
      EXIT_ON_ERROR(pthread_mutex_unlock(&work_lock), "pull_work_buffer[--]");
      dprintf("Processor thread %d working\n", tid);
      return taken;
    }
    // work stolen by other thread?
    EXIT_ON_ERROR(pthread_mutex_unlock(&work_lock), "pull_work_buffer");
  }
}

#define AUDIT_BUFFER_TO_STR(buff) (char*)(NLMSG_DATA((struct nlmsghdr*)buff))
#define AUDIT_BUFFER_CODE(buff) ((struct nlmsghdr*)buff)->nlmsg_type
#define MAX_TEXT 8192

struct str {
  char *buff;
  int len;
  int capacity;
};

struct str* str_new(int size) {
  struct str* str = (struct str*)malloc(sizeof(struct str));
  if (str==NULL) {
    perror("str_new");
    exit(-1);
  }
  str->len=0;
  str->capacity=size;
  str->buff = (char*)malloc(size);
  if (str->buff==NULL) {
    perror("str new");
    exit(-1);
  }
  //memset(str->buff, 0, size);
  str->buff[0]=0;
  return str;
}

void str_append(struct str* str, const char* s) {
  int s_len = strlen(s);
  if (str->len + s_len + 1 > str->capacity) {
    char *extended = realloc(str->buff, str->capacity = str->capacity << 1);
    if (extended==NULL) {
      perror("str_append");
      exit(-1);
    }
    str->buff=extended;
  }
  strcat(str->buff+str->len, s);
  str->len += s_len;
}

void* processor(void* arg) {
  struct managed_buffer *mb;
  int id = *((int*)arg);
  struct str* txt = str_new(MAX_TEXT);
  unsigned long int seq = 0;
  while (running) {
    mb = pull_work_buffer(id);
    txt->buff[0] = 0;
    txt->len = 0;
    seq = 0;
    do {
      char* data = AUDIT_BUFFER_TO_STR(mb->addr);
      int code = AUDIT_BUFFER_CODE(mb->addr);
      const audit_msg_type* type = get_audit_msg_type(code);
      if (txt->len==0) {
         char *ts_start = data+6;
         time_t ts = 0;
         int millis = 0;
         sscanf(ts_start, "%ld.%d:%ld)", &ts, &millis, &seq);
         struct tm* at = localtime(&ts);
         if (type!=NULL) {
           str_append(txt, type->name);
           str_append(txt, " ");
         }
         else {
           txt->len = sprintf(txt->buff, "AUDIT_CODE=%d ",code);
         }
         str_append(txt, "ts=");
         strftime(txt->buff + txt->len, txt->capacity, "%FT%T.000%z ", at);
         txt->len = strlen(txt->buff);
         int i=0;
         for (;i<3; i++) {
           char* digit = ts_start+11+i;
           txt->buff[txt->len - 9 + i] = *digit;
         }
      }
      else {
        if (type!=NULL) {
          str_append(txt, " ");
          str_append(txt, type->name);
        }
      }
      char* text = strstr(data+24, " ");
      if (strstr(text, " arch=c000003e syscall=")==text) {
        char *digit = text+23;
        int nr = 0;
        int cnt = 0;
        for (; cnt < 3; cnt++) {
          if (*digit!=' ') {
            nr = 10*nr + (*digit - '0');
            digit++;
          }
        }
        const char* syscall64=get_syscall64_name(nr);
        if (syscall64) {
          str_append(txt, "syscall64=");
          str_append(txt, (char*)syscall64);
          text = digit;
        }
      }
      if (code==AUDIT_PROCTITLE && strlen(data)>0) {
        char *proctitle=strstr(text, "proctitle=");
        if (proctitle!=NULL) {
          proctitle += 10;
          unsigned int c = 0;
          char *fwd = proctitle;
          char *ptr = fwd;
          int init = 1;
          while (*fwd) {
            sscanf(fwd, "%2x", &c);
            if (init) {
              ptr[0]='"';
              ptr++;
              init = 0;
            }
            *ptr = (char)(c & 0xff);
            fwd += 2;
            ptr++;
          }
          *ptr = 0;
          strcat(proctitle, "\"");
        }
      }
      if (text[0]==' ' && text[1]==' ') {
        text++;
      }
      str_append(txt, text);
      struct managed_buffer *done = mb;
      mb = mb->link;
      release_buffer(done, id);
    }
    while (mb);
    syslog(LOG_INFO, "seq=%ld %s\n", seq, txt->buff);
  }
  free(txt);
  return NULL;
}

void start_threads() {
  int i=0;
  for (; i < MAX_ACTIVE_JOBS; i++) {
    int *id = (int*)malloc(sizeof(int));
    *id = i+1;
    int res = pthread_create(&processors[i], NULL, processor, id);
    if (res!=0) {
      perror("thread create");
      exit(-1);
    }
  }
}

void init(int fd, struct sockaddr_nl *sa) {
  int pkt_size = NLMSG_SPACE(sizeof(struct audit_status));
  struct nlmsghdr *hdr = (struct nlmsghdr*)malloc(pkt_size);
  if (hdr==NULL) {
    perror("malloc hdr");
    exit(-1);
  }
  memset(hdr, 0, pkt_size);
  struct audit_status status;
  status.mask = AUDIT_STATUS_ENABLED | AUDIT_STATUS_PID | AUDIT_STATUS_RATE_LIMIT | AUDIT_STATUS_BACKLOG_LIMIT;
  status.enabled = 1;
  status.pid = sa->nl_pid;
  status.rate_limit = 0;
  status.backlog_limit = 65536;
  memcpy(NLMSG_DATA(hdr), &status, sizeof(status));
  hdr->nlmsg_len = pkt_size;
  hdr->nlmsg_pid = sa->nl_pid;
  hdr->nlmsg_seq = 1;
  hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  hdr->nlmsg_type = AUDIT_SET;
  struct iovec iov = { hdr, pkt_size };
  struct msghdr msg = { sa, sizeof(struct sockaddr_nl), &iov, 1, NULL, 0, 0 };
  sa->nl_pid = 0;

  int ret = -1;
  do {
    ret = sendmsg(fd, &msg, 0);
  }
  while (ret < 0 && errno == EINTR);
  free(hdr);
  if (ret==-1) {
    perror("sendmsg()");
    exit(-1);
  }
}

int is_mcast_capable() {
  struct utsname osver;
  memset(&osver, 0, sizeof(osver));
  if (uname(&osver)) {
    perror("os detection failed, uname()");
    exit(-1);
  }
  int major = 0, minor = 0, patch = 0;
  sscanf(osver.release, "%d.%d.%d", &major, &minor, &patch);
  /* https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=451f921639fea4600dfb9ab2889332bdcc7b48d3 */
  return major >= 3 && minor >= 16 ? AUDIT_NLGRP_READLOG : 0;
}

int main(int argc, char **argv) {
  int mcast_grp = 0;
  struct sockaddr_nl sa;
  memset(&sa, 0, sizeof(sa));
  sa.nl_family	= AF_NETLINK;
  sa.nl_pid 	= 0;
  sa.nl_groups 	= mcast_grp;
  struct iovec iov = { NULL, 0 };
  struct msghdr msg = {
    .msg_name 		= (void*)&sa,
    .msg_namelen 	= sizeof(sa),
    .msg_iov 		= &iov,
    .msg_iovlen 	= 1,
    .msg_control	= NULL,
    .msg_controllen	= 0,
    .msg_flags		= 0,
  };
  printf("Stopping auditd.\n");
  system("/bin/pkill auditd 1>/dev/null 2>/dev/null");
  openlog("linAUDIT", 0, LOG_AUTH);
  printf("Silently reloading /etc/audit/audit.rules via auditctl -R.\n");
  EXIT_ON_ERROR(system("/sbin/auditctl -R /etc/audit/audit.rules 1>/dev/null 2>/dev/null"), "auditctl");

  int fd = socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC|SOCK_NONBLOCK, NETLINK_AUDIT);
  if (fd==-1) {
    perror("Cannot open netlink interface via socket()");
    exit(1);
  }
  int size = BUFFER_SIZE;
  int ret = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
  /* we can live with an error here */

  if (mcast_grp > 0) {
    ret = setsockopt(fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &mcast_grp, sizeof(mcast_grp));
    /* it works on newer kernels, we ignore ret */
  }

  int opt_on = 1;
  /* we won't get ENOBUFS */
  ret = setsockopt(fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &opt_on, sizeof(opt_on));

  ret = bind(fd, (const struct sockaddr*)&sa, sizeof(sa));
  if (ret==-1) {
    perror("Binding error via bind()");
    exit(2);
  }

  struct sockaddr_nl kernel_sa;
  int socklen = sizeof(kernel_sa);
  ret = getsockname(fd, (struct sockaddr*)&kernel_sa, &socklen);
  if (ret==-1) {
    perror("getsockname()");
    exit(3);
  }

  if (mcast_grp==0) {
    init(fd, &kernel_sa);
  }
  start_threads();

  struct pollfd pollfd = { .fd = fd, .events = POLLIN, .revents = 0 };

  printf("Starting event polling.\n");
  struct managed_buffer *last_event = NULL;
  unsigned long last_seq = -1;
  int postponed = 0;
  int success = 0;

  while (1) {
    ret = poll(&pollfd, 1, 10000);
    if (ret==-1) {
      perror("Error in waiting for socket data via poll()");
      exit(4);
    }
    else if (ret==0) {
      //continue; /* unexpected timeout */
    }
    dprintf("Main loop %s\n","..");
    struct managed_buffer *buff = acquire_buffer();
    iov.iov_base = buff->addr;
    iov.iov_len = BUFFER_SIZE;
    ret = recvmsg(fd, &msg, MSG_DONTWAIT);
    if (ret==0) {
      printf("Kaudit shutdown. Exiting.\n");
      exit(0);
    }
    else if (ret > 0) {
      char* data = AUDIT_BUFFER_TO_STR(buff->addr);
      int len = strlen(data);
      if (len==0 || data[len-2]==':' && data[len-1]==' ') {
        dprintf("Discarded src buffer: %s\n", data);
        release_buffer(buff, 0);
        postponed = 0;
      }
      else {
        unsigned long current_seq = 0;
        sscanf(data+21,"%ld)", &current_seq);
        struct managed_buffer *to_push  = buff;
        if (current_seq == last_seq) {
          struct managed_buffer *it = last_event;
          if (it) {
            while (it->link) {
              it = it->link;
            }
            it->link = buff;
          }
          else {
            last_event = buff;
          }
          to_push = NULL;
          postponed++;
        }
        else {
          to_push = last_event;
          postponed = 0;
        }
        last_seq = current_seq;
        if (to_push) {
          last_event = buff;
          dprintf("Pushing %d postponed work buffers\n", postponed);
          push_work_buffer(to_push);
          dprintf("Work pushed: %ld\n", last_seq);
        }
        else {
          dprintf("Postponed to push work buffer for %d time\n", postponed);
        }
      }
      if (success==0 && last_seq > 1) {
        success=1;
        printf("Auditing is active. See /var/log/messages or configured destination.\n");
      }
    }
    else if (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR) {
      release_buffer(buff, -1);
      continue;
    }
    else if (ret==ENOBUFS) {
      release_buffer(buff, -2);
      dprintf("Buffer content lost, expect inconsistent event%s","\n");
    }
    else {
      printf("Receiver failed with errno %d\n", errno);
      perror("recvmsg()");
      exit(5);
    }
  }
  return 0;
}
