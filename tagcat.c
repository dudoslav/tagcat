/* See LICENSE file for license details. */
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define ADV_PORT 42069
#define BUF_SIZE 1024
#define TAG_SIZE 128

static const size_t
ip_size = sizeof(struct sockaddr_in);

static void
die(const char *errstr, ...) {
  va_list ap;

  va_start(ap, errstr);
  vfprintf(stderr, errstr, ap);
  va_end(ap);

  exit(1);
}

/* Compare local tag with remote tag */
static int
cmptag(const char* lt, const char* rt, const unsigned rt_len) {
  if (strlen(lt) != rt_len) return -1;
  return strncmp(lt, rt, rt_len);
}

/* Advertise specified tag */
static void
advertise(const char *tag, short port) {
  int adv_fd, c;
  struct sockaddr_in adv_ip, cli_ip;
  socklen_t cli_ip_size = sizeof(struct sockaddr_in);
  char buf[BUF_SIZE];

  adv_fd = socket(PF_INET, SOCK_DGRAM, 0);
  if (adv_fd < 0)
    die("failed to create advertise socket: %s\n",
        strerror(errno));

  memset(&adv_ip, 0, sizeof(struct sockaddr_in));
  adv_ip.sin_family = AF_INET;
  adv_ip.sin_addr.s_addr = INADDR_ANY;
  adv_ip.sin_port = htons(ADV_PORT);

  if (bind(adv_fd, (struct sockaddr*) &adv_ip, ip_size))
    die("failed to bind advertise socket: %s\n",
        strerror(errno));

  port = htons(port);

  for(;;) {
    c = recvfrom(adv_fd, buf, BUF_SIZE, 0,
        (struct sockaddr*) &cli_ip, &cli_ip_size);
    if (c < 0)
      die("failed to recv on advertise socket: %s\n",
          strerror(errno));
    if (cmptag(tag, buf, c)) continue;

    if (sendto(adv_fd, &port, sizeof(short), 0,
          (struct sockaddr*) &cli_ip, cli_ip_size) < 0)
      die("failed to send on advertise socket: %s\n",
          strerror(errno));
    break;
  }

  close(adv_fd);
}

/* Request tag socket, fill ip with remote IP of tag */
static void
request_tag(const char *tag, struct sockaddr_in *addr) {
  int req_fd, sockopt, c;
  short port;
  struct sockaddr_in brd_ip;
  socklen_t addr_size = sizeof(struct sockaddr_in);

  req_fd = socket(PF_INET, SOCK_DGRAM, 0);
  if (req_fd < 0)
    die("failed to create tag request socket: %s\n",
        strerror(errno));

  brd_ip.sin_family = AF_INET;
  brd_ip.sin_addr.s_addr = INADDR_BROADCAST;
  brd_ip.sin_port = htons(ADV_PORT);

  sockopt = 1;
  setsockopt(req_fd, SOL_SOCKET, SO_BROADCAST,
      &sockopt, sizeof(int));

  c = sendto(req_fd, tag, strlen(tag), 0,
      (struct sockaddr*) &brd_ip, ip_size);
  if (c < 0)
    die("failed to send on tag request socket: %s\n",
        strerror(errno));
  
  c = recvfrom(req_fd, &port, sizeof(short), 0,
      (struct sockaddr*) addr, &addr_size);
  if (c < 0)
    die("failed to recv on tag request socket: %s\n",
        strerror(errno));

  addr->sin_port = ntohs(port);

  close(req_fd);
}

/* Open socket stream for data transfer. (server) */
static int
create_provide(struct sockaddr_in *addr) {
  int pro_fd;
  socklen_t pro_ip_size = sizeof(struct sockaddr_in);

  pro_fd = socket(PF_INET, SOCK_STREAM, 0);
  if (pro_fd < 0)
    die("failed to create provide socket: %s\n", 
        strerror(errno));

  memset(addr, 0, sizeof(struct sockaddr_in));
  addr->sin_family = AF_INET;
  addr->sin_addr.s_addr = INADDR_ANY;

  if (bind(pro_fd, (struct sockaddr*) addr, ip_size))
    die("failed to bind provide socket: %s\n",
        strerror(errno));

  if (getsockname(pro_fd, (struct sockaddr *) addr, &pro_ip_size))
    die("failed to retrieve provide socket addr: %s\n",
        strerror(errno));

  listen(pro_fd, SOMAXCONN);

  return pro_fd;
}

/* Provides data on specified socket. (server) */
static void
provide(const int pro_fd) {
  int cli_fd, c;
  char buf[BUF_SIZE];

  cli_fd = accept(pro_fd, NULL, NULL);

  while ((c = read(STDIN_FILENO, buf, BUF_SIZE)) > 0)
    if ((c = write(cli_fd, buf, c)) < 0)
      die("failed to write to provide socket: %s\n",
          strerror(errno));

  if (c < 0)
    die("failed to read on input file descriptor: %s\n",
        strerror(errno));

  close(cli_fd);
}

/* Creates stream socket and connect to provider. (client) */
static void
consume(const struct sockaddr_in *addr) {
  int con_fd, c;
  char buf[BUF_SIZE];

  con_fd = socket(PF_INET, SOCK_STREAM, 0);
  if (con_fd < 0)
    die("failed to create consume socket: %s\n",
        strerror(errno));

  if (connect(con_fd, (struct sockaddr*) addr, ip_size) < 0)
    die("failed to connect on consume socket: %s\n",
        strerror(errno));

  while ((c = read(con_fd, buf, BUF_SIZE)) > 0)
    if ((c = write(STDOUT_FILENO, buf, c)) < 0)
      die("failed to write on output file descriptor: %s\n",
          strerror(errno));

  if (c < 0)
    die("failed to read on consume socket: %s\n",
        strerror(errno));

  close(con_fd);
}

/* Print help */
static void
help(const char *progname) {
  printf("Usage: %s [-t tag] [-l]\n", progname);
  printf("Order of opperations:\n");
  printf("\t1. %s -l ...\n", progname);
  printf("\t2. %s ...\n", progname);
}

int
main(int argc, char *argv[]) {
  enum { MODE_PROVIDE, MODE_RECEIVE } mode = MODE_RECEIVE;
  char tag[TAG_SIZE] = "";
  int opt;

  while ((opt = getopt(argc, argv, "hlt:")) != -1) {
    switch (opt) {
    case 'l': mode = MODE_PROVIDE; break; /* -l as listen */
    case 't':
              assert(strlen(tag) < TAG_SIZE);
              strcpy(tag, optarg);
              break;
    case 'h': 
              help(argv[0]);
              return 0;
    }
  }

  struct sockaddr_in addr;
  int pro_fd;
  switch (mode) {
  case MODE_RECEIVE: 
                     request_tag(tag, &addr);
                     consume(&addr);
                     break;
  case MODE_PROVIDE:
                     pro_fd = create_provide(&addr);
                     advertise(tag, addr.sin_port);
                     provide(pro_fd);
                     close(pro_fd);
                     break;
  }

  return 0;
}
