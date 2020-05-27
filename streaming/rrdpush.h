// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef NETDATA_RRDPUSH_H
#define NETDATA_RRDPUSH_H 1

#include "../database/rrd.h"
#include "../libnetdata/libnetdata.h"
#include "web/server/web_client.h"
#include "daemon/common.h"

#define CONNECTED_TO_SIZE 100

// #define STREAMING_PROTOCOL_CURRENT_VERSION (uint32_t)3       Gap-filling
#define STREAMING_PROTOCOL_CURRENT_VERSION (uint32_t)2

#define STREAMING_PROTOCOL_VERSION "1.1"
#define START_STREAMING_PROMPT "Hit me baby, push them over..."
#define START_STREAMING_PROMPT_V2  "Hit me baby, push them over and bring the host labels..."
#define START_STREAMING_PROMPT_VN "Hit me baby, push them over with the version="

#define HTTP_HEADER_SIZE 8192

typedef enum {
    RRDPUSH_MULTIPLE_CONNECTIONS_ALLOW,
    RRDPUSH_MULTIPLE_CONNECTIONS_DENY_NEW
} RRDPUSH_MULTIPLE_CONNECTIONS_STRATEGY;

typedef struct {
    char *os_name;
    char *os_id;
    char *os_version;
    char *kernel_name;
    char *kernel_version;
} stream_encoded_t;

// Thread-local storage
    // Metric transmission: collector threads asynchronously fill the buffer, sender thread uses it.

struct sender_state {
    RRDHOST *host;
    pid_t task_id;
    unsigned int overflow:1;
    int timeout, default_port;
    size_t max_size;
    usec_t reconnect_delay;
    char connected_to[CONNECTED_TO_SIZE + 1];   // We don't know which proxy we connect to, passed back from socket.c
    size_t begin;
    size_t reconnects_counter;
    size_t sent_bytes;
    size_t sent_bytes_on_this_connection;
    size_t send_attempts;
    time_t last_sent_t;
    size_t not_connected_loops;
    // metrics may be collected asynchronously
    // these synchronize all the threads willing the write to our sending buffer
    netdata_mutex_t mutex;    // Guard access to buffer / build
    struct circular_buffer *buffer;
    BUFFER *build;
    char read_buffer[512];
    int read_len;
};

extern unsigned int default_rrdpush_enabled;
extern char *default_rrdpush_destination;
extern char *default_rrdpush_api_key;
extern char *default_rrdpush_send_charts_matching;
extern unsigned int remote_clock_resync_iterations;

extern void sender_init(struct sender_state *s, RRDHOST *parent);
void sender_start(struct sender_state *s);
void sender_commit(struct sender_state *s);
extern int rrdpush_init();
extern int configured_as_master();
extern void rrdset_done_push(RRDSET *st);
extern void rrdset_push_chart_definition_now(RRDSET *st);
extern void *rrdpush_sender_thread(void *ptr);
extern void rrdpush_send_labels(RRDHOST *host);

extern int rrdpush_receiver_thread_spawn(RRDHOST *host, struct web_client *w, char *url);
extern void rrdpush_sender_thread_stop(RRDHOST *host);

extern void rrdpush_sender_send_this_host_variable_now(RRDHOST *host, RRDVAR *rv);

#endif //NETDATA_RRDPUSH_H
