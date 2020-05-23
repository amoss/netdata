// SPDX-License-Identifier: GPL-3.0-or-later

#include "rrdpush.h"
#include "../parser/parser.h"

/*
 * rrdpush
 *
 * 3 threads are involved for all stream operations
 *
 * 1. a random data collection thread, calling rrdset_done_push()
 *    this is called for each chart.
 *
 *    the output of this work is kept in a BUFFER in RRDHOST
 *    the sender thread is signalled via a pipe (also in RRDHOST)
 *
 * 2. a sender thread running at the sending netdata
 *    this is spawned automatically on the first chart to be pushed
 *
 *    It tries to push the metrics to the remote netdata, as fast
 *    as possible (i.e. immediately after they are collected).
 *
 * 3. a receiver thread, running at the receiving netdata
 *    this is spawned automatically when the sender connects to
 *    the receiver.
 *
 */

struct config stream_config = {
        .first_section = NULL,
        .last_section = NULL,
        .mutex = NETDATA_MUTEX_INITIALIZER,
        .index = {
                .avl_tree = {
                        .root = NULL,
                        .compar = appconfig_section_compare
                },
                .rwlock = AVL_LOCK_INITIALIZER
        }
};

unsigned int default_rrdpush_enabled = 0;
char *default_rrdpush_destination = NULL;
char *default_rrdpush_api_key = NULL;
char *default_rrdpush_send_charts_matching = NULL;
#ifdef ENABLE_HTTPS
int netdata_use_ssl_on_stream = NETDATA_SSL_OPTIONAL;
char *netdata_ssl_ca_path = NULL;
char *netdata_ssl_ca_file = NULL;
#endif

static void load_stream_conf() {
    errno = 0;
    char *filename = strdupz_path_subpath(netdata_configured_user_config_dir, "stream.conf");
    if(!appconfig_load(&stream_config, filename, 0, NULL)) {
        info("CONFIG: cannot load user config '%s'. Will try stock config.", filename);
        freez(filename);

        filename = strdupz_path_subpath(netdata_configured_stock_config_dir, "stream.conf");
        if(!appconfig_load(&stream_config, filename, 0, NULL))
            info("CONFIG: cannot load stock config '%s'. Running with internal defaults.", filename);
    }
    freez(filename);
}

int rrdpush_init() {
    // --------------------------------------------------------------------
    // load stream.conf
    load_stream_conf();

    default_rrdpush_enabled     = (unsigned int)appconfig_get_boolean(&stream_config, CONFIG_SECTION_STREAM, "enabled", default_rrdpush_enabled);
    default_rrdpush_destination = appconfig_get(&stream_config, CONFIG_SECTION_STREAM, "destination", "");
    default_rrdpush_api_key     = appconfig_get(&stream_config, CONFIG_SECTION_STREAM, "api key", "");
    default_rrdpush_send_charts_matching      = appconfig_get(&stream_config, CONFIG_SECTION_STREAM, "send charts matching", "*");
    rrdhost_free_orphan_time    = config_get_number(CONFIG_SECTION_GLOBAL, "cleanup orphan hosts after seconds", rrdhost_free_orphan_time);


    if(default_rrdpush_enabled && (!default_rrdpush_destination || !*default_rrdpush_destination || !default_rrdpush_api_key || !*default_rrdpush_api_key)) {
        error("STREAM [send]: cannot enable sending thread - information is missing.");
        default_rrdpush_enabled = 0;
    }

#ifdef ENABLE_HTTPS
    if (netdata_use_ssl_on_stream == NETDATA_SSL_OPTIONAL) {
        if (default_rrdpush_destination){
            char *test = strstr(default_rrdpush_destination,":SSL");
            if(test){
                *test = 0X00;
                netdata_use_ssl_on_stream = NETDATA_SSL_FORCE;
            }
        }
    }

    char *invalid_certificate = appconfig_get(&stream_config, CONFIG_SECTION_STREAM, "ssl skip certificate verification", "no");

    if ( !strcmp(invalid_certificate,"yes")){
        if (netdata_validate_server == NETDATA_SSL_VALID_CERTIFICATE){
            info("Netdata is configured to accept invalid SSL certificate.");
            netdata_validate_server = NETDATA_SSL_INVALID_CERTIFICATE;
        }
    }

    netdata_ssl_ca_path = appconfig_get(&stream_config, CONFIG_SECTION_STREAM, "CApath", "/etc/ssl/certs/");
    netdata_ssl_ca_file = appconfig_get(&stream_config, CONFIG_SECTION_STREAM, "CAfile", "/etc/ssl/certs/certs.pem");
#endif

    return default_rrdpush_enabled;
}

// data collection happens from multiple threads
// each of these threads calls rrdset_done()
// which in turn calls rrdset_done_push()
// which uses this pipe to notify the streaming thread
// that there are more data ready to be sent
#define PIPE_READ 0
#define PIPE_WRITE 1

// to have the remote netdata re-sync the charts
// to its current clock, we send for this many
// iterations a BEGIN line without microseconds
// this is for the first iterations of each chart
unsigned int remote_clock_resync_iterations = 60;


static inline int should_send_chart_matching(RRDSET *st) {
    if(unlikely(!rrdset_flag_check(st, RRDSET_FLAG_ENABLED))) {
        rrdset_flag_clear(st, RRDSET_FLAG_UPSTREAM_SEND);
        rrdset_flag_set(st, RRDSET_FLAG_UPSTREAM_IGNORE);
    }
    else if(!rrdset_flag_check(st, RRDSET_FLAG_UPSTREAM_SEND|RRDSET_FLAG_UPSTREAM_IGNORE)) {
        RRDHOST *host = st->rrdhost;

        if(simple_pattern_matches(host->rrdpush_send_charts_matching, st->id) ||
            simple_pattern_matches(host->rrdpush_send_charts_matching, st->name)) {
            rrdset_flag_clear(st, RRDSET_FLAG_UPSTREAM_IGNORE);
            rrdset_flag_set(st, RRDSET_FLAG_UPSTREAM_SEND);
        }
        else {
            rrdset_flag_clear(st, RRDSET_FLAG_UPSTREAM_SEND);
            rrdset_flag_set(st, RRDSET_FLAG_UPSTREAM_IGNORE);
        }
    }

    return(rrdset_flag_check(st, RRDSET_FLAG_UPSTREAM_SEND));
}

int configured_as_master() {
    struct section *section = NULL;
    int is_master = 0;

    appconfig_wrlock(&stream_config);
    for (section = stream_config.first_section; section; section = section->next) {
        uuid_t uuid;

        if (uuid_parse(section->name, uuid) != -1 &&
                appconfig_get_boolean_by_section(section, "enabled", 0)) {
            is_master = 1;
            break;
        }
    }
    appconfig_unlock(&stream_config);

    return is_master;
}

// checks if the current chart definition has been sent
static inline int need_to_send_chart_definition(RRDSET *st) {
    rrdset_check_rdlock(st);

    if(unlikely(!(rrdset_flag_check(st, RRDSET_FLAG_UPSTREAM_EXPOSED))))
        return 1;

    RRDDIM *rd;
    rrddim_foreach_read(rd, st) {
        if(unlikely(!rd->exposed)) {
            #ifdef NETDATA_INTERNAL_CHECKS
            info("host '%s', chart '%s', dimension '%s' flag 'exposed' triggered chart refresh to upstream", st->rrdhost->hostname, st->id, rd->id);
            #endif
            return 1;
        }
    }

    return 0;
}

// sends the current chart definition
static inline void rrdpush_send_chart_definition_nolock(RRDSET *st) {
    RRDHOST *host = st->rrdhost;

    rrdset_flag_set(st, RRDSET_FLAG_UPSTREAM_EXPOSED);

    // properly set the name for the remote end to parse it
    char *name = "";
    if(likely(st->name)) {
        if(unlikely(strcmp(st->id, st->name))) {
            // they differ
            name = strchr(st->name, '.');
            if(name)
                name++;
            else
                name = "";
        }
    }

    // info("CHART '%s' '%s'", st->id, name);
    buffer_flush(host->sender_build);

    // send the chart
    buffer_sprintf(
            host->sender_build
            , "CHART \"%s\" \"%s\" \"%s\" \"%s\" \"%s\" \"%s\" \"%s\" %ld %d \"%s %s %s %s\" \"%s\" \"%s\"\n"
            , st->id
            , name
            , st->title
            , st->units
            , st->family
            , st->context
            , rrdset_type_name(st->chart_type)
            , st->priority
            , st->update_every
            , rrdset_flag_check(st, RRDSET_FLAG_OBSOLETE)?"obsolete":""
            , rrdset_flag_check(st, RRDSET_FLAG_DETAIL)?"detail":""
            , rrdset_flag_check(st, RRDSET_FLAG_STORE_FIRST)?"store_first":""
            , rrdset_flag_check(st, RRDSET_FLAG_HIDDEN)?"hidden":""
            , (st->plugin_name)?st->plugin_name:""
            , (st->module_name)?st->module_name:""
    );

    // send the dimensions
    RRDDIM *rd;
    rrddim_foreach_read(rd, st) {
        buffer_sprintf(
                host->sender_build
                , "DIMENSION \"%s\" \"%s\" \"%s\" " COLLECTED_NUMBER_FORMAT " " COLLECTED_NUMBER_FORMAT " \"%s %s %s\"\n"
                , rd->id
                , rd->name
                , rrd_algorithm_name(rd->algorithm)
                , rd->multiplier
                , rd->divisor
                , rrddim_flag_check(rd, RRDDIM_FLAG_OBSOLETE)?"obsolete":""
                , rrddim_flag_check(rd, RRDDIM_FLAG_HIDDEN)?"hidden":""
                , rrddim_flag_check(rd, RRDDIM_FLAG_DONT_DETECT_RESETS_OR_OVERFLOWS)?"noreset":""
        );
        rd->exposed = 1;
    }

    // send the chart local custom variables
    RRDSETVAR *rs;
    for(rs = st->variables; rs ;rs = rs->next) {
        if(unlikely(rs->type == RRDVAR_TYPE_CALCULATED && rs->options & RRDVAR_OPTION_CUSTOM_CHART_VAR)) {
            calculated_number *value = (calculated_number *) rs->value;

            buffer_sprintf(
                    host->sender_build
                    , "VARIABLE CHART %s = " CALCULATED_NUMBER_FORMAT "\n"
                    , rs->variable
                    , *value
            );
        }
    }
    cbuffer_add(host->sender_buffer, buffer_tostring(host->sender_build), host->sender_build->len);

    st->upstream_resync_time = st->last_collected_time.tv_sec + (remote_clock_resync_iterations * st->update_every);
}

// sends the current chart dimensions
static inline void rrdpush_send_chart_metrics_nolock(RRDSET *st) {
    RRDHOST *host = st->rrdhost;
    buffer_flush(host->sender_build);
    buffer_sprintf(host->sender_build, "BEGIN \"%s\" %llu\n", st->id, (st->last_collected_time.tv_sec > st->upstream_resync_time)?st->usec_since_last_update:0);

    RRDDIM *rd;
    rrddim_foreach_read(rd, st) {
        if(rd->updated && rd->exposed)
            buffer_sprintf(host->sender_build
                           , "SET \"%s\" = " COLLECTED_NUMBER_FORMAT "\n"
                           , rd->id
                           , rd->collected_value
        );
    }
    buffer_strcat(host->sender_build, "END\n");
    cbuffer_add(host->sender_buffer, buffer_tostring(host->sender_build), host->sender_build->len);
}

static void rrdpush_sender_thread_spawn(RRDHOST *host);

void rrdset_push_chart_definition_now(RRDSET *st) {
    RRDHOST *host = st->rrdhost;

    if(unlikely(!host->rrdpush_send_enabled || !should_send_chart_matching(st)))
        return;

    rrdset_rdlock(st);
    rrdpush_buffer_lock(host);
    rrdpush_send_chart_definition_nolock(st);
    rrdpush_buffer_unlock(host);
    rrdset_unlock(st);
}

void rrdset_done_push(RRDSET *st) {
    if(unlikely(!should_send_chart_matching(st)))
        return;

    RRDHOST *host = st->rrdhost;

    rrdpush_buffer_lock(host);

    if(unlikely(host->rrdpush_send_enabled && !host->rrdpush_sender_spawn))
        rrdpush_sender_thread_spawn(host);

    // TODO-GAPS Replace sender_build state with proper state
    if(unlikely(!host->sender_build || !host->rrdpush_sender_connected)) {
        if(unlikely(!host->rrdpush_sender_error_shown))
            error("STREAM %s [send]: not ready - discarding collected metrics.", host->hostname);

        host->rrdpush_sender_error_shown = 1;

        rrdpush_buffer_unlock(host);
        return;
    }
    else if(unlikely(host->rrdpush_sender_error_shown)) {
        info("STREAM %s [send]: sending metrics...", host->hostname);
        host->rrdpush_sender_error_shown = 0;
    }

    if(need_to_send_chart_definition(st))
        rrdpush_send_chart_definition_nolock(st);

    rrdpush_send_chart_metrics_nolock(st);

    // signal the sender there are more data
    if(host->rrdpush_sender_pipe[PIPE_WRITE] != -1 && write(host->rrdpush_sender_pipe[PIPE_WRITE], " ", 1) == -1)
        error("STREAM %s [send]: cannot write to internal pipe", host->hostname);

    rrdpush_buffer_unlock(host);
}

// labels
void rrdpush_send_labels(RRDHOST *host) {
    if (!host->labels || !(host->labels_flag & LABEL_FLAG_UPDATE_STREAM) || (host->labels_flag & LABEL_FLAG_STOP_STREAM))
        return;

    // TODO-GAPS Update mutex for new state
    buffer_flush(host->sender_build);
    rrdpush_buffer_lock(host);
    rrdhost_rdlock(host);
    netdata_rwlock_rdlock(&host->labels_rwlock);

    struct label *labels = host->labels;
    while(labels) {
        buffer_sprintf(host->sender_build
                , "LABEL \"%s\" = %d %s\n"
                , labels->key
                , (int)labels->label_source
                , labels->value);

        labels = labels->next;
    }

    buffer_sprintf(host->sender_build
            , "OVERWRITE %s\n", "labels");

    netdata_rwlock_unlock(&host->labels_rwlock);
    rrdhost_unlock(host);

    if(host->rrdpush_sender_pipe[PIPE_WRITE] != -1 && write(host->rrdpush_sender_pipe[PIPE_WRITE], " ", 1) == -1)
        error("STREAM %s [send]: cannot write to internal pipe", host->hostname);

    cbuffer_add(host->sender_buffer, buffer_tostring(host->sender_build), host->sender_build->len);
    rrdpush_buffer_unlock(host);
    host->labels_flag &= ~LABEL_FLAG_UPDATE_STREAM;
}
// ----------------------------------------------------------------------------
// rrdpush sender thread

void rrdpush_sender_thread_stop(RRDHOST *host) {
    rrdpush_buffer_lock(host);
    rrdhost_wrlock(host);

    netdata_thread_t thr = 0;

    if(host->rrdpush_sender_spawn) {
        info("STREAM %s [send]: signaling sending thread to stop...", host->hostname);

        // signal the thread that we want to join it
        host->rrdpush_sender_join = 1;

        // copy the thread id, so that we will be waiting for the right one
        // even if a new one has been spawn
        thr = host->rrdpush_sender_thread;

        // signal it to cancel
        netdata_thread_cancel(host->rrdpush_sender_thread);
    }

    rrdhost_unlock(host);
    rrdpush_buffer_unlock(host);

    if(thr != 0) {
        info("STREAM %s [send]: waiting for the sending thread to stop...", host->hostname);
        void *result;
        netdata_thread_join(thr, &result);
        info("STREAM %s [send]: sending thread has exited.", host->hostname);
    }
}


// ----------------------------------------------------------------------------
// rrdpush receiver thread

static void log_stream_connection(const char *client_ip, const char *client_port, const char *api_key, const char *machine_guid, const char *host, const char *msg) {
    log_access("STREAM: %d '[%s]:%s' '%s' host '%s' api key '%s' machine guid '%s'", gettid(), client_ip, client_port, msg, host, api_key, machine_guid);
}

static int rrdpush_receive(int fd
                           , const char *key
                           , const char *hostname
                           , const char *registry_hostname
                           , const char *machine_guid
                           , const char *os
                           , const char *timezone
                           , const char *tags
                           , const char *program_name
                           , const char *program_version
                           , struct rrdhost_system_info *system_info
                           , int update_every
                           , char *client_ip
                           , char *client_port
                           , uint32_t stream_version
#ifdef ENABLE_HTTPS
                           , struct netdata_ssl *ssl
#endif
) {
    RRDHOST *host;
    int history = default_rrd_history_entries;
    RRD_MEMORY_MODE mode = default_rrd_memory_mode;
    int health_enabled = default_health_enabled;
    int rrdpush_enabled = default_rrdpush_enabled;
    char *rrdpush_destination = default_rrdpush_destination;
    char *rrdpush_api_key = default_rrdpush_api_key;
    char *rrdpush_send_charts_matching = default_rrdpush_send_charts_matching;
    time_t alarms_delay = 60;

    update_every = (int)appconfig_get_number(&stream_config, machine_guid, "update every", update_every);
    if(update_every < 0) update_every = 1;

    history = (int)appconfig_get_number(&stream_config, key, "default history", history);
    history = (int)appconfig_get_number(&stream_config, machine_guid, "history", history);
    if(history < 5) history = 5;

    mode = rrd_memory_mode_id(appconfig_get(&stream_config, key, "default memory mode", rrd_memory_mode_name(mode)));
    mode = rrd_memory_mode_id(appconfig_get(&stream_config, machine_guid, "memory mode", rrd_memory_mode_name(mode)));

    health_enabled = appconfig_get_boolean_ondemand(&stream_config, key, "health enabled by default", health_enabled);
    health_enabled = appconfig_get_boolean_ondemand(&stream_config, machine_guid, "health enabled", health_enabled);

    alarms_delay = appconfig_get_number(&stream_config, key, "default postpone alarms on connect seconds", alarms_delay);
    alarms_delay = appconfig_get_number(&stream_config, machine_guid, "postpone alarms on connect seconds", alarms_delay);

    rrdpush_enabled = appconfig_get_boolean(&stream_config, key, "default proxy enabled", rrdpush_enabled);
    rrdpush_enabled = appconfig_get_boolean(&stream_config, machine_guid, "proxy enabled", rrdpush_enabled);

    rrdpush_destination = appconfig_get(&stream_config, key, "default proxy destination", rrdpush_destination);
    rrdpush_destination = appconfig_get(&stream_config, machine_guid, "proxy destination", rrdpush_destination);

    rrdpush_api_key = appconfig_get(&stream_config, key, "default proxy api key", rrdpush_api_key);
    rrdpush_api_key = appconfig_get(&stream_config, machine_guid, "proxy api key", rrdpush_api_key);

    rrdpush_send_charts_matching = appconfig_get(&stream_config, key, "default proxy send charts matching", rrdpush_send_charts_matching);
    rrdpush_send_charts_matching = appconfig_get(&stream_config, machine_guid, "proxy send charts matching", rrdpush_send_charts_matching);

    tags = appconfig_set_default(&stream_config, machine_guid, "host tags", (tags)?tags:"");
    if(tags && !*tags) tags = NULL;

    if (strcmp(machine_guid, localhost->machine_guid) == 0) {
        log_stream_connection(client_ip, client_port, key, machine_guid, hostname, "DENIED - ATTEMPT TO RECEIVE METRICS FROM MACHINE_GUID IDENTICAL TO MASTER");
        error("STREAM %s [receive from %s:%s]: denied to receive metrics, machine GUID [%s] is my own. Did you copy the master/proxy machine guid to a slave?", hostname, client_ip, client_port, machine_guid);
        close(fd);
        return 1;
    }

    /*
     * Quick path for rejecting multiple connections. Don't take any locks so that progress is made. The same
     * condition will be checked again below, while holding the global and host writer locks. Any potential false
     * positives will not cause harm. Data hazards with host deconstruction will be handled when reference counting
     * is implemented.
     */
    host = rrdhost_find_by_guid(machine_guid, 0);
    if(host && host->connected_senders > 0) {
        log_stream_connection(client_ip, client_port, key, host->machine_guid, host->hostname, "REJECTED - ALREADY CONNECTED");
        info("STREAM %s [receive from [%s]:%s]: multiple streaming connections for the same host detected. Rejecting new connection.", host->hostname, client_ip, client_port);
        close(fd);
        return 0;
    }

    host = rrdhost_find_or_create(
            hostname
            , registry_hostname
            , machine_guid
            , os
            , timezone
            , tags
            , program_name
            , program_version
            , update_every
            , history
            , mode
            , (unsigned int)(health_enabled != CONFIG_BOOLEAN_NO)
            , (unsigned int)(rrdpush_enabled && rrdpush_destination && *rrdpush_destination && rrdpush_api_key && *rrdpush_api_key)
            , rrdpush_destination
            , rrdpush_api_key
            , rrdpush_send_charts_matching
            , system_info
    );

    if(!host) {
        close(fd);
        log_stream_connection(client_ip, client_port, key, machine_guid, hostname, "FAILED - CANNOT ACQUIRE HOST");
        error("STREAM %s [receive from [%s]:%s]: failed to find/create host structure.", hostname, client_ip, client_port);
        return 1;
    }

#ifdef NETDATA_INTERNAL_CHECKS
    info("STREAM %s [receive from [%s]:%s]: client willing to stream metrics for host '%s' with machine_guid '%s': update every = %d, history = %ld, memory mode = %s, health %s, tags '%s'"
         , hostname
         , client_ip
         , client_port
         , host->hostname
         , host->machine_guid
         , host->rrd_update_every
         , host->rrd_history_entries
         , rrd_memory_mode_name(host->rrd_memory_mode)
         , (health_enabled == CONFIG_BOOLEAN_NO)?"disabled":((health_enabled == CONFIG_BOOLEAN_YES)?"enabled":"auto")
         , host->tags?host->tags:""
    );
#endif // NETDATA_INTERNAL_CHECKS

    struct plugind cd = {
            .enabled = 1,
            .update_every = default_rrd_update_every,
            .pid = 0,
            .serial_failures = 0,
            .successful_collections = 0,
            .obsolete = 0,
            .started_t = now_realtime_sec(),
            .next = NULL,
            .version = 0,
    };

    // put the client IP and port into the buffers used by plugins.d
    snprintfz(cd.id,           CONFIG_MAX_NAME,  "%s:%s", client_ip, client_port);
    snprintfz(cd.filename,     FILENAME_MAX,     "%s:%s", client_ip, client_port);
    snprintfz(cd.fullfilename, FILENAME_MAX,     "%s:%s", client_ip, client_port);
    snprintfz(cd.cmd,          PLUGINSD_CMD_MAX, "%s:%s", client_ip, client_port);

    info("STREAM %s [receive from [%s]:%s]: initializing communication...", host->hostname, client_ip, client_port);
    char initial_response[HTTP_HEADER_SIZE];
    if (stream_version > 1) {
        info("STREAM %s [receive from [%s]:%s]: Netdata is using the stream version %u.", host->hostname, client_ip, client_port, stream_version);
        sprintf(initial_response, "%s%u", START_STREAMING_PROMPT_VN, stream_version);
    } else if (stream_version == 1) {
        info("STREAM %s [receive from [%s]:%s]: Netdata is using the stream version %u.", host->hostname, client_ip, client_port, stream_version);
        sprintf(initial_response, "%s", START_STREAMING_PROMPT_V2);
    } else {
        info("STREAM %s [receive from [%s]:%s]: Netdata is using first stream protocol.", host->hostname, client_ip, client_port);
        sprintf(initial_response, "%s", START_STREAMING_PROMPT);
    }
    #ifdef ENABLE_HTTPS
    host->stream_ssl.conn = ssl->conn;
    host->stream_ssl.flags = ssl->flags;
    if(send_timeout(ssl, fd, initial_response, strlen(initial_response), 0, 60) != (ssize_t)strlen(initial_response)) {
#else
    if(send_timeout(fd, initial_response, strlen(initial_response), 0, 60) != strlen(initial_response)) {
#endif
        log_stream_connection(client_ip, client_port, key, host->machine_guid, host->hostname, "FAILED - CANNOT REPLY");
        error("STREAM %s [receive from [%s]:%s]: cannot send ready command.", host->hostname, client_ip, client_port);
        close(fd);
        return 0;
    }

    // remove the non-blocking flag from the socket
    if(sock_delnonblock(fd) < 0)
        error("STREAM %s [receive from [%s]:%s]: cannot remove the non-blocking flag from socket %d", host->hostname, client_ip, client_port, fd);

    // convert the socket to a FILE *
    FILE *fp = fdopen(fd, "r");
    if(!fp) {
        log_stream_connection(client_ip, client_port, key, host->machine_guid, host->hostname, "FAILED - SOCKET ERROR");
        error("STREAM %s [receive from [%s]:%s]: failed to get a FILE for FD %d.", host->hostname, client_ip, client_port, fd);
        close(fd);
        return 0;
    }

    rrdhost_wrlock(host);
    if(host->connected_senders > 0) {
        rrdhost_unlock(host);
        log_stream_connection(client_ip, client_port, key, host->machine_guid, host->hostname, "REJECTED - ALREADY CONNECTED");
        info("STREAM %s [receive from [%s]:%s]: multiple streaming connections for the same host detected. Rejecting new connection.", host->hostname, client_ip, client_port);
        fclose(fp);
        return 0;
    }

    rrdhost_flag_clear(host, RRDHOST_FLAG_ORPHAN);
    host->connected_senders++;
    host->senders_disconnected_time = 0;
    host->labels_flag = (stream_version > 0)?LABEL_FLAG_UPDATE_STREAM:LABEL_FLAG_STOP_STREAM;

    if(health_enabled != CONFIG_BOOLEAN_NO) {
        if(alarms_delay > 0) {
            host->health_delay_up_to = now_realtime_sec() + alarms_delay;
            info("Postponing health checks for %ld seconds, on host '%s', because it was just connected."
            , alarms_delay
            , host->hostname
            );
        }
    }
    rrdhost_unlock(host);

    // call the plugins.d processor to receive the metrics
    info("STREAM %s [receive from [%s]:%s]: receiving metrics...", host->hostname, client_ip, client_port);
    log_stream_connection(client_ip, client_port, key, host->machine_guid, host->hostname, "CONNECTED");

    cd.version = stream_version;
    if (stream_version >= 2) {
        info("STREAM %s [receive from [%s]:%s]: Checking for gaps...", host->hostname, client_ip, client_port);
    }
    size_t count = pluginsd_process(host, &cd, fp, 1);

    log_stream_connection(client_ip, client_port, key, host->machine_guid, host->hostname, "DISCONNECTED");
    error("STREAM %s [receive from [%s]:%s]: disconnected (completed %zu updates).", host->hostname, client_ip, client_port, count);

    rrdhost_wrlock(host);
    host->senders_disconnected_time = now_realtime_sec();
    host->connected_senders--;
    if(!host->connected_senders) {
        rrdhost_flag_set(host, RRDHOST_FLAG_ORPHAN);
        if(health_enabled == CONFIG_BOOLEAN_AUTO)
            host->health_enabled = 0;
    }
    rrdhost_unlock(host);

    if(host->connected_senders == 0)
        rrdpush_sender_thread_stop(host);

    // cleanup
    fclose(fp);

    return (int)count;
}

struct rrdpush_thread {
    int fd;
    char *key;
    char *hostname;
    char *registry_hostname;
    char *machine_guid;
    char *os;
    char *timezone;
    char *tags;
    char *client_ip;
    char *client_port;
    char *program_name;
    char *program_version;
    struct rrdhost_system_info *system_info;
    int update_every;
    uint32_t stream_version;
#ifdef ENABLE_HTTPS
    struct netdata_ssl ssl;
#endif
};

static void rrdpush_receiver_thread_cleanup(void *ptr) {
    static __thread int executed = 0;
    if(!executed) {
        executed = 1;
        struct rrdpush_thread *rpt = (struct rrdpush_thread *) ptr;

        info("STREAM %s [receive from [%s]:%s]: receive thread ended (task id %d)", rpt->hostname, rpt->client_ip, rpt->client_port, gettid());

        freez(rpt->key);
        freez(rpt->hostname);
        freez(rpt->registry_hostname);
        freez(rpt->machine_guid);
        freez(rpt->os);
        freez(rpt->timezone);
        freez(rpt->tags);
        freez(rpt->client_ip);
        freez(rpt->client_port);
        freez(rpt->program_name);
        freez(rpt->program_version);
#ifdef ENABLE_HTTPS
        if(rpt->ssl.conn){
            SSL_free(rpt->ssl.conn);
        }
#endif
        freez(rpt);

    }
}

static void *rrdpush_receiver_thread(void *ptr) {
    netdata_thread_cleanup_push(rrdpush_receiver_thread_cleanup, ptr);

    struct rrdpush_thread *rpt = (struct rrdpush_thread *)ptr;
    info("STREAM %s [%s]:%s: receive thread created (task id %d)", rpt->hostname, rpt->client_ip, rpt->client_port, gettid());

    rrdpush_receive(
	    rpt->fd
	    , rpt->key
	    , rpt->hostname
	    , rpt->registry_hostname
	    , rpt->machine_guid
	    , rpt->os
	    , rpt->timezone
	    , rpt->tags
	    , rpt->program_name
	    , rpt->program_version
        , rpt->system_info
	    , rpt->update_every
	    , rpt->client_ip
	    , rpt->client_port
	    , rpt->stream_version
#ifdef ENABLE_HTTPS
	    , &rpt->ssl
#endif
    );

    netdata_thread_cleanup_pop(1);
    return NULL;
}

static void rrdpush_sender_thread_spawn(RRDHOST *host) {
    rrdhost_wrlock(host);

    if(!host->rrdpush_sender_spawn) {
        char tag[NETDATA_THREAD_TAG_MAX + 1];
        snprintfz(tag, NETDATA_THREAD_TAG_MAX, "STREAM_SENDER[%s]", host->hostname);

        if(netdata_thread_create(&host->rrdpush_sender_thread, tag, NETDATA_THREAD_OPTION_JOINABLE, rrdpush_sender_thread, (void *) host))
            error("STREAM %s [send]: failed to create new thread for client.", host->hostname);
        else
            host->rrdpush_sender_spawn = 1;
    }

    rrdhost_unlock(host);
}

int rrdpush_receiver_permission_denied(struct web_client *w) {
    // we always respond with the same message and error code
    // to prevent an attacker from gaining info about the error
    buffer_flush(w->response.data);
    buffer_sprintf(w->response.data, "You are not permitted to access this. Check the logs for more info.");
    return 401;
}

int rrdpush_receiver_too_busy_now(struct web_client *w) {
    // we always respond with the same message and error code
    // to prevent an attacker from gaining info about the error
    buffer_flush(w->response.data);
    buffer_sprintf(w->response.data, "The server is too busy now to accept this request. Try later.");
    return 503;
}

int rrdpush_receiver_thread_spawn(RRDHOST *host, struct web_client *w, char *url) {
    (void)host;

    info("clients wants to STREAM metrics.");

    char *key = NULL, *hostname = NULL, *registry_hostname = NULL, *machine_guid = NULL, *os = "unknown", *timezone = "unknown", *tags = NULL;
    int update_every = default_rrd_update_every;
    uint32_t stream_version = UINT_MAX;
    char buf[GUID_LEN + 1];

    struct rrdhost_system_info *system_info = callocz(1, sizeof(struct rrdhost_system_info));

    while(url) {
        char *value = mystrsep(&url, "&");
        if(!value || !*value) continue;

        char *name = mystrsep(&value, "=");
        if(!name || !*name) continue;
        if(!value || !*value) continue;

        if(!strcmp(name, "key"))
            key = value;
        else if(!strcmp(name, "hostname"))
            hostname = value;
        else if(!strcmp(name, "registry_hostname"))
            registry_hostname = value;
        else if(!strcmp(name, "machine_guid"))
            machine_guid = value;
        else if(!strcmp(name, "update_every"))
            update_every = (int)strtoul(value, NULL, 0);
        else if(!strcmp(name, "os"))
            os = value;
        else if(!strcmp(name, "timezone"))
            timezone = value;
        else if(!strcmp(name, "tags"))
            tags = value;
        else if(!strcmp(name, "ver"))
            stream_version = MIN((uint32_t) strtoul(value, NULL, 0), STREAMING_PROTOCOL_CURRENT_VERSION);
        else {
            // An old Netdata slave does not have a compatible streaming protocol, map to something sane.
            if (!strcmp(name, "NETDATA_SYSTEM_OS_NAME"))
                name = "NETDATA_HOST_OS_NAME";
            else if (!strcmp(name, "NETDATA_SYSTEM_OS_ID"))
                name = "NETDATA_HOST_OS_ID";
            else if (!strcmp(name, "NETDATA_SYSTEM_OS_ID_LIKE"))
                name = "NETDATA_HOST_OS_ID_LIKE";
            else if (!strcmp(name, "NETDATA_SYSTEM_OS_VERSION"))
                name = "NETDATA_HOST_OS_VERSION";
            else if (!strcmp(name, "NETDATA_SYSTEM_OS_VERSION_ID"))
                name = "NETDATA_HOST_OS_VERSION_ID";
            else if (!strcmp(name, "NETDATA_SYSTEM_OS_DETECTION"))
                name = "NETDATA_HOST_OS_DETECTION";
            else if(!strcmp(name, "NETDATA_PROTOCOL_VERSION") && stream_version == UINT_MAX) {
                stream_version = 1;
            }

            if (unlikely(rrdhost_set_system_info_variable(system_info, name, value))) {
                info("STREAM [receive from [%s]:%s]: request has parameter '%s' = '%s', which is not used.",
                     w->client_ip, w->client_port, name, value);
            }
        }
    }

    if (stream_version == UINT_MAX)
        stream_version = 0;

    if(!key || !*key) {
        rrdhost_system_info_free(system_info);
        log_stream_connection(w->client_ip, w->client_port, (key && *key)?key:"-", (machine_guid && *machine_guid)?machine_guid:"-", (hostname && *hostname)?hostname:"-", "ACCESS DENIED - NO KEY");
        error("STREAM [receive from [%s]:%s]: request without an API key. Forbidding access.", w->client_ip, w->client_port);
        return rrdpush_receiver_permission_denied(w);
    }

    if(!hostname || !*hostname) {
        rrdhost_system_info_free(system_info);
        log_stream_connection(w->client_ip, w->client_port, (key && *key)?key:"-", (machine_guid && *machine_guid)?machine_guid:"-", (hostname && *hostname)?hostname:"-", "ACCESS DENIED - NO HOSTNAME");
        error("STREAM [receive from [%s]:%s]: request without a hostname. Forbidding access.", w->client_ip, w->client_port);
        return rrdpush_receiver_permission_denied(w);
    }

    if(!machine_guid || !*machine_guid) {
        rrdhost_system_info_free(system_info);
        log_stream_connection(w->client_ip, w->client_port, (key && *key)?key:"-", (machine_guid && *machine_guid)?machine_guid:"-", (hostname && *hostname)?hostname:"-", "ACCESS DENIED - NO MACHINE GUID");
        error("STREAM [receive from [%s]:%s]: request without a machine GUID. Forbidding access.", w->client_ip, w->client_port);
        return rrdpush_receiver_permission_denied(w);
    }

    if(regenerate_guid(key, buf) == -1) {
        rrdhost_system_info_free(system_info);
        log_stream_connection(w->client_ip, w->client_port, (key && *key)?key:"-", (machine_guid && *machine_guid)?machine_guid:"-", (hostname && *hostname)?hostname:"-", "ACCESS DENIED - INVALID KEY");
        error("STREAM [receive from [%s]:%s]: API key '%s' is not valid GUID (use the command uuidgen to generate one). Forbidding access.", w->client_ip, w->client_port, key);
        return rrdpush_receiver_permission_denied(w);
    }

    if(regenerate_guid(machine_guid, buf) == -1) {
        rrdhost_system_info_free(system_info);
        log_stream_connection(w->client_ip, w->client_port, (key && *key)?key:"-", (machine_guid && *machine_guid)?machine_guid:"-", (hostname && *hostname)?hostname:"-", "ACCESS DENIED - INVALID MACHINE GUID");
        error("STREAM [receive from [%s]:%s]: machine GUID '%s' is not GUID. Forbidding access.", w->client_ip, w->client_port, machine_guid);
        return rrdpush_receiver_permission_denied(w);
    }

    if(!appconfig_get_boolean(&stream_config, key, "enabled", 0)) {
        rrdhost_system_info_free(system_info);
        log_stream_connection(w->client_ip, w->client_port, (key && *key)?key:"-", (machine_guid && *machine_guid)?machine_guid:"-", (hostname && *hostname)?hostname:"-", "ACCESS DENIED - KEY NOT ENABLED");
        error("STREAM [receive from [%s]:%s]: API key '%s' is not allowed. Forbidding access.", w->client_ip, w->client_port, key);
        return rrdpush_receiver_permission_denied(w);
    }

    {
        SIMPLE_PATTERN *key_allow_from = simple_pattern_create(appconfig_get(&stream_config, key, "allow from", "*"), NULL, SIMPLE_PATTERN_EXACT);
        if(key_allow_from) {
            if(!simple_pattern_matches(key_allow_from, w->client_ip)) {
                simple_pattern_free(key_allow_from);
                rrdhost_system_info_free(system_info);
                log_stream_connection(w->client_ip, w->client_port, (key && *key)?key:"-", (machine_guid && *machine_guid)?machine_guid:"-", (hostname && *hostname) ? hostname : "-", "ACCESS DENIED - KEY NOT ALLOWED FROM THIS IP");
                error("STREAM [receive from [%s]:%s]: API key '%s' is not permitted from this IP. Forbidding access.", w->client_ip, w->client_port, key);
                return rrdpush_receiver_permission_denied(w);
            }
            simple_pattern_free(key_allow_from);
        }
    }

    if(!appconfig_get_boolean(&stream_config, machine_guid, "enabled", 1)) {
        rrdhost_system_info_free(system_info);
        log_stream_connection(w->client_ip, w->client_port, (key && *key)?key:"-", (machine_guid && *machine_guid)?machine_guid:"-", (hostname && *hostname)?hostname:"-", "ACCESS DENIED - MACHINE GUID NOT ENABLED");
        error("STREAM [receive from [%s]:%s]: machine GUID '%s' is not allowed. Forbidding access.", w->client_ip, w->client_port, machine_guid);
        return rrdpush_receiver_permission_denied(w);
    }

    {
        SIMPLE_PATTERN *machine_allow_from = simple_pattern_create(appconfig_get(&stream_config, machine_guid, "allow from", "*"), NULL, SIMPLE_PATTERN_EXACT);
        if(machine_allow_from) {
            if(!simple_pattern_matches(machine_allow_from, w->client_ip)) {
                simple_pattern_free(machine_allow_from);
                rrdhost_system_info_free(system_info);
                log_stream_connection(w->client_ip, w->client_port, (key && *key)?key:"-", (machine_guid && *machine_guid)?machine_guid:"-", (hostname && *hostname) ? hostname : "-", "ACCESS DENIED - MACHINE GUID NOT ALLOWED FROM THIS IP");
                error("STREAM [receive from [%s]:%s]: Machine GUID '%s' is not permitted from this IP. Forbidding access.", w->client_ip, w->client_port, machine_guid);
                return rrdpush_receiver_permission_denied(w);
            }
            simple_pattern_free(machine_allow_from);
        }
    }

    if(unlikely(web_client_streaming_rate_t > 0)) {
        static netdata_mutex_t stream_rate_mutex = NETDATA_MUTEX_INITIALIZER;
        static volatile time_t last_stream_accepted_t = 0;

        netdata_mutex_lock(&stream_rate_mutex);
        time_t now = now_realtime_sec();

        if(unlikely(last_stream_accepted_t == 0))
            last_stream_accepted_t = now;

        if(now - last_stream_accepted_t < web_client_streaming_rate_t) {
            netdata_mutex_unlock(&stream_rate_mutex);
            rrdhost_system_info_free(system_info);
            error("STREAM [receive from [%s]:%s]: too busy to accept new streaming request. Will be allowed in %ld secs.", w->client_ip, w->client_port, (long)(web_client_streaming_rate_t - (now - last_stream_accepted_t)));
            return rrdpush_receiver_too_busy_now(w);
        }

        last_stream_accepted_t = now;
        netdata_mutex_unlock(&stream_rate_mutex);
    }

    struct rrdpush_thread *rpt = callocz(1, sizeof(struct rrdpush_thread));
    rpt->fd                = w->ifd;
    rpt->key               = strdupz(key);
    rpt->hostname          = strdupz(hostname);
    rpt->registry_hostname = strdupz((registry_hostname && *registry_hostname)?registry_hostname:hostname);
    rpt->machine_guid      = strdupz(machine_guid);
    rpt->os                = strdupz(os);
    rpt->timezone          = strdupz(timezone);
    rpt->tags              = (tags)?strdupz(tags):NULL;
    rpt->client_ip         = strdupz(w->client_ip);
    rpt->client_port       = strdupz(w->client_port);
    rpt->update_every      = update_every;
    rpt->system_info       = system_info;
    rpt->stream_version    = stream_version;
#ifdef ENABLE_HTTPS
    rpt->ssl.conn          = w->ssl.conn;
    rpt->ssl.flags         = w->ssl.flags;

    w->ssl.conn = NULL;
    w->ssl.flags = NETDATA_SSL_START;
#endif

    if(w->user_agent && w->user_agent[0]) {
        char *t = strchr(w->user_agent, '/');
        if(t && *t) {
            *t = '\0';
            t++;
        }

        rpt->program_name = strdupz(w->user_agent);
        if(t && *t) rpt->program_version = strdupz(t);
    }


    netdata_thread_t thread;

    debug(D_SYSTEM, "starting STREAM receive thread.");

    char tag[FILENAME_MAX + 1];
    snprintfz(tag, FILENAME_MAX, "STREAM_RECEIVER[%s,[%s]:%s]", rpt->hostname, w->client_ip, w->client_port);

    if(netdata_thread_create(&thread, tag, NETDATA_THREAD_OPTION_DEFAULT, rrdpush_receiver_thread, (void *)rpt))
        error("Failed to create new STREAM receive thread for client.");

    // prevent the caller from closing the streaming socket
    if(web_server_mode == WEB_SERVER_MODE_STATIC_THREADED) {
        web_client_flag_set(w, WEB_CLIENT_FLAG_DONT_CLOSE_SOCKET);
    }
    else {
        if(w->ifd == w->ofd)
            w->ifd = w->ofd = -1;
        else
            w->ifd = -1;
    }

    buffer_flush(w->response.data);
    return 200;
}
