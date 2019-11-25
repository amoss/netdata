// SPDX-License-Identifier: GPL-3.0-or-later

#include "../../../libnetdata/libnetdata.h"
#include "../../../libnetdata/required_dummies.h"
#include "../../../database/rrd.h"
#include "../../../web/server/web_client.h"

#include <setjmp.h>
#include <cmocka.h>
#include <stdbool.h>

void repr(char *result, int result_size, char const *buf, int size)
{
    int n;
    char *end = result + result_size - 1;
    unsigned char const *ubuf = (unsigned char const *)buf;
    while (size && result_size > 0) {
        if (*ubuf <= 0x20 || *ubuf >= 0x80) {
            n = snprintf(result, result_size, "\\%02X", *ubuf);
        } else {
            *result = *ubuf;
            n = 1;
        }
        result += n;
        result_size -= n;
        ubuf++;
        size--;
    }
    if (result_size > 0)
        *(result++) = 0;
    else
        *end = 0;
}

// ---------------------------------- Mocking accesses from web_client ------------------------------------------------


WEB_SERVER_MODE web_server_mode = WEB_SERVER_MODE_STATIC_THREADED;
char *netdata_configured_web_dir = "UNKNOWN FIXME";
RRDHOST *localhost = NULL;

struct config netdata_config = { .sections = NULL,
                                 .mutex = NETDATA_MUTEX_INITIALIZER,
                                 .index = { .avl_tree = { .root = NULL, .compar = appconfig_section_compare },
                                            .rwlock = AVL_LOCK_INITIALIZER } };

/* Note: this is not a CMocka group_test_setup/teardown pair. This is performed per-test.
*/
static struct web_client *setup_fresh_web_client()
{
    struct web_client *w = (struct web_client *)malloc(sizeof(struct web_client));
    memset(w, 0, sizeof(struct web_client));
    w->response.data = buffer_create(NETDATA_WEB_RESPONSE_INITIAL_SIZE);
    w->response.header = buffer_create(NETDATA_WEB_RESPONSE_HEADER_SIZE);
    w->response.header_output = buffer_create(NETDATA_WEB_RESPONSE_HEADER_SIZE);
    strcpy(w->origin, "*"); // Simulate web_client_create_on_fd()
    w->cookie1[0] = 0;      // Simulate web_client_create_on_fd()
    w->cookie2[0] = 0;      // Simulate web_client_create_on_fd()
    w->acl = 0x1f;          // Everything on
    return w;
}

static void destroy_web_client(struct web_client *w)
{
    buffer_free(w->response.data);
    buffer_free(w->response.header);
    buffer_free(w->response.header_output);
    free(w);
}

//////////////////////////// Test cases ///////////////////////////////////////////////////////////////////////////////

static void simple_lines(void **state)
{
    (void)state;

    struct token tokens[5];
    const char *text = "Some text\nwith line\nbreaks";
    int n = tokenize(tokens, sizeof(tokens), text, strlen(text), 0, "\n");

    for(int i=0; i<n; i++)
        printf("Start %d End %d ->%.*s<-\n",tokens[i].start, tokens[i].end, tokens[i].end - tokens[i].start + 1,
               text + tokens[i].start);

    assert_int_equal(n,3);
    assert_int_equal(tokens[0].start,0);
    assert_int_equal(tokens[0].end,8);
    assert_int_equal(tokens[1].start,10);
    assert_int_equal(tokens[1].end,18);
    assert_int_equal(tokens[2].start,20);
    assert_int_equal(tokens[2].end,25);
}

static void empty_line(void **state)
{
    (void)state;

    struct token tokens[5];
    const char *text = "Some text\n\nbreaks";
    int n = tokenize(tokens, sizeof(tokens), text, strlen(text), 0, "\n");

    for(int i=0; i<n; i++)
        printf("Start %d End %d ->%.*s<-\n",tokens[i].start, tokens[i].end, tokens[i].end - tokens[i].start + 1,
               text + tokens[i].start);

    assert_int_equal(n,3);
    assert_int_equal(tokens[0].start,0);
    assert_int_equal(tokens[0].end,8);
    int token_empty = (tokens[1].end < tokens[1].start) ? 1 : 0;
    assert_int_equal(token_empty,1);
    assert_int_equal(tokens[2].start,11);
    assert_int_equal(tokens[2].end,16);
}

static void empty_start(void **state)
{
    (void)state;

    struct token tokens[5];
    const char *text = "\na single longer token at the end";
    int n = tokenize(tokens, sizeof(tokens), text, strlen(text), 0, "\n");

    for(int i=0; i<n; i++)
        printf("Start %d End %d ->%.*s<-\n",tokens[i].start, tokens[i].end, tokens[i].end - tokens[i].start + 1,
               text + tokens[i].start);


    int token_empty = (tokens[0].end < tokens[0].start) ? 1 : 0;
    assert_int_equal(n,2);
    assert_int_equal(tokens[0].start,0);
    assert_int_equal(token_empty,1);
    assert_int_equal(tokens[1].start,1);
    assert_int_equal(tokens[1].end,32);
}

static void empty_end(void **state)
{
    (void)state;

    struct token tokens[5];
    const char *text = "a single longer token at the start\n";
    int n = tokenize(tokens, sizeof(tokens), text, strlen(text), 0, "\n");

    for(int i=0; i<n; i++)
        printf("Start %d End %d ->%.*s<-\n",tokens[i].start, tokens[i].end, tokens[i].end - tokens[i].start + 1,
               text + tokens[i].start);


    assert_int_equal(n,2);
    assert_int_equal(tokens[0].start,0);
    assert_int_equal(tokens[0].end,33);
    assert_int_equal(tokens[1].start,35);
    int token_empty = (tokens[1].end < tokens[1].start) ? 1 : 0;
    assert_int_equal(token_empty,1);
}


int main(void)
{
    debug_flags = 0xffffffffffff;
    int fails = 0;

    struct CMUnitTest static_tests[] = {
        cmocka_unit_test(simple_lines),
        cmocka_unit_test(empty_line),
        cmocka_unit_test(empty_start),
        cmocka_unit_test(empty_end)
    };

    fails += cmocka_run_group_tests_name("static_tests", static_tests, NULL, NULL);
    return fails;
}
