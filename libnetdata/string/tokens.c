// SPDX-License-Identifier: GPL-3.0-or-later

#include <stddef.h>
#include "libnetdata/libnetdata.h"

/* To reduce complexity we tokenize without altering the original. This allows us to tokenize tokens.
 * We cannot reallocate memory because of performance so assume we must operate on fixed size buffers
 * (i.e. the token output). The offset parameter allows restart mid-stream to continue tokenization.
 * On a restart we overwrite the old tokens to reuse the output buffer.
*/
int tokenize(struct token *out_start, size_t out_size, char *in_start, size_t size, int offset,
             const char * const delimitors) {
    char *in = in_start, *in_end = in_start + size;
    struct token *out_end = (struct token *)(((char *)out_start)+out_size);
    struct token *out = out_start;
    int num_delims = strlen(delimitors);
    out->start = offset;
    while (out < out_end && in < in_end) {
        for (int i = 0; i < num_delims; i++) {
            if (*in == delimitors[i]) {
                out->end = offset + in - in_start - 1;      // Zero length tokens have end<start, ranges are inclusive
                out++;
                if (out<out_end)
                    out->start = offset + in - in_start;
                break;
            }
        }
        in++;
    }
    return out - out_start;
}

