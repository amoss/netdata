// SPDX-License-Identifier: GPL-3.0-or-later

struct token {
    int start;
    int end;
};

int tokenize(struct token *out_start, size_t out_size, const char *in_start, size_t size, int offset,
             const char * const delimitors) ;
int token_next(struct token *t);
