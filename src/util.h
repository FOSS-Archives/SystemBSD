/*
 * Copyright (c) 2014 Ian Sutton <ian@kremlin.cc>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

typedef enum {
    AUTHORIZED_NATIVELY,   AUTHORIZED_BY_PROMPT,
    UNAUTHORIZED_NATIVELY, UNAUTHORIZED_FAILED_PROMPT,
    ERROR_BADBUS, ERROR_BADACTION, ERROR_GENERIC
} check_auth_result;

check_auth_result polkit_try_auth(const gchar *bus, const gchar *action, gboolean prompt);

gchar *  config_get(const gchar *path, gchar *key);
gboolean config_set(const gchar *path, gchar *key, gchar *value);
gchar *get_file_sha256(const gchar *path);
