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

#include <unistd.h>
#include <limits.h>
#include <string.h>

#include <glib/gprintf.h>
#include <glib-unix.h>
#include <polkit/polkit.h>

#include "util.h"

const gint MAX_TOKENS = 20;

/* return must be g_free()'d */
gchar *get_file_sha256(const gchar *path) {

    gchar *checksum;
    GMappedFile *file;
    GBytes *data;
    GError *err = NULL;

    file = g_mapped_file_new(path, FALSE, &err);

    if(file) {

        data = g_mapped_file_get_bytes(file);
        g_mapped_file_unref(file);
        checksum = g_compute_checksum_for_bytes(G_CHECKSUM_SHA256, data);
        return checksum;
    } else
        return NULL;
}

/* return must be g_free()'d */
gchar *config_get(const gchar *path, gchar *key) {

    gchar  *content, **split_content, *cur, **cur_split, *ret;
    GError *err;
    int incr = 0;
    gboolean breaker = TRUE;

    ret = (gchar *) g_malloc0(4096);

    if(!g_file_get_contents(path, &content, NULL, &err))
        return NULL;

    split_content = g_strsplit(content, "\n", MAX_TOKENS);

    while(breaker && (cur = split_content[incr]) && (cur_split = g_strsplit(cur, "=", 2))) {

        if(!g_strcmp0(key, cur_split[0])) {

            g_strlcpy(ret, cur_split[1], 2048);
            breaker = FALSE;
        }

        incr++;
        g_strfreev(cur_split);
    }

    if(split_content)
        g_strfreev(split_content);
    if(content)
        g_free(content);

    return (ret ? ret : NULL);
}

gboolean config_set(const gchar *path, gchar *key, gchar *value) {

    gchar  *content, **split_content, *cur, **cur_split, *rewrite;
    GError *err_set, *err_get;
    gboolean ret = FALSE;
    int incr = 0;
    gboolean breaker = TRUE;

    err_get = err_set = NULL;

    if(!g_file_get_contents(path, &content, NULL, &err_get))
        return FALSE;

    split_content = g_strsplit(content, "\n", MAX_TOKENS);

    while(breaker && (cur = split_content[incr]) && (cur_split = g_strsplit(cur, "=", 2))) {
        
        if(!g_strcmp0(key, cur_split[0])) {

            cur_split[1] = value;
            split_content[incr] = g_strjoinv("=", cur_split);
            ret = TRUE;
            breaker = FALSE;
        }

        incr++;
    }

    if(ret) {

        rewrite = g_strjoinv("\n", split_content);
        ret = g_file_set_contents(path, rewrite, -1, &err_set);
        g_free(rewrite);
    }

    if(cur_split)
        g_strfreev(cur_split);
    if(split_content)
        g_strfreev(split_content);
    if(content)
        g_free(content);

    return ret;
}

static gboolean is_valid_action(GList *action_list, const gchar *action) {

    PolkitActionDescription *action_descr;
    const gchar *action_descr_id;
    GList *cur;
    gboolean ret;

    ret = FALSE;
    cur = g_list_first(action_list);

    while(cur && (action_descr = ((PolkitActionDescription *)(cur->data))) && (action_descr_id = polkit_action_description_get_action_id(action_descr))) {
        
        if(!g_strcmp0(action, action_descr_id)) {
            ret = TRUE;
            break;
        }

        cur = cur->next;
    }

    g_list_free(action_list);

    return ret;
}

check_auth_result polkit_try_auth(const gchar *bus, const gchar *action, gboolean prompt) {

    GList           *valid_actions;
    PolkitAuthority *auth;
    PolkitSubject   *subj;
    PolkitAuthorizationResult *result;
    PolkitCheckAuthorizationFlags prompt_flag;
    gboolean authorized, challenge;
    
    auth  = NULL;
    subj  = NULL;
    result = NULL;
    valid_actions = NULL;
    authorized = challenge = FALSE;
    prompt_flag = prompt ? POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION : POLKIT_CHECK_AUTHORIZATION_FLAGS_NONE;

    auth = polkit_authority_get_sync(NULL, NULL); /* TODO timeout for this */
    subj = polkit_system_bus_name_new(bus);
    valid_actions = polkit_authority_enumerate_actions_sync(auth, NULL, NULL);

   if(!auth || !valid_actions)
        return ERROR_GENERIC; /* extremely unlikely */
    else if(!subj)
        return ERROR_BADBUS;
    else if(!is_valid_action(valid_actions, action))
        return ERROR_BADACTION;

   if(!(result = polkit_authority_check_authorization_sync(auth, subj, action, NULL, prompt_flag, NULL, NULL)))
        return ERROR_GENERIC; /* TODO pass, check gerror and return more relevant error */

    authorized = polkit_authorization_result_get_is_authorized(result);
    challenge = polkit_authorization_result_get_is_challenge(result);

    /* free()'s before return */
    if(auth)
        g_object_unref(auth);
    if(subj)
        g_object_unref(subj);
    if(result)
        g_object_unref(result);

    if(authorized) {

        if(challenge)
            return AUTHORIZED_BY_PROMPT;
        
        return AUTHORIZED_NATIVELY;

    } else if(challenge)
        return UNAUTHORIZED_FAILED_PROMPT;

    return UNAUTHORIZED_NATIVELY;
}
