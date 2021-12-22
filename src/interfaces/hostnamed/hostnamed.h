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

void hostnamed_mem_clean();

const gchar *our_get_pretty_hostname();

int up_apm_get_fd();

gboolean determine_chassis_and_icon();
gboolean up_native_get_sensordev(const char * id, struct sensordev * snsrdev);
gboolean up_native_is_laptop();
gboolean is_server(gchar *arch);
gboolean set_uname_properties();
gboolean set_names();
static gboolean is_valid_chassis_type(gchar *test);
static gchar *get_bsd_hostname(gchar *proposed_hostname);
static gchar *has_domain(const gchar *test);
