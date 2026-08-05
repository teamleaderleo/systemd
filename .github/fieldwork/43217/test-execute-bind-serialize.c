/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cgroup.h"
#include "dynamic-user.h"
#include "execute-serialize.h"
#include "execute.h"
#include "fd-util.h"
#include "fdset.h"
#include "namespace.h"
#include "tests.h"

static void bind_mount_set(
                BindMount *m,
                const char *source,
                const char *destination,
                bool read_only,
                bool recursive,
                bool ignore_enoent) {

        assert(m);

        *m = (BindMount) {
                .source = ASSERT_PTR(strdup(source)),
                .destination = ASSERT_PTR(strdup(destination)),
                .read_only = read_only,
                .recursive = recursive,
                .ignore_enoent = ignore_enoent,
                .uid = UID_INVALID,
                .gid = GID_INVALID,
        };
}

static void init_serializable_context(ExecContext *c) {
        assert(c);

        exec_context_init(c);
        /* exec_context_init() deliberately leaves this tri-state enum invalid
         * until unit defaults are applied. A direct serialization fixture must
         * supply the same valid state used by the native serialization fuzz
         * harness before calling exec_serialize_invocation(). */
        c->private_var_tmp = PRIVATE_TMP_DISCONNECTED;
}

static void populate_context(ExecContext *c) {
        assert(c);

        init_serializable_context(c);
        c->bind_mounts = new0(BindMount, 8);
        ASSERT_NOT_NULL(c->bind_mounts);
        c->n_bind_mounts = 8;

        bind_mount_set(&c->bind_mounts[0],
                       "/tmp/plain-source",
                       "/tmp/plain-destination",
                       /* read_only= */ false,
                       /* recursive= */ true,
                       /* ignore_enoent= */ false);
        bind_mount_set(&c->bind_mounts[1],
                       "/tmp/source with space",
                       "/tmp/destination with space",
                       /* read_only= */ true,
                       /* recursive= */ false,
                       /* ignore_enoent= */ true);
        bind_mount_set(&c->bind_mounts[2],
                       "/tmp/source:with:colon",
                       "/tmp/destination:with:colon",
                       /* read_only= */ false,
                       /* recursive= */ false,
                       /* ignore_enoent= */ false);
        bind_mount_set(&c->bind_mounts[3],
                       "/tmp/source\"with\"quote",
                       "/tmp/destination\"with\"quote",
                       /* read_only= */ true,
                       /* recursive= */ true,
                       /* ignore_enoent= */ false);
        bind_mount_set(&c->bind_mounts[4],
                       "/tmp/same path",
                       "/tmp/same path",
                       /* read_only= */ false,
                       /* recursive= */ true,
                       /* ignore_enoent= */ true);
        bind_mount_set(&c->bind_mounts[5],
                       "/tmp/source\\with\\backslash",
                       "/tmp/destination\\with\\backslash",
                       /* read_only= */ true,
                       /* recursive= */ false,
                       /* ignore_enoent= */ false);
        bind_mount_set(&c->bind_mounts[6],
                       "/tmp/source\twith\ttab",
                       "/tmp/destination\twith\ttab",
                       /* read_only= */ false,
                       /* recursive= */ false,
                       /* ignore_enoent= */ true);
        bind_mount_set(&c->bind_mounts[7],
                       "/tmp/source\nwith\nnewline",
                       "/tmp/destination\nwith\nnewline",
                       /* read_only= */ true,
                       /* recursive= */ true,
                       /* ignore_enoent= */ false);
}

static void assert_context_equal(const ExecContext *a, const ExecContext *b) {
        assert(a);
        assert(b);

        ASSERT_EQ(a->n_bind_mounts, b->n_bind_mounts);
        for (size_t i = 0; i < a->n_bind_mounts; i++) {
                const BindMount *x = &a->bind_mounts[i];
                const BindMount *y = &b->bind_mounts[i];

                ASSERT_STREQ(x->source, y->source);
                ASSERT_STREQ(x->destination, y->destination);
                ASSERT_EQ(x->read_only, y->read_only);
                ASSERT_EQ(x->recursive, y->recursive);
                ASSERT_EQ(x->ignore_enoent, y->ignore_enoent);
        }
}

static void init_runtime(ExecRuntime *runtime, ExecSharedRuntime *shared, DynamicCreds *creds) {
        assert(runtime);
        assert(shared);
        assert(creds);

        *shared = (ExecSharedRuntime) {
                .userns_storage_socket = EBADF_PAIR,
                .netns_storage_socket = EBADF_PAIR,
                .ipcns_storage_socket = EBADF_PAIR,
        };
        *runtime = (ExecRuntime) {
                .ephemeral_storage_socket = EBADF_PAIR,
                .shared = shared,
                .dynamic_creds = creds,
        };
}

static void runtime_done(ExecRuntime *runtime, ExecSharedRuntime *shared, DynamicCreds *creds) {
        assert(runtime);
        assert(shared);
        assert(creds);

        exec_shared_runtime_done(shared);
        if (creds->group != creds->user)
                dynamic_user_free(creds->group);
        dynamic_user_free(creds->user);
        free(runtime->ephemeral_copy);
        safe_close_pair(runtime->ephemeral_storage_socket);
}

static char* serialize_context(const ExecContext *context) {
        _cleanup_(exec_params_deep_clear) ExecParameters params = EXEC_PARAMETERS_INIT(/* flags= */ 0);
        _cleanup_(cgroup_context_done) CGroupContext cgroup = {};
        _cleanup_fdset_free_ FDSet *fdset = NULL;
        DynamicCreds creds = {};
        ExecCommand command = {};
        ExecRuntime runtime = {};
        ExecSharedRuntime shared = {};
        char *serialized = NULL;
        size_t size = 0;
        FILE *f;

        cgroup_context_init(&cgroup);
        init_runtime(&runtime, &shared, &creds);
        ASSERT_NOT_NULL(fdset = fdset_new());
        ASSERT_NOT_NULL(f = open_memstream(&serialized, &size));

        ASSERT_OK(exec_serialize_invocation(f, fdset, context, &command, &params, &runtime, &cgroup));
        ASSERT_OK_ERRNO(fflush(f));
        ASSERT_OK_ERRNO(fclose(f));
        ASSERT_NOT_NULL(serialized);
        ASSERT_GT(size, 0U);

        exec_command_done_array(&command, 1);
        runtime_done(&runtime, &shared, &creds);
        return serialized;
}

static int try_deserialize_context(const char *serialized, ExecContext *context, long *offset) {
        _cleanup_(exec_params_deep_clear) ExecParameters params = EXEC_PARAMETERS_INIT(/* flags= */ 0);
        _cleanup_(cgroup_context_done) CGroupContext cgroup = {};
        _cleanup_fdset_free_ FDSet *fdset = NULL;
        DynamicCreds creds = {};
        ExecCommand command = {};
        ExecRuntime runtime = {};
        ExecSharedRuntime shared = {};
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(serialized);
        assert(context);
        assert(offset);

        init_serializable_context(context);
        cgroup_context_init(&cgroup);
        init_runtime(&runtime, &shared, &creds);
        ASSERT_NOT_NULL(fdset = fdset_new());
        ASSERT_NOT_NULL(f = fmemopen((void*) serialized, strlen(serialized), "r"));

        r = exec_deserialize_invocation(f, fdset, context, &command, &params, &runtime, &cgroup);
        *offset = ftell(f);

        exec_command_done_array(&command, 1);
        runtime_done(&runtime, &shared, &creds);
        return r;
}

static void diagnose_context_prefix(const char *serialized) {
        const char *context_end, *tail, *cursor;
        size_t tail_size, line = 0;

        assert(serialized);

        context_end = strstr(serialized, "\n\n");
        if (!context_end) {
                fputs("serialized invocation has no context delimiter\n", stderr);
                return;
        }

        tail = context_end + 2;
        tail_size = strlen(tail);
        cursor = serialized;

        while (cursor < context_end) {
                _cleanup_(exec_context_done) ExecContext probe_context = {};
                _cleanup_free_ char *probe = NULL;
                const char *line_end;
                size_t context_size, line_size;
                long offset;
                int r;

                line_end = memchr(cursor, '\n', (size_t) (context_end - cursor));
                if (!line_end) {
                        fputs("serialized context line lacks newline terminator\n", stderr);
                        return;
                }

                line++;
                line_size = (size_t) (line_end - cursor);
                context_size = (size_t) (line_end + 1 - serialized);
                probe = new(char, context_size + 1 + tail_size + 1);
                ASSERT_NOT_NULL(probe);
                memcpy(probe, serialized, context_size);
                probe[context_size] = '\n';
                memcpy(probe + context_size + 1, tail, tail_size + 1);

                r = try_deserialize_context(probe, &probe_context, &offset);
                if (r < 0 && offset >= 0 && (size_t) offset <= context_size + 1) {
                        fprintf(stderr,
                                "first context-local failure at line %zu: %.*s (status=%d, offset=%ld)\n",
                                line,
                                (int) line_size,
                                cursor,
                                r,
                                offset);
                        return;
                }

                cursor = line_end + 1;
        }

        fputs("every context prefix reached a later invocation section; no context-local line was isolated\n", stderr);
}

static void deserialize_context(const char *serialized, ExecContext *context) {
        long offset;
        int r;

        r = try_deserialize_context(serialized, context, &offset);
        if (r < 0) {
                fprintf(stderr, "complete invocation failed at stream offset %ld (status=%d)\n", offset, r);
                diagnose_context_prefix(serialized);
        }
        ASSERT_OK(r);
}

TEST(bind_mount_serialization_roundtrip) {
        _cleanup_(exec_context_done) ExecContext original = {};
        _cleanup_(exec_context_done) ExecContext restored = {};
        _cleanup_free_ char *serialized = NULL, *reserialized = NULL;

        populate_context(&original);
        serialized = serialize_context(&original);

        /* Flush the exact wire image before deserialization. A parser failure
         * must retain the line that triggered it instead of producing an empty
         * stdout artifact. */
        fputs(serialized, stdout);
        ASSERT_OK_ERRNO(fflush(stdout));

        ASSERT_NOT_NULL(strstr(serialized, "exec-context-bind-path="));
        ASSERT_NOT_NULL(strstr(serialized, "exec-context-bind-read-only-path="));
        ASSERT_NOT_NULL(strstr(serialized, "norbind"));
        ASSERT_NOT_NULL(strstr(serialized, "rbind"));
        ASSERT_NOT_NULL(strstr(serialized, "\\t"));
        ASSERT_NOT_NULL(strstr(serialized, "\\n"));

        deserialize_context(serialized, &restored);
        assert_context_equal(&original, &restored);

        reserialized = serialize_context(&restored);
        ASSERT_STREQ(serialized, reserialized);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
