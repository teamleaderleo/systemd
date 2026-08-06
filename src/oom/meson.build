# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_OOMD') != 1
        subdir_done()
endif

systemd_oomd_sources = files(
        'oomd.c',
        'oomd-conf.c',
        'oomd-manager.c',
        'oomd-manager-bus.c',
)
systemd_oomd_export_sources = files(
        'oomd-managed-oom-message.c',
        'oomd-policy.c',
        'oomd-reporter-adapter.c',
        'oomd-reporter-lifecycle.c',
        'oomd-reporter-registry.c',
        'oomd-util.c',
)

executables += [
        libexec_template + {
                'name' : 'systemd-oomd',
                'dbus' : true,
                'sources' : systemd_oomd_sources,
                'export' : systemd_oomd_export_sources,
                'dependencies' : libatomic,
        },
        executable_template + {
                'name' : 'oomctl',
                'public' : true,
                'sources' : files('oomctl.c'),
        },
        test_template + {
                'sources' : files('test-oomd-policy.c'),
                'import' : ['systemd-oomd'],
                'dependencies' : libatomic,
        },
        test_template + {
                'sources' : files('test-oomd-reporter-lifecycle.c'),
                'import' : ['systemd-oomd'],
                'dependencies' : libatomic,
        },
        test_template + {
                'sources' : files('test-oomd-reporter-registry.c'),
                'import' : ['systemd-oomd'],
                'dependencies' : libatomic,
        },
        test_template + {
                'sources' : files('test-oomd-reporter-adapter.c'),
                'import' : ['systemd-oomd'],
                'dependencies' : libatomic,
        },
        test_template + {
                'sources' : files('test-oomd-reporter-adapter-reuse.c'),
                'import' : ['systemd-oomd'],
                'dependencies' : libatomic,
        },
        test_template + {
                'sources' : files('test-oomd-reporter-adapter-events.c'),
                'import' : ['systemd-oomd'],
                'dependencies' : libatomic,
        },
        test_template + {
                'sources' : files('test-oomd-reporter-batch.c'),
                'import' : ['systemd-oomd'],
                'dependencies' : libatomic,
        },
        test_template + {
                'sources' : files('test-oomd-managed-oom-message.c'),
                'import' : ['systemd-oomd'],
                'dependencies' : libatomic,
        },
        test_template + {
                'sources' : files('test-oomd-util.c'),
                'import' : ['systemd-oomd'],
                'dependencies' : libatomic,
        },
]

install_data('org.freedesktop.oom1.conf',
                install_dir : dbuspolicydir)

install_data('org.freedesktop.oom1.service',
                install_dir : dbussystemservicedir)

if install_sysconfdir_samples
        install_data('oomd.conf',
                install_dir : pkgconfigfiledir)
endif
