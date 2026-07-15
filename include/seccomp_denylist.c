// seccomp_denylist.c -- included inside seccomp_init()'s BPF array
// initializer.  The caller must have defined:
//   DENY(nr) -> expands to a jump-kill BPF instruction pair.
//
// Every entry is guarded by #ifdef on the SYS_* constant so that
// the file compiles on any architecture -- missing syscalls are
// simply skipped (they do not exist on that arch anyway).

// -- networking --------------------------------------
#ifdef SYS_socket
        DENY(SYS_socket),
#endif
#ifdef SYS_socketpair
        DENY(SYS_socketpair),
#endif
#ifdef SYS_bind
        DENY(SYS_bind),
#endif
#ifdef SYS_connect
        DENY(SYS_connect),
#endif
#ifdef SYS_listen
        DENY(SYS_listen),
#endif
#ifdef SYS_accept
        DENY(SYS_accept),
#endif
#ifdef SYS_accept4
        DENY(SYS_accept4),
#endif
#ifdef SYS_getpeername
        DENY(SYS_getpeername),
#endif
#ifdef SYS_getsockname
        DENY(SYS_getsockname),
#endif
#ifdef SYS_setsockopt
        DENY(SYS_setsockopt),
#endif
#ifdef SYS_getsockopt
        DENY(SYS_getsockopt),
#endif
#ifdef SYS_shutdown
        DENY(SYS_shutdown),
#endif
#ifdef SYS_sendto
        DENY(SYS_sendto),
#endif
#ifdef SYS_sendmsg
        DENY(SYS_sendmsg),
#endif
#ifdef SYS_sendmmsg
        DENY(SYS_sendmmsg),
#endif
#ifdef SYS_recvfrom
        DENY(SYS_recvfrom),
#endif
#ifdef SYS_recvmsg
        DENY(SYS_recvmsg),
#endif

// -- io_uring (bypass seccomp read/write paths) ------
#ifdef SYS_io_uring_setup
        DENY(SYS_io_uring_setup),
#endif
#ifdef SYS_io_uring_enter
        DENY(SYS_io_uring_enter),
#endif
#ifdef SYS_io_uring_register
        DENY(SYS_io_uring_register),
#endif

// -- kernel modules (rootkit) -------------------------
#ifdef SYS_init_module
        DENY(SYS_init_module),
#endif
#ifdef SYS_finit_module
        DENY(SYS_finit_module),
#endif
#ifdef SYS_delete_module
        DENY(SYS_delete_module),
#endif
#ifdef SYS_create_module
        DENY(SYS_create_module),
#endif
#ifdef SYS_query_module
        DENY(SYS_query_module),
#endif
#ifdef SYS_get_kernel_syms
        DENY(SYS_get_kernel_syms),
#endif

// -- kexec (hot-reboot into malicious kernel) ---------
#ifdef SYS_kexec_load
        DENY(SYS_kexec_load),
#endif
#ifdef SYS_kexec_file_load
        DENY(SYS_kexec_file_load),
#endif

// -- deprecated kernel interfaces ---------------------
#ifdef SYS_uselib
        DENY(SYS_uselib),
#endif
#ifdef SYS_nfsservctl
        DENY(SYS_nfsservctl),
#endif

// -- device-node creation -----------------------------
#ifdef SYS_mknod
        DENY(SYS_mknod),
#endif
#ifdef SYS_mknodat
        DENY(SYS_mknodat),
#endif

// -- filesystem escape (CAP_SYS_ADMIN would permit) ----
#ifdef SYS_pivot_root
        DENY(SYS_pivot_root),
#endif

// -- information leaks ---------------------------------
#ifdef SYS_syslog
        DENY(SYS_syslog),
#endif
#ifdef SYS_lookup_dcookie
        DENY(SYS_lookup_dcookie),
#endif
#ifdef SYS_perf_event_open
        DENY(SYS_perf_event_open),
#endif

// -- process manipulation ------------------------------
#ifdef SYS_acct
        DENY(SYS_acct),
#endif
#ifdef SYS_personality
        DENY(SYS_personality),
#endif

// -- arch-specific hardware / VM escapes --------------
#ifdef SYS_vm86
        DENY(SYS_vm86),
#endif
#ifdef SYS_vm86old
        DENY(SYS_vm86old),
#endif
#ifdef SYS_s390_pci_mmio_write
        DENY(SYS_s390_pci_mmio_write),
#endif
#ifdef SYS_s390_pci_mmio_read
        DENY(SYS_s390_pci_mmio_read),
#endif
#ifdef SYS_pciconfig_read
        DENY(SYS_pciconfig_read),
#endif
#ifdef SYS_pciconfig_write
        DENY(SYS_pciconfig_write),
#endif
#ifdef SYS_iopl
        DENY(SYS_iopl),
#endif
#ifdef SYS_ioperm
        DENY(SYS_ioperm),
#endif

// -- swap control (memory exfiltration) ---------------
#ifdef SYS_swapoff
        DENY(SYS_swapoff),
#endif
#ifdef SYS_swapon
        DENY(SYS_swapon),
#endif

// -- seccomp / BPF (escape sandbox) -------------------
#ifdef SYS_seccomp
        DENY(SYS_seccomp),
#endif
#ifdef SYS_bpf
        DENY(SYS_bpf),
#endif

// -- process injection --------------------------------
#ifdef SYS_ptrace
        DENY(SYS_ptrace),
#endif
#ifdef SYS_process_vm_writev
        DENY(SYS_process_vm_writev),
#endif
#ifdef SYS_process_vm_readv
        DENY(SYS_process_vm_readv),
#endif

// -- system power -------------------------------------
#ifdef SYS_reboot
        DENY(SYS_reboot),
#endif
