/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Portions Copyright 2009 Apple Inc. All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_ZFS_CONTEXT_H
#define	_SYS_ZFS_CONTEXT_H

/* This is the zfs_context for the *userland* implementation libzpool! */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	_SYS_MUTEX_H
#define	_SYS_RWLOCK_H
#define	_SYS_CONDVAR_H
#define	_SYS_SYSTM_H
#define	_SYS_DEBUG_H
#define	_SYS_T_LOCK_H
#define	_SYS_VNODE_H
#define	_SYS_VFS_H
#define	_SYS_SUNDDI_H
#define	_SYS_CALLB_H

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#ifndef __APPLE__
#include <synch.h>
#endif
#include <thread.h>
#include <assert.h>
#include <alloca.h>
#ifndef __APPLE__
#include <umem.h>
#endif
#include <limits.h>
#include <atomic.h>
#include <dirent.h>
#include <time.h>
#ifndef __APPLE__
#include <sys/note.h>
#endif
#include <sys/types.h>
#include <sys/cred.h>
#include <sys/sysmacros.h>
#include <sys/bitmap.h>
#include <sys/resource.h>
#include <sys/byteorder.h>
#include <sys/list.h>
#include <sys/uio.h>
#include <sys/zfs_debug.h>
#include <sys/sdt.h>
#include <sys/kstat.h>
#ifndef __APPLE__
#include <sys/sysevent/eventdefs.h>
#endif

#ifdef __APPLE__
  /*
   * Apple's zfs_znode.c needs access to (a subset of) znode_t even
   * when build in userland mode.  To define that subset, we need
   * znode_phys_t (the whole thing) which is in zfs_znode.h.
   *
   * Note that almost all of zfs_znode.h is 'ifdef _KERNEL ...'
   * protected, so it will really only define znode_phys_t here.  The
   * subset of znode_t is define below.  Note that we can not easily
   * include the full zfs_znode.h (by temporarily defining _KERNEL),
   * because that would pull in a lot of vfs stuff not easily emulated
   * in userland.
   */
#endif

#ifdef __APPLE__	
#include <va_list.h>
#include <pthread.h>
#include <libkern/OSAtomic.h>
#include <libkern/OSTypes.h>
#include <mach/mach_time.h>
#include <mach/mach_init.h>
#include <sys/sysctl.h>
#include <sys/fs/zfs_sysctl.h>
	
/*
 * Threads and locking. We use POSIX threads and functions.
 */ 
#define THR_BOUND     1
#define THR_DETACHED  2
	
#define USYNC_THREAD 0
	
#define thr_self()               pthread_self()
#define mutex_lock(l)            pthread_mutex_lock(l)
#define mutex_trylock(l)         pthread_mutex_trylock(l)
#define mutex_unlock(l)          pthread_mutex_unlock(l)
#define _mutex_destroy(l)        pthread_mutex_destroy(l)
#define _mutex_init(l,f,a)       pthread_mutex_init(l,NULL)
#define rwlock_init(l,f,a)       pthread_rwlock_init(l,NULL)
#define rwlock_destroy(l)        pthread_rwlock_destroy(l)
#define rw_rdlock(l)             pthread_rwlock_rdlock(l)
#define rw_wrlock(l)             pthread_rwlock_wrlock(l)
#define rw_tryrdlock(l)          pthread_rwlock_tryrdlock(l)
#define rw_trywrlock(l)          pthread_rwlock_trywrlock(l)
#define rw_unlock(l)             pthread_rwlock_unlock(l)
#define cond_init(l,f,a)         pthread_cond_init(l,NULL)
#define cond_destroy(l)          pthread_cond_destroy(l)
#define cond_wait(l,m)           pthread_cond_wait(l,m)
#define cond_signal(l)           pthread_cond_signal(l)
#define cond_broadcast(l)        pthread_cond_broadcast(l)
#define cond_timedwait(l,m,t)    pthread_cond_timedwait(l,m,t)
#define thr_join(t,d,s)          pthread_join(t,s)
#define thread_exit(r)			 pthread_exit(NULL)
	
typedef pthread_mutex_t mutex_t;
typedef pthread_rwlock_t rwlock_t;
typedef pthread_cond_t cond_t;
/* XXX/ztest: workaround for type conflict from including mach/mach_time.h */
//typedef pthread_t thread_t;
#define thread_t pthread_t

/* open-only modes */
#include  <sys/fcntl.h>
#define	FCREAT		O_CREAT
#define	FTRUNC		O_TRUNC

extern zfs_memory_stats_t zfs_footprint;
	
/* user / kernel address space type flags. borrowed from bsd/sys/uio.h */
enum uio_seg {
	UIO_USERSPACE       = 0,    /* kernel address is virtual,  to/from user virtual */
	UIO_SYSSPACE        = 2,    /* kernel address is virtual,  to/from system virtual */
	UIO_USERSPACE32     = 5,    /* kernel address is virtual,  to/from user 32-bit virtual */
	UIO_USERSPACE64     = 8,    /* kernel address is virtual,  to/from user 64-bit virtual */
	UIO_SYSSPACE32      = 11    /* deprecated */
};
	
#define ERESTART (-1)
	
typedef int cred_t;
#define kcred (cred_t *)NOCRED

/* Modified from atomic.h */
/* We need the userspace atomic operations. */
/*
 * Add delta to target
 */
#define atomic_add_32(addr, amt)	(void)OSAtomicAdd32(amt, (volatile int32_t *)addr)
#define atomic_add_64(addr, amt)	(void)OSAtomicAdd64(amt, (volatile int64_t *)addr)
#define atomic_inc_64(addr)			(void)OSAtomicIncrement64((volatile int64_t *)addr)
#define atomic_inc_32(addr)			(void)OSAtomicIncrement32((volatile int32_t *)addr)

extern SInt64 OSAddAtomic64_NV(SInt64 theAmount, volatile SInt64 *address);
#define atomic_add_64_nv(addr, amt)	(uint64_t)OSAddAtomic64_NV(amt, (volatile SInt64 *)addr)

extern uint64_t atomic_cas_64(volatile uint64_t *, uint64_t, uint64_t);
/*
 * logical OR bits with target
 */
#define atomic_or_8(addr, mask)		(void)OSBitOrAtomic8((UInt32)mask, (volatile UInt8 *)addr)

extern void *atomic_cas_ptr(volatile void *, void *, void *);

/*
 * Decrement target.
 */
#define atomic_dec_32(addr)	(void)OSAtomicDecrement32((volatile int32_t *)addr)
#define atomic_dec_64(addr)	(void)OSAtomicAdd64(-1, (volatile int64_t *)addr)

/* From OSAtomic.h */
extern UInt8	OSBitOrAtomic8(UInt32 mask, volatile UInt8 * address);

#if !defined(__i386__) && !defined(__x86_64__)
extern SInt64	OSAtomicAdd64(int64_t theAmount, volatile int64_t *address);
extern SInt64	OSAtomicIncrement64(volatile int64_t *address);
#endif	

	/* needed to emulate some atomic function not available in userspace. */
extern pthread_mutex_t zfs_global_atomic_mutex;

/* Constants for sysevents framework*/
#define ESC_ZFS_VDEV_CLEAR      "ESC_ZFS_vdev_clear"
#define ESC_ZFS_VDEV_REMOVE     "ESC_ZFS_vdev_remove"
#define ESC_ZFS_POOL_DESTROY    "ESC_ZFS_pool_destroy"
#define ESC_ZFS_RESILVER_FINISH "ESC_ZFS_resilver_finish"
#define ESC_ZFS_RESILVER_START "ESC_ZFS_resilver_start"
#define ESC_ZFS_VDEV_CHECK      "ESC_ZFS_vdev_check"
	
/*
 * Arrange that all stores issued before this point in the code reach
 * global visibility before any stores that follow; useful in producer
 * modules that update a data item, then set a flag that it is available.
 * The memory barrier guarantees that the available flag is not visible
 * earlier than the updated data, i.e. it imposes store ordering.
 */
extern void membar_producer(void);
	
/* file flags */
#define	FOFFMAX		0x2000	/* large file */

	
#define RLIM64_INFINITY     ((rlim64_t)-3)
	
#define open64 open
#define pread64 pread
#define pwrite64 pwrite
	
#define	enable_extended_FILE_stdio(fd, act)		(0)

typedef u_longlong_t	rlim64_t;

typedef struct timespec timestruc_t;
	
struct dk_callback {
	void (*dkc_callback)(void *dkc_cookie, int error);
	void *dkc_cookie;
};
	
static inline int thr_create(void *stack_base,
  size_t stack_size, void *(*start_func) (void*),
  void *arg, long flags, thread_t *new_thread_ID)
{
	assert(stack_base == NULL);
	assert(stack_size == 0);
	assert((flags & ~THR_BOUND & ~THR_DETACHED) == 0);
	
	int ret;
	pthread_attr_t attr;
	
	pthread_attr_init(&attr);
	
	if (flags & THR_DETACHED)
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	
	ret = pthread_create(new_thread_ID, &attr, start_func, arg);
	
	pthread_attr_destroy(&attr);
	
	return ret;
}

extern hrtime_t gethrtime(void);
/* XXX/ztest: old code -- remove
static inline hrtime_t gethrtime(void) {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (((u_int64_t)tv.tv_sec) << 32) | tv.tv_usec;
}
*/

#define debug_msg(a...)

#undef PAGE_SIZE
#define PAGESIZE     PAGE_SIZE
#define	PAGE_SIZE		(sysconf(_SC_PAGE_SIZE))

#define EBADE EBADMACHO	

#include <sys/disk.h>
#define DKIOCFLUSHWRITECACHE DKIOCSYNCHRONIZECACHE

#define kstat_create(a...) (NULL)
#define kstat_install(a...)
#define kstat_delete(a...)

/*
 * vnodes
 */
/* A subset of the kernel vnode structure. */ 
struct vnode {
	uint64_t	v_size;
	int		v_fd;
	char		*v_path;
};
#define vnode_t struct vnode

extern int vn_open(char *path, int x1, int oflags, int mode, vnode_t **vpp,
    int x2, int x3);
extern int vn_openat(char *path, int x1, int oflags, int mode, vnode_t **vpp,
#ifdef __APPLE__
    int x2, int x3, vnode_t *vp);
#else
    int x2, int x3, vnode_t *vp, int fd);
#endif
extern int vn_rdwr(int uio, vnode_t *vp, void *addr, ssize_t len,
    offset_t offset, int x1, int x2, rlim64_t x3, void *x4, ssize_t *residp);
extern void vn_close(vnode_t *vp);

#define getrootdir() (struct vnode *)0xabcd1234

struct _buf {
	vnode_t *	 _fd;
};
	
/* From user.h */
/*
 * VFS context structure (part of uthread)
 */
struct vfs_context {
	thread_t	vc_thread;		/* pointer to Mach thread */
};

typedef struct vfs_context * vfs_context_t;

/*
 * From sys/vnode.h
 *
 *  We need IO_APPEND, but for completeness I copied all IO_* defines -- BjoKaSH
 */
/*
 * Flags for ioflag.
 */
#define IO_UNIT         0x0001          /* do I/O as atomic unit */
#define IO_APPEND       0x0002          /* append write to end */
#define IO_SYNC         0x0004          /* do I/O synchronously */
#define IO_NODELOCKED   0x0008          /* underlying node already locked */
#define IO_NDELAY       0x0010          /* FNDELAY flag set in file table */
#define IO_NOZEROFILL   0x0020          /* F_SETSIZE fcntl uses to prevent zero filling */
#define IO_TAILZEROFILL 0x0040          /* zero fills at the tail of write */
#define IO_HEADZEROFILL 0x0080          /* zero fills at the head of write */
#define IO_NOZEROVALID  0x0100          /* do not zero fill if valid page */
#define IO_NOZERODIRTY  0x0200          /* do not zero fill if page is dirty */
#define IO_CLOSE        0x0400          /* I/O issued from close path */
#define IO_NOCACHE      0x0800          /* same effect as VNOCACHE_DATA, but only for this 1 I/O */
#define IO_RAOFF        0x1000          /* same effect as VRAOFF, but only for this 1 I/O */
#define IO_DEFWRITE     0x2000          /* defer write if vfs.defwrite is set */
#define IO_PASSIVE      0x4000          /* this I/O is marked as background I/O so it won't throttle Throttleable I/O */
#define IO_BACKGROUND IO_PASSIVE /* used for backward compatibility.  to be removed after IO_BACKGROUND is no longer
                                                                  * used by DiskImages in-kernel mode */
#define IO_NOAUTH       0x8000          /* No authorization checks. */



/* A subset of the kernel vnode_attr structure. */ 
struct vnode_attr {
	/* bitfields */
	uint64_t	va_supported;
	uint64_t	va_active;
	
	/*
	 * Control flags.  The low 16 bits are reserved for the
	 * ioflags being passed for truncation operations.
	 */
	int		va_vaflags;
	
	/* traditional stat(2) parameter fields */
	u_offset_t	va_data_size;	/* file size in bytes */
};

/*
 * Vnode attributes, new-style.
 *
 * The vnode_attr structure is used to transact attribute changes and queries
 * with the filesystem.
 *
 * Note that this structure may be extended, but existing fields must not move.
 */
#define VATTR_INIT(v)			do {(v)->va_supported = (v)->va_active = 0ll; (v)->va_vaflags = 0;} while(0)
#define VATTR_SET_ACTIVE(v, a)		((v)->va_active |= VNODE_ATTR_ ## a)
#define VATTR_IS_SUPPORTED(v, a)	(1)
#define VATTR_WANTED(v, a)		VATTR_SET_ACTIVE(v, a)

#define VNODE_ATTR_va_data_size		(1LL<< 4)	/* 00000010 */

vfs_context_t vfs_context_create(vfs_context_t ctx);
int vfs_context_rele(vfs_context_t ctx);

#define	vnode_getattr(vp, vap, co)	((vap)->va_data_size = (vp)->v_size, 0)
#define	vnode_close(vp, f, c)	0

struct vmem {
	int vm_quantum;
	int vm_qcache_max;
	int vm_cflags;
};
typedef struct vmem vmem_t;

/* We don't have umem on OS X, so we fake it. */
	
#define	UMEM_CACHE_NAMELEN	31

/* A workaround so that the umem_cache operations are simple implementations of malloc/free/etc, 
   with the object constructor/destructor allowing initialization/destruction of structures. */
   
typedef struct umem_cache {
	char		cache_name[UMEM_CACHE_NAMELEN + 1];
	size_t		cache_bufsize;		/* object size */
	int			(*cache_constructor)(void *, void *, int);
	void		(*cache_destructor)(void *, void *);
	void		*cache_private;		/* opaque arg to callbacks */
	int			cache_objcount;		/* number of object in cache. */
} umem_cache_t;

/* From umem.h */

extern void *umem_alloc(size_t size, int umflag);
extern void *umem_zalloc(size_t size, int umflag);
extern void umem_free(void * buf, size_t size);

#define	UMEM_DEFAULT	0x0000	/* normal -- may fail */
#define	UMEM_NOFAIL	0x0100	/* Never fails -- may call exit(2) */
#define	UMC_NODEBUG	0x00020000

typedef int umem_constructor_t(void *, void *, int);
typedef void umem_destructor_t(void *, void *);
typedef void umem_reclaim_t(void *);

typedef int umem_nofail_callback_t(void);
#define UMEM_CALLBACK_RETRY             0
#define UMEM_CALLBACK_EXIT(status)      (0x100 | ((status) & 0xFF))

extern void umem_nofail_callback(umem_nofail_callback_t *);

extern umem_cache_t *umem_cache_create(char *name, size_t bufsize,
    size_t align, umem_constructor_t *constructor, umem_destructor_t *destructor,
	umem_reclaim_t *reclaim, void *private, void *vmp, int cflags);
extern void umem_cache_destroy(umem_cache_t *cp);

extern void *umem_cache_alloc(umem_cache_t *cp, int);
extern void umem_cache_free(umem_cache_t *cp, void *);
	
#endif /* __APPLE__ */
	
	
/*
 * Debugging
 */

/*
 * Note that we are not using the debugging levels.
 */

#define	CE_CONT		0	/* continuation		*/
#define	CE_NOTE		1	/* notice		*/
#define	CE_WARN		2	/* warning		*/
#define	CE_PANIC	3	/* panic		*/
#define	CE_IGNORE	4	/* print nothing	*/

/*
 * ZFS debugging
 */

#ifdef ZFS_DEBUG
extern void dprintf_setup(int *argc, char **argv);
#endif /* ZFS_DEBUG */

extern void cmn_err(int, const char *, ...);
extern void vcmn_err(int, const char *, __va_list);
extern void panic(const char *, ...);
extern void vpanic(const char *, __va_list);

#ifdef __APPLE__
	
#define	verify(ex) (void)((ex) || \
(assert(ex), 0))
	
#else /* !__APPLE__ */

/* This definition is copied from assert.h. */
#if defined(__STDC__)
#if __STDC_VERSION__ - 0 >= 199901L
#define	verify(EX) (void)((EX) || \
	(__assert_c99(#EX, __FILE__, __LINE__, __func__), 0))
#else
#define	verify(EX) (void)((EX) || (__assert(#EX, __FILE__, __LINE__), 0))
#endif /* __STDC_VERSION__ - 0 >= 199901L */
#else
#define	verify(EX) (void)((EX) || (_assert("EX", __FILE__, __LINE__), 0))
#endif	/* __STDC__ */
#endif /* !__APPLE__ */


#define	VERIFY	verify
#define	ASSERT	assert

#ifdef __APPLE__
	
#define	VERIFY3_IMPL(LEFT, OP, RIGHT, TYPE) do { \
	const TYPE __left = (TYPE)(LEFT); \
	const TYPE __right = (TYPE)(RIGHT); \
	if (!(__left OP __right)) { \
		char *__buf = alloca(256); \
		(void) snprintf(__buf, 256, "%s %s %s (0x%llx %s 0x%llx)", \
			#LEFT, #OP, #RIGHT, \
			(u_longlong_t)__left, #OP, (u_longlong_t)__right); \
		fprintf (stderr, "%s:%u: failed assertion `%s'\n", __FILE__, __LINE__, __buf); \
		fflush (stderr); \
		abort (); \
	} \
} while (0)
	
#define _NOTE(x)

#else /* !__APPLE__ */
extern void __assert(const char *, const char *, int);

#ifdef lint
#define	VERIFY3_IMPL(x, y, z, t)	if (x == z) ((void)0)
#else
/* BEGIN CSTYLED */
#define	VERIFY3_IMPL(LEFT, OP, RIGHT, TYPE) do { \
	const TYPE __left = (TYPE)(LEFT); \
	const TYPE __right = (TYPE)(RIGHT); \
	if (!(__left OP __right)) { \
		char *__buf = alloca(256); \
		(void) snprintf(__buf, 256, "%s %s %s (0x%llx %s 0x%llx)", \
			#LEFT, #OP, #RIGHT, \
			(u_longlong_t)__left, #OP, (u_longlong_t)__right); \
		__assert(__buf, __FILE__, __LINE__); \
	} \
_NOTE(CONSTCOND) } while (0)
/* END CSTYLED */
#endif /* lint */
#endif /* !__APPLE__ */

#define	VERIFY3S(x, y, z)	VERIFY3_IMPL(x, y, z, int64_t)
#define	VERIFY3U(x, y, z)	VERIFY3_IMPL(x, y, z, uint64_t)
#define	VERIFY3P(x, y, z)	VERIFY3_IMPL(x, y, z, uintptr_t)

#ifdef NDEBUG
#define	ASSERT3S(x, y, z)	((void)0)
#define	ASSERT3U(x, y, z)	((void)0)
#define	ASSERT3P(x, y, z)	((void)0)
#else
#define	ASSERT3S(x, y, z)	VERIFY3S(x, y, z)
#define	ASSERT3U(x, y, z)	VERIFY3U(x, y, z)
#define	ASSERT3P(x, y, z)	VERIFY3P(x, y, z)
#endif

/*
 * DTrace SDT probes have different signatures in userland than they do in
 * kernel.  If they're being used in kernel code, re-define them out of
 * existence for their counterparts in libzpool.
 */
	
#ifdef __APPLE__
#undef	DTRACE_PROBE1
#define	DTRACE_PROBE1(a, b, c)	((void)0)
	
#undef	DTRACE_PROBE2
#define	DTRACE_PROBE2(a, b, c, d, e)	((void)0)
	
#undef	DTRACE_PROBE3
#define	DTRACE_PROBE3(a, b, c, d, e, f, g)	((void)0)

#else /* !__APPLE__ */
	
#ifdef DTRACE_PROBE1
#undef	DTRACE_PROBE1
#define	DTRACE_PROBE1(a, b, c)	((void)0)
#endif	/* DTRACE_PROBE1 */

#ifdef DTRACE_PROBE2
#undef	DTRACE_PROBE2
#define	DTRACE_PROBE2(a, b, c, d, e)	((void)0)
#endif	/* DTRACE_PROBE2 */

#ifdef DTRACE_PROBE3
#undef	DTRACE_PROBE3
#define	DTRACE_PROBE3(a, b, c, d, e, f, g)	((void)0)
#endif	/* DTRACE_PROBE3 */

#ifdef DTRACE_PROBE4
#undef	DTRACE_PROBE4
#define	DTRACE_PROBE4(a, b, c, d, e, f, g, h, i)	((void)0)
#endif	/* DTRACE_PROBE4 */

#endif /* !__APPLE__ */
	
	
/*
 * Threads
 */
#define	curthread	((void *)(uintptr_t)thr_self())

#ifndef __APPLE__
typedef struct kthread kthread_t;
#endif /* !__APPLE__ */
	
#define	thread_create(stk, stksize, func, arg, len, pp, state, pri)	\
	zk_thread_create(func, arg)
	
#ifndef __APPLE__
#define	thread_exit() thr_exit(0)
#endif /* !__APPLE__ */
	
extern kthread_t *zk_thread_create(void (*func)(), void *arg);

#define	issig(why)	(FALSE)
#define	ISSIG(thr, why)	(FALSE)

/*
 * Mutexes
 */
typedef struct kmutex {
	void		*m_owner;
	boolean_t	initialized;
	mutex_t		m_lock;
} kmutex_t;

#define	MUTEX_DEFAULT	USYNC_THREAD
#ifdef __APPLE__
extern int mutex_owned(kmutex_t *);
#define	MUTEX_HELD(x)		(mutex_owned(x))
#define	MUTEX_NOT_HELD(x)	(!mutex_owned(x))
#else /* __APPLE__ */
#undef MUTEX_HELD
#define	MUTEX_HELD(m) _mutex_held(&(m)->m_lock)

/*
 * Argh -- we have to get cheesy here because the kernel and userland
 * have different signatures for the same routine.
 */
extern int _mutex_init(mutex_t *mp, int type, void *arg);
extern int _mutex_destroy(mutex_t *mp);
#endif /* !__APPLE__ */

#define	mutex_init(mp, b, c, d)		zmutex_init((kmutex_t *)(mp))
#define	mutex_destroy(mp)		zmutex_destroy((kmutex_t *)(mp))

extern void zmutex_init(kmutex_t *mp);
extern void zmutex_destroy(kmutex_t *mp);
extern void mutex_enter(kmutex_t *mp);
extern void mutex_exit(kmutex_t *mp);
extern int mutex_tryenter(kmutex_t *mp);
extern void *mutex_owner(kmutex_t *mp);

/*
 * RW locks
 */
typedef struct krwlock {
	void		*rw_owner;
	boolean_t	initialized;
	rwlock_t	rw_lock;
#ifdef __APPLE__
	kmutex_t   mutex;
	int        reader_thr_count;
#endif
} krwlock_t;

typedef int krw_t;

#define	RW_READER	0
#define	RW_WRITER	1
#define	RW_DEFAULT	USYNC_THREAD

#ifdef __APPLE__

extern  int   rw_write_held(krwlock_t *);
extern  int   rw_lock_held(krwlock_t *);
#define	RW_WRITE_HELD(x)	(rw_write_held((x)))
#define	RW_LOCK_HELD(x)		(rw_lock_held((x)))
	
#else /* !__APPLE__ */
	
#undef RW_READ_HELD
#define	RW_READ_HELD(x)		_rw_read_held(&(x)->rw_lock)

#undef RW_WRITE_HELD
#define	RW_WRITE_HELD(x)	_rw_write_held(&(x)->rw_lock)

#endif /* !__APPLE__ */

extern void rw_init(krwlock_t *rwlp, char *name, int type, void *arg);
extern void rw_destroy(krwlock_t *rwlp);
extern void rw_enter(krwlock_t *rwlp, krw_t rw);
extern int rw_tryenter(krwlock_t *rwlp, krw_t rw);
extern int rw_tryupgrade(krwlock_t *rwlp);
extern void rw_exit(krwlock_t *rwlp);
#define	rw_downgrade(rwlp) do { } while (0)

#ifndef __APPLE__
extern uid_t crgetuid(cred_t *cr);
extern gid_t crgetgid(cred_t *cr);
extern int crgetngroups(cred_t *cr);
extern gid_t *crgetgroups(cred_t *cr);
#endif

/*
 * Condition variables
 */
typedef cond_t kcondvar_t;

#define	CV_DEFAULT	USYNC_THREAD

extern void cv_init(kcondvar_t *cv, char *name, int type, void *arg);
extern void cv_destroy(kcondvar_t *cv);
extern void cv_wait(kcondvar_t *cv, kmutex_t *mp);
extern clock_t cv_timedwait(kcondvar_t *cv, kmutex_t *mp, clock_t abstime);
extern void cv_signal(kcondvar_t *cv);
extern void cv_broadcast(kcondvar_t *cv);

#ifndef __APPLE__
/*
 * kstat creation, installation and deletion
 */
extern kstat_t *kstat_create(char *, int,
    char *, char *, uchar_t, ulong_t, uchar_t);
extern void kstat_install(kstat_t *);
extern void kstat_delete(kstat_t *);
#endif

/*
 * Kernel memory
 */
#define	KM_SLEEP		UMEM_NOFAIL
#define	KM_NOSLEEP		UMEM_DEFAULT
#define	KMC_NODEBUG		UMC_NODEBUG
#define	kmem_alloc(_s, _f)	umem_alloc(_s, _f)
#define	kmem_zalloc(_s, _f)	umem_zalloc(_s, _f)
#define	kmem_free(_b, _s)	umem_free(_b, _s)
#define	kmem_cache_create(_a, _b, _c, _d, _e, _f, _g, _h, _i) \
	umem_cache_create(_a, _b, _c, _d, _e, _f, _g, _h, _i)
#define	kmem_cache_destroy(_c)	umem_cache_destroy(_c)
#define	kmem_cache_alloc(_c, _f) umem_cache_alloc(_c, _f)
#define	kmem_cache_free(_c, _b)	umem_cache_free(_c, _b)
#define	kmem_debugging()	0
#define	kmem_cache_reap_now(c)

typedef umem_cache_t kmem_cache_t;

/*
 * Task queues
 */
typedef struct taskq taskq_t;
typedef uintptr_t taskqid_t;
typedef void (task_func_t)(void *);

#define	TASKQ_PREPOPULATE	0x0001
#define	TASKQ_CPR_SAFE		0x0002	/* Use CPR safe protocol */
#define	TASKQ_DYNAMIC		0x0004	/* Use dynamic thread scheduling */

#define	TQ_SLEEP	KM_SLEEP	/* Can block for memory */
#define	TQ_NOSLEEP	KM_NOSLEEP	/* cannot block for memory; may fail */
#define	TQ_NOQUEUE	0x02	/* Do not enqueue if can't dispatch */

extern taskq_t	*taskq_create(const char *, int, pri_t, int, int, uint_t);
extern taskqid_t taskq_dispatch(taskq_t *, task_func_t, void *, uint_t);
extern void	taskq_destroy(taskq_t *);
extern void	taskq_wait(taskq_t *);
extern int	taskq_member(taskq_t *, void *);

#ifndef __APPLE__
/*
 * vnodes
 */
typedef struct vnode {
	uint64_t	v_size;
	int		v_fd;
	char		*v_path;
} vnode_t;
#endif /* !__APPLE__ */


typedef struct vattr {
	uint_t		va_mask;	/* bit-mask of attributes */
	u_offset_t	va_size;	/* file size in bytes */
} vattr_t;


#define	AT_TYPE		0x0001
#define	AT_MODE		0x0002
#define	AT_UID		0x0004
#define	AT_GID		0x0008
#define	AT_FSID		0x0010
#define	AT_NODEID	0x0020
#define	AT_NLINK	0x0040
#define	AT_SIZE		0x0080
#define	AT_ATIME	0x0100
#define	AT_MTIME	0x0200
#define	AT_CTIME	0x0400
#define	AT_RDEV		0x0800
#define	AT_BLKSIZE	0x1000
#define	AT_NBLOCKS	0x2000
#define	AT_SEQ		0x8000

#define	CRCREAT		0

#define	VOP_CLOSE(vp, f, c, o, cr)	0
#define	VOP_PUTPAGE(vp, of, sz, fl, cr)	0
#define	VOP_GETATTR(vp, vap, fl, cr)	((vap)->va_size = (vp)->v_size, 0)

#define	VOP_FSYNC(vp, f, cr)	fsync((vp)->v_fd)

#define	VN_RELE(vp)	vn_close(vp)

#ifndef __APPLE__
extern int vn_open(char *path, int x1, int oflags, int mode, vnode_t **vpp,
    int x2, int x3);
extern int vn_openat(char *path, int x1, int oflags, int mode, vnode_t **vpp,
    int x2, int x3, vnode_t *vp);
extern int vn_rdwr(int uio, vnode_t *vp, void *addr, ssize_t len,
    offset_t offset, int x1, int x2, rlim64_t x3, void *x4, ssize_t *residp);
extern void vn_close(vnode_t *vp);
#endif /* !__APPLE__ */

#define	vn_remove(path, x1, x2)		remove(path)
#define	vn_rename(from, to, seg)	rename((from), (to))
#define	vn_is_readonly(vp)		B_FALSE

extern vnode_t *rootdir;

#ifdef __APPLE__
#include <sys/zfs_file.h>		/* for FREAD, FWRITE, etc */
#else
#include <sys/file.h>		/* for FREAD, FWRITE, etc */
#endif

/*
 * Random stuff
 */
#define	lbolt	(gethrtime() >> 23)
#define	lbolt64	(gethrtime() >> 23)
#define	hz	119	/* frequency when using gethrtime() >> 23 for lbolt */

extern void delay(clock_t ticks);

#define	gethrestime_sec() time(NULL)

#define	max_ncpus	64

#define	minclsyspri	60
#define	maxclsyspri	99

/*
 * On Mac OS X we don't yet have access to cpu_number on all platforms.
 *
 * So we currently don't support per processor transaction state.
 */
#ifdef __APPLE__
#define	CPU_SEQID	(0)
#else /* !__APPLE__ */
#define	CPU_SEQID	(thr_self() & (max_ncpus - 1))

#endif
/*#define	kcred		NULL*/
#define	CRED()		NULL

extern uint64_t physmem;

extern int highbit(ulong_t i);
extern int random_get_bytes(uint8_t *ptr, size_t len);
extern int random_get_pseudo_bytes(uint8_t *ptr, size_t len);

extern void kernel_init(int);
extern void kernel_fini(void);

struct spa;
extern void nicenum(uint64_t num, char *buf);
extern void show_pool_stats(struct spa *);

typedef struct callb_cpr {
	kmutex_t	*cc_lockp;
} callb_cpr_t;

#define	CALLB_CPR_INIT(cp, lockp, func, name)	{		\
	(cp)->cc_lockp = lockp;					\
}

#define	CALLB_CPR_SAFE_BEGIN(cp) {				\
	ASSERT(MUTEX_HELD((cp)->cc_lockp));			\
}

#define	CALLB_CPR_SAFE_END(cp, lockp) {				\
	ASSERT(MUTEX_HELD((cp)->cc_lockp));			\
}

#define	CALLB_CPR_EXIT(cp) {					\
	ASSERT(MUTEX_HELD((cp)->cc_lockp));			\
	mutex_exit((cp)->cc_lockp);				\
}

#define	zone_dataset_visible(x, y)	(1)
#define	INGLOBALZONE(z)			(1)

/*
 * Hostname information
 */
extern char hw_serial[];
extern int ddi_strtoul(const char *str, char **nptr, int base,
    unsigned long *result);

#ifndef __APPLE__
/* ZFS Boot Related stuff. */

struct _buf {
	intptr_t	_fd;
};
#endif

struct bootstat {
	uint64_t st_size;
};


extern struct _buf *kobj_open_file(char *name);
extern int kobj_read_file(struct _buf *file, char *buf, unsigned size,
    unsigned off);
extern void kobj_close_file(struct _buf *file);
extern int kobj_get_filesize(struct _buf *file, uint64_t *size);
extern int zfs_secpolicy_snapshot_perms(const char *name, cred_t *cr);
extern int zfs_secpolicy_rename_perms(const char *from, const char *to,
    cred_t *cr);
extern int zfs_secpolicy_destroy_perms(const char *name, cred_t *cr);

#define get_disk_size get_disk_size_libzpool

#ifndef __APPLE__
extern zoneid_t getzoneid(void);
	
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ZFS_CONTEXT_H */
