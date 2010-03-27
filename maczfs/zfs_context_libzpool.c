/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2010 Alex Blewitt.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/time.h>

#define _ZFS_CONTEXT_IMP

#include <sys/dbuf.h>
#include <sys/dmu.h>
#include <sys/spa.h>

/*
 * Arrange that all stores issued before this point in the code reach
 * global visibility before any stores that follow; useful in producer
 * modules that update a data item, then set a flag that it is available.
 * The memory barrier guarantees that the available flag is not visible
 * earlier than the updated data, i.e. it imposes store ordering.
 */
void
membar_producer(void)
{
#if defined (__ppc__) || defined (__ppc64__)
	__asm__ volatile("sync");
#elif defined (__i386__) || defined(__x86_64__)
	__asm__ volatile("sfence");
#elif defined (__arm__)
#if defined(_ARM_ARCH_6)
//	__asm__ volatile("dmb");
#endif
#else
#error architecture not supported
#endif
}

/*
 * gethrtime() provides high-resolution timestamps with machine-dependent origin.
 * Hence its primary use is to specify intervals.
 */

hrtime_t zfs_gettimeofday_nano(struct timeval *tv) {
	const long long mio = 1000000;
	hrtime_t res = tv->tv_sec * mio;
	res += tv->tv_usec;
	res *= 1000;
	return res;	
}

hrtime_t
gethrtime(void)
{
	static uint64_t start = 0;

	struct timeval tv;
	gettimeofday(&tv, 0);

	if (start == 0) {
		start = zfs_gettimeofday_nano(&tv);
		return 0;
	}

	return (zfs_gettimeofday_nano(&tv) - start);
}

void
gethrestime(struct timespec *ts)
{
	struct timeval tv;
	gettimeofday(&tv, 0);
	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = tv.tv_usec * 1000;
}


void log_message(const char *fmt, ...) {
	char msgbuffer[1024];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(msgbuffer, 1023, fmt, ap);
	va_end(ap);
}

int umem_nofail_default_callback(void) {
	return UMEM_CALLBACK_EXIT(255);
}

umem_nofail_callback_t *umem_no_fail_callback_global_ptr = &umem_nofail_default_callback;

void umem_nofail_callback(umem_nofail_callback_t *cb_a) {
  umem_no_fail_callback_global_ptr = cb_a;
}

int umem_alloc_retry(umem_cache_t *cp, int umflag) {
	/* some "alloc" function ran out of memory. decide what to do: */

	if ( (umflag & UMEM_NOFAIL) == UMEM_NOFAIL) {
		int nofail_cb_res = umem_no_fail_callback_global_ptr();

		if (nofail_cb_res == UMEM_CALLBACK_RETRY)
			/* we are allowed to retry */
			return 1;

		if ( (nofail_cb_res & ~0xff) != UMEM_CALLBACK_EXIT(0) ) {
			/* callback returned unexpected value. */
			log_message("nofail callback returned %x\n", nofail_cb_res);
			nofail_cb_res = UMEM_CALLBACK_EXIT(255);
		}

		exit(nofail_cb_res & 0xff);
		/*NOTREACHED*/
	}

	/* allocation was allowed to fail. */
	return 0;
}


/* umem_alloc(size_t size, int flags) */
void *umem_alloc(size_t size, int _) 
{
	return malloc(size);
}

/* umem_free(void *mem, size_t size_of_object_freed) */
void umem_free(void *mem, size_t _)
{
	free(mem);
}

/* umem_zalloc(size_t size, int flags) */
void *umem_zalloc(size_t size, int _) 
{
	void *p = malloc(size);
	bzero(p, size);
	return p;
}

umem_cache_t *
umem_cache_create(
        char *name,             /* descriptive name for this cache */
        size_t bufsize,         /* size of the objects it manages */
        size_t align,           /* required object alignment */
        umem_constructor_t *constructor, /* object constructor */
        umem_destructor_t *destructor, /* object destructor */
        umem_reclaim_t *reclaim, /* memory reclaim callback */
        void *private,          /* pass-thru arg for constr/destr/reclaim */
        void *vmp,            /* vmem source for slab allocation */
        int cflags)             /* cache creation flags */
{
	/* in this simple implementation we ignore the vmem source.  all
	   memory comes from malloc().

	   In fact not even have a real cache here!
	*/

	umem_cache_t *cp = (umem_cache_t *)malloc(sizeof(umem_cache_t));

	if (0 == cp) {
		if (umem_alloc_retry(0, cflags)) {
			/* retry requested.  Do so, but don't allow another retry
			   to avoid infinit loops. */
			cp = umem_cache_create(name, bufsize, align,
								   constructor, destructor, reclaim, private,
								   vmp, cflags & ~UMEM_NOFAIL);
			if (cp)
				return cp;

			/* no luck again, and failing not allowed -> commit suicide. */
			exit(UMEM_CALLBACK_EXIT(255));

		} else {

			/* allocation was allowed to fail. */
			return 0;
		}
	}

	bzero(cp, sizeof(umem_cache_t));

	if (0 == name)
		name = "zfs anon umem cache";
	strncpy(cp->cache_name, name, UMEM_CACHE_NAMELEN);

	cp->cache_bufsize = bufsize;
	cp->cache_constructor = constructor;
	cp->cache_destructor = destructor;
	cp->cache_private = private;

	return cp;
}

void umem_cache_destroy(umem_cache_t *cp) {
	if (cp->cache_objcount != 0)
		log_message("Destroying umem cache with active objects!\n");

	free(cp);
}

void *umem_cache_alloc(umem_cache_t *cp, int umflag) {
	void *buf = malloc(cp->cache_bufsize);
	if (0 == buf) {
		/* check what to do in case of no memory */
		if (umem_alloc_retry(cp, umflag) == 1) {
			/* we are not allowed to fail and should retry.
			 Avoid infinit loop by allowing failure. */
			buf = umem_cache_alloc(cp, umflag & ~UMEM_NOFAIL);
			if (0 == buf) {
				/* no luck & failure not allowed -> commit suicide */
				exit(UMEM_CALLBACK_EXIT(255));
			}

		}
		/* reached if (1) got our memory, or (2) ran out of memory and
		   were allowed to fail. */
		return buf;
	}

	if (cp->cache_constructor)
		cp->cache_constructor(buf, cp->cache_private, UMEM_DEFAULT);
	cp->cache_objcount++;
	return buf;
}

void umem_cache_free(umem_cache_t *cp, void *buf) {
	if (cp->cache_destructor)
		cp->cache_destructor(buf, cp->cache_private);

	free(buf);
	cp->cache_objcount--;
}


/*
 * MISCELLANEOUS WRAPPERS
 */
#if 0
int
uio_move(caddr_t cp, int n, int rw_flag, struct uio *uio)
{
	uio_setrw(uio, rw_flag);
	return uiomove(cp, n, uio);
}
#endif

void
dmu_buf_will_dirty(dmu_buf_t *db, dmu_tx_t *tx)
{
	dbuf_will_dirty((dmu_buf_impl_t *)db, tx);
}

void
dmu_buf_fill_done(dmu_buf_t *db, dmu_tx_t *tx)
{
	dbuf_fill_done((dmu_buf_impl_t *)db, tx);
}

void
dmu_buf_add_ref(dmu_buf_t *db, void* tag)
{
	dbuf_add_ref((dmu_buf_impl_t *)db, tag);
}

void
dmu_buf_rele(dmu_buf_t *db, void *tag)
{
	dbuf_rele((dmu_buf_impl_t *)db, tag);
}

uint64_t
dmu_buf_refcount(dmu_buf_t *db)
{
	return dbuf_refcount((dmu_buf_impl_t *)db);
}



/*
 * MUTEX LOCKS
 */

#if 0
/* most of this is now in kernel.c */

void
zmutex_init(kmutex_t *mp)
{
	pthread_mutex_init(&mp->m_lock, 0);
	mp->initialized = TRUE;
	mp->m_owner = NULL;
}

void
zmutex_destroy(kmutex_t *mp)
{
	pthread_mutex_destroy(&mp->m_lock);
}

void
mutex_enter(kmutex_t *mp)
{
	if (mp->m_owner == thr_self())
		panic("mutex_enter: locking against myself!");
		
	mutex_lock(&mp->m_lock);
	mp->m_owner = thr_self();
}

void
mutex_exit(kmutex_t *mp)
{
	mp->m_owner = NULL;
	mutex_unlock(&mp->m_lock);
}

int
mutex_tryenter(kmutex_t *mp)
{
	int held;

	if (mp->m_owner == thr_self())
		panic("mutex_tryenter: locking against myself!");

	held = mutex_trylock(&mp->m_lock);
	if (held == 0)
		mp->m_owner = thr_self();
	 return (held);
}
#endif

int
mutex_owned(kmutex_t *mp)
{
	/* thr_self is def'ed to pthread_self() is zfs_context.h */
	return (mp->m_owner == thr_self());
}

#if 0
kthread_t *
mutex_owner(kmutex_t *mp)
{
	return (mp->m_owner);
}
#endif

/*
 * READER/WRITER LOCKS
 */
#if 0
/* most of this is now in kernel.c */
void
rw_init(krwlock_t *rwlp, char *name, int type, __unused void *arg)
{
	ASSERT(type != RW_DRIVER);

	lck_rw_init((lck_rw_t *)&rwlp->rw_lock[0],
	            zfs_rwlock_group, zfs_lock_attr);
	rwlp->rw_owner = NULL;
	rwlp->rw_readers = 0;
}

void
rw_destroy(krwlock_t *rwlp)
{
	lck_rw_destroy((lck_rw_t *)&rwlp->rw_lock[0], zfs_rwlock_group);
}

void
rw_enter(krwlock_t *rwlp, krw_t rw)
{
	if (rw == RW_READER) {
		lck_rw_lock_shared((lck_rw_t *)&rwlp->rw_lock[0]);
		OSIncrementAtomic((volatile SInt32 *)&rwlp->rw_readers);
	} else {
		if (rwlp->rw_owner == current_thread())
			panic("rw_enter: locking against myself!");
		lck_rw_lock_exclusive((lck_rw_t *)&rwlp->rw_lock[0]);
		rwlp->rw_owner = current_thread();
	}
}

/*
 * kernel private from osfmk/kern/locks.h
 */
extern boolean_t lck_rw_try_lock(lck_rw_t *lck, lck_rw_type_t lck_rw_type);


int
rw_tryenter(krwlock_t *rwlp, krw_t rw)
{
	int held = 0;

	if (rw == RW_READER) {
		held = lck_rw_try_lock((lck_rw_t *)&rwlp->rw_lock[0],
		                       LCK_RW_TYPE_SHARED);
		if (held)
			OSIncrementAtomic((volatile SInt32 *)&rwlp->rw_readers);
	} else {
		if (rwlp->rw_owner == current_thread())
			panic("rw_tryenter: locking against myself!");
		held = lck_rw_try_lock((lck_rw_t *)&rwlp->rw_lock[0],
		                       LCK_RW_TYPE_EXCLUSIVE);
		if (held)
			rwlp->rw_owner = current_thread();
	}

	return (held);
}

/*
 * Not supported in Mac OS X kernel.
 */
int
rw_tryupgrade(krwlock_t *rwlp)
{
	return (0);
}

void
rw_exit(krwlock_t *rwlp)
{
	if (rwlp->rw_owner == current_thread()) {
		rwlp->rw_owner = NULL;
		lck_rw_unlock_exclusive((lck_rw_t *)&rwlp->rw_lock[0]);
	} else {
		OSDecrementAtomic((volatile SInt32 *)&rwlp->rw_readers);
		lck_rw_unlock_shared((lck_rw_t *)&rwlp->rw_lock[0]);
	}
}

#endif

int
rw_lock_held(krwlock_t *rwlp)
{
	/*
	 * ### not sure about this one ###
	 */
	return (rwlp->rw_owner == thr_self() || rwlp->reader_thr_count > 0);
}

int
rw_write_held(krwlock_t *rwlp)
{
	return (rwlp->rw_owner == thr_self());
}

vfs_context_t vfs_context_create(vfs_context_t vctx) {

	if (vctx == 0)
		vctx = malloc(sizeof(struct vfs_context));

	vctx->vc_thread = thr_self();

	return vctx;
}

int vfs_context_rele(vfs_context_t vctx) {
	/* do nothing */
	return 0;
}

zfs_memory_stats_t zfs_footprint;

/* copied from usr/src/lib/libzfs/common/libzfs_util.c */
off_t
get_disk_size_libzpool(int fd)
{
        uint32_t blksize;
        uint64_t blkcnt;
        off_t d_size = 0;

        if (ioctl(fd, DKIOCGETBLOCKSIZE, &blksize) < 0) {
                return (-1);
        }
        if (ioctl(fd, DKIOCGETBLOCKCOUNT, &blkcnt) < 0) {
                return (-1);
        }
        
        d_size = (off_t)((uint64_t)blksize * blkcnt);
        return (d_size);
}

/*
 * Returns true if any vdevs in the hierarchy is a disk
 */
int
vdev_contains_disks(vdev_t *vd)
{
	/* ztest does not access full disks from userland. */
	return (0);
}


SInt64 OSAddAtomic64_NV(SInt64 theAmount, volatile SInt64 *address) {
	return OSAtomicAdd64(theAmount, address);
}

/* MacOSX has no userland 8-bit atomic function. so we should use a
   global mutext to lockout other threads while we manipulate the
   byte.  On the other hand, a simple byte or should be a single cpu
   instruction, making it atomic wrt. the same cpu. */

pthread_mutex_t zfs_global_atomic_mutex;

UInt8 OSBitOrAtomic8(UInt32 mask, volatile UInt8 *addr) {
	pthread_mutex_lock(&zfs_global_atomic_mutex);
	UInt8 old = *addr;
	*addr |= mask;
	pthread_mutex_unlock(&zfs_global_atomic_mutex);
	return old;
}

/*
 * This operation is not thread-safe and the user must
 * protect it my some other means.  The only known caller
 * is zfs_vnop_write() and the value is protected by the
 * znode's mutex.
 */
uint64_t
atomic_cas_64(volatile uint64_t *target, uint64_t cmp, uint64_t new)
{

	pthread_mutex_lock(&zfs_global_atomic_mutex);
	uint64_t old = *target;
	if (old == cmp)
		*target = new;
	pthread_mutex_unlock(&zfs_global_atomic_mutex);
	return (old);
}

void *
atomic_cas_ptr(volatile void *target, void *cmp, void *new)
{
	void *old = *(void **)target;
	
#ifdef __LP64__
	OSAtomicCompareAndSwapPtr(cmp, new, target);
#else
	OSAtomicCompareAndSwap32( (uint32_t)cmp, (uint32_t)new, (unsigned long *)target );
#endif
	return old;
}



/* End */
