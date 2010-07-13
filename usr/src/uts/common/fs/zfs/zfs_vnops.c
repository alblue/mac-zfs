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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Portions Copyright 2007-2008 Apple Inc. All rights reserved.
 * Use is subject to license terms.
 */

/* Portions Copyright 2007 Jeremy Teo */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/systm.h>
#ifdef __APPLE__
#include <sys/kernel.h>
#include <sys/fcntl.h>
#include <sys/vnode.h>
#include <sys/vnode_if.h>
#include <sys/stat.h>
#include <sys/ucred.h>
#include <sys/unistd.h>
#include <sys/xattr.h>
#include <sys/zfs_context.h>
#else
#include <sys/sysmacros.h>
#include <sys/resource.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/kmem.h>
#include <sys/taskq.h>
#include <sys/uio.h>
#include <sys/vmsystm.h>
#include <sys/atomic.h>
#include <sys/vm.h>
#include <vm/seg_vn.h>
#include <vm/pvn.h>
#include <vm/as.h>
#include <sys/mman.h>
#include <sys/pathname.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/unistd.h>
#endif /* __APPLE__ */
#include <sys/zfs_vfsops.h>
#include <sys/zfs_dir.h>
#include <sys/zfs_acl.h>
#include <sys/zfs_ioctl.h>
#include <sys/fs/zfs.h>
#include <sys/dmu.h>
#include <sys/spa.h>
#include <sys/txg.h>
#include <sys/dbuf.h>
#include <sys/zap.h>
#include <sys/dirent.h>
#ifdef __APPLE__
#include <sys/zfs_ctldir.h>
#include <sys/zfs_rlock.h>
#include <sys/unistd.h>
#include <sys/utfconv.h>
#include <sys/ubc.h>
#else
#include <sys/policy.h>
#include <sys/sunddi.h>
#include <sys/filio.h>
#include "fs/fs_subr.h"
#include <sys/zfs_ctldir.h>
#include <sys/dnlc.h>
#include <sys/zfs_rlock.h>
#endif /* __APPLE__ */

/*
 * Programming rules.
 *
 * Each vnode op performs some logical unit of work.  To do this, the ZPL must
 * properly lock its in-core state, create a DMU transaction, do the work,
 * record this work in the intent log (ZIL), commit the DMU transaction,
 * and wait the the intent log to commit if it's is a synchronous operation.
 * Morover, the vnode ops must work in both normal and log replay context.
 * The ordering of events is important to avoid deadlocks and references
 * to freed memory.  The example below illustrates the following Big Rules:
 *
 *  (1) A check must be made in each zfs thread for a mounted file system.
 *	This is done avoiding races using ZFS_ENTER(zfsvfs).
 *	A ZFS_EXIT(zfsvfs) is needed before all returns.
 *
 *  (2)	VN_RELE() should always be the last thing except for zil_commit()
 *	(if necessary) and ZFS_EXIT(). This is for 3 reasons:
 *	First, if it's the last reference, the vnode/znode
 *	can be freed, so the zp may point to freed memory.  Second, the last
 *	reference will call zfs_zinactive(), which may induce a lot of work --
 *	pushing cached pages (which acquires range locks) and syncing out
 *	cached atime changes.  Third, zfs_zinactive() may require a new tx,
 *	which could deadlock the system if you were already holding one.
 *
 *  (3)	All range locks must be grabbed before calling dmu_tx_assign(),
 *	as they can span dmu_tx_assign() calls.
 *
 *  (4)	Always pass zfsvfs->z_assign as the second argument to dmu_tx_assign().
 *	In normal operation, this will be TXG_NOWAIT.  During ZIL replay,
 *	it will be a specific txg.  Either way, dmu_tx_assign() never blocks.
 *	This is critical because we don't want to block while holding locks.
 *	Note, in particular, that if a lock is sometimes acquired before
 *	the tx assigns, and sometimes after (e.g. z_lock), then failing to
 *	use a non-blocking assign can deadlock the system.  The scenario:
 *
 *	Thread A has grabbed a lock before calling dmu_tx_assign().
 *	Thread B is in an already-assigned tx, and blocks for this lock.
 *	Thread A calls dmu_tx_assign(TXG_WAIT) and blocks in txg_wait_open()
 *	forever, because the previous txg can't quiesce until B's tx commits.
 *
 *	If dmu_tx_assign() returns ERESTART and zfsvfs->z_assign is TXG_NOWAIT,
 *	then drop all locks, call dmu_tx_wait(), and try again.
 *
 *  (5)	If the operation succeeded, generate the intent log entry for it
 *	before dropping locks.  This ensures that the ordering of events
 *	in the intent log matches the order in which they actually occurred.
 *
 *  (6)	At the end of each vnode op, the DMU tx must always commit,
 *	regardless of whether there were any errors.
 *
 *  (7)	After dropping all locks, invoke zil_commit(zilog, seq, foid)
 *	to ensure that synchronous semantics are provided when necessary.
 *
 * In general, this is how things should be ordered in each vnode op:
 *
 *	ZFS_ENTER(zfsvfs);		// exit if unmounted
 * top:
 *	zfs_dirent_lock(&dl, ...)	// lock directory entry (may VN_HOLD())
 *	rw_enter(...);			// grab any other locks you need
 *	tx = dmu_tx_create(...);	// get DMU tx
 *	dmu_tx_hold_*();		// hold each object you might modify
 *	error = dmu_tx_assign(tx, zfsvfs->z_assign);	// try to assign
 *	if (error) {
 *		rw_exit(...);		// drop locks
 *		zfs_dirent_unlock(dl);	// unlock directory entry
 *		VN_RELE(...);		// release held vnodes
 *		if (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT) {
 *			dmu_tx_wait(tx);
 *			dmu_tx_abort(tx);
 *			goto top;
 *		}
 *		dmu_tx_abort(tx);	// abort DMU tx
 *		ZFS_EXIT(zfsvfs);	// finished in zfs
 *		return (error);		// really out of space
 *	}
 *	error = do_real_work();		// do whatever this VOP does
 *	if (error == 0)
 *		zfs_log_*(...);		// on success, make ZIL entry
 *	dmu_tx_commit(tx);		// commit DMU tx -- error or not
 *	rw_exit(...);			// drop locks
 *	zfs_dirent_unlock(dl);		// unlock directory entry
 *	VN_RELE(...);			// release held vnodes
 *	zil_commit(zilog, seq, foid);	// synchronous when necessary
 *	ZFS_EXIT(zfsvfs);		// finished in zfs
 *	return (error);			// done, report error
 */

#ifdef __APPLE__
typedef int vcexcl_t;

enum vcexcl	{ NONEXCL, EXCL };


static int zfs_getsecattr(znode_t *, kauth_acl_t *, cred_t *);

static int zfs_setsecattr(znode_t *, kauth_acl_t, cred_t *);

int zfs_obtain_xattr(znode_t *, const char *, mode_t, cred_t *,
                     struct vnode **, int);

static int zfs_vnop_fsync(struct vnop_fsync_args *ap);
#endif /* __APPLE__ */

#ifdef __APPLE__
static int
zfs_vnop_open(struct vnop_open_args *ap)
{
	return (0);
}

static int
zfs_vnop_close(struct vnop_close_args *ap)
{
	return (0);
}
#endif /* __APPLE__ */

#ifndef __APPLE__
/* ARGSUSED */
static int
zfs_open(vnode_t **vpp, int flag, cred_t *cr)
{
	znode_t	*zp = VTOZ(*vpp);

	/* Keep a count of the synchronous opens in the znode */
	if (flag & (FSYNC | FDSYNC))
		atomic_inc_32(&zp->z_sync_cnt);
	return (0);
}
#endif /* !__APPLE__ */

#ifndef __APPLE__
/* ARGSUSED */
static int
zfs_close(vnode_t *vp, int flag, int count, offset_t offset, cred_t *cr)
{
	znode_t	*zp = VTOZ(vp);

	/* Decrement the synchronous opens in the znode */
	if ((flag & (FSYNC | FDSYNC)) && (count == 1))
		atomic_dec_32(&zp->z_sync_cnt);

	/*
	 * Clean up any locks held by this process on the vp.
	 */
	cleanlocks(vp, ddi_get_pid(), 0);
	cleanshares(vp, ddi_get_pid());

	return (0);
}
#endif /* !__APPLE__ */

#ifdef __APPLE__
/*
 * Spotlight specific fcntl()'s
 */
#define SPOTLIGHT_GET_MOUNT_TIME	(FCNTL_FS_SPECIFIC_BASE + 0x00002)
#define SPOTLIGHT_GET_UNMOUNT_TIME	(FCNTL_FS_SPECIFIC_BASE + 0x00003)
#endif /* __APPLE */

#ifdef __APPLE__
static int
zfs_vnop_ioctl(struct vnop_ioctl_args *ap)
{
	znode_t	*zp = VTOZ(ap->a_vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	user_addr_t useraddr = CAST_USER_ADDR_T(ap->a_data);
	int error;

	ZFS_ENTER(zfsvfs);

	switch (ap->a_command) {
	case F_FULLFSYNC: {
		struct vnop_fsync_args fsync_args;

		fsync_args.a_vp = ap->a_vp;
		fsync_args.a_waitfor = MNT_WAIT;
		fsync_args.a_context = ap->a_context;
		if ((error = zfs_vnop_fsync(&fsync_args)))
			break;

		if (zfsvfs->z_log != NULL)
			zil_commit(zfsvfs->z_log, UINT64_MAX, 0);
		else
			txg_wait_synced(dmu_objset_pool(zfsvfs->z_os), 0);
		break;
	}

	case SPOTLIGHT_GET_MOUNT_TIME:
		error = copyout(&zfsvfs->z_mount_time, useraddr,
		                sizeof (zfsvfs->z_mount_time));
		break;

	case SPOTLIGHT_GET_UNMOUNT_TIME:
		error = copyout(&zfsvfs->z_last_unmount_time, useraddr,
		                sizeof (zfsvfs->z_last_unmount_time));
		break;

	default:
		error = ENOTTY;
	}

	ZFS_EXIT(zfsvfs);
	return (error);
}
#endif /* __APPLE */

#ifndef __APPLE__ 
/*
 * Lseek support for finding holes (cmd == _FIO_SEEK_HOLE) and
 * data (cmd == _FIO_SEEK_DATA). "off" is an in/out parameter.
 */
static int
zfs_holey(vnode_t *vp, int cmd, offset_t *off)
{
	znode_t	*zp = VTOZ(vp);
	uint64_t noff = (uint64_t)*off; /* new offset */
	uint64_t file_sz;
	int error;
	boolean_t hole;

	file_sz = zp->z_phys->zp_size;
	if (noff >= file_sz)  {
		return (ENXIO);
	}

	if (cmd == _FIO_SEEK_HOLE)
		hole = B_TRUE;
	else
		hole = B_FALSE;

	error = dmu_offset_next(zp->z_zfsvfs->z_os, zp->z_id, hole, &noff);

	/* end of file? */
	if ((error == ESRCH) || (noff > file_sz)) {
		/*
		 * Handle the virtual hole at the end of file.
		 */
		if (hole) {
			*off = file_sz;
			return (0);
		}
		return (ENXIO);
	}

	if (noff < *off)
		return (error);
	*off = noff;
	return (error);
}

/* ARGSUSED */
static int
zfs_ioctl(vnode_t *vp, int com, intptr_t data, int flag, cred_t *cred,
    int *rvalp)
{
	offset_t off;
	int error;
	zfsvfs_t *zfsvfs;

	switch (com) {
	case _FIOFFS:
		return (zfs_sync(vp->v_vfsp, 0, cred));

		/*
		 * The following two ioctls are used by bfu.  Faking out,
		 * necessary to avoid bfu errors.
		 */
	case _FIOGDIO:
	case _FIOSDIO:
		return (0);

	case _FIO_SEEK_DATA:
	case _FIO_SEEK_HOLE:
		if (ddi_copyin((void *)data, &off, sizeof (off), flag))
			return (EFAULT);

		zfsvfs = VTOZ(vp)->z_zfsvfs;
		ZFS_ENTER(zfsvfs);

		/* offset parameter is in/out */
		error = zfs_holey(vp, com, &off);
		ZFS_EXIT(zfsvfs);
		if (error)
			return (error);
		if (ddi_copyout(&off, (void *)data, sizeof (off), flag))
			return (EFAULT);
		return (0);
	}
	return (ENOTTY);
}
#endif /* !__APPLE__ */

/*
 * When a file is memory mapped, we must keep the IO data synchronized
 * between the DMU cache and the memory mapped pages.  What this means:
 *
 * On Write:	If we find a memory mapped page, we write to *both*
 *		the page and the dmu buffer.
 *
 * NOTE: We will always "break up" the IO into PAGESIZE uiomoves when
 *	the file is memory mapped.
 */
static int
#ifdef __APPLE__
mappedwrite(struct vnode *vp, int nbytes, struct uio *uio, dmu_tx_t *tx)
#else
mappedwrite(vnode_t *vp, int nbytes, uio_t *uio, dmu_tx_t *tx)
#endif /* __APPLE__ */
{
	znode_t	*zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	int len = nbytes;
	int error = 0;
#ifdef __APPLE__
	vm_offset_t vaddr = 0;
	upl_t upl;
	upl_page_info_t *pl = NULL;
	off_t upl_start;
	int upl_size;
	int upl_page;
	off_t off;
#else
	int64_t start, off;
#endif /* __APPLE__ */

#ifdef __APPLE__
	upl_start = uio_offset(uio);
	off = upl_start & (PAGE_SIZE - 1);
	upl_start &= ~PAGE_MASK;
	upl_size = (off + nbytes + (PAGE_SIZE - 1)) & ~PAGE_MASK;

	/*
	 * Create a UPL for the current range and map its
	 * page list into the kernel virtual address space.
	 */
	if ( ubc_create_upl(vp, upl_start, upl_size, &upl, NULL,
	                    UPL_FILE_IO | UPL_SET_LITE) == KERN_SUCCESS ) {
		pl = ubc_upl_pageinfo(upl);
		ubc_upl_map(upl, &vaddr);
	}

	for (upl_page = 0; len > 0; ++upl_page) 
#else
	start = uio->uio_loffset;
	off = start & PAGEOFFSET;
	for (start &= PAGEMASK; len > 0; start += PAGESIZE) 
#endif /* __APPLE__ */
	{ // for loop
		uint64_t bytes = MIN(PAGESIZE - off, len);
#ifdef __APPLE__
		uint64_t woff = uio_offset(uio);
#else
		page_t *pp;
		uint64_t woff = uio->uio_loffset;
#endif /* __APPLE__ */

		/*
		 * We don't want a new page to "appear" in the middle of
		 * the file update (because it may not get the write
		 * update data), so we grab a lock to block
		 * zfs_getpage().
		 */
		rw_enter(&zp->z_map_lock, RW_WRITER);
#ifdef __APPLE__
		if (pl && upl_valid_page(pl, upl_page)) {
			rw_exit(&zp->z_map_lock);
			uio_setrw(uio, UIO_WRITE);
			error = uiomove((caddr_t)vaddr + off, bytes, uio);
			if (error == 0) {
				dmu_write(zfsvfs->z_os, zp->z_id,
				    woff, bytes, (caddr_t)vaddr + off, tx);
				/*
				 * We don't need a ubc_upl_commit_range()
				 * here since the dmu_write() effectively
				 * pushed this page to disk.
				 */
			} else {
				/*
				 * page is now in an unknown state so dump it.
				 */
				ubc_upl_abort_range(upl, upl_start, PAGESIZE,
				                    UPL_ABORT_DUMP_PAGES);
			}
		} // else below
#else
		if (pp = page_lookup(vp, start, SE_SHARED)) {
			caddr_t va;

			rw_exit(&zp->z_map_lock);
			va = ppmapin(pp, PROT_READ | PROT_WRITE, (caddr_t)-1L);
			error = uiomove(va+off, bytes, UIO_WRITE, uio);
			if (error == 0) {
				dmu_write(zfsvfs->z_os, zp->z_id,
				    woff, bytes, va+off, tx);
			}
			ppmapout(va);
			page_unlock(pp);
		} // else below
#endif /* __APPLE__ */
		else {
			error = dmu_write_uio(zfsvfs->z_os, zp->z_id,
			    uio, bytes, tx);
			rw_exit(&zp->z_map_lock);
		}
#ifdef __APPLE__
		vaddr += PAGE_SIZE;
		upl_start += PAGE_SIZE;
#endif /* __APPLE__ */
		len -= bytes;
		off = 0;
		if (error)
			break;
	}

#ifdef __APPLE__
	/*
	 * Unmap the page list and free the UPL.
	 */
	if (pl) {
		(void) ubc_upl_unmap(upl);
		/*
		 * We want to abort here since due to dmu_write()
		 * we effectively didn't dirty any pages.
		 */
		(void) ubc_upl_abort(upl, UPL_ABORT_FREE_ON_EMPTY);
	}
#endif /* __APPLE__ */

	return (error);
}

/*
 * When a file is memory mapped, we must keep the IO data synchronized
 * between the DMU cache and the memory mapped pages.  What this means:
 *
 * On Read:	We "read" preferentially from memory mapped pages,
 *		else we default from the dmu buffer.
 *
 * NOTE: We will always "break up" the IO into PAGESIZE uiomoves when
 *	the file is memory mapped.
 */
static int
#ifdef __APPLE__
mappedread(struct vnode *vp, int nbytes, struct uio *uio)
#else
mappedread(vnode_t *vp, int nbytes, uio_t *uio)
#endif /* __APPLE__ */
{
	znode_t *zp = VTOZ(vp);
	objset_t *os = zp->z_zfsvfs->z_os;
	int len = nbytes;
	int error = 0;
#ifdef __APPLE__
	vm_offset_t vaddr = 0;
	upl_t upl;
	upl_page_info_t *pl = NULL;
	off_t upl_start;
	int upl_size;
	int upl_page;
	off_t off;
#else
        int64_t start, off;
#endif /* __APPLE__ */

#ifdef __APPLE__
	upl_start = uio_offset(uio);
	off = upl_start & PAGE_MASK;
	upl_start &= ~PAGE_MASK;
	upl_size = (off + nbytes + (PAGE_SIZE - 1)) & ~PAGE_MASK;

	/*
	 * Create a UPL for the current range and map its
	 * page list into the kernel virtual address space.
	 */
	if ( ubc_create_upl(vp, upl_start, upl_size, &upl, NULL,
	                    UPL_FILE_IO | UPL_SET_LITE) == KERN_SUCCESS ) {
		pl = ubc_upl_pageinfo(upl);
		ubc_upl_map(upl, &vaddr);
	}

	for (upl_page = 0; len > 0; ++upl_page) 
#else
	start = uio->uio_loffset;
	off = start & PAGEOFFSET;
	for (start &= PAGEMASK; len > 0; start += PAGESIZE) 
#endif /* __APPLE__ */
	{ // for loop
		uint64_t bytes = MIN(PAGE_SIZE - off, len);
#ifdef __APPLE__
		if (pl && upl_valid_page(pl, upl_page)) {
			uio_setrw(uio, UIO_READ);
			error = uiomove((caddr_t)vaddr + off, bytes, uio);
		} else {
			error = dmu_read_uio(os, zp->z_id, uio, bytes);
		}
		vaddr += PAGE_SIZE;
#else
		page_t *pp;
		if (pp = page_lookup(vp, start, SE_SHARED)) {
			caddr_t va;

			va = ppmapin(pp, PROT_READ, (caddr_t)-1L);
			error = uiomove(va + off, bytes, UIO_READ, uio);
			ppmapout(va);
			page_unlock(pp);
		} else {
			error = dmu_read_uio(os, zp->z_id, uio, bytes);
		}
#endif /* __APPLE__ */
		len -= bytes;
		off = 0;
		if (error)
			break;
	}

#ifdef __APPLE__
	/*
	 * Unmap the page list and free the UPL.
	 */
	if (pl) {
		(void) ubc_upl_unmap(upl);
		(void) ubc_upl_abort(upl, UPL_ABORT_FREE_ON_EMPTY);
	}
#endif /* __APPLE__ */
	return (error);
}

#ifdef __APPLE__
uint_t zfs_read_chunk_size = MAX_UPL_TRANSFER * PAGE_SIZE; /* Tunable */
#else
offset_t zfs_read_chunk_size = 1024 * 1024; /* Tunable */
#endif /* __APPLE__ */

/*
 * Read bytes from specified file into supplied buffer.
 * MacOSX uses 'struct vnop read args', whereas OpenSolaris passes values as args
 *
 *	IN:	vp	- vnode of file to be read from.
 *		uio	- structure supplying read location, range info,
 *			  and return buffer.
 *		ioflag	- SYNC flags; used to provide FRSYNC semantics.
 *		cr	- credentials of caller.
 *
 *	OUT:	uio	- updated offset and range, buffer filled.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Side Effects:
 *	vp - atime updated if byte count > 0
 */
/* ARGSUSED */
static int
#ifdef __APPLE__
zfs_vnop_read(struct vnop_read_args *ap)
#else
zfs_read(vnode_t *vp, uio_t *uio, int ioflag, cred_t *cr, caller_context_t *ct)
#endif /* __APPLE__ */
{
#ifdef __APPLE__
        struct vnode    *vp = ap->a_vp;
        struct uio      *uio = ap->a_uio;
        int  		ioflag = ap->a_ioflag;
#endif
	znode_t		*zp = VTOZ(vp);
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	objset_t	*os = zfsvfs->z_os;
	ssize_t		n, nbytes;
	int		error = 0;
	rl_t		*rl;

	ZFS_ENTER(zfsvfs);

	/*
	 * Validate file offset
	 */
#ifdef __APPLE__
	if (uio_offset(uio) < (offset_t)0) 
#else
	if (uio->uio_loffset < (offset_t)0) 
#endif /* __APPLE__ */
	{
		ZFS_EXIT(zfsvfs);
		return (EINVAL);
	}

	/*
	 * Fasttrack empty reads
	 */
#ifdef __APPLE__
	if (uio_resid(uio) == 0) 
#else
	if (uio->uio_resid == 0) 
#endif /* __APPLE__ */
	{
		ZFS_EXIT(zfsvfs);
		return (0);
	}

	/*
	 * Note: In Mac OS X, mandatory lock checking occurs up in VFS layer.
	 * Check for mandatory locks
	 */
#ifndef __APPLE__
	if (MANDMODE((mode_t)zp->z_phys->zp_mode)) {
		if (error = chklock(vp, FREAD,
		    uio->uio_loffset, uio->uio_resid, uio->uio_fmode, ct)) {
			ZFS_EXIT(zfsvfs);
			return (error);
		}
	}
#endif /* !__APPLE__ */

	/*
	 * If we're in FRSYNC mode, sync out this znode before reading it.
	 */
	if (ioflag & FRSYNC)
		zil_commit(zfsvfs->z_log, zp->z_last_itx, zp->z_id);

	/*
	 * Lock the range against changes.
	 */
#ifdef __APPLE__
	rl = zfs_range_lock(zp, uio_offset(uio), uio_resid(uio), RL_READER);
#else
	rl = zfs_range_lock(zp, uio->uio_loffset, uio->uio_resid, RL_READER);
#endif /* __APPLE__ */

	/*
	 * If we are reading past end-of-file we can skip
	 * to the end; but we might still need to set atime.
	 */
#ifdef __APPLE__
	if (uio_offset(uio) >= zp->z_phys->zp_size) 
#else
	if (uio->uio_loffset >= zp->z_phys->zp_size) 
#endif /* __APPLE__ */
	{
		error = 0;
		goto out;
	}

#ifdef __APPLE__
	ASSERT(uio_offset(uio) < zp->z_phys->zp_size);
	n = MIN(uio_resid(uio), zp->z_phys->zp_size - uio_offset(uio));
#else
	ASSERT(uio->uio_loffset < zp->z_phys->zp_size);
	n = MIN(uio->uio_resid, zp->z_phys->zp_size - uio->uio_loffset);
#endif /* __APPLE__ */

	while (n > 0) {
#ifdef __APPLE__
		nbytes = MIN(n, zfs_read_chunk_size -
		    P2PHASE(uio_offset(uio), zfs_read_chunk_size));
#else
		nbytes = MIN(n, zfs_read_chunk_size -
		    P2PHASE(uio->uio_loffset, zfs_read_chunk_size));
#endif /* __APPLE__ */

		if (vn_has_cached_data(vp))
			error = mappedread(vp, nbytes, uio);
		else
			error = dmu_read_uio(os, zp->z_id, uio, nbytes);
		if (error)
			break;

		n -= nbytes;
	}

out:
	zfs_range_unlock(rl);

	ZFS_ACCESSTIME_STAMP(zfsvfs, zp);
	ZFS_EXIT(zfsvfs);
	return (error);
}

#ifndef __APPLE__
// Prefault-writing isn't supported get - zfs_prefault_write is a no-op in zfs_context
/*
 * Fault in the pages of the first n bytes specified by the uio structure.
 * 1 byte in each page is touched and the uio struct is unmodified.
 * Any error will exit this routine as this is only a best
 * attempt to get the pages resident. This is a copy of ufs_trans_touch().
 */
static void
zfs_prefault_write(ssize_t n, struct uio *uio)
{
	struct iovec *iov;
	ulong_t cnt, incr;
	caddr_t p;
	uint8_t tmp;

	iov = uio->uio_iov;

	while (n) {
		cnt = MIN(iov->iov_len, n);
		if (cnt == 0) {
			/* empty iov entry */
			iov++;
			continue;
		}
		n -= cnt;
		/*
		 * touch each page in this segment.
		 */
		p = iov->iov_base;
		while (cnt) {
			switch (uio->uio_segflg) {
			case UIO_USERSPACE:
			case UIO_USERISPACE:
				if (fuword8(p, &tmp))
					return;
				break;
			case UIO_SYSSPACE:
				if (kcopy(p, &tmp, 1))
					return;
				break;
			}
			incr = MIN(cnt, PAGESIZE);
			p += incr;
			cnt -= incr;
		}
		/*
		 * touch the last byte in case it straddles a page.
		 */
		p--;
		switch (uio->uio_segflg) {
		case UIO_USERSPACE:
		case UIO_USERISPACE:
			if (fuword8(p, &tmp))
				return;
			break;
		case UIO_SYSSPACE:
			if (kcopy(p, &tmp, 1))
				return;
			break;
		}
		iov++;
	}
}
#endif /* !__APPLE__ */

/*
 * Write the bytes to a file.
 *
 *	IN:	vp	- vnode of file to be written to.
 *		uio	- structure supplying write location, range info,
 *			  and data buffer.
 *		ioflag	- FAPPEND flag set if in append mode.
 *		cr	- credentials of caller.
 *
 *	OUT:	uio	- updated offset and range.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	vp - ctime|mtime updated if byte count > 0
 */
/* ARGSUSED */
static int
#ifdef __APPLE__
zfs_vnop_write(struct vnop_write_args *ap)
#else
zfs_write(vnode_t *vp, uio_t *uio, int ioflag, cred_t *cr, caller_context_t *ct)
#endif /* __APPLE__ */
{
#ifdef __APPLE__
	struct vnode	*vp = ap->a_vp;
	struct uio	*uio = ap->a_uio;
	int		ioflag = ap->a_ioflag;
	cred_t		*cr = (cred_t *)vfs_context_ucred(ap->a_context);
#endif /* __APPLE__ */
	znode_t		*zp = VTOZ(vp);
#ifdef __APPLE__
	rlim64_t	limit = MAXOFFSET_T;
	ssize_t		start_resid = uio_resid(uio);
#else
	rlim64_t	limit = uio->uio_llimit;
	ssize_t		start_resid = uio->uio_resid;
#endif /* __APPLE__ */
	ssize_t		tx_bytes = 0;
	uint64_t	end_size;
	dmu_tx_t	*tx;
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	zilog_t		*zilog = zfsvfs->z_log;
	offset_t	woff;
	ssize_t		n, nbytes;
	rl_t		*rl;
	int		max_blksz = zfsvfs->z_max_blksz;
	int		error = 0;

	/*
	 * Fasttrack empty write
	 */
	n = start_resid;
	if (n == 0)
		return (0);

	if (limit == RLIM64_INFINITY || limit > MAXOFFSET_T)
		limit = MAXOFFSET_T;

	ZFS_ENTER(zfsvfs);

	/*
	 * Pre-fault the pages to ensure slow (eg NFS) pages
	 * don't hold up txg.
	 */
	zfs_prefault_write(n, uio);

	/*
	 * If in append mode, set the io offset pointer to eof.
	 *
	 * Note: OSX uses IO_APPEND flag in order to indicate to 
	 * append to a file as opposed to Solaris which uses the
	 * FAPPEND ioflag
	 */
#ifdef __APPLE__
	if (ioflag & IO_APPEND) 
#else
	if (ioflag & FAPPEND) 
#endif /* __APPLE__ */
	{
		/*
		 * Range lock for a file append:
		 * The value for the start of range will be determined by
		 * zfs_range_lock() (to guarantee append semantics).
		 * If this write will cause the block size to increase,
		 * zfs_range_lock() will lock the entire file, so we must
		 * later reduce the range after we grow the block size.
		 */
		rl = zfs_range_lock(zp, 0, n, RL_APPEND);
		if (rl->r_len == UINT64_MAX) {
			/* overlocked, zp_size can't change */
#ifdef __APPLE__
			woff = zp->z_phys->zp_size;
#else
			woff = uio->uio_loffset = zp->z_phys->zp_size;
#endif /* __APPLE__ */
		} else {
#ifdef __APPLE__
			woff = rl->r_off;
#else
			woff = uio->uio_loffset = rl->r_off;
#endif /* __APPLE__ */
		}
#ifdef __APPLE__
		uio_setoffset(uio, woff);
#endif
	} else {
#ifdef __APPLE__
		woff = uio_offset(uio);
#else
		woff = uio->uio_loffset;
#endif /* __APPLE__ */
		/*
		 * Validate file offset
		 */
		if (woff < 0) {
			ZFS_EXIT(zfsvfs);
			return (EINVAL);
		}

		/*
		 * If we need to grow the block size then zfs_range_lock()
		 * will lock a wider range than we request here.
		 * Later after growing the block size we reduce the range.
		 */
		rl = zfs_range_lock(zp, woff, n, RL_WRITER);
	}

	if (woff >= limit) {
		zfs_range_unlock(rl);
		ZFS_EXIT(zfsvfs);
		return (EFBIG);
	}

	if ((woff + n) > limit || woff > (limit - n))
		n = limit - woff;

	/*
	 * Note: In Mac OS X, mandatory lock checking occurs up in VFS layer.
	 * Check for mandatory locks
	 */
#ifndef __APPLE__
	if (MANDMODE((mode_t)zp->z_phys->zp_mode) &&
	    (error = chklock(vp, FWRITE, woff, n, uio->uio_fmode, ct)) != 0) {
		zfs_range_unlock(rl);
		ZFS_EXIT(zfsvfs);
		return (error);
	}
#endif /* !__APPLE__ */
	end_size = MAX(zp->z_phys->zp_size, woff + n);

	/*
	 * Write the file in reasonable size chunks.  Each chunk is written
	 * in a separate transaction; this keeps the intent log records small
	 * and allows us to do more fine-grained space accounting.
	 */
	while (n > 0) {
		/*
		 * Start a transaction.
		 */
#ifdef __APPLE__
		woff = uio_offset(uio);
#else
		woff = uio->uio_loffset;
#endif /* __APPLE__ */
		tx = dmu_tx_create(zfsvfs->z_os);
		dmu_tx_hold_bonus(tx, zp->z_id);
		dmu_tx_hold_write(tx, zp->z_id, woff, MIN(n, max_blksz));
		error = dmu_tx_assign(tx, zfsvfs->z_assign);
		if (error) {
			if (error == ERESTART &&
			    zfsvfs->z_assign == TXG_NOWAIT) {
				dmu_tx_wait(tx);
				dmu_tx_abort(tx);
				continue;
			}
			dmu_tx_abort(tx);
			break;
		}

		/*
		 * If zfs_range_lock() over-locked we grow the blocksize
		 * and then reduce the lock range.  This will only happen
		 * on the first iteration since zfs_range_reduce() will
		 * shrink down r_len to the appropriate size.
		 */
		if (rl->r_len == UINT64_MAX) {
			uint64_t new_blksz;

			if (zp->z_blksz > max_blksz) {
				ASSERT(!ISP2(zp->z_blksz));
				new_blksz = MIN(end_size, SPA_MAXBLOCKSIZE);
			} else {
				new_blksz = MIN(end_size, max_blksz);
			}
			zfs_grow_blocksize(zp, new_blksz, tx);
			zfs_range_reduce(rl, woff, n);
		}

		/*
		 * XXX - should we really limit each write to z_max_blksz?
		 * Perhaps we should use SPA_MAXBLOCKSIZE chunks?
		 */
		nbytes = MIN(n, max_blksz - P2PHASE(woff, max_blksz));
		rw_enter(&zp->z_map_lock, RW_READER);

#ifdef __APPLE__
		tx_bytes = uio_resid(uio);
#else
		tx_bytes = uio->uio_resid;
#endif /* __APPLE__ */
		if (vn_has_cached_data(vp)) {
			rw_exit(&zp->z_map_lock);
			error = mappedwrite(vp, nbytes, uio, tx);
		} else {
			error = dmu_write_uio(zfsvfs->z_os, zp->z_id,
			    uio, nbytes, tx);
			rw_exit(&zp->z_map_lock);
		}
#ifdef __APPLE__
		tx_bytes -= uio_resid(uio);
#else
		tx_bytes -= uio->uio_resid;
#endif /* __APPLE__ */

		/*
		 * If we made no progress, we're done.  If we made even
		 * partial progress, update the znode and ZIL accordingly.
		 */
		if (tx_bytes == 0) {
			dmu_tx_commit(tx);
			ASSERT(error != 0);
			break;
		}

		/*
		 * Clear Set-UID/Set-GID bits on successful write if not
		 * privileged and at least one of the excute bits is set.
		 *
		 * It would be nice to to this after all writes have
		 * been done, but that would still expose the ISUID/ISGID
		 * to another app after the partial write is committed.
		 */
		mutex_enter(&zp->z_acl_lock);
		if ((zp->z_phys->zp_mode & (S_IXUSR | (S_IXUSR >> 3) |
		    (S_IXUSR >> 6))) != 0 &&
		    (zp->z_phys->zp_mode & (S_ISUID | S_ISGID)) != 0 &&
		    secpolicy_vnode_setid_retain(cr,
		    (zp->z_phys->zp_mode & S_ISUID) != 0 &&
		    zp->z_phys->zp_uid == 0) != 0) {
			zp->z_phys->zp_mode &= ~(S_ISUID | S_ISGID);
		}
		mutex_exit(&zp->z_acl_lock);

		/*
		 * Update time stamp.  NOTE: This marks the bonus buffer as
		 * dirty, so we don't have to do it again for zp_size.
		 */
		zfs_time_stamper(zp, CONTENT_MODIFIED, tx);

		/*
		 * Update the file size (zp_size) if it has changed;
		 * account for possible concurrent updates.
		 */
#ifdef __APPLE__
		while ((end_size = zp->z_phys->zp_size) < uio_offset(uio))
			(void) atomic_cas_64(&zp->z_phys->zp_size, end_size,
			    uio_offset(uio));
#else
		while ((end_size = zp->z_phys->zp_size) < uio->uio_loffset)
			(void) atomic_cas_64(&zp->z_phys->zp_size, end_size,
			    uio->uio_loffset);
#endif /* __APPLE__ */
		zfs_log_write(zilog, tx, TX_WRITE, zp, woff, tx_bytes, ioflag);
		dmu_tx_commit(tx);

		if (error != 0)
			break;
		ASSERT(tx_bytes == nbytes);
		n -= nbytes;
	}

	zfs_range_unlock(rl);

	/*
	 * If we're in replay mode, or we made no progress, return error.
	 * Otherwise, it's at least a partial write, so it's successful.
	 */
#ifdef __APPLE__
	if (zfsvfs->z_assign >= TXG_INITIAL || uio_resid(uio) == start_resid) {
#else
	if (zfsvfs->z_assign >= TXG_INITIAL || uio->uio_resid == start_resid) {
#endif /* __APPLE__ */
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	if (ioflag & (FSYNC | FDSYNC))
		zil_commit(zilog, zp->z_last_itx, zp->z_id);

#ifdef __APPLE__
	/* Mac OS X: pageout requires that the UBC file size be current. */
	if (tx_bytes != 0) {
		ubc_setsize(vp, zp->z_phys->zp_size);
	}
#endif /* __APPLE__ */

	ZFS_EXIT(zfsvfs);
	return (0);
}

static void
zfs_get_done(dmu_buf_t *db, void *vzgd)
{
	zgd_t *zgd = (zgd_t *)vzgd;
	rl_t *rl = zgd->zgd_rl;
// Issue 27
#ifdef __APPLE__
	struct vnode *vp = ZTOV(rl->r_zp);
#else
	vnode_t *vp = ZTOV(rl->r_zp);
#endif /* __APPLE__ */

	dmu_buf_rele(db, vzgd);
	zfs_range_unlock(rl);
	VN_RELE(vp);
	zil_add_vdev(zgd->zgd_zilog, DVA_GET_VDEV(BP_IDENTITY(zgd->zgd_bp)));
	kmem_free(zgd, sizeof (zgd_t));
}

/*
 * Get data to generate a TX_WRITE intent log record.
 */
int
zfs_get_data(void *arg, lr_write_t *lr, char *buf, zio_t *zio)
{
	zfsvfs_t *zfsvfs = arg;
	objset_t *os = zfsvfs->z_os;
	znode_t *zp;
	uint64_t off = lr->lr_offset;
	dmu_buf_t *db;
	rl_t *rl;
	zgd_t *zgd;
	int dlen = lr->lr_length;		/* length of user data */
	int error = 0;

	ASSERT(zio);
	ASSERT(dlen != 0);

	/*
	 * Nothing to do if the file has been removed
	 */
	if (zfs_zget(zfsvfs, lr->lr_foid, &zp) != 0)
		return (ENOENT);
	if (zp->z_unlinked) {
		VN_RELE(ZTOV(zp));
		return (ENOENT);
	}

	/*
	 * Write records come in two flavors: immediate and indirect.
	 * For small writes it's cheaper to store the data with the
	 * log record (immediate); for large writes it's cheaper to
	 * sync the data and get a pointer to it (indirect) so that
	 * we don't have to write the data twice.
	 */
	if (buf != NULL) { /* immediate write */
		rl = zfs_range_lock(zp, off, dlen, RL_READER);
		/* test for truncation needs to be done while range locked */
		if (off >= zp->z_phys->zp_size) {
			error = ENOENT;
			goto out;
		}
		VERIFY(0 == dmu_read(os, lr->lr_foid, off, dlen, buf));
	} else { /* indirect write */
		uint64_t boff; /* block starting offset */

		/*
		 * Have to lock the whole block to ensure when it's
		 * written out and it's checksum is being calculated
		 * that no one can change the data. We need to re-check
		 * blocksize after we get the lock in case it's changed!
		 */
		for (;;) {
			if (ISP2(zp->z_blksz)) {
				boff = P2ALIGN_TYPED(off, zp->z_blksz,
				    uint64_t);
			} else {
				boff = 0;
			}
			dlen = zp->z_blksz;
			rl = zfs_range_lock(zp, boff, dlen, RL_READER);
			if (zp->z_blksz == dlen)
				break;
			zfs_range_unlock(rl);
		}
		/* test for truncation needs to be done while range locked */
		if (off >= zp->z_phys->zp_size) {
			error = ENOENT;
			goto out;
		}
		zgd = (zgd_t *)kmem_alloc(sizeof (zgd_t), KM_SLEEP);
		zgd->zgd_rl = rl;
		zgd->zgd_zilog = zfsvfs->z_log;
		zgd->zgd_bp = &lr->lr_blkptr;
		VERIFY(0 == dmu_buf_hold(os, lr->lr_foid, boff, zgd, &db));
		ASSERT(boff == db->db_offset);
		lr->lr_blkoff = off - boff;
		error = dmu_sync(zio, db, &lr->lr_blkptr,
		    lr->lr_common.lrc_txg, zfs_get_done, zgd);
		ASSERT((error && error != EINPROGRESS) ||
		    lr->lr_length <= zp->z_blksz);
		if (error == 0) {
			zil_add_vdev(zfsvfs->z_log,
			    DVA_GET_VDEV(BP_IDENTITY(&lr->lr_blkptr)));
		}
		/*
		 * If we get EINPROGRESS, then we need to wait for a
		 * write IO initiated by dmu_sync() to complete before
		 * we can release this dbuf.  We will finish everything
		 * up in the zfs_get_done() callback.
		 */
		if (error == EINPROGRESS)
			return (0);
		dmu_buf_rele(db, zgd);
		kmem_free(zgd, sizeof (zgd_t));
	}
out:
	zfs_range_unlock(rl);
	VN_RELE(ZTOV(zp));
	return (error);
}

/*ARGSUSED*/
static int
#ifdef __APPLE__
zfs_vnop_access(struct vnop_access_args *ap)
#else
zfs_access(vnode_t *vp, int mode, int flags, cred_t *cr)
#endif /* __APPLE__ */
{
	znode_t *zp = VTOZ(ap->a_vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	int error;

#ifdef __APPLE__
	cred_t *cr;
	int mode = 0;
	int action = ap->a_action;

	cr = (cred_t *)vfs_context_ucred(ap->a_context);
	/* owner permissions */
	if (action & VREAD)
		mode |= S_IRUSR;
	if (action & VWRITE)
		mode |= S_IWUSR;
	if (action & VEXEC)
		mode |= S_IXUSR;

	/* group permissions */
	if (action & VREAD)
		mode |= S_IRGRP;
	if (action & VWRITE)
		mode |= S_IWGRP;
	if (action & VEXEC)
		mode |= S_IXGRP;

	/* world permissions */
	if (action & VREAD)
		mode |= S_IROTH;
	if (action & VWRITE)
		mode |= S_IWOTH;
	if (action & VEXEC)
		mode |= S_IXOTH;

#endif /* __APPLE__ */
	ZFS_ENTER(zfsvfs);
	error = zfs_zaccess_rwx(zp, mode, cr);
	ZFS_EXIT(zfsvfs);
	return (error);
}

/*
 * Lookup an entry in a directory, or an extended attribute directory.
 * If it exists, return a held vnode reference for it.
 *
 *	IN:	dvp	- vnode of directory to search.
 *		nm	- name of entry to lookup.
 *		pnp	- full pathname to lookup [UNUSED].
 *		flags	- LOOKUP_XATTR set if looking for an attribute.
 *		rdir	- root directory vnode [UNUSED].
 *		cr	- credentials of caller.
 *
 *	OUT:	vpp	- vnode of located entry, NULL if not found.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	NA
 */
/* ARGSUSED */
static int
#ifdef __APPLE__
zfs_vnop_lookup(struct vnop_lookup_args *ap)
#else
zfs_lookup(vnode_t *dvp, char *nm, vnode_t **vpp, struct pathname *pnp,
    int flags, vnode_t *rdir, cred_t *cr)
#endif /* __APPLE__ */
{
#ifdef __APPLE__
	struct vnode *dvp = ap->a_dvp;
	struct vnode **vpp = ap->a_vpp;
	struct componentname *cnp = ap->a_cnp;
	struct componentname cn;
	char smallname[64];
	char *filename = NULL;
	char * nm;
	// cred_t *cr = (cred_t *)vfs_context_ucred(ap->a_context);
#endif /* __APPLE__ */
	znode_t *zdp = VTOZ(dvp);
	zfsvfs_t *zfsvfs = zdp->z_zfsvfs;
	int	error;

	ZFS_ENTER(zfsvfs);

	*vpp = NULL;

#ifndef __APPLE__
	if (flags & LOOKUP_XATTR) {
		/*
		 * If the xattr property is off, refuse the lookup request.
		 */
		if (!(zfsvfs->z_vfs->vfs_flag & VFS_XATTR)) {
			ZFS_EXIT(zfsvfs);
			return (EINVAL);
		}

		/*
		 * We don't allow recursive attributes..
		 * Maybe someday we will.
		 */
		if (zdp->z_phys->zp_flags & ZFS_XATTR) {
			ZFS_EXIT(zfsvfs);
			return (EINVAL);
		}

		if (error = zfs_get_xattrdir(VTOZ(dvp), vpp, cr, flags)) {
			ZFS_EXIT(zfsvfs);
			return (error);
		}

		/*
		 * Do we have permission to get into attribute directory?
		 */

		if (error = zfs_zaccess(VTOZ(*vpp), ACE_EXECUTE, cr)) {
			VN_RELE(*vpp);
		}

		ZFS_EXIT(zfsvfs);
		return (error);
	}
#endif /* !__APPLE__ */

#ifdef __APPLE__
	if (!vnode_isdir(dvp)) 
#else
	if (dvp->v_type != VDIR) 
#endif /* __APPLE__ */
	{
		ZFS_EXIT(zfsvfs);
		return (ENOTDIR);
	}

#ifdef __APPLE__
	/*
	 * Copy the component name so we can null terminate it.
	 */
	if (cnp->cn_namelen < sizeof(smallname)) {
		filename = &smallname[0];
	} else {
		MALLOC(filename, char *, cnp->cn_namelen+1, M_TEMP, M_WAITOK);
		if (filename == NULL) {
			error = ENOMEM;
			goto out;
		}
	}	
	bcopy(cnp->cn_nameptr, filename, cnp->cn_namelen);
	filename[cnp->cn_namelen] = '\0';
	bcopy(cnp, &cn, sizeof (cn));
	cn.cn_nameptr = filename;
	cn.cn_namelen = strlen(filename);

	error = zfs_dirlook(zdp, &cn, vpp);

	if (filename != &smallname[0]) {
		FREE(filename, M_TEMP);
	}

	switch (cnp->cn_nameiop) {
	case CREATE:
	case RENAME:
		if ((cnp->cn_flags & ISLASTCN) && (error == ENOENT)) {
			error = EJUSTRETURN;
		}
		break;
	}
#else
	/*
	 * Check accessibility of directory.
	 */
	if (error = zfs_zaccess(zdp, ACE_EXECUTE, cr)) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	if ((error = zfs_dirlook(zdp, nm, vpp)) == 0) {

		/*
		 * Convert device special files
		 */
		if (IS_DEVVP(*vpp)) {
			vnode_t	*svp;

			svp = specvp(*vpp, (*vpp)->v_rdev, (*vpp)->v_type, cr);
			VN_RELE(*vpp);
			if (svp == NULL)
				error = ENOSYS;
			else
				*vpp = svp;
		}
	}
#endif /* __APPLE__ */
out:
	ZFS_EXIT(zfsvfs);
	return (error);
}

/*
 * Attempt to create a new entry in a directory.  If the entry
 * already exists, truncate the file if permissible, else return
 * an error.  Return the vp of the created or trunc'd file.
 *
 *	IN:	dvp	- vnode of directory to put new file entry in.
 *		name	- name of new file entry.
 *		vap	- attributes of new file.
 *		excl	- flag indicating exclusive or non-exclusive mode.
 *		mode	- mode to open file with.
 *		cr	- credentials of caller.
 *		flag	- large file flag [UNUSED].  *
 *	OUT:	vpp	- vnode of created or trunc'd entry.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	dvp - ctime|mtime updated if new entry created
 *	 vp - ctime|mtime always, atime if new
 */
/* ARGSUSED */
static int
#ifdef __APPLE__
zfs_vnop_create(struct vnop_create_args *ap)
#else
zfs_create(vnode_t *dvp, char *name, vattr_t *vap, vcexcl_t excl,
    int mode, vnode_t **vpp, cred_t *cr, int flag)
#endif
{
#ifdef __APPLE__
	struct vnode  *dvp = ap->a_dvp;
	struct vnode **vpp = ap->a_vpp;
	cred_t *cr = (cred_t *)vfs_context_ucred(ap->a_context);
	struct vnode_attr  *vap = ap->a_vap;
	struct componentname  *cnp = ap->a_cnp;
	vcexcl_t excl;
	int  mode;
#endif /* __APPLE__ */
        znode_t         *zp;
        znode_t         *dzp = VTOZ(dvp);
        zfsvfs_t        *zfsvfs = dzp->z_zfsvfs;
        zilog_t         *zilog = zfsvfs->z_log;
	objset_t	*os = zfsvfs->z_os;
	zfs_dirlock_t	*dl;
	dmu_tx_t	*tx;
	int		error;
	uint64_t	zoid;

	ZFS_ENTER(zfsvfs);

top:
	*vpp = NULL;

#ifdef __APPLE__
	excl = (vap->va_vaflags & VA_EXCLUSIVE) ? EXCL : NONEXCL;
	mode = MAKEIMODE(vap->va_type, vap->va_mode);

	if (cnp->cn_namelen >= ZAP_MAXNAMELEN) {
		ZFS_EXIT(zfsvfs);
		return (ENAMETOOLONG);
	}

	if (error = zfs_dirent_lock(&dl, dzp, cnp, &zp, 0)) {
		if (strcmp(cnp->cn_nameptr, "..") == 0)
			error = EISDIR;
		ZFS_EXIT(zfsvfs);
		return (error);
	}
#else
	if ((vap->va_mode & VSVTX) && secpolicy_vnode_stky_modify(cr))
		vap->va_mode &= ~VSVTX;

	if (*name == '\0') {
		/*
		 * Null component name refers to the directory itself.
		 */
		VN_HOLD(dvp);
		zp = dzp;
		dl = NULL;
		error = 0;
	} else {
		/* possible VN_HOLD(zp) */
		if (error = zfs_dirent_lock(&dl, dzp, name, &zp, 0)) {
			if (strcmp(name, "..") == 0)
				error = EISDIR;
			ZFS_EXIT(zfsvfs);
			return (error);
		}
	}
#endif /* __APPLE__ */

	zoid = zp ? zp->z_id : -1ULL;

	if (zp == NULL) {
		/*
		 * Create a new file object and update the directory
		 * to reference it.
		 */
#ifndef __APPLE__
		/* On Mac OS X, VFS performs the necessary access checks. */
		if (error = zfs_zaccess(dzp, ACE_ADD_FILE, cr)) {
			goto out;
		}
#endif /*!__APPLE__*/
		/*
		 * We only support the creation of regular files in
		 * extended attribute directories.
		 */
		if ((dzp->z_phys->zp_flags & ZFS_XATTR) &&
		    (vap->va_type != VREG)) {
			error = EINVAL;
			goto out;
		}

		tx = dmu_tx_create(os);
		dmu_tx_hold_bonus(tx, DMU_NEW_OBJECT);
		dmu_tx_hold_bonus(tx, dzp->z_id);
#ifdef __APPLE__
		dmu_tx_hold_zap(tx, dzp->z_id, TRUE, cnp->cn_nameptr);
#else
		dmu_tx_hold_zap(tx, dzp->z_id, TRUE, name);
#endif /* __APPLE__ */
		if (dzp->z_phys->zp_flags & ZFS_INHERIT_ACE)
			dmu_tx_hold_write(tx, DMU_NEW_OBJECT,
			    0, SPA_MAXBLOCKSIZE);
		error = dmu_tx_assign(tx, zfsvfs->z_assign);
		if (error) {
			zfs_dirent_unlock(dl);
			if (error == ERESTART &&
			    zfsvfs->z_assign == TXG_NOWAIT) {
				dmu_tx_wait(tx);
				dmu_tx_abort(tx);
				goto top;
			}
			dmu_tx_abort(tx);
			ZFS_EXIT(zfsvfs);
			return (error);
		}
		zfs_mknode(dzp, vap, &zoid, tx, cr, 0, &zp, 0);
		ASSERT(zp->z_id == zoid);
		(void) zfs_link_create(dl, zp, tx, ZNEW);
// XXX Why don't we just assign 'name' to 'cnp->cn_nameptr' somewhere above?
#ifdef __APPLE__
		zfs_log_create(zilog, tx, TX_CREATE, dzp, zp, cnp->cn_nameptr);
#else
		zfs_log_create(zilog, tx, TX_CREATE, dzp, zp, name);
#endif /* __APPLE__ */
		dmu_tx_commit(tx);

#ifdef __APPLE__
		/*
		 * OSX: Obtain and attach the vnode after committing the transaction
		 */
		zfs_attach_vnode(zp);
#endif /* __APPLE__ */
	} else {
		/*
		 * A directory entry already exists for this name.
		 */
		/*
		 * Can't truncate an existing file if in exclusive mode.
		 */
		if (excl == EXCL) {
			error = EEXIST;
			goto out;
		}
		/*
		 * Can't open a directory for writing.
		 */
#ifdef __APPLE__
		if (vnode_isdir(ZTOV(zp)) && (mode & S_IWRITE)) 
#else
		if ((ZTOV(zp)->v_type == VDIR) && (mode & S_IWRITE)) 
#endif /* __APPLE__ */
		{
			error = EISDIR;
			goto out;
		}
		/*
		 * Verify requested access to file.
		 */
#ifndef __APPLE__
		/* On Mac OS X, VFS performs the necessary access checks. */
		if (mode && (error = zfs_zaccess_rwx(zp, mode, cr))) {
			goto out;
		}
#endif /*!__APPLE__*/

		mutex_enter(&dzp->z_lock);
		dzp->z_seq++;
		mutex_exit(&dzp->z_lock);

		/*
		 * Truncate regular files if requested.
		 */
#ifdef __APPLE__
		if (vnode_isreg(ZTOV(zp)) &&
		    (zp->z_phys->zp_size != 0) &&
		    (vap->va_mask & AT_SIZE) && (vap->va_size == 0)) 
#else
		if ((ZTOV(zp)->v_type == VREG) &&
		    (vap->va_mask & AT_SIZE) && (vap->va_size == 0)) 
#endif /* __APPLE__ */
		{
			error = zfs_freesp(zp, 0, 0, mode, TRUE);
			if (error == ERESTART &&
			    zfsvfs->z_assign == TXG_NOWAIT) {
				/* NB: we already did dmu_tx_wait() */
				zfs_dirent_unlock(dl);
				VN_RELE(ZTOV(zp));
				goto top;
			}

#ifndef __APPLE__
			if (error == 0) {
				vnevent_create(ZTOV(zp));
			}
#endif /* !__APPLE__ */
		}
	}
out:

	if (dl)
		zfs_dirent_unlock(dl);

	if (error) {
		if (zp)
// Issue 34
#ifdef __APPLE__
			vnode_put(ZTOV(zp));
#else
			VN_RELE(ZTOV(zp));
#endif /* __APPLE__ */
	} else {
		*vpp = ZTOV(zp);
#ifndef __APPLE__
		/*
		 * If vnode is for a device return a specfs vnode instead.
		 */
		if (IS_DEVVP(*vpp)) {
			struct vnode *svp;

			svp = specvp(*vpp, (*vpp)->v_rdev, (*vpp)->v_type, cr);
			VN_RELE(*vpp);
			if (svp == NULL) {
				error = ENOSYS;
			}
			*vpp = svp;
		}
#endif /* __APPLE__ */
	}

	ZFS_EXIT(zfsvfs);
	return (error);
}

/*
 * Remove an entry from a directory.
 *
 *	IN:	dvp	- vnode of directory to remove entry from.
 *		name	- name of entry to remove.
 *		cr	- credentials of caller.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	dvp - ctime|mtime
 *	 vp - ctime (if nlink > 0)
 */
static int
#ifdef __APPLE__
zfs_vnop_remove(struct vnop_remove_args *ap)
#else
zfs_remove(vnode_t *dvp, char *name, cred_t *cr)
#endif /* __APPLE__ */
{
// Issue 28
#ifdef __APPLE__
	struct vnode  *dvp = ap->a_dvp;
	struct vnode  *vp;
	struct componentname  *cnp = ap->a_cnp;
	// cred_t  *cr = (cred_t *)vfs_context_ucred(ap->a_context);
#else
	vnode_t		*vp;
#endif /* __APPLE__ */
	znode_t		*dzp = VTOZ(dvp);
	znode_t		*zp;
	znode_t		*xzp = NULL;
	zfsvfs_t	*zfsvfs = dzp->z_zfsvfs;
	zilog_t		*zilog = zfsvfs->z_log;
	uint64_t	acl_obj, xattr_obj;
	zfs_dirlock_t	*dl;
	dmu_tx_t	*tx;
	boolean_t	may_delete_now = FALSE, delete_now = FALSE;
	boolean_t	unlinked;
	int		error;

	ZFS_ENTER(zfsvfs);

top:
	/*
	 * Attempt to lock directory; fail if entry doesn't exist.
	 */
#ifdef __APPLE__
	if (error = zfs_dirent_lock(&dl, dzp, cnp, &zp, ZEXISTS)) {
#else
	if (error = zfs_dirent_lock(&dl, dzp, name, &zp, ZEXISTS)) {
#endif /* __APPLE__ */
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	vp = ZTOV(zp);

#ifndef __APPLE__
	/* On Mac OS X, VFS performs the necessary access checks. */
	if (error = zfs_zaccess_delete(dzp, zp, cr)) {
		goto out;
	}
#endif /*!__APPLE__*/

	/*
	 * Need to use rmdir for removing directories.
	 */
#ifdef __APPLE__
	if (vnode_isdir(vp)) 
#else
	if (vp->v_type == VDIR) 
#endif /* __APPLE__ */
	{
		error = EPERM;
		goto out;
	}
#ifdef __APPLE__
	/* Remove our entry from the namei cache. */
	cache_purge(vp);
#else
	vnevent_remove(vp, dvp, name);

	dnlc_remove(dvp, name);
#endif /* __APPLE__ */
	
	/*
	 * On Mac OSX, we lose the option of having this optimization because 
	 * the VFS layer holds the last reference on the vnode whereas in 
	 * Solaris this code holds the last ref.  Hence, it's sketchy 
	 * business(not to mention hackish) to start deleting the znode 
	 * and clearing out the vnode when the VFS still has a reference 
	 * open on it, even though it's dropping it shortly.
	 */	
#ifndef __APPLE__
        mutex_enter(&vp->v_lock);
        may_delete_now = vp->v_count == 1 && !vn_has_cached_data(vp);
        mutex_exit(&vp->v_lock);
#endif

	/*
	 * We may delete the znode now, or we may put it in the unlinked set;
	 * it depends on whether we're the last link, and on whether there are
	 * other holds on the vnode.  So we dmu_tx_hold() the right things to
	 * allow for either case.
	 */
	tx = dmu_tx_create(zfsvfs->z_os);
#ifdef __APPLE__
	dmu_tx_hold_zap(tx, dzp->z_id, FALSE, cnp->cn_nameptr);
#else
	dmu_tx_hold_zap(tx, dzp->z_id, FALSE, name);
#endif /* __APPLE__ */
	dmu_tx_hold_bonus(tx, zp->z_id);
	if (may_delete_now)
		dmu_tx_hold_free(tx, zp->z_id, 0, DMU_OBJECT_END);

	/* are there any extended attributes? */
	if ((xattr_obj = zp->z_phys->zp_xattr) != 0) {
		/* XXX - do we need this if we are deleting? */
		dmu_tx_hold_bonus(tx, xattr_obj);
	}

	/* are there any additional acls */
	if ((acl_obj = zp->z_phys->zp_acl.z_acl_extern_obj) != 0 &&
	    may_delete_now)
		dmu_tx_hold_free(tx, acl_obj, 0, DMU_OBJECT_END);

	/* charge as an update -- would be nice not to charge at all */
	dmu_tx_hold_zap(tx, zfsvfs->z_unlinkedobj, FALSE, NULL);

	error = dmu_tx_assign(tx, zfsvfs->z_assign);
	if (error) {
		zfs_dirent_unlock(dl);
		VN_RELE(vp);
		if (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT) {
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	/*
	 * Remove the directory entry.
	 */
	error = zfs_link_destroy(dl, zp, tx, 0, &unlinked);

	if (error) {
		dmu_tx_commit(tx);
		goto out;
	}

	if (unlinked) {
#ifndef __APPLE__
		mutex_enter(&vp->v_lock);
#endif /* !__APPLE__ */
		delete_now = may_delete_now &&
#ifdef __APPLE__
			!vnode_isinuse(vp, 0) &&
#else
		    vp->v_count == 1 && !vn_has_cached_data(vp) &&
#endif /* __APPLE__ */
		    zp->z_phys->zp_xattr == xattr_obj &&
		    zp->z_phys->zp_acl.z_acl_extern_obj == acl_obj;
#ifndef __APPLE__
		mutex_exit(&vp->v_lock);
#endif /* !__APPLE__ */
	}

	if (delete_now) {
		if (zp->z_phys->zp_xattr) {
			error = zfs_zget(zfsvfs, zp->z_phys->zp_xattr, &xzp);
			ASSERT3U(error, ==, 0);
			ASSERT3U(xzp->z_phys->zp_links, ==, 2);
			dmu_buf_will_dirty(xzp->z_dbuf, tx);
			mutex_enter(&xzp->z_lock);
			xzp->z_unlinked = 1;
			xzp->z_phys->zp_links = 0;
			mutex_exit(&xzp->z_lock);
			zfs_unlinked_add(xzp, tx);
			zp->z_phys->zp_xattr = 0; /* probably unnecessary */
		}
#ifdef __APPLE__		
		/* Release the hold zfs_zget put on the vnode */ 
		vnode_put(vp);
		
		/* zfs_znode_delete clears out the dbufs AND 
		 * frees the entire znode as part of the dmu's 
		 * evict func during the sync thread 
		 */
		zfs_znode_delete(zp, tx);
	        vnode_removefsref(vp);
	        vnode_clearfsnode(vp);
		vnode_recycle(vp);
#else
		mutex_enter(&zp->z_lock);
		mutex_enter(&vp->v_lock);
		vp->v_count--;
		ASSERT3U(vp->v_count, ==, 0);
		mutex_exit(&vp->v_lock);
		mutex_exit(&zp->z_lock);
		zfs_znode_delete(zp, tx);
#endif /* __APPLE__ */
		VFS_RELE(zfsvfs->z_vfs);
	} else if (unlinked) {
		zfs_unlinked_add(zp, tx);
	}

#ifdef __APPLE__
	zfs_log_remove(zilog, tx, TX_REMOVE, dzp, cnp->cn_nameptr);
#else
	zfs_log_remove(zilog, tx, TX_REMOVE, dzp, name);
#endif /* __APPLE__ */
	dmu_tx_commit(tx);
out:
	zfs_dirent_unlock(dl);

	if (!delete_now) {
		VN_RELE(vp);
	} else if (xzp) {
		/* this rele delayed to prevent nesting transactions */
		VN_RELE(ZTOV(xzp));
	}

	ZFS_EXIT(zfsvfs);
	return (error);
}

/*
 * Create a new directory and insert it into dvp using the name
 * provided.  Return a pointer to the inserted directory.
 *
 *	IN:	dvp	- vnode of directory to add subdir to.
 *		dirname	- name of new directory.
 *		vap	- attributes of new directory.
 *		cr	- credentials of caller.
 *
 *	OUT:	vpp	- vnode of created directory.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	dvp - ctime|mtime updated
 *	 vp - ctime|mtime|atime updated
 */
static int
#ifdef __APPLE__
zfs_vnop_mkdir(struct vnop_mkdir_args *ap)
#else
zfs_mkdir(vnode_t *dvp, char *dirname, vattr_t *vap, vnode_t **vpp, cred_t *cr)
#endif /* __APPLE__ */
{
#ifdef __APPLE__
	struct vnode  *dvp = ap->a_dvp;
	struct vnode  **vpp = ap->a_vpp;
	struct vnode_attr  *vap = ap->a_vap;
	struct componentname  *cnp = ap->a_cnp;
	char * dirname = (char *)cnp->cn_nameptr;
	cred_t  *cr = (cred_t *)vfs_context_ucred(ap->a_context);
#endif /* __APPLE__ */
	znode_t		*dzp = VTOZ(dvp);
	znode_t		*zp;
	zfsvfs_t	*zfsvfs = dzp->z_zfsvfs;
	zilog_t		*zilog = zfsvfs->z_log;
	zfs_dirlock_t	*dl;
	uint64_t	zoid = 0;
	dmu_tx_t	*tx;
	int		error;

	ASSERT(vap->va_type == VDIR);

	ZFS_ENTER(zfsvfs);

	if (dzp->z_phys->zp_flags & ZFS_XATTR) {
		ZFS_EXIT(zfsvfs);
		return (EINVAL);
	}
#ifdef __APPLE__
	if (cnp->cn_namelen >= ZAP_MAXNAMELEN) {
		ZFS_EXIT(zfsvfs);
		return (ENAMETOOLONG);
	}
#endif /* __APPLE__ */
top:
	*vpp = NULL;

	/*
	 * First make sure the new directory doesn't exist.
	 */
#ifdef __APPLE__
	if (error = zfs_dirent_lock(&dl, dzp, cnp, &zp, ZNEW)) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

#else
	if (error = zfs_dirent_lock(&dl, dzp, dirname, &zp, ZNEW)) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	/* On Mac OS X, VFS performs the necessary access checks. */
	if (error = zfs_zaccess(dzp, ACE_ADD_SUBDIRECTORY, cr)) {
		zfs_dirent_unlock(dl);
		ZFS_EXIT(zfsvfs);
		return (error);
	}
#endif /*!__APPLE__*/

	/*
	 * Add a new entry to the directory.
	 */
	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_zap(tx, dzp->z_id, TRUE, dirname);
	dmu_tx_hold_zap(tx, DMU_NEW_OBJECT, FALSE, NULL);
	if (dzp->z_phys->zp_flags & ZFS_INHERIT_ACE)
		dmu_tx_hold_write(tx, DMU_NEW_OBJECT,
		    0, SPA_MAXBLOCKSIZE);
	error = dmu_tx_assign(tx, zfsvfs->z_assign);
	if (error) {
		zfs_dirent_unlock(dl);
		if (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT) {
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	/*
	 * Create new node.
	 */
	zfs_mknode(dzp, vap, &zoid, tx, cr, 0, &zp, 0);

	/*
	 * Now put new name in parent dir.
	 */
	(void) zfs_link_create(dl, zp, tx, ZNEW);

#ifndef __APPLE__
	*vpp = ZTOV(zp);
#endif /* !__APPLE__ */

	zfs_log_create(zilog, tx, TX_MKDIR, dzp, zp, dirname);
	dmu_tx_commit(tx);

#ifdef __APPLE__
        /*
         * Obtain and attach the vnode after committing the transaction
         */
        zfs_attach_vnode(zp);
        *vpp = ZTOV(zp);
#endif /* __APPLE__ */

	zfs_dirent_unlock(dl);

	ZFS_EXIT(zfsvfs);
	return (0);
}

/*
 * Remove a directory subdir entry.  If the current working
 * directory is the same as the subdir to be removed, the
 * remove will fail.
 *
 *	IN:	dvp	- vnode of directory to remove from.
 *		name	- name of directory to be removed.
 *		cwd	- vnode of current working directory.
 *		cr	- credentials of caller.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	dvp - ctime|mtime updated
 */
static int
#ifdef __APPLE__
zfs_vnop_rmdir(struct vnop_rmdir_args *ap)
#else
zfs_rmdir(vnode_t *dvp, char *name, vnode_t *cwd, cred_t *cr)
#endif /* __APPLE__ */
{
#ifdef __APPLE__
	struct vnode  *dvp = ap->a_dvp;
	struct vnode  *vp;
	struct componentname  *cnp = ap->a_cnp;
        char * name = (char *)cnp->cn_nameptr;
	// cred_t  *cr = (cred_t *)vfs_context_ucred(ap->a_context);
#else
	vnode_t		*vp;
#endif /* __APPLE__ */
	znode_t		*dzp = VTOZ(dvp);
	znode_t		*zp;
	zfsvfs_t	*zfsvfs = dzp->z_zfsvfs;
	zilog_t		*zilog = zfsvfs->z_log;
	zfs_dirlock_t	*dl;
	dmu_tx_t	*tx;
	int		error;

	ZFS_ENTER(zfsvfs);

top:
	zp = NULL;

	/*
	 * Attempt to lock directory; fail if entry doesn't exist.
	 */
#ifdef __APPLE__
	if (error = zfs_dirent_lock(&dl, dzp, cnp, &zp, ZEXISTS)) 
#else
	if (error = zfs_dirent_lock(&dl, dzp, name, &zp, ZEXISTS)) 
#endif
	{
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	vp = ZTOV(zp);

#ifndef __APPLE__
	/* On Mac OS X, VFS performs the necessary access checks. */
	if (error = zfs_zaccess_delete(dzp, zp, cr)) {
		goto out;
	}
#endif /*!__APPLE__*/

#ifdef __APPLE__
	if (!vnode_isdir(vp)) 
#else
	if (vp->v_type != VDIR) 
#endif /* __APPLE__ */
	{
		error = ENOTDIR;
		goto out;
	}

#ifdef __APPLE__
	/* Remove our entry from the namei cache. */
	cache_purge(vp);
#else
        if (vp == cwd) {
                error = EINVAL;
                goto out;
        }

        vnevent_rmdir(vp, dvp, name);
#endif /* __APPLE__ */


	/*
	 * Grab a lock on the directory to make sure that noone is
	 * trying to add (or lookup) entries while we are removing it.
	 */
	rw_enter(&zp->z_name_lock, RW_WRITER);

	/*
	 * Grab a lock on the parent pointer to make sure we play well
	 * with the treewalk and directory rename code.
	 */
	rw_enter(&zp->z_parent_lock, RW_WRITER);

	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_zap(tx, dzp->z_id, FALSE, name);
	dmu_tx_hold_bonus(tx, zp->z_id);
	dmu_tx_hold_zap(tx, zfsvfs->z_unlinkedobj, FALSE, NULL);
	error = dmu_tx_assign(tx, zfsvfs->z_assign);
	if (error) {
		rw_exit(&zp->z_parent_lock);
		rw_exit(&zp->z_name_lock);
		zfs_dirent_unlock(dl);
		VN_RELE(vp);
		if (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT) {
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	error = zfs_link_destroy(dl, zp, tx, 0, NULL);

	if (error == 0)
		zfs_log_remove(zilog, tx, TX_RMDIR, dzp, name);

	dmu_tx_commit(tx);

	rw_exit(&zp->z_parent_lock);
	rw_exit(&zp->z_name_lock);
out:
	zfs_dirent_unlock(dl);
// Issue 34
#ifdef __APPLE__
	vnode_put(vp);
#else
	VN_RELE(vp);
#endif /* __APPLE__ */

	ZFS_EXIT(zfsvfs);
	return (error);
}

/*
 * Read as many directory entries as will fit into the provided
 * buffer from the given directory cursor position (specified in
 * the uio structure.
 *
 *	IN:	vp	- vnode of directory to read.
 *		uio	- structure supplying read location, range info,
 *			  and return buffer.
 *		cr	- credentials of caller.
 *
 *	OUT:	uio	- updated offset and range, buffer filled.
 *		eofp	- set to true if end-of-file detected.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	vp - atime updated
 *
 * Note that the low 4 bits of the cookie returned by zap is always zero.
 * This allows us to use the low range for "special" directory entries:
 * We use 0 for '.', and 1 for '..'.  If this is the root of the filesystem,
 * we use the offset 2 for the '.zfs' directory.
 */
/* ARGSUSED */
static int
#ifdef __APPLE__
zfs_vnop_readdir(struct vnop_readdir_args *ap)
#else
zfs_readdir(vnode_t *vp, uio_t *uio, cred_t *cr, int *eofp)
#endif /* __APPLE__ */
{
#ifdef __APPLE__
	struct vnode	*vp = ap->a_vp;
	uio_t		uio = ap->a_uio;
	// cred_t		*cr = (cred_t *)vfs_context_ucred(ap->a_context);
	int		*eofp =  ap->a_eofflag;
	char		*bufptr;
#else
	iovec_t		*iovp;
	dirent64_t	*odp;
#endif /* __APPLE__ */
	znode_t		*zp = VTOZ(vp);	
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	objset_t	*os;
	caddr_t		outbuf;
	size_t		bufsize;
	zap_cursor_t	zc;
	zap_attribute_t	zap;
	uint_t		bytes_wanted;
	uint64_t	offset; /* must be unsigned; checks for < 1 */
	int		local_eof;
	int		outcount;
	int		error;
	uint8_t		prefetch;
#ifdef __APPLE__
	int		extended;
	int		numdirent;
	boolean_t	isdotdir = B_TRUE;
#endif /* __APPLE__ */

	ZFS_ENTER(zfsvfs);

	/*
	 * If we are not given an eof variable,
	 * use a local one.
	 */
	if (eofp == NULL)
		eofp = &local_eof;

#ifndef __APPLE__
	/*
	 * Check for valid iov_len.
	 */
	if (uio->uio_iov->iov_len <= 0) {
		ZFS_EXIT(zfsvfs);
		return (EINVAL);
	}
#endif

	/*
	 * Quit if directory has been removed (posix)
	 */
	if ((*eofp = zp->z_unlinked) != 0) {
		ZFS_EXIT(zfsvfs);
		return (0);
	}

	os = zfsvfs->z_os;
#ifdef __APPLE__
	offset = uio_offset(uio);
	extended = (ap->a_flags & VNODE_READDIR_EXTENDED);
	numdirent = 0;
#else
	offset = uio->uio_loffset;
#endif
	prefetch = zp->z_zn_prefetch;

	/*
	 * Initialize the iterator cursor.
	 */
	if (offset <= 3) {
		/*
		 * Start iteration from the beginning of the directory.
		 */
		zap_cursor_init(&zc, os, zp->z_id);
	} else {
		/*
		 * The offset is a serialized cursor.
		 */
		zap_cursor_init_serialized(&zc, os, zp->z_id, offset);
	}

	/*
	 * Get space to change directory entries into fs independent format.
	 */
#ifdef __APPLE__
	bytes_wanted = uio_curriovlen(uio);
	bufsize = (size_t)bytes_wanted;
	outbuf = kmem_alloc(bufsize, KM_SLEEP);
	bufptr = (char *)outbuf;
#else
	iovp = uio->uio_iov;
	bytes_wanted = iovp->iov_len;
	if (uio->uio_segflg != UIO_SYSSPACE || uio->uio_iovcnt != 1) {
		bufsize = bytes_wanted;
		outbuf = kmem_alloc(bufsize, KM_SLEEP);
		odp = (struct dirent64 *)outbuf;
	} else {
		bufsize = bytes_wanted;
		odp = (struct dirent64 *)iovp->iov_base;
	}
#endif /* __APPLE__ */

	/*
	 * Transform to file-system independent format
	 */
	outcount = 0;
	while (outcount < bytes_wanted) {
		ino64_t objnum;
		ushort_t reclen;
#ifdef __APPLE__
		uint64_t *next;
		uint8_t dtype;
		size_t namelen;
		int ascii;
#else
		off64_t *next;
#endif /* __APPLE__ */
		/*
		 * Special case `.', `..', and `.zfs'.
		 */
		if (offset == 0) {
			(void) strcpy(zap.za_name, ".");
			objnum = zp->z_id;
		} else if (offset == 1) {
			(void) strcpy(zap.za_name, "..");
			objnum = zp->z_phys->zp_parent;
		} else if (offset == 2 && zfs_show_ctldir(zp)) {
			(void) strcpy(zap.za_name, ZFS_CTLDIR_NAME);
			objnum = ZFSCTL_INO_ROOT;
		} else {
#ifdef __APPLE__
			/* This is not a special case directory */
			isdotdir = B_FALSE;
#endif /* __APPLE__ */

			/*
			 * Grab next entry.
			 */
			if (error = zap_cursor_retrieve(&zc, &zap)) {
				if ((*eofp = (error == ENOENT)) != 0)
					break;
				else
					goto update;
			}

			if (zap.za_integer_length != 8 ||
			    zap.za_num_integers != 1) {
				cmn_err(CE_WARN, "zap_readdir: bad directory "
				    "entry, obj = %lld, offset = %lld\n",
				    (u_longlong_t)zp->z_id,
				    (u_longlong_t)offset);
				error = ENXIO;
				goto update;
			}
			objnum = ZFS_DIRENT_OBJ(zap.za_first_integer);
			/*
			 * MacOS X can extract the object type here such as:
			 * uint8_t type = ZFS_DIRENT_TYPE(zap.za_first_integer);
			 */
		}
		
#ifdef __APPLE__
		/* Extract the object type for OSX to use */
		if (isdotdir)
			dtype = DT_DIR;
		else
			dtype = ZFS_DIRENT_TYPE(zap.za_first_integer);

		/*
		 * Check if name will fit.
		 *
		 * Note: non-ascii names may expand (up to 3x) when converted to NFD
		 */
		namelen = strlen(zap.za_name);
		ascii = is_ascii_str(zap.za_name);
		if (!ascii)
			namelen = MIN(extended ? MAXPATHLEN-1 : MAXNAMLEN, namelen * 3);

		reclen = DIRENT_RECLEN(namelen, extended);
#else
		reclen = DIRENT64_RECLEN(strlen(zap.za_name));
#endif

		/*
		 * Will this entry fit in the buffer?
		 */
		if (outcount + reclen > bufsize) {
			/*
			 * Did we manage to fit anything in the buffer?
			 */
			if (!outcount) {
				error = EINVAL;
				goto update;
			}
			break;
		}
		/*
		 * Add this entry:
		 */
#ifdef __APPLE__
		if (extended) {
			dirent64_t  *odp;
			size_t  nfdlen;

			odp = (dirent64_t  *)bufptr;
			/* NOTE: d_seekoff is the offset for the *next* entry */
			next = &(odp->d_seekoff);
			odp->d_ino = objnum;
			odp->d_type = dtype;
	
			/*
			 * Mac OS X: non-ascii names are UTF-8 NFC on disk 
			 * so convert to NFD before exporting them.
			 */
			namelen = strlen(zap.za_name);
			if (ascii ||
			    utf8_normalizestr((const u_int8_t *)zap.za_name, namelen,
			                      (u_int8_t *)odp->d_name, &nfdlen,
			                      MAXPATHLEN-1, UTF_DECOMPOSED) != 0) {
				/* ASCII or normalization failed, just copy zap name. */
				(void) bcopy(zap.za_name, odp->d_name, namelen + 1);
			} else {
				/* Normalization succeeded (already in buffer). */
				namelen = nfdlen;
			}
			odp->d_namlen = namelen;
			odp->d_reclen = reclen = DIRENT_RECLEN(namelen, extended);
		} else {
			dirent_t  *odp;
			size_t  nfdlen;

			odp = (dirent_t  *)bufptr;
			odp->d_ino = objnum;
			odp->d_type = dtype;

			/*
			 * Mac OS X: non-ascii names are UTF-8 NFC on disk 
			 * so convert to NFD before exporting them.
			 */
			namelen = strlen(zap.za_name);
			if (ascii ||
			    utf8_normalizestr((const u_int8_t *)zap.za_name, namelen,
			                      (u_int8_t *)odp->d_name, &nfdlen,
			                      MAXNAMLEN, UTF_DECOMPOSED) != 0) {
				/* ASCII or normalization failed, just copy zap name. */
				(void) bcopy(zap.za_name, odp->d_name, namelen + 1);
			} else {
				/* Normalization succeeded (already in buffer). */
				namelen = nfdlen;
			}
			odp->d_namlen = namelen;
			odp->d_reclen = reclen = DIRENT_RECLEN(namelen, extended);
		}
		outcount += reclen;
		bufptr += reclen;
		numdirent++;
#else
		odp->d_ino = objnum;
		odp->d_reclen = reclen;
		/* NOTE: d_off is the offset for the *next* entry */
		next = &(odp->d_off);
		(void) strncpy(odp->d_name, zap.za_name,
		    DIRENT64_NAMELEN(reclen));
		outcount += reclen;
		odp = (dirent64_t *)((intptr_t)odp + reclen);
#endif /* __APPLE__ */

		ASSERT(outcount <= bufsize);

		/* Prefetch znode */
		if (prefetch)
			dmu_prefetch(os, objnum, 0, 0);

		/*
		 * Move to the next entry, fill in the previous offset.
		 */
		if (offset > 2 || (offset == 2 && !zfs_show_ctldir(zp))) {
			zap_cursor_advance(&zc);
			offset = zap_cursor_serialize(&zc);
		} else {
			offset += 1;
		}
#ifdef __APPLE__
		if (extended) 
#endif
		*next = offset;
	}
	zp->z_zn_prefetch = B_FALSE; /* a lookup will re-enable pre-fetching */

#ifdef __APPLE__
	if (error = uio_move(outbuf, (long)outcount, UIO_READ, uio)) {
		/*
		 * Reset the pointer.
		 */
		offset = uio_offset(uio);
	} 
#else
	if (uio->uio_segflg == UIO_SYSSPACE && uio->uio_iovcnt == 1) {
		iovp->iov_base += outcount;
		iovp->iov_len -= outcount;
		uio->uio_resid -= outcount;
	} else if (error = uiomove(outbuf, (long)outcount, UIO_READ, uio)) {
		/*
		 * Reset the pointer.
		 */
		offset = uio->uio_loffset;
	}
#endif /* __APPLE__ */
update:
	zap_cursor_fini(&zc);
#ifdef __APPLE__
	if (outbuf) {
		kmem_free(outbuf, bufsize);
	}
#else
	if (uio->uio_segflg != UIO_SYSSPACE || uio->uio_iovcnt != 1)
		kmem_free(outbuf, bufsize);
#endif /* __APPLE__ */
	if (error == ENOENT) {
		error = 0;
	}
	ZFS_ACCESSTIME_STAMP(zfsvfs, zp);

#ifdef __APPLE__
	uio_setoffset(uio, offset);
	if (ap->a_numdirent) {
		*ap->a_numdirent = numdirent;
	}
#else
	uio->uio_loffset = offset;
#endif /* __APPLE__ */
	ZFS_EXIT(zfsvfs);
	return (error);
}

ulong_t zfs_fsync_sync_cnt = 4;

static int
#ifdef __APPLE__
zfs_vnop_fsync(struct vnop_fsync_args *ap)
#else
zfs_fsync(vnode_t *vp, int syncflag, cred_t *cr)
#endif __APPLE__
{
#ifdef __APPLE__
	struct vnode  *vp = ap->a_vp;
#endif /* __APPLE__ */
	znode_t	*zp = VTOZ(vp);
	zfsvfs_t *zfsvfs;
	
#ifndef __APPLE__	
	/*
	 * Regardless of whether this is required for standards conformance,
	 * this is the logical behavior when fsync() is called on a file with
	 * dirty pages.  We use B_ASYNC since the ZIL transactions are already
	 * going to be pushed out as part of the zil_commit().
	 */
	if (vn_has_cached_data(vp) && !(syncflag & FNODSYNC) &&
		(vp->v_type == VREG) && !(IS_SWAPVP(vp)))
		(void) VOP_PUTPAGE(vp, (offset_t)0, (size_t)0, B_ASYNC, cr);
	
	(void) tsd_set(zfs_fsyncer_key, (void *)zfs_fsync_sync_cnt);
#else
	/* Check if this znode has already been synced, freed,
	 * and recycled by znode_pageout_func
	 */
	if (zp == NULL)
		return(0);
#endif /* !__APPLE__ */
	zfsvfs = zp->z_zfsvfs;
		
	ZFS_ENTER(zfsvfs);
#ifdef ZFS_DEBUG
	znode_stalker(zp, N_vnop_fsync_zil);
#endif
	zil_commit(zfsvfs->z_log, zp->z_last_itx, zp->z_id);
	ZFS_EXIT(zfsvfs);
	return (0);
}

/*
 * Get the requested file attributes and place them in the provided
 * vattr structure.
 *
 *	IN:	vp	- vnode of file.
 *		vap	- va_mask identifies requested attributes.
 *		flags	- [UNUSED]
 *		cr	- credentials of caller.
 *
 *	OUT:	vap	- attribute values.
 *
 *	RETURN:	0 (always succeeds)
 */
/* ARGSUSED */
static int
#ifdef __APPLE__
zfs_vnop_getattr(struct vnop_getattr_args *ap)
#else
zfs_getattr(vnode_t *vp, vattr_t *vap, int flags, cred_t *cr)
#endif
{
#ifdef __APPLE__
	struct vnode  *vp = ap->a_vp;
	struct vnode_attr  *vap = ap->a_vap;
	cred_t  *cr = (cred_t *)vfs_context_ucred(ap->a_context);
#endif /* __APPLE__ */
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	znode_phys_t *pzp = zp->z_phys;
	int	error;
	uint64_t links;

	ZFS_ENTER(zfsvfs);

	/*
	 * Return all attributes.  It's cheaper to provide the answer
	 * than to determine whether we were asked the question.
	 */
	mutex_enter(&zp->z_lock);

#ifdef __APPLE__
	vap->va_mode = pzp->zp_mode & MODEMASK;
	vap->va_uid = pzp->zp_uid;
	vap->va_gid = pzp->zp_gid;
//	vap->va_fsid = zp->z_zfsvfs->z_vfs->vfs_dev;
	/*
	 * On Mac OS X we always export the root directory id as 2
	 */
	vap->va_fileid = (zp->z_id == zfsvfs->z_root) ? 2 : zp->z_id;
	vap->va_nlink = pzp->zp_links;
	vap->va_data_size = pzp->zp_size;
	vap->va_total_size = pzp->zp_size;
	vap->va_rdev = pzp->zp_rdev;
	vap->va_gen = pzp->zp_gen;

	ZFS_TIME_DECODE(&vap->va_create_time, pzp->zp_crtime);
	ZFS_TIME_DECODE(&vap->va_access_time, pzp->zp_atime);
	ZFS_TIME_DECODE(&vap->va_modify_time, pzp->zp_mtime);
	ZFS_TIME_DECODE(&vap->va_change_time, pzp->zp_ctime);
	/*
	 * For Carbon compatibility, pretend to support this legacy/unused attribute
	 */
	if (VATTR_IS_ACTIVE(vap, va_backup_time)) {
		vap->va_backup_time.tv_sec = 0;
		vap->va_backup_time.tv_nsec = 0;	
		VATTR_SET_SUPPORTED(vap, va_backup_time);
	}
	vap->va_flags = zfs_getbsdflags(zp);
	/*
	 * On Mac OS X we always export the root directory id as 2 and its parent as 1
	 */
	if (zp->z_id == zfsvfs->z_root)
		vap->va_parentid = 1;
	else if (pzp->zp_parent == zfsvfs->z_root)
		vap->va_parentid = 2;
	else
		vap->va_parentid = pzp->zp_parent;

	vap->va_iosize = zp->z_blksz ? zp->z_blksz : zfsvfs->z_max_blksz;

	vap->va_supported |=
		VNODE_ATTR_va_mode |
		VNODE_ATTR_va_uid |
		VNODE_ATTR_va_gid |
//		VNODE_ATTR_va_fsid |
		VNODE_ATTR_va_fileid |
		VNODE_ATTR_va_nlink |
		VNODE_ATTR_va_data_size |
		VNODE_ATTR_va_total_size |
		VNODE_ATTR_va_rdev |
		VNODE_ATTR_va_gen |
		VNODE_ATTR_va_create_time |
		VNODE_ATTR_va_access_time |
		VNODE_ATTR_va_modify_time |
		VNODE_ATTR_va_change_time |
		VNODE_ATTR_va_flags |
		VNODE_ATTR_va_parentid |
		VNODE_ATTR_va_iosize;

	if (VATTR_IS_ACTIVE(vap, va_nchildren) && vnode_isdir(vp))
		VATTR_RETURN(vap, va_nchildren, pzp->zp_size);

	if (VATTR_IS_ACTIVE(vap, va_acl)) {
		if (zp->z_phys->zp_acl.z_acl_count == 0) {
			vap->va_acl = (kauth_acl_t) KAUTH_FILESEC_NONE;
		} else {
			if ((error = zfs_getacl(zp, &vap->va_acl, cr))) {
				ZFS_EXIT(zfsvfs);
				return (error);
			}
		}
		VATTR_SET_SUPPORTED(vap, va_acl);
		/* va_acl implies that va_uuuid and va_guuid are also supported. */
		VATTR_RETURN(vap, va_uuuid, kauth_null_guid);
		VATTR_RETURN(vap, va_guuid, kauth_null_guid);
	}
#else /* OpenSolaris */

	vap->va_type = vp->v_type;
	vap->va_mode = pzp->zp_mode & MODEMASK;
	vap->va_uid = zp->z_phys->zp_uid;
	vap->va_gid = zp->z_phys->zp_gid;
	vap->va_fsid = zp->z_zfsvfs->z_vfs->vfs_dev;
	vap->va_nodeid = zp->z_id;
	if ((vp->v_flag & VROOT) && zfs_show_ctldir(zp))
		links = pzp->zp_links + 1;
	else
		links = pzp->zp_links;
	vap->va_nlink = MIN(links, UINT32_MAX);	/* nlink_t limit! */
	vap->va_size = pzp->zp_size;
	vap->va_rdev = vp->v_rdev;
	vap->va_seq = zp->z_seq;

	ZFS_TIME_DECODE(&vap->va_atime, pzp->zp_atime);
	ZFS_TIME_DECODE(&vap->va_mtime, pzp->zp_mtime);
	ZFS_TIME_DECODE(&vap->va_ctime, pzp->zp_ctime);

	/*
	 * If ACL is trivial don't bother looking for ACE_READ_ATTRIBUTES.
	 * Also, if we are the owner don't bother, since owner should
	 * always be allowed to read basic attributes of file.
	 */
	if (!(zp->z_phys->zp_flags & ZFS_ACL_TRIVIAL) &&
	    (zp->z_phys->zp_uid != crgetuid(cr))) {
		if (error = zfs_zaccess(zp, ACE_READ_ATTRIBUTES, cr)) {
			mutex_exit(&zp->z_lock);
			ZFS_EXIT(zfsvfs);
			return (error);
		}
	}
#endif /*!__APPLE__*/

	mutex_exit(&zp->z_lock);

#ifdef __APPLE__ 
	if (VATTR_IS_ACTIVE(vap, va_data_alloc) || VATTR_IS_ACTIVE(vap, va_total_alloc)) {
		uint32_t  blksize;
		u_longlong_t  nblks;
		dmu_object_size_from_db(zp->z_dbuf, &blksize, &nblks);
		vap->va_data_alloc = (uint64_t)512LL * (uint64_t)nblks;
		vap->va_total_alloc = vap->va_data_alloc;
		vap->va_supported |= VNODE_ATTR_va_data_alloc | 
					VNODE_ATTR_va_total_alloc;
	}

	if (VATTR_IS_ACTIVE(vap, va_name) && !vnode_isvroot(vp)) {
		if (zap_value_search(zfsvfs->z_os, pzp->zp_parent, zp->z_id, 
			 	    ZFS_DIRENT_OBJ(-1ULL), vap->va_name) == 0)
			VATTR_SET_SUPPORTED(vap, va_name);
	}

#else

	dmu_object_size_from_db(zp->z_dbuf, &vap->va_blksize, &vap->va_nblocks);

	if (zp->z_blksz == 0) {
		/*
		 * Block size hasn't been set; suggest maximal I/O transfers.
		 */
		vap->va_blksize = zfsvfs->z_max_blksz;
	}
#endif
	ZFS_EXIT(zfsvfs);
	return (0);
}

/*
 * Set the file attributes to the values contained in the
 * vattr structure.
 *
 *	IN:	vp	- vnode of file to be modified.
 *		vap	- new attribute values.
 *		flags	- ATTR_UTIME set if non-default time values provided.
 *		cr	- credentials of caller.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	vp - ctime updated, mtime updated if size changed.
 */
/* ARGSUSED */
static int
#ifdef __APPLE__
zfs_vnop_setattr(struct vnop_setattr_args *ap)
#else
zfs_setattr(vnode_t *vp, vattr_t *vap, int flags, cred_t *cr,
	caller_context_t *ct)
#endif
{
#ifdef __APPLE__
	struct vnode  *vp = ap->a_vp;
	struct vnode_attr  *vap = ap->a_vap;
	uint64_t  mask; // = vap->va_active;
	uint64_t  saved_mask;
	cred_t  *cr = (cred_t *)vfs_context_ucred(ap->a_context);
#else
	vattr_t		oldva;
	uint_t		mask = vap->va_mask;
	uint_t		saved_mask;
#endif
	struct znode	*zp = VTOZ(vp);
	znode_phys_t	*pzp = zp->z_phys;
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	zilog_t		*zilog = zfsvfs->z_log;
	dmu_tx_t	*tx;
	int		trim_mask = 0;
	uint64_t	new_mode = 0;
	znode_t		*attrzp;
	int		need_policy = FALSE;
	int		err;

#ifndef __APPLE__
	if (mask == 0)
		return (0);

	if (mask & AT_NOSET)
		return (EINVAL);

	if (mask & AT_SIZE && vp->v_type == VDIR)
		return (EISDIR);

	if (mask & AT_SIZE && vp->v_type != VREG && vp->v_type != VFIFO)
		return (EINVAL);
#endif /* !__APPLE__ */

	ZFS_ENTER(zfsvfs);

top:
	attrzp = NULL;

#ifdef __APPLE__
	if (vfs_isrdonly(zfsvfs->z_vfs)) 
#else
	if (zfsvfs->z_vfs->vfs_flag & VFS_RDONLY) 
#endif
	{
		ZFS_EXIT(zfsvfs);
		return (EROFS);
	}

	/*
	 * First validate permissions
	 */
#ifdef __APPLE__
	if (VATTR_IS_ACTIVE(vap, va_data_size)) 
#else
	if (mask & AT_SIZE) 
#endif
	{
#ifndef __APPLE__
		err = zfs_zaccess(zp, ACE_WRITE_DATA, cr);
		if (err) {
			ZFS_EXIT(zfsvfs);
			return (err);
		}
#endif /* !__APPLE__ */
		/*
		 * XXX - Note, we are not providing any open
		 * mode flags here (like FNDELAY), so we may
		 * block if there are locks present... this
		 * should be addressed in openat().
		 */
		do {
#ifdef __APPLE__
			err = zfs_freesp(zp, vap->va_data_size, 0, 0, FALSE);
#else
			err = zfs_freesp(zp, vap->va_size, 0, 0, FALSE);
#endif
			/* NB: we already did dmu_tx_wait() if necessary */
		} while (err == ERESTART && zfsvfs->z_assign == TXG_NOWAIT);
		if (err) {
			ZFS_EXIT(zfsvfs);
			return (err);
		}
#ifdef __APPLE__
		/* Mac OS X: pageout requires that the UBC file size to be current. */
		ubc_setsize(vp, vap->va_data_size);

		VATTR_SET_SUPPORTED(vap, va_data_size);
#endif __APPLE__
	}

#ifndef __APPLE__
	if (mask & (AT_ATIME|AT_MTIME))
		need_policy = zfs_zaccess_v4_perm(zp, ACE_WRITE_ATTRIBUTES, cr);

	if (mask & (AT_UID|AT_GID)) {
		int	idmask = (mask & (AT_UID|AT_GID));
		int	take_owner;
		int	take_group;

		/*
		 * NOTE: even if a new mode is being set,
		 * we may clear S_ISUID/S_ISGID bits.
		 */

		if (!(mask & AT_MODE))
			vap->va_mode = pzp->zp_mode;

		/*
		 * Take ownership or chgrp to group we are a member of
		 */

		take_owner = (mask & AT_UID) && (vap->va_uid == crgetuid(cr));
		take_group = (mask & AT_GID) && groupmember(vap->va_gid, cr);

		/*
		 * If both AT_UID and AT_GID are set then take_owner and
		 * take_group must both be set in order to allow taking
		 * ownership.
		 *
		 * Otherwise, send the check through secpolicy_vnode_setattr()
		 *
		 */

		if (((idmask == (AT_UID|AT_GID)) && take_owner && take_group) ||
		    ((idmask == AT_UID) && take_owner) ||
		    ((idmask == AT_GID) && take_group)) {
			if (zfs_zaccess_v4_perm(zp, ACE_WRITE_OWNER, cr) == 0) {
				/*
				 * Remove setuid/setgid for non-privileged users
				 */
				secpolicy_setid_clear(vap, cr);
				trim_mask = (mask & (AT_UID|AT_GID));
			} else {
				need_policy =  TRUE;
			}
		} else {
			need_policy =  TRUE;
		}
	}
	mutex_enter(&zp->z_lock);
	oldva.va_mode = pzp->zp_mode;
	oldva.va_uid = zp->z_phys->zp_uid;
	oldva.va_gid = zp->z_phys->zp_gid;
	mutex_exit(&zp->z_lock);

	if (mask & AT_MODE) {
		if (zfs_zaccess_v4_perm(zp, ACE_WRITE_ACL, cr) == 0) {
			err = secpolicy_setid_setsticky_clear(vp, vap,
			    &oldva, cr);
			if (err) {
				ZFS_EXIT(zfsvfs);
				return (err);
			}
			trim_mask |= AT_MODE;
		} else {
			need_policy = TRUE;
		}
	}

	if (need_policy) {
		/*
		 * If trim_mask is set then take ownership
		 * has been granted or write_acl is present and user
		 * has the ability to modify mode.  In that case remove
		 * UID|GID and or MODE from mask so that
		 * secpolicy_vnode_setattr() doesn't revoke it.
		 */

		if (trim_mask) {
			saved_mask = vap->va_mask;
			vap->va_mask &= ~trim_mask;

		}
		err = secpolicy_vnode_setattr(cr, vp, vap, &oldva, flags,
		    (int (*)(void *, int, cred_t *))zfs_zaccess_rwx, zp);
		if (err) {
			ZFS_EXIT(zfsvfs);
			return (err);
		}

		if (trim_mask)
			vap->va_mask |= saved_mask;
	}
#endif /* !__APPLE__ */

	/*
	 * secpolicy_vnode_setattr, or take ownership may have
	 * changed va_mask
	 */
#ifdef __APPLE__
        mask = vap->va_active;
#else
	mask = vap->va_mask;
#endif /* __APPLE__ */

	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_bonus(tx, zp->z_id);

#ifdef __APPLE__
	if (VATTR_IS_ACTIVE(vap, va_mode) || VATTR_IS_ACTIVE(vap, va_acl)) 
#else
	if (mask & AT_MODE) 
#endif
	{
		uint64_t pmode = pzp->zp_mode;

		new_mode = (pmode & S_IFMT) | (vap->va_mode & ~S_IFMT);

		if (zp->z_phys->zp_acl.z_acl_extern_obj)
			dmu_tx_hold_write(tx,
			    pzp->zp_acl.z_acl_extern_obj, 0, SPA_MAXBLOCKSIZE);
		else
			dmu_tx_hold_write(tx, DMU_NEW_OBJECT,
			    0, ZFS_ACL_SIZE(MAX_ACL_SIZE));
	}

#ifdef __APPLE__
	if ((mask & (VNODE_ATTR_va_uid | VNODE_ATTR_va_gid)) &&
	    zp->z_phys->zp_xattr != 0) 
#else
	if ((mask & (AT_UID | AT_GID)) && zp->z_phys->zp_xattr != 0) 
#endif
	{
		err = zfs_zget(zp->z_zfsvfs, zp->z_phys->zp_xattr, &attrzp);
		if (err) {
			dmu_tx_abort(tx);
			ZFS_EXIT(zfsvfs);
			return (err);
		}
		dmu_tx_hold_bonus(tx, attrzp->z_id);
	}

	err = dmu_tx_assign(tx, zfsvfs->z_assign);
	if (err) {
		if (attrzp)
// Issue 34
#ifdef __APPLE__
			vnode_put(ZTOV(attrzp));
#else
			VN_RELE(ZTOV(attrzp));
#endif
		if (err == ERESTART && zfsvfs->z_assign == TXG_NOWAIT) {
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		ZFS_EXIT(zfsvfs);
		return (err);
	}

	dmu_buf_will_dirty(zp->z_dbuf, tx);

	/*
	 * Set each attribute requested.
	 * We group settings according to the locks they need to acquire.
	 *
	 * Note: you cannot set ctime directly, although it will be
	 * updated as a side-effect of calling this function.
	 */

#ifdef __APPLE__
	if (VATTR_IS_ACTIVE(vap, va_acl)) {
		if ((vap->va_acl != (kauth_acl_t) KAUTH_FILESEC_NONE) &&
		    (vap->va_acl->acl_entrycount != KAUTH_FILESEC_NOACL)) {
			if ((err = zfs_setacl(zp, vap->va_acl, cr, tx)))
				goto out;
		} else {
			struct kauth_acl blank_acl;
	
			bzero(&blank_acl, sizeof blank_acl);
			if ((err = zfs_setacl(zp, &blank_acl, cr, tx)))
				goto out;
		}
		VATTR_SET_SUPPORTED(vap, va_acl);
	}
#endif

	mutex_enter(&zp->z_lock);

#ifdef __APPLE__
	if (VATTR_IS_ACTIVE(vap, va_mode)) 
#else
	if (mask & AT_MODE) 
#endif /* __APPLE__ */
	{
#ifdef __APPLE__
		zp->z_phys->zp_mode = new_mode;
#else
		err = zfs_acl_chmod_setattr(zp, new_mode, tx);
#endif /* __APPLE__ */
		ASSERT3U(err, ==, 0);
#ifdef __APPLE__
		VATTR_SET_SUPPORTED(vap, va_mode);
#endif /* __APPLE__ */
	}

	if (attrzp)
		mutex_enter(&attrzp->z_lock);

#ifdef __APPLE__
	if (VATTR_IS_ACTIVE(vap, va_uid)) 
#else
	if (mask & AT_UID) 
#endif /* __APPLE__ */
	{
		zp->z_phys->zp_uid = (uint64_t)vap->va_uid;
		if (attrzp) {
			attrzp->z_phys->zp_uid = (uint64_t)vap->va_uid;
		}
#ifdef __APPLE__
		VATTR_SET_SUPPORTED(vap, va_uid);
#endif /* __APPLE__ */
	}

#ifdef __APPLE__
	if (VATTR_IS_ACTIVE(vap, va_gid)) 
#else
	if (mask & AT_GID) 
#endif /* __APPLE__ */
	{
		zp->z_phys->zp_gid = (uint64_t)vap->va_gid;
		if (attrzp)
			attrzp->z_phys->zp_gid = (uint64_t)vap->va_gid;
#ifdef __APPLE__
		VATTR_SET_SUPPORTED(vap, va_gid);
#endif /* __APPLE__ */
	}

	if (attrzp)
		mutex_exit(&attrzp->z_lock);

#ifdef __APPLE__
	if (VATTR_IS_ACTIVE(vap, va_access_time)) {
		ZFS_TIME_ENCODE(&vap->va_access_time, pzp->zp_atime);
		VATTR_SET_SUPPORTED(vap, va_access_time);
	}
	if (VATTR_IS_ACTIVE(vap, va_modify_time)) {
		ZFS_TIME_ENCODE(&vap->va_modify_time, pzp->zp_mtime);
		VATTR_SET_SUPPORTED(vap, va_modify_time);
	}
	if (VATTR_IS_ACTIVE(vap, va_create_time)) {
		ZFS_TIME_ENCODE(&vap->va_create_time, pzp->zp_crtime);
		VATTR_SET_SUPPORTED(vap, va_create_time);
	}
	/*
	 * For Carbon compatibility, pretend to support this legacy/unused attribute
	 */
	if (VATTR_IS_ACTIVE(vap, va_backup_time)) {
		VATTR_SET_SUPPORTED(vap, va_backup_time);
	}

	if (VATTR_IS_ACTIVE(vap, va_flags)) {
		zfs_setbsdflags(zp, vap->va_flags);
		VATTR_SET_SUPPORTED(vap, va_flags);
	}

	if (VATTR_IS_ACTIVE(vap, va_data_size))
// body follows further below
#else /* OpenSolaris */
	if (mask & AT_ATIME)
		ZFS_TIME_ENCODE(&vap->va_atime, pzp->zp_atime);

	if (mask & AT_MTIME)
		ZFS_TIME_ENCODE(&vap->va_mtime, pzp->zp_mtime);

	if (mask & AT_SIZE)
#endif /* __APPLE__ */
		zfs_time_stamper_locked(zp, CONTENT_MODIFIED, tx);
	else if (mask != 0)
		zfs_time_stamper_locked(zp, STATE_CHANGED, tx);

	if (mask != 0)
		zfs_log_setattr(zilog, tx, TX_SETATTR, zp, vap, mask);

	mutex_exit(&zp->z_lock);
#ifdef __APPLE__
out:
#endif
	if (attrzp) 
	{
// Issue 34
#ifdef __APPLE__
		vnode_put(ZTOV(attrzp));
#else
		VN_RELE(ZTOV(attrzp));
#endif /* __APPLE__ */
	}
	dmu_tx_commit(tx);

	ZFS_EXIT(zfsvfs);
	return (err);
}

typedef struct zfs_zlock {
	krwlock_t	*zl_rwlock;	/* lock we acquired */
	znode_t		*zl_znode;	/* znode we held */
	struct zfs_zlock *zl_next;	/* next in list */
} zfs_zlock_t;

/*
 * Drop locks and release vnodes that were held by zfs_rename_lock().
 */
static void
zfs_rename_unlock(zfs_zlock_t **zlpp)
{
	zfs_zlock_t *zl;

	while ((zl = *zlpp) != NULL) {
		if (zl->zl_znode != NULL)
			VN_RELE(ZTOV(zl->zl_znode));
		rw_exit(zl->zl_rwlock);
		*zlpp = zl->zl_next;
		kmem_free(zl, sizeof (*zl));
	}
}

/*
 * Search back through the directory tree, using the ".." entries.
 * Lock each directory in the chain to prevent concurrent renames.
 * Fail any attempt to move a directory into one of its own descendants.
 * XXX - z_parent_lock can overlap with map or grow locks
 */
static int
zfs_rename_lock(znode_t *szp, znode_t *tdzp, znode_t *sdzp, zfs_zlock_t **zlpp)
{
	zfs_zlock_t	*zl;
	znode_t		*zp = tdzp;
	uint64_t	rootid = zp->z_zfsvfs->z_root;
	uint64_t	*oidp = &zp->z_id;
	krwlock_t	*rwlp = &szp->z_parent_lock;
	krw_t		rw = RW_WRITER;

	/*
	 * First pass write-locks szp and compares to zp->z_id.
	 * Later passes read-lock zp and compare to zp->z_parent.
	 */
	do {
		if (!rw_tryenter(rwlp, rw)) {
			/*
			 * Another thread is renaming in this path.
			 * Note that if we are a WRITER, we don't have any
			 * parent_locks held yet.
			 */
			if (rw == RW_READER && zp->z_id > szp->z_id) {
				/*
				 * Drop our locks and restart
				 */
				zfs_rename_unlock(&zl);
				*zlpp = NULL;
				zp = tdzp;
				oidp = &zp->z_id;
				rwlp = &szp->z_parent_lock;
				rw = RW_WRITER;
				continue;
			} else {
				/*
				 * Wait for other thread to drop its locks
				 */
				rw_enter(rwlp, rw);
			}
		}

		zl = kmem_alloc(sizeof (*zl), KM_SLEEP);
		zl->zl_rwlock = rwlp;
		zl->zl_znode = NULL;
		zl->zl_next = *zlpp;
		*zlpp = zl;

		if (*oidp == szp->z_id)		/* We're a descendant of szp */
			return (EINVAL);

		if (*oidp == rootid)		/* We've hit the top */
			return (0);

		if (rw == RW_READER) {		/* i.e. not the first pass */
			int error = zfs_zget(zp->z_zfsvfs, *oidp, &zp);
			if (error)
				return (error);
			zl->zl_znode = zp;
		}
		oidp = &zp->z_phys->zp_parent;
		rwlp = &zp->z_parent_lock;
		rw = RW_READER;

	} while (zp->z_id != sdzp->z_id);

	return (0);
}

/*
 * Move an entry from the provided source directory to the target
 * directory.  Change the entry name as indicated.
 *
 *	IN:	sdvp	- Source directory containing the "old entry".
 *		snm	- Old entry name.
 *		tdvp	- Target directory to contain the "new entry".
 *		tnm	- New entry name.
 *		cr	- credentials of caller.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	sdvp,tdvp - ctime|mtime updated
 */
static int
#ifdef __APPLE__
zfs_vnop_rename(struct vnop_rename_args *ap)
#else
zfs_rename(vnode_t *sdvp, char *snm, vnode_t *tdvp, char *tnm, cred_t *cr)
#endif /* __APPLE__ */
{
#ifdef __APPLE__
	struct vnode  *sdvp = ap->a_fdvp;
	struct vnode  *tdvp = ap->a_tdvp;
	struct componentname *scnp = ap->a_fcnp;
	struct componentname *tcnp = ap->a_tcnp;
        char *snm = (char *)scnp->cn_nameptr;
        char *tnm = (char *)tcnp->cn_nameptr;
#else
	vnode_t		*realvp;
#endif /* __APPLE__ */
	znode_t		*tdzp, *szp, *tzp;
	znode_t		*sdzp = VTOZ(sdvp);
	zfsvfs_t	*zfsvfs = sdzp->z_zfsvfs;
	zilog_t		*zilog = zfsvfs->z_log;
	zfs_dirlock_t	*sdl, *tdl;
	dmu_tx_t	*tx;
	zfs_zlock_t	*zl;
	int		cmp, serr, terr, error;

	ZFS_ENTER(zfsvfs);

#ifndef __APPLE__
	/*
	 * Make sure we have the real vp for the target directory.
	 */
	if (VOP_REALVP(tdvp, &realvp) == 0)
		tdvp = realvp;

	if (tdvp->v_vfsp != sdvp->v_vfsp) {
		ZFS_EXIT(zfsvfs);
		return (EXDEV);
	}
#endif /*!__APPLE__*/

	tdzp = VTOZ(tdvp);
top:
	szp = NULL;
	tzp = NULL;
	zl = NULL;

	/*
	 * This is to prevent the creation of links into attribute space
	 * by renaming a linked file into/outof an attribute directory.
	 * See the comment in zfs_link() for why this is considered bad.
	 */
	if ((tdzp->z_phys->zp_flags & ZFS_XATTR) !=
	    (sdzp->z_phys->zp_flags & ZFS_XATTR)) {
		ZFS_EXIT(zfsvfs);
		return (EINVAL);
	}

	/*
	 * Lock source and target directory entries.  To prevent deadlock,
	 * a lock ordering must be defined.  We lock the directory with
	 * the smallest object id first, or if it's a tie, the one with
	 * the lexically first name.
	 */
	if (sdzp->z_id < tdzp->z_id) {
		cmp = -1;
	} else if (sdzp->z_id > tdzp->z_id) {
		cmp = 1;
	} else {
		cmp = strcmp(snm, tnm);
		if (cmp == 0) {
			/*
			 * POSIX: "If the old argument and the new argument
			 * both refer to links to the same existing file,
			 * the rename() function shall return successfully
			 * and perform no other action."
			 */
			ZFS_EXIT(zfsvfs);
			return (0);
		}
	}
#ifdef __APPLE__
        if (cmp < 0) {
                serr = zfs_dirent_lock(&sdl, sdzp, scnp, &szp, ZEXISTS);
                terr = zfs_dirent_lock(&tdl, tdzp, tcnp, &tzp, 0);
        } else {
                terr = zfs_dirent_lock(&tdl, tdzp, tcnp, &tzp, 0);
                serr = zfs_dirent_lock(&sdl, sdzp, scnp, &szp, ZEXISTS);
        }
#else
	if (cmp < 0) {
		serr = zfs_dirent_lock(&sdl, sdzp, snm, &szp, ZEXISTS);
		terr = zfs_dirent_lock(&tdl, tdzp, tnm, &tzp, 0);
	} else {
		terr = zfs_dirent_lock(&tdl, tdzp, tnm, &tzp, 0);
		serr = zfs_dirent_lock(&sdl, sdzp, snm, &szp, ZEXISTS);
	}
#endif /* __APPLE__ */

	if (serr) {
		/*
		 * Source entry invalid or not there.
		 */
		if (!terr) {
			zfs_dirent_unlock(tdl);
			if (tzp)
				VN_RELE(ZTOV(tzp));
		}
		if (strcmp(snm, "..") == 0)
			serr = EINVAL;
		ZFS_EXIT(zfsvfs);
		return (serr);
	}
	if (terr) {
		zfs_dirent_unlock(sdl);
		VN_RELE(ZTOV(szp));
		if (strcmp(tnm, "..") == 0)
			terr = EINVAL;
		ZFS_EXIT(zfsvfs);
		return (terr);
	}

#ifndef __APPLE__
	/* On Mac OS X, VFS performs the necessary access checks. */
	/*
	 * Must have write access at the source to remove the old entry
	 * and write access at the target to create the new entry.
	 * Note that if target and source are the same, this can be
	 * done in a single check.
	 */
	if (error = zfs_zaccess_rename(sdzp, szp, tdzp, tzp, cr))
		goto out;
#endif /*!__APPLE__*/

#ifdef __APPLE__
	if (vnode_isdir(ZTOV(szp))) 
#else
	if (ZTOV(szp)->v_type == VDIR) 
#endif /* __APPLE__ */
	{
		/*
		 * Check to make sure rename is valid.
		 * Can't do a move like this: /usr/a/b to /usr/a/b/c/d
		 */
		if (error = zfs_rename_lock(szp, tdzp, sdzp, &zl))
			goto out;
	}

#ifndef __APPLE__
	/*
	 * Does target exist?
	 */
	if (tzp) {
		/*
		 * Source and target must be the same type.
		 */
		if (ZTOV(szp)->v_type == VDIR) {
			if (ZTOV(tzp)->v_type != VDIR) {
				error = ENOTDIR;
				goto out;
			}
		} else {
			if (ZTOV(tzp)->v_type == VDIR) {
				error = EISDIR;
				goto out;
			}
		}
		/*
		 * POSIX dictates that when the source and target
		 * entries refer to the same file object, rename
		 * must do nothing and exit without error.
		 */
		if (szp->z_id == tzp->z_id) {
			error = 0;
			goto out;
		}
	}

	vnevent_rename_src(ZTOV(szp), sdvp, snm);
	if (tzp)
		vnevent_rename_dest(ZTOV(tzp), tdvp, tnm);

	/*
	 * notify the target directory if it is not the same
	 * as source directory.
	 */
	if (tdvp != sdvp) {
		vnevent_rename_dest_dir(tdvp);
	}
#endif /*!__APPLE__*/

	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_bonus(tx, szp->z_id);	/* nlink changes */
	dmu_tx_hold_bonus(tx, sdzp->z_id);	/* nlink changes */
	dmu_tx_hold_zap(tx, sdzp->z_id, FALSE, snm);
	dmu_tx_hold_zap(tx, tdzp->z_id, TRUE, tnm);
	if (sdzp != tdzp)
		dmu_tx_hold_bonus(tx, tdzp->z_id);	/* nlink changes */
	if (tzp)
		dmu_tx_hold_bonus(tx, tzp->z_id);	/* parent changes */
	dmu_tx_hold_zap(tx, zfsvfs->z_unlinkedobj, FALSE, NULL);
	error = dmu_tx_assign(tx, zfsvfs->z_assign);
	if (error) {
		if (zl != NULL)
			zfs_rename_unlock(&zl);
		zfs_dirent_unlock(sdl);
		zfs_dirent_unlock(tdl);
		VN_RELE(ZTOV(szp));
		if (tzp)
			VN_RELE(ZTOV(tzp));
		if (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT) {
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	if (tzp)	/* Attempt to remove the existing target */
		error = zfs_link_destroy(tdl, tzp, tx, 0, NULL);

	if (error == 0) {
		error = zfs_link_create(tdl, szp, tx, ZRENAMING);
		if (error == 0) {
			error = zfs_link_destroy(sdl, szp, tx, ZRENAMING, NULL);
			ASSERT(error == 0);
			zfs_log_rename(zilog, tx, TX_RENAME, sdzp,
			    sdl->dl_name, tdzp, tdl->dl_name, szp);
		}
	}

#ifdef __APPLE__
	/* Remove entries from the namei cache. */
	cache_purge(ZTOV(szp));
	if (tzp)
		cache_purge(ZTOV(tzp));
#endif /* __APPLE__ */

	dmu_tx_commit(tx);
out:
	if (zl != NULL)
		zfs_rename_unlock(&zl);

	zfs_dirent_unlock(sdl);
	zfs_dirent_unlock(tdl);

	VN_RELE(ZTOV(szp));
	if (tzp)
// Issue 34
#ifdef __APPLE__
		vnode_put(ZTOV(tzp));
#else
		VN_RELE(ZTOV(tzp));
#endif

	ZFS_EXIT(zfsvfs);
	return (error);
}

/*
 * Insert the indicated symbolic reference entry into the directory.
 *
 *	IN:	dvp	- Directory to contain new symbolic link.
 *		link	- Name for new symlink entry.
 *		vap	- Attributes of new entry.
 *		target	- Target path of new symlink.
 *		cr	- credentials of caller.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	dvp - ctime|mtime updated
 */
static int
#ifdef __APPLE__
zfs_vnop_symlink(struct vnop_symlink_args *ap)
#else
zfs_symlink(vnode_t *dvp, char *name, vattr_t *vap, char *link, cred_t *cr)
#endif
{
#ifdef __APPLE__
	struct vnode  *dvp = ap->a_dvp;
	struct componentname  *cnp = ap->a_cnp;
        char * name = (char *)cnp->cn_nameptr;
	struct vnode_attr  *vap = ap->a_vap;
	cred_t  *cr = (cred_t *)vfs_context_ucred(ap->a_context);
	char  *link = ap->a_target;
#endif /* __APPLE__ */
	znode_t		*zp, *dzp = VTOZ(dvp);
	zfs_dirlock_t	*dl;
	dmu_tx_t	*tx;
	zfsvfs_t	*zfsvfs = dzp->z_zfsvfs;
	zilog_t		*zilog = zfsvfs->z_log;
	uint64_t	zoid;
	int		len = strlen(link);
	int		error;

	ASSERT(vap->va_type == VLNK);

	ZFS_ENTER(zfsvfs);
top:

#ifndef __APPLE__
	/* On Mac OS X, VFS performs the necessary access checks. */
	if (error = zfs_zaccess(dzp, ACE_ADD_FILE, cr)) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}
#endif /*!__APPLE__*/

#ifdef __APPLE__
	if ((len > MAXPATHLEN) || (cnp->cn_namelen >= ZAP_MAXNAMELEN)) 
#else
	if (len > MAXPATHLEN) 
#endif /* __APPLE__ */
	{
		ZFS_EXIT(zfsvfs);
		return (ENAMETOOLONG);
	}

	/*
	 * Attempt to lock directory; fail if entry already exists.
	 */
#ifdef __APPLE__
	if (error = zfs_dirent_lock(&dl, dzp, cnp, &zp, ZNEW)) 
#else
	if (error = zfs_dirent_lock(&dl, dzp, name, &zp, ZNEW)) 
#endif /* __APPLE__ */
	{
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_write(tx, DMU_NEW_OBJECT, 0, MAX(1, len));
	dmu_tx_hold_bonus(tx, dzp->z_id);
	dmu_tx_hold_zap(tx, dzp->z_id, TRUE, name);
	if (dzp->z_phys->zp_flags & ZFS_INHERIT_ACE)
		dmu_tx_hold_write(tx, DMU_NEW_OBJECT, 0, SPA_MAXBLOCKSIZE);
	error = dmu_tx_assign(tx, zfsvfs->z_assign);
	if (error) {
		zfs_dirent_unlock(dl);
		if (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT) {
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	dmu_buf_will_dirty(dzp->z_dbuf, tx);

	/*
	 * Create a new object for the symlink.
	 * Put the link content into bonus buffer if it will fit;
	 * otherwise, store it just like any other file data.
	 */
	zoid = 0;
	if (sizeof (znode_phys_t) + len <= dmu_bonus_max()) {
		zfs_mknode(dzp, vap, &zoid, tx, cr, 0, &zp, len);
		if (len != 0)
			bcopy(link, zp->z_phys + 1, len);
	} else {
		dmu_buf_t *dbp;

		zfs_mknode(dzp, vap, &zoid, tx, cr, 0, &zp, 0);

		/*
		 * Nothing can access the znode yet so no locking needed
		 * for growing the znode's blocksize.
		 */
		zfs_grow_blocksize(zp, len, tx);

		VERIFY(0 == dmu_buf_hold(zfsvfs->z_os, zoid, 0, FTAG, &dbp));
		dmu_buf_will_dirty(dbp, tx);

		ASSERT3U(len, <=, dbp->db_size);
		bcopy(link, dbp->db_data, len);
		dmu_buf_rele(dbp, FTAG);
	}
	zp->z_phys->zp_size = len;

	/*
	 * Insert the new object into the directory.
	 */
	(void) zfs_link_create(dl, zp, tx, ZNEW);
#ifndef __APPLE__
out:
#endif
	if (error == 0)
		zfs_log_symlink(zilog, tx, TX_SYMLINK, dzp, zp, name, link);

	dmu_tx_commit(tx);

#ifdef __APPLE__
        /*
         * Obtain and attach the vnode after committing the transaction
         */
        zfs_attach_vnode(zp);
#endif

	zfs_dirent_unlock(dl);
// Issue 34
#ifdef __APPLE__
        vnode_put(ZTOV(zp));
#else
	VN_RELE(ZTOV(zp));
#endif

	ZFS_EXIT(zfsvfs);
	return (error);
}

/*
 * Return, in the buffer contained in the provided uio structure,
 * the symbolic path referred to by vp.
 *
 *	IN:	vp	- vnode of symbolic link.
 *		uoip	- structure to contain the link path.
 *		cr	- credentials of caller.
 *
 *	OUT:	uio	- structure to contain the link path.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	vp - atime updated
 */
/* ARGSUSED */
static int
#ifdef __APPLE__
zfs_vnop_readlink(struct vnop_readlink_args *ap)
#else
zfs_readlink(vnode_t *vp, uio_t *uio, cred_t *cr)
#endif /* __APPLE__ */
{
#ifdef __APPLE__
	struct vnode  *vp = ap->a_vp;
	struct uio  *uio = ap->a_uio;
#endif
	znode_t		*zp = VTOZ(vp);
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	size_t		bufsz;
	int		error;

	ZFS_ENTER(zfsvfs);

	bufsz = (size_t)zp->z_phys->zp_size;
	if (bufsz + sizeof (znode_phys_t) <= zp->z_dbuf->db_size) {
#ifdef __APPLE__
		error = uio_move((caddr_t)(zp->z_phys + 1),
		    MIN((size_t)bufsz, uio_resid(uio)), UIO_READ, uio);
#else
		error = uiomove(zp->z_phys + 1,
		    MIN((size_t)bufsz, uio->uio_resid), UIO_READ, uio);
#endif /* __APPLE__ */
	} else {
		dmu_buf_t *dbp;
		error = dmu_buf_hold(zfsvfs->z_os, zp->z_id, 0, FTAG, &dbp);
		if (error) {
			ZFS_EXIT(zfsvfs);
			return (error);
		}
#ifdef __APPLE__
		error = uio_move(dbp->db_data,
		    MIN((size_t)bufsz, uio_resid(uio)), UIO_READ, uio);
#else
		error = uiomove(dbp->db_data,
		    MIN((size_t)bufsz, uio->uio_resid), UIO_READ, uio);
#endif /* __APPLE__ */
		dmu_buf_rele(dbp, FTAG);
	}

	ZFS_ACCESSTIME_STAMP(zfsvfs, zp);
	ZFS_EXIT(zfsvfs);
	return (error);
}

/*
 * Insert a new entry into directory tdvp referencing svp.
 *
 *	IN:	tdvp	- Directory to contain new entry.
 *		svp	- vnode of new entry.
 *		name	- name of new entry.
 *		cr	- credentials of caller.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	tdvp - ctime|mtime updated
 *	 svp - ctime updated
 */
/* ARGSUSED */
static int
#ifdef __APPLE__
zfs_vnop_link(struct vnop_link_args *ap)
#else
zfs_link(vnode_t *tdvp, vnode_t *svp, char *name, cred_t *cr)
#endif /* __APPLE__ */
{
#ifdef __APPLE__
	struct vnode  *tdvp = ap->a_tdvp;
	struct vnode  *svp = ap->a_vp;
	struct componentname  *cnp = ap->a_cnp;
        char * name = (char *)cnp->cn_nameptr;
#endif
	znode_t		*dzp = VTOZ(tdvp);
	znode_t		*tzp, *szp;
	zfsvfs_t	*zfsvfs = dzp->z_zfsvfs;
	zilog_t		*zilog = zfsvfs->z_log;
	zfs_dirlock_t	*dl;
	dmu_tx_t	*tx;
	vnode_t		*realvp;
	int		error;

#ifdef __APPLE__
	ASSERT(vnode_isdir(tdvp));
#else
	ASSERT(tdvp->v_type == VDIR);
#endif

	ZFS_ENTER(zfsvfs);

#ifdef __APPLE__
        if (vnode_mount(svp) != vnode_mount(tdvp)) {
                ZFS_EXIT(zfsvfs);
                return (EXDEV);
        }

        if (cnp->cn_namelen >= ZAP_MAXNAMELEN) {
                ZFS_EXIT(zfsvfs);
                return (ENAMETOOLONG);
        }
#else
        if (VOP_REALVP(svp, &realvp) == 0)
                svp = realvp;

        if (svp->v_vfsp != tdvp->v_vfsp) {
                ZFS_EXIT(zfsvfs);
                return (EXDEV);
        }
#endif /*!__APPLE__*/

	szp = VTOZ(svp);
top:
	/*
	 * We do not support links between attributes and non-attributes
	 * because of the potential security risk of creating links
	 * into "normal" file space in order to circumvent restrictions
	 * imposed in attribute space.
	 */
	if ((szp->z_phys->zp_flags & ZFS_XATTR) !=
	    (dzp->z_phys->zp_flags & ZFS_XATTR)) {
		ZFS_EXIT(zfsvfs);
		return (EINVAL);
	}

	/*
	 * POSIX dictates that we return EPERM here.
	 * Better choices include ENOTSUP or EISDIR.
	 */
#ifdef __APPLE__
	if (vnode_isdir(svp)) 
#else
	if (svp->v_type == VDIR) 
#endif
	{
		ZFS_EXIT(zfsvfs);
		return (EPERM);
	}

#ifndef __APPLE__
	/* On Mac OS X, VFS performs the necessary access checks. */
	if ((uid_t)szp->z_phys->zp_uid != crgetuid(cr) &&
	    secpolicy_basic_link(cr) != 0) {
		ZFS_EXIT(zfsvfs);
		return (EPERM);
	}

	if (error = zfs_zaccess(dzp, ACE_ADD_FILE, cr)) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}
#endif /*!__APPLE__*/

	/*
	 * Attempt to lock directory; fail if entry already exists.
	 */
#ifdef __APPLE__
	if (error = zfs_dirent_lock(&dl, dzp, cnp, &tzp, ZNEW)) {
#else
	if (error = zfs_dirent_lock(&dl, dzp, name, &tzp, ZNEW)) {
#endif
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_bonus(tx, szp->z_id);
	dmu_tx_hold_zap(tx, dzp->z_id, TRUE, name);
	error = dmu_tx_assign(tx, zfsvfs->z_assign);
	if (error) {
		zfs_dirent_unlock(dl);
		if (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT) {
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	error = zfs_link_create(dl, szp, tx, 0);

	if (error == 0)
		zfs_log_link(zilog, tx, TX_LINK, dzp, szp, name);

	dmu_tx_commit(tx);

	zfs_dirent_unlock(dl);

#ifndef __APPLE__
        if (error == 0) {
                vnevent_link(svp);
        }
#endif /* !__APPLE__ */

	ZFS_EXIT(zfsvfs);
	return (error);
}

static int
zfs_vnop_pagein(struct vnop_pagein_args *ap)
{
	struct vnode	*vp = ap->a_vp;
	offset_t	off = ap->a_f_offset;
	size_t		len = ap->a_size;
	upl_t		upl = ap->a_pl;
	vm_offset_t	upl_offset = ap->a_pl_offset;
	znode_t		*zp = VTOZ(vp);
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	vm_offset_t	vaddr;
	int		flags = ap->a_flags;
	int		need_unlock = 0;
	int		error = 0;

	if (upl == (upl_t)NULL)
		panic("zfs_vnop_pagein: no upl!");

	if (len <= 0) {
		printf("zfs_vnop_pagein: invalid size %ld", len);
		if (!(flags & UPL_NOCOMMIT))
			(void) ubc_upl_abort(upl, 0);
		return (EINVAL);
	}

	ZFS_ENTER(zfsvfs);

	ASSERT(vn_has_cached_data(vp));
	ASSERT(zp->z_dbuf_held && zp->z_phys);

	/* can't fault past EOF */
	if ((off < 0) || (off >= zp->z_phys->zp_size) ||
	    (len & PAGE_MASK) || (upl_offset & PAGE_MASK)) {
		ZFS_EXIT(zfsvfs);
		if (!(flags & UPL_NOCOMMIT))
			ubc_upl_abort_range(upl, upl_offset, len,
				UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY);
		return (EFAULT);
	}

	/*
	 * If we already own the lock, then we must be page faulting
	 * in the middle of a write to this file (i.e., we are writing
	 * to this file using data from a mapped region of the file).
	 */
	if (!rw_write_held(&zp->z_map_lock)) {
		rw_enter(&zp->z_map_lock, RW_WRITER);
		need_unlock = TRUE;
	}

	ubc_upl_map(upl, &vaddr);
	vaddr += upl_offset;
	/*
	 * Fill pages with data from the file.
	 */
	while (len > 0) {
		if (len < PAGESIZE)
			break;

		error = dmu_read(zp->z_zfsvfs->z_os, zp->z_id, off, PAGESIZE, (void *)vaddr);
		if (error) {
			printf("zfs_vnop_pagein: dmu_read err %d\n", error);
			break;
		}
		off += PAGESIZE;
		vaddr += PAGESIZE;
		if (len > PAGESIZE)
			len -= PAGESIZE;
		else
			len = 0;
	}
	ubc_upl_unmap(upl);

	if (!(flags & UPL_NOCOMMIT)) {
		if (error) {
			ubc_upl_abort_range(upl, upl_offset, ap->a_size,
					    UPL_ABORT_ERROR |
					    UPL_ABORT_FREE_ON_EMPTY);
		} else {
			ubc_upl_commit_range(upl, upl_offset, ap->a_size,
					     UPL_COMMIT_CLEAR_DIRTY |
					     UPL_COMMIT_FREE_ON_EMPTY);
		}
	}
	ZFS_ACCESSTIME_STAMP(zfsvfs, zp);

	/*
	 * We can't grab the range lock for the page as reader which would
	 * stop truncation as this leads to deadlock. So we need to recheck
	 * the file size.
	 */
	if (ap->a_f_offset >= zp->z_phys->zp_size) {
		error = EFAULT;
	}
	if (need_unlock) {
		rw_exit(&zp->z_map_lock);
	}

	ZFS_EXIT(zfsvfs);
	return (error);
}

#ifndef __APPLE__
/*
 * zfs_null_putapage() is used when the file system has been force
 * unmounted. It just drops the pages.
 */
/* ARGSUSED */
static int
zfs_null_putapage(vnode_t *vp, page_t *pp, u_offset_t *offp,
		size_t *lenp, int flags, cred_t *cr)
{
	pvn_write_done(pp, B_INVAL|B_FORCE|B_ERROR);
	return (0);
}
#endif /* !__APPLE__ */

/*
 * Push a page out to disk, klustering if possible.
 *
 *	IN:	vp	- file to push page to.
 *		pp	- page to push.
 *		flags	- additional flags.
 *		cr	- credentials of caller.
 *
 *	OUT:	offp	- start of range pushed.
 *		lenp	- len of range pushed.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * NOTE: callers must have locked the page to be pushed.  On
 * exit, the page (and all other pages in the kluster) must be
 * unlocked.
 */
/* ARGSUSED */
static int
#ifdef __APPLE__
zfs_vnop_pageout(struct vnop_pageout_args *ap)
#else
zfs_putapage(vnode_t *vp, page_t *pp, u_offset_t *offp,
		size_t *lenp, int flags, cred_t *cr)
#endif /* __APPLE__ */
{
#ifdef __APPLE__
// Issue 27
	struct vnode	*vp = ap->a_vp;
	int		flags = ap->a_flags;
	upl_t		upl = ap->a_pl;
	vm_offset_t	upl_offset = ap->a_pl_offset;
	size_t          len = ap->a_size;
	offset_t        off = ap->a_f_offset;
#else
	u_offset_t	off, koff;
	size_t		len, klen;
#endif /* __APPLE__ */
	znode_t		*zp = VTOZ(vp);
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	zilog_t		*zilog = zfsvfs->z_log;
	dmu_tx_t	*tx;
	rl_t		*rl;
	uint64_t	filesz;
	int		err;

#ifdef __APPLE__
	if (zfsvfs == NULL) {
		if (!(flags & UPL_NOCOMMIT))
			ubc_upl_abort(upl, UPL_ABORT_DUMP_PAGES |
			              UPL_ABORT_FREE_ON_EMPTY);
		return (ENXIO);
	}

	ZFS_ENTER(zfsvfs);

	ASSERT(vn_has_cached_data(vp));
	ASSERT(zp->z_dbuf_held && zp->z_phys);

	if (upl == (upl_t)NULL) {
		panic("zfs_vnop_pageout: no upl!");
	}
	if (len <= 0) {
		printf("zfs_vnop_pageout: invalid size %ld", len);
		if (!(flags & UPL_NOCOMMIT))
			(void) ubc_upl_abort(upl, 0);
		err = EINVAL;
		goto exit;
	}
        if (vnode_vfsisrdonly(vp)) {
		if (!(flags & UPL_NOCOMMIT))
		        ubc_upl_abort_range(upl, upl_offset, len,
		                            UPL_ABORT_FREE_ON_EMPTY);
		err = EROFS;
		goto exit;
	}
	filesz = zp->z_phys->zp_size; /* get consistent copy of zp_size */
	if ((off < 0) || (off >= filesz) ||
	    (off & PAGE_MASK_64) || (len & PAGE_MASK)) {
		if (!(flags & UPL_NOCOMMIT))
			ubc_upl_abort_range(upl, upl_offset, len,
			                    UPL_ABORT_FREE_ON_EMPTY);
		err = EINVAL;
		goto exit;
	}
	len = MIN(len, filesz - off);

#else /* OpenSolaris */

	filesz = zp->z_phys->zp_size;
	off = pp->p_offset;
	len = PAGESIZE;
	/*
	 * If our blocksize is bigger than the page size, try to kluster
	 * muiltiple pages so that we write a full block (thus avoiding
	 * a read-modify-write).
	 */
	if (off < filesz && zp->z_blksz > PAGESIZE) {
		if (!ISP2(zp->z_blksz)) {
			/* Only one block in the file. */
			klen = P2ROUNDUP((ulong_t)zp->z_blksz, PAGESIZE);
			koff = 0;
		} else {
			klen = zp->z_blksz;
			koff = P2ALIGN(off, (u_offset_t)klen);
		}
		ASSERT(koff <= filesz);
		if (koff + klen > filesz)
			klen = P2ROUNDUP(filesz - koff, (uint64_t)PAGESIZE);
		pp = pvn_write_kluster(vp, pp, &off, &len, koff, klen, flags);
	}
	ASSERT3U(btop(len), ==, btopr(len));
#endif /* __APPLE__ */
top:
	rl = zfs_range_lock(zp, off, len, RL_WRITER);
	/*
	 * Can't push pages past end-of-file.
	 */
	filesz = zp->z_phys->zp_size;
	if (off >= filesz) {
		/* ignore all pages */
		err = 0;
		goto out;
	} else if (off + len > filesz) {
#if 0
		int npages = btopr(filesz - off);
		page_t *trunc;

		page_list_break(&pp, &trunc, npages);
		/* ignore pages past end of file */
		if (trunc)
			pvn_write_done(trunc,  flags);
#endif
		len = filesz - off;
	}

	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_write(tx, zp->z_id, off, len);
	dmu_tx_hold_bonus(tx, zp->z_id);
	err = dmu_tx_assign(tx, zfsvfs->z_assign);
	if (err != 0) {
		if (err == ERESTART && zfsvfs->z_assign == TXG_NOWAIT) {
			zfs_range_unlock(rl);
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		goto out;
	}

#ifdef __APPLE__
	if (len <= PAGESIZE) 
#else
	if (zp->z_blksz <= PAGESIZE) 
#endif
	{
#ifdef __APPLE__
		caddr_t va;
#else
                caddr_t va = ppmapin(pp, PROT_READ, (caddr_t)-1);
#endif /* __APPLE__ */
		ASSERT3U(len, <=, PAGESIZE);
#ifdef __APPLE__
		ubc_upl_map(upl, (vm_offset_t *)&va);
		va += upl_offset;
#endif /* __APPLE__ */
		dmu_write(zfsvfs->z_os, zp->z_id, off, len, va, tx);
#ifdef __APPLE__
		ubc_upl_unmap(upl);
#else
                ppmapout(va);
#endif /* __APPLE__ */
	} else {
		err = dmu_write_pages(zfsvfs->z_os, zp->z_id, off, len, upl, tx);
	}

	if (err == 0) {
		zfs_time_stamper(zp, CONTENT_MODIFIED, tx);
		zfs_log_write(zilog, tx, TX_WRITE, zp, off, len, 0);
		dmu_tx_commit(tx);
#ifdef __APPLE__
	} else {
		/* XXX TBD, but at least clean up the tx */
		dmu_tx_abort(tx);
#endif
	}
out:
	zfs_range_unlock(rl);

#ifdef __APPLE__
	if (flags & UPL_IOSYNC)
		zil_commit(zfsvfs->z_log, UINT64_MAX, zp->z_id);

	if (!(flags & UPL_NOCOMMIT)) {
		if (err)
			ubc_upl_abort_range(upl, upl_offset, ap->a_size,
					    UPL_ABORT_ERROR |
					    UPL_ABORT_FREE_ON_EMPTY);
		else
			ubc_upl_commit_range(upl, upl_offset, ap->a_size,
					     UPL_COMMIT_CLEAR_DIRTY |
					     UPL_COMMIT_FREE_ON_EMPTY);
	}
#else
	pvn_write_done(pp, (err ? B_ERROR : 0) | flags);
	if (offp)
		*offp = off;
	if (lenp)
		*lenp = len;
#endif /* __APPLE__ */

#ifdef __APPLE__
exit:
	ZFS_EXIT(zfsvfs);
#endif /* __APPLE__ */
	return (err);
}

#ifdef __APPLE__
static int
zfs_vnop_mmap(struct vnop_mmap_args *ap)
{
	struct vnode *vp = ap->a_vp;
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;

	ZFS_ENTER(zfsvfs);

	if ( !vnode_isreg(vp) ) {
		ZFS_EXIT(zfsvfs);
		return (ENODEV);
	}

	rw_enter(&zp->z_map_lock, RW_WRITER);
	zp->z_mmapped = 1;
	rw_exit(&zp->z_map_lock);

	ZFS_EXIT(zfsvfs);
	return (0);
}
#endif /* __APPLE__ */

static int
zfs_vnop_inactive(struct vnop_inactive_args *ap)
{
	struct vnode  *vp = ap->a_vp;
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	znode_phys_t  *pzp = zp->z_phys;

	rw_enter(&zfsvfs->z_unmount_inactive_lock, RW_READER);	

#ifdef ZFS_DEBUG
	znode_stalker(zp, N_vnop_inactive);
#endif
	/* If we're force unmounting, go to reclaim */
	if (zfsvfs->z_unmounted) {
		rw_exit(&zfsvfs->z_unmount_inactive_lock);
		return(0);
	}

	/*
	 * Destroy the on-disk znode and flag the vnode to be recycled. 
	 * If this was a directory then zfs_link_destroy will have set 
	 * zp_links = 0
	 */
	if (pzp->zp_links == 0) {
		vnode_recycle(vp);
	}

	rw_exit(&zfsvfs->z_unmount_inactive_lock);
	return (0);
}

#ifdef __APPLE__
static int
zfs_vnop_reclaim(struct vnop_reclaim_args *ap)
{
	struct vnode  *vp = ap->a_vp;
	znode_t *zp = VTOZ(vp);
	if (zp == NULL)
	{
		// Issue 39
		vnode_clearfsnode(vp);
		return(0);
	}
	
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;

	rw_enter(&zfsvfs->z_unmount_inactive_lock, RW_READER);

#ifdef ZFS_DEBUG
	znode_stalker(zp, N_vnop_reclaim);
#endif

      	mutex_enter(&zp->z_lock);
	if (zp->z_dbuf_held && vfs_isforce(zfsvfs->z_vfs)) {
		/*
		 * A forced unmount relclaim prior to zfs_unmount.
		 * Relinquish the vnode back to VFS and let
		 * zfs_objset_close() deal with the znode.
		 */
		zp->z_vnode = NULL;
		mutex_exit(&zp->z_lock);
	} else {
		mutex_exit(&zp->z_lock);
		zfs_zinactive(zp);
	}

	/* Mark the vnode as not used and NULL out the vp's data*/
	vnode_removefsref(vp);
	vnode_clearfsnode(vp);
	rw_exit(&zfsvfs->z_unmount_inactive_lock);
	return (0);
}
#endif /* __APPLE__ */

#ifdef __APPLE__
static int
zfs_vnop_mknod(struct vnop_mknod_args *ap)
{
	return zfs_vnop_create((struct vnop_create_args *)ap);
}
#endif /* __APPLE__ */

#ifdef __APPLE__
static int
zfs_vnop_allocate(struct vnop_allocate_args *ap)
{
	struct vnode *vp = ap->a_vp;
	off_t length = ap->a_length;
	znode_t *zp;
	zfsvfs_t *zfsvfs;
	int err;

	/* Sanity checks */
	if (!vnode_isreg(vp))
		return (EISDIR);
	if (length < (off_t)0)
		return (EINVAL);

	zp = VTOZ(vp);
	zfsvfs = zp->z_zfsvfs;

	err = dmu_allocate_check(zfsvfs->z_os, length);
	
	/*
	 * XXX If space is available, set bytesallocated to size requested.
	 * This is place holder code for when we do a more complete 
	 * preallocate solution later.
	 */
	if(!err)
		*(ap->a_bytesallocated) += length;
	return (err);
}
#endif /* __APPLE__ */


#ifdef __APPLE__ 
static int 
zfs_vnop_whiteout(struct vnop_whiteout_args *ap)
{
	struct vnode *vp = NULLVP;
	int error = 0;

	switch (ap->a_flags) {
		case LOOKUP: {
			error = 0;
			break;
		}
		case CREATE: {
			struct vnop_mknod_args mknod_args;
			struct vnode_attr va;

			VATTR_INIT(&va);
			VATTR_SET(&va, va_type, VREG);
			VATTR_SET(&va, va_mode, S_IFWHT);
			VATTR_SET(&va, va_uid, 0);
			VATTR_SET(&va, va_gid, 0);

			mknod_args.a_desc = &vnop_mknod_desc;
			mknod_args.a_dvp = ap->a_dvp;
			mknod_args.a_vpp = &vp;
			mknod_args.a_cnp = ap->a_cnp;
			mknod_args.a_vap = &va;
			mknod_args.a_context = ap->a_context;
			
			error = zfs_vnop_mknod(&mknod_args);
			/*
			 * No need to release the vnode since
			 * a vnode isn't created for whiteouts.
			 */
			break;
		}
		case DELETE: {
			struct vnop_remove_args remove_args;
			struct vnop_lookup_args lookup_args;

			lookup_args.a_dvp = ap->a_dvp;
			lookup_args.a_vpp = &vp;
			lookup_args.a_cnp = ap->a_cnp;
			lookup_args.a_context = ap->a_context;

			error = zfs_vnop_lookup(&lookup_args);
			if (error) {
				break;
			}
			
			remove_args.a_dvp = ap->a_dvp;
			remove_args.a_vp = vp;
			remove_args.a_cnp = ap->a_cnp;
			remove_args.a_flags = 0;
			remove_args.a_context = ap->a_context;

			error = zfs_vnop_remove(&remove_args);
			vnode_put(vp);
			break;
		}

		default:
			error = EINVAL;
	};

	return (error);
}
#endif /* __APPLE__ */

static int
zfs_vnop_pathconf(struct vnop_pathconf_args *ap)
{
	int32_t  *valp = ap->a_retval;

	switch (ap->a_name) {
	case _PC_LINK_MAX:
		*valp = INT_MAX;
		break;

	case _PC_PIPE_BUF:
		*valp = PIPE_BUF;
		break;

	case _PC_CHOWN_RESTRICTED:
		*valp = 200112;  /* POSIX */
		break;

	case _PC_NO_TRUNC:
		*valp = 200112;  /* POSIX */
		break;

	case _PC_NAME_MAX:
	case _PC_NAME_CHARS_MAX:
		*valp = ZAP_MAXNAMELEN - 1;  /* 255 */
		break;

	case _PC_PATH_MAX:
	case _PC_SYMLINK_MAX:
		*valp = PATH_MAX;  /* 1024 */
		break;

	case _PC_CASE_SENSITIVE:
		*valp = 1;
		break;

	case _PC_CASE_PRESERVING:
		*valp = 1;
		break;

	case _PC_FILESIZEBITS:
		*valp = 64;
		break;

	default:
		return (EINVAL);
	}
	return (0);
}

/*
 * Retrieve the data of an extended attribute.
 */
static int
zfs_vnop_getxattr(struct vnop_getxattr_args *ap)
{
	struct vnode  *vp = ap->a_vp;
	struct vnode  *xdvp = NULLVP;
	struct vnode  *xvp = NULLVP;
	znode_t  *zp = VTOZ(vp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	uio_t  uio = ap->a_uio;
	cred_t  *cr = (cred_t *)vfs_context_ucred(ap->a_context);
	struct componentname  cn;
	int  error;

	ZFS_ENTER(zfsvfs);

	/*
	 * Recursive attributes are not allowed.
	 */
	if (zp->z_phys->zp_flags & ZFS_XATTR) {
		error = EINVAL;
		goto out;
	}

	if (zp->z_phys->zp_xattr == 0) {
		error = ENOATTR;
		goto out;
	}

	/* Grab the hidden attribute directory vnode. */
	if ( (error = zfs_get_xattrdir(zp, &xdvp, cr, 0)) ) {
		goto out;
	}

	bzero(&cn, sizeof (cn));
	cn.cn_nameiop = LOOKUP;
	cn.cn_flags = ISLASTCN;
	cn.cn_nameptr = (char *)ap->a_name;
	cn.cn_namelen = strlen(cn.cn_nameptr);

	/* Lookup the attribute name. */
	if ( (error = zfs_dirlook(VTOZ(xdvp), &cn, &xvp)) ) {
		if (error == ENOENT)
			error = ENOATTR;
		goto out;
	}

	/* Read the attribute data. */
	if (uio == NULL) {
		znode_t  *xzp = VTOZ(xvp);
	
		mutex_enter(&xzp->z_lock);
		*ap->a_size = (size_t)xzp->z_phys->zp_size;
		mutex_exit(&xzp->z_lock);
	} else {
		error = VNOP_READ(xvp, uio, 0, ap->a_context);
	}
out:
	if (xvp) {
		vnode_put(xvp);
	}
	if (xdvp) {
		vnode_put(xdvp);
	}
	ZFS_EXIT(zfsvfs);

	return (error);
}

/*
 * Lookup/Create an extended attribute entry.
 *
 * Input arguments:
 *	dzp	- znode for hidden attribute directory
 *	name	- name of attribute
 *	flag	- ZNEW: if the entry already exists, fail with EEXIST.
 *		  ZEXISTS: if the entry does not exist, fail with ENOENT.
 *
 * Output arguments:
 *	vpp	- pointer to the vnode for the entry (NULL if there isn't one)
 *
 * Return value: 0 on success or errno value on failure.
 */
int
zfs_obtain_xattr(znode_t *dzp, const char *name, mode_t mode, cred_t *cr,
                 struct vnode **vpp, int flag)
{
	znode_t  *xzp = NULL;
	zfsvfs_t  *zfsvfs = dzp->z_zfsvfs;
	zilog_t  *zilog = zfsvfs->z_log;
	zfs_dirlock_t  *dl;
	dmu_tx_t  *tx;
	struct vnode_attr  vattr;
	uint64_t  zoid;
	int error;
	struct componentname cn;

	/* zfs_dirent_lock() expects a component name */
	bzero(&cn, sizeof (cn));
	cn.cn_nameiop = LOOKUP;
	cn.cn_flags = ISLASTCN;
	cn.cn_nameptr = (char *)name;
	cn.cn_namelen = strlen(name);
top:
	/* Lock the attribute entry name. */
	if ( (error = zfs_dirent_lock(&dl, dzp, &cn, &xzp, flag)) ) {
		goto out;
	}
	/* If the name already exists, we're done. */
	if (xzp != NULL) {
		zfs_dirent_unlock(dl);
		goto out;
	}
	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_bonus(tx, DMU_NEW_OBJECT);
	dmu_tx_hold_bonus(tx, dzp->z_id);
	dmu_tx_hold_zap(tx, dzp->z_id, TRUE, (char *)name);
	if (dzp->z_phys->zp_flags & ZFS_INHERIT_ACE) {
		dmu_tx_hold_write(tx, DMU_NEW_OBJECT, 0, SPA_MAXBLOCKSIZE);
	}
	error = dmu_tx_assign(tx, zfsvfs->z_assign);
	if (error) {
		zfs_dirent_unlock(dl);
		if ((error == ERESTART) && (zfsvfs->z_assign == TXG_NOWAIT)) {
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		goto out;
	}

	VATTR_INIT(&vattr);
	VATTR_SET(&vattr, va_type, VREG);
	VATTR_SET(&vattr, va_mode, mode & ~S_IFMT);
	zfs_mknode(dzp, &vattr, &zoid, tx, cr, 0, &xzp, 0);

	ASSERT(xzp->z_id == zoid);
	(void) zfs_link_create(dl, xzp, tx, ZNEW);
	zfs_log_create(zilog, tx, TX_CREATE, dzp, xzp, (char *)name);
	dmu_tx_commit(tx);

	/*
	 * Obtain and attach the vnode after committing the transaction
	 */
	zfs_attach_vnode(xzp);

	zfs_dirent_unlock(dl);
out:
	if (error == EEXIST)
		error = ENOATTR;
	if (xzp)
		*vpp = ZTOV(xzp);
	return (error);
}

#ifndef __APPLE__
/*
 * Copy the portion of the file indicated from pages into the file.
 * The pages are stored in a page list attached to the files vnode.
 *
 *	IN:	vp	- vnode of file to push page data to.
 *		off	- position in file to put data.
 *		len	- amount of data to write.
 *		flags	- flags to control the operation.
 *		cr	- credentials of caller.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	vp - ctime|mtime updated
 */
static int
zfs_putpage(vnode_t *vp, offset_t off, size_t len, int flags, cred_t *cr)
{
	znode_t		*zp = VTOZ(vp);
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	page_t		*pp;
	size_t		io_len;
	u_offset_t	io_off;
	uint64_t	filesz;
	int		error = 0;

	ZFS_ENTER(zfsvfs);

	ASSERT(zp->z_dbuf_held && zp->z_phys);

	if (len == 0) {
		/*
		 * Search the entire vp list for pages >= off.
		 */
		error = pvn_vplist_dirty(vp, (u_offset_t)off, zfs_putapage,
		    flags, cr);
		goto out;
	}

	filesz = zp->z_phys->zp_size; /* get consistent copy of zp_size */
	if (off > filesz) {
		/* past end of file */
		ZFS_EXIT(zfsvfs);
		return (0);
	}

	len = MIN(len, filesz - off);

	for (io_off = off; io_off < off + len; io_off += io_len) {
		if ((flags & B_INVAL) || ((flags & B_ASYNC) == 0)) {
			pp = page_lookup(vp, io_off,
			    (flags & (B_INVAL | B_FREE)) ? SE_EXCL : SE_SHARED);
		} else {
			pp = page_lookup_nowait(vp, io_off,
			    (flags & B_FREE) ? SE_EXCL : SE_SHARED);
		}

		if (pp != NULL && pvn_getdirty(pp, flags)) {
			int err;

			/*
			 * Found a dirty page to push
			 */
			err = zfs_putapage(vp, pp, &io_off, &io_len, flags, cr);
			if (err)
				error = err;
		} else {
			io_len = PAGESIZE;
		}
	}
out:
	if ((flags & B_ASYNC) == 0)
		zil_commit(zfsvfs->z_log, UINT64_MAX, zp->z_id);
	ZFS_EXIT(zfsvfs);
	return (error);
}
#endif /* !__APPLE__ */
	
#ifndef __APPLE__
void
zfs_inactive(vnode_t *vp, cred_t *cr)
{
	znode_t	*zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	int error;

	rw_enter(&zfsvfs->z_unmount_inactive_lock, RW_READER);
	if (zfsvfs->z_unmounted) {
		ASSERT(zp->z_dbuf_held == 0);

		if (vn_has_cached_data(vp)) {
			(void) pvn_vplist_dirty(vp, 0, zfs_null_putapage,
			    B_INVAL, cr);
		}

		mutex_enter(&zp->z_lock);
		vp->v_count = 0; /* count arrives as 1 */
		if (zp->z_dbuf == NULL) {
			mutex_exit(&zp->z_lock);
			zfs_znode_free(zp);
		} else {
			mutex_exit(&zp->z_lock);
		}
		rw_exit(&zfsvfs->z_unmount_inactive_lock);
		VFS_RELE(zfsvfs->z_vfs);
		return;
	}

	/*
	 * Attempt to push any data in the page cache.  If this fails
	 * we will get kicked out later in zfs_zinactive().
	 */
	if (vn_has_cached_data(vp)) {
		(void) pvn_vplist_dirty(vp, 0, zfs_putapage, B_INVAL|B_ASYNC,
		    cr);
	}

	if (zp->z_atime_dirty && zp->z_unlinked == 0) {
		dmu_tx_t *tx = dmu_tx_create(zfsvfs->z_os);

		dmu_tx_hold_bonus(tx, zp->z_id);
		error = dmu_tx_assign(tx, TXG_WAIT);
		if (error) {
			dmu_tx_abort(tx);
		} else {
			dmu_buf_will_dirty(zp->z_dbuf, tx);
			mutex_enter(&zp->z_lock);
			zp->z_atime_dirty = 0;
			mutex_exit(&zp->z_lock);
			dmu_tx_commit(tx);
		}
	}

	zfs_zinactive(zp);
	rw_exit(&zfsvfs->z_unmount_inactive_lock);
}
#endif /* !__APPLE__ */

#ifndef __APPLE__	
/*
 * Bounds-check the seek operation.
 *
 *	IN:	vp	- vnode seeking within
 *		ooff	- old file offset
 *		noffp	- pointer to new file offset
 *
 *	RETURN:	0 if success
 *		EINVAL if new offset invalid
 */
/* ARGSUSED */
static int
zfs_seek(vnode_t *vp, offset_t ooff, offset_t *noffp)
{
 	if (vp->v_type == VDIR)
		return (0);
	return ((*noffp < 0 || *noffp > MAXOFFSET_T) ? EINVAL : 0);
}
#endif /* !__APPLE__ */

#ifndef __APPLE__
/*
 * Pre-filter the generic locking function to trap attempts to place
 * a mandatory lock on a memory mapped file.
 */
static int
zfs_frlock(vnode_t *vp, int cmd, flock64_t *bfp, int flag, offset_t offset,
    flk_callback_t *flk_cbp, cred_t *cr)
{
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	int error;

	ZFS_ENTER(zfsvfs);

	/*
	 * We are following the UFS semantics with respect to mapcnt
	 * here: If we see that the file is mapped already, then we will
	 * return an error, but we don't worry about races between this
	 * function and zfs_map().
	 */
	if (zp->z_mapcnt > 0 && MANDMODE((mode_t)zp->z_phys->zp_mode)) {
		ZFS_EXIT(zfsvfs);
		return (EAGAIN);
	}
	error = fs_frlock(vp, cmd, bfp, flag, offset, flk_cbp, cr);
	ZFS_EXIT(zfsvfs);
	return (error);
}
#endif /* !__APPLE__ */

/*
 * Set the data of an extended attribute.
 */
static int
zfs_vnop_setxattr(struct vnop_setxattr_args *ap)
{
	struct vnode  *vp = ap->a_vp;
	struct vnode  *xdvp = NULLVP;
	struct vnode  *xvp = NULLVP;
	znode_t  *zp = VTOZ(vp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	uio_t  uio = ap->a_uio;
	cred_t  *cr = (cred_t *)vfs_context_ucred(ap->a_context);
	int  flag;
	int  error;

	ZFS_ENTER(zfsvfs);

	/*
	 * Recursive attributes are not allowed.
	 */
	if (zp->z_phys->zp_flags & ZFS_XATTR) {
		error = EINVAL;
		goto out;
	}

	if (strlen(ap->a_name) >= ZAP_MAXNAMELEN) {
		error = ENAMETOOLONG;
		goto out;
	}

	/* Grab the hidden attribute directory vnode. */
	if ( (error = zfs_get_xattrdir(zp, &xdvp, cr, CREATE_XATTR_DIR)) ) {
		goto out;
	}

	if (ap->a_options & XATTR_CREATE)
		flag = ZNEW;     /* expect no pre-existing entry */
	else if (ap->a_options & XATTR_REPLACE)
		flag = ZEXISTS;  /* expect an existing entry */
	else
		flag = 0;

	/* Lookup or create the named attribute. */
	error = zfs_obtain_xattr(VTOZ(xdvp), ap->a_name,
	                         VTOZ(vp)->z_phys->zp_mode, cr, &xvp, flag);
	if (error)
		goto out;

	/* Write the attribute data. */
	ASSERT(uio != NULL);
	error = VNOP_WRITE(xvp, uio, 0, ap->a_context);

out:
	if (xdvp) {
		vnode_put(xdvp);
	}
	if (xvp) {
		vnode_put(xvp);
	}
	ZFS_EXIT(zfsvfs);

	return (error);
}

/*
 * Remove an extended attribute.
 */
static int
zfs_vnop_removexattr(struct vnop_removexattr_args *ap)
{
	struct vnode  *vp = ap->a_vp;
	struct vnode  *xdvp = NULLVP;
	struct vnode  *xvp = NULLVP;
	znode_t  *zp = VTOZ(vp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	cred_t  *cr = (cred_t *)vfs_context_ucred(ap->a_context);
	struct vnop_remove_args  args;
	struct componentname  cn;
	int  error;

	ZFS_ENTER(zfsvfs);

	/*
	 * Recursive attributes are not allowed.
	 */
	if (zp->z_phys->zp_flags & ZFS_XATTR) {
		error = EINVAL;
		goto out;
	}

	if (zp->z_phys->zp_xattr == 0) {
		error = ENOATTR;
		goto out;
	}

	/* Grab the hidden attribute directory vnode. */
	if ( (error = zfs_get_xattrdir(zp, &xdvp, cr, 0)) ) {
		goto out;
	}

	bzero(&cn, sizeof (cn));
	cn.cn_nameiop = DELETE;
	cn.cn_flags = ISLASTCN;
	cn.cn_nameptr = (char *)ap->a_name;
	cn.cn_namelen = strlen(cn.cn_nameptr);

	/* Lookup the attribute name. */
	if ( (error = zfs_dirlook(VTOZ(xdvp), &cn, &xvp)) ) {
		if (error == ENOENT)
			error = ENOATTR;
		goto out;
	}

	args.a_desc = &vnop_remove_desc;
	args.a_dvp = xdvp;
	args.a_vp = xvp;
	args.a_cnp = &cn;
	args.a_flags = 0;
	args.a_context = ap->a_context;

	error = zfs_vnop_remove(&args);

out:
	if (xvp) {
		vnode_put(xvp);
	}
	if (xdvp) {
		vnode_put(xdvp);
	}
	ZFS_EXIT(zfsvfs);

	return (error);
}

/*
 * Generate a list of extended attribute names.
 */
static int
zfs_vnop_listxattr(struct vnop_listxattr_args *ap)
{
	struct vnode  *vp = ap->a_vp;
	struct vnode  *xdvp = NULLVP;
	znode_t  *zp = VTOZ(vp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	uio_t  uio = ap->a_uio;
	cred_t  *cr = (cred_t *)vfs_context_ucred(ap->a_context);
	zap_cursor_t  zc;
	zap_attribute_t  za;
	objset_t  *os;
	size_t size = 0;
	char  *nameptr;
	char  nfd_name[ZAP_MAXNAMELEN];
	size_t  namelen;
	int  error = 0;

	ZFS_ENTER(zfsvfs);

	/*
	 * Recursive attributes are not allowed.
	 */
	if (zp->z_phys->zp_flags & ZFS_XATTR) {
		error = EINVAL;
		goto out;
	}

	/* Do we even have any attributes? */
	if (zp->z_phys->zp_xattr == 0) {
		goto out;  /* all done */
	}
	/* Grab the hidden attribute directory vnode. */
	if (zfs_get_xattrdir(zp, &xdvp, cr, 0) != 0) {
		goto out;
	}
	os = zfsvfs->z_os;

	for (zap_cursor_init(&zc, os, VTOZ(xdvp)->z_id);
	     zap_cursor_retrieve(&zc, &za) == 0;
	     zap_cursor_advance(&zc)) {

		if (xattr_protected(za.za_name))
			continue;     /* skip */

		/*
		 * Mac OS X: non-ascii names are UTF-8 NFC on disk 
		 * so convert to NFD before exporting them.
		 */
		namelen = strlen(za.za_name);
		if (!is_ascii_str(za.za_name) &&
		    utf8_normalizestr((const u_int8_t *)za.za_name, namelen,
				      (u_int8_t *)nfd_name, &namelen,
				      sizeof (nfd_name), UTF_DECOMPOSED) == 0) {
			nameptr = nfd_name;
		} else {
			nameptr = &za.za_name[0];
		}

		++namelen;  /* account for NULL termination byte */
		if (uio == NULL) {
			size += namelen;
		} else {
			if (namelen > uio_resid(uio)) {
				error = ERANGE;
				break;
			}
			error = uiomove((caddr_t)nameptr, namelen, uio);
			if (error) {
				break;
			}
		}
	}
	zap_cursor_fini(&zc);
out:
	if (uio == NULL) {
		*ap->a_size = size;
	}
	if (xdvp) {
		vnode_put(xdvp);
	}
	ZFS_EXIT(zfsvfs);

	return (error);
}

/*
 * Obtain the vnode for a stream.
 */
static int
zfs_vnop_getnamedstream(struct vnop_getnamedstream_args* ap)
{
	struct vnode  *vp = ap->a_vp;
	struct vnode  **svpp = ap->a_svpp;
	struct vnode  *xdvp = NULLVP;
	znode_t  *zp = VTOZ(vp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	cred_t  *cr = (cred_t *)vfs_context_ucred(ap->a_context);
	struct componentname  cn;
	int  error = ENOATTR;

	*svpp = NULLVP;
	ZFS_ENTER(zfsvfs);

	/*
	 * Mac OS X only supports the "com.apple.ResourceFork" stream.
	 */
	if (bcmp(ap->a_name, XATTR_RESOURCEFORK_NAME, sizeof(XATTR_RESOURCEFORK_NAME)) != 0 ||
	    zp->z_phys->zp_xattr == 0) {
		goto out;
	}

	/* Grab the hidden attribute directory vnode. */
	if (zfs_get_xattrdir(zp, &xdvp, cr, 0) != 0) {
		goto out;
	}

	bzero(&cn, sizeof (cn));
	cn.cn_nameiop = LOOKUP;
	cn.cn_flags = ISLASTCN;
	cn.cn_nameptr = (char *)ap->a_name;
	cn.cn_namelen = strlen(cn.cn_nameptr);

	/* Lookup the attribute name. */
	if ( (error = zfs_dirlook(VTOZ(xdvp), &cn, svpp)) ) {
		if (error == ENOENT)
			error = ENOATTR;
	}
out:
	if (xdvp) {
		vnode_put(xdvp);
	}
	ZFS_EXIT(zfsvfs);

	return (error);
}

/*
 * Create a stream.
 */
static int
zfs_vnop_makenamedstream(struct vnop_makenamedstream_args* ap)
{
	struct vnode  *vp = ap->a_vp;
	struct vnode  *xdvp = NULLVP;
	znode_t  *zp = VTOZ(vp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	cred_t  *cr = (cred_t *)vfs_context_ucred(ap->a_context);
	struct componentname  cn;
	struct vnode_attr  vattr;
	struct vnop_create_args  args;
	int  error = 0;

	*ap->a_svpp = NULLVP;
	ZFS_ENTER(zfsvfs);

	/* Only regular files can have a resource fork stream. */
	if ( !vnode_isreg(vp) ) {
		error = EPERM;
		goto out;
	}

	/*
	 * Mac OS X only supports the "com.apple.ResourceFork" stream.
	 */
	if (bcmp(ap->a_name, XATTR_RESOURCEFORK_NAME, sizeof(XATTR_RESOURCEFORK_NAME)) != 0) {
		error = ENOATTR;
		goto out;
	}

	/* Grab the hidden attribute directory vnode. */
	if ( (error = zfs_get_xattrdir(zp, &xdvp, cr, CREATE_XATTR_DIR)) ) {
		goto out;
	}

	bzero(&cn, sizeof (cn));
	cn.cn_nameiop = CREATE;
	cn.cn_flags = ISLASTCN;
	cn.cn_nameptr = (char *)ap->a_name;
	cn.cn_namelen = strlen(cn.cn_nameptr);

	VATTR_INIT(&vattr);
	VATTR_SET(&vattr, va_type, VREG);
	VATTR_SET(&vattr, va_mode, VTOZ(vp)->z_phys->zp_mode & ~S_IFMT);

	args.a_desc = &vnop_create_desc;
	args.a_dvp = xdvp;
	args.a_vpp = ap->a_svpp;
	args.a_cnp = &cn;
	args.a_vap = &vattr;
	args.a_context = ap->a_context;

	error = zfs_vnop_create(&args);
out:
	if (xdvp) {
		vnode_put(xdvp);
	}
	ZFS_EXIT(zfsvfs);

	return (error);
}

/*
 * Remove a stream.
 */
static int
zfs_vnop_removenamedstream(struct vnop_removenamedstream_args* ap)
{
	vnode_t svp = ap->a_svp;
	znode_t  *zp = VTOZ(svp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	int error = 0;

	ZFS_ENTER(zfsvfs);

	/*
	 * Mac OS X only supports the "com.apple.ResourceFork" stream.
	 */
	if (bcmp(ap->a_name, XATTR_RESOURCEFORK_NAME, sizeof(XATTR_RESOURCEFORK_NAME)) != 0) {
		error = ENOATTR;
		goto out;
	}

	/* ### MISING CODE ### */
	printf("zfs_vnop_removenamedstream\n");
	error = EPERM;
out:
	ZFS_EXIT(zfsvfs);

	return (error);
}

static int
zfs_vnop_exchange(__unused struct vnop_exchange_args *ap)
{
	struct vnode  *fvp = ap->a_fvp;
	struct vnode  *tvp = ap->a_tvp;
	znode_t  *fzp;
	znode_t  *tzp;
	zfsvfs_t  *zfsvfs;

	/* The files must be on the same volume. */
	if (vnode_mount(fvp) != vnode_mount(tvp))
		return (EXDEV);

	if (fvp == tvp)
		return (EINVAL);

	/* Only normal files can be exchanged. */
	if (!vnode_isreg(fvp) || !vnode_isreg(tvp))
		return (EINVAL);

	fzp = VTOZ(fvp);
	// tzp = VTOZ(tvp);
	zfsvfs = fzp->z_zfsvfs;

	ZFS_ENTER(zfsvfs);

	/* ADD MISSING CODE HERE */

	ZFS_EXIT(zfsvfs);

	return (EPERM);
}

#ifndef __APPLE__
/*
 * If we can't find a page in the cache, we will create a new page
 * and fill it with file data.  For efficiency, we may try to fill
 * multiple pages at once (klustering).
 */
static int
zfs_fillpage(vnode_t *vp, u_offset_t off, struct seg *seg,
    caddr_t addr, page_t *pl[], size_t plsz, enum seg_rw rw)
{
	znode_t *zp = VTOZ(vp);
	page_t *pp, *cur_pp;
	objset_t *os = zp->z_zfsvfs->z_os;
	caddr_t va;
	u_offset_t io_off, total;
	uint64_t oid = zp->z_id;
	size_t io_len;
	uint64_t filesz;
	int err;

	/*
	 * If we are only asking for a single page don't bother klustering.
	 */
	filesz = zp->z_phys->zp_size; /* get consistent copy of zp_size */
	if (off >= filesz)
		return (EFAULT);
	if (plsz == PAGESIZE || zp->z_blksz <= PAGESIZE) {
		io_off = off;
		io_len = PAGESIZE;
		pp = page_create_va(vp, io_off, io_len, PG_WAIT, seg, addr);
	} else {
		/*
		 * Try to fill a kluster of pages (a blocks worth).
		 */
		size_t klen;
		u_offset_t koff;

		if (!ISP2(zp->z_blksz)) {
			/* Only one block in the file. */
			klen = P2ROUNDUP((ulong_t)zp->z_blksz, PAGESIZE);
			koff = 0;
		} else {
			/*
			 * It would be ideal to align our offset to the
			 * blocksize but doing so has resulted in some
			 * strange application crashes. For now, we
			 * leave the offset as is and only adjust the
			 * length if we are off the end of the file.
			 */
			koff = off;
			klen = plsz;
		}
		ASSERT(koff <= filesz);
		if (koff + klen > filesz)
			klen = P2ROUNDUP(filesz, (uint64_t)PAGESIZE) - koff;
		ASSERT3U(off, >=, koff);
		ASSERT3U(off, <, koff + klen);
		pp = pvn_read_kluster(vp, off, seg, addr, &io_off,
		    &io_len, koff, klen, 0);
	}
	if (pp == NULL) {
		/*
		 * Some other thread entered the page before us.
		 * Return to zfs_getpage to retry the lookup.
		 */
		*pl = NULL;
		return (0);
	}

	/*
	 * Fill the pages in the kluster.
	 */
	cur_pp = pp;
	for (total = io_off + io_len; io_off < total; io_off += PAGESIZE) {
		ASSERT3U(io_off, ==, cur_pp->p_offset);
		va = ppmapin(cur_pp, PROT_READ | PROT_WRITE, (caddr_t)-1);
		err = dmu_read(os, oid, io_off, PAGESIZE, va);
		ppmapout(va);
		if (err) {
			/* On error, toss the entire kluster */
			pvn_read_done(pp, B_ERROR);
			return (err);
		}
		cur_pp = cur_pp->p_next;
	}
out:
	/*
	 * Fill in the page list array from the kluster.  If
	 * there are too many pages in the kluster, return
	 * as many pages as possible starting from the desired
	 * offset `off'.
	 * NOTE: the page list will always be null terminated.
	 */
	pvn_plist_init(pp, pl, plsz, off, io_len, rw);

	return (0);
}
#endif /* !__APPLE__ */

#ifndef __APPLE__
/*
 * Return pointers to the pages for the file region [off, off + len]
 * in the pl array.  If plsz is greater than len, this function may
 * also return page pointers from before or after the specified
 * region (i.e. some region [off', off' + plsz]).  These additional
 * pages are only returned if they are already in the cache, or were
 * created as part of a klustered read.
 *
 *	IN:	vp	- vnode of file to get data from.
 *		off	- position in file to get data from.
 *		len	- amount of data to retrieve.
 *		plsz	- length of provided page list.
 *		seg	- segment to obtain pages for.
 *		addr	- virtual address of fault.
 *		rw	- mode of created pages.
 *		cr	- credentials of caller.
 *
 *	OUT:	protp	- protection mode of created pages.
 *		pl	- list of pages created.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	vp - atime updated
 */
/* ARGSUSED */
static int
zfs_getpage(vnode_t *vp, offset_t off, size_t len, uint_t *protp,
	page_t *pl[], size_t plsz, struct seg *seg, caddr_t addr,
	enum seg_rw rw, cred_t *cr)
{
	znode_t		*zp = VTOZ(vp);
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	page_t		*pp, **pl0 = pl;
	int		need_unlock = 0, err = 0;
	offset_t	orig_off;

	ZFS_ENTER(zfsvfs);

	if (protp)
		*protp = PROT_ALL;

	ASSERT(zp->z_dbuf_held && zp->z_phys);

	/* no faultahead (for now) */
	if (pl == NULL) {
		ZFS_EXIT(zfsvfs);
		return (0);
	}

	/* can't fault past EOF */
	if (off >= zp->z_phys->zp_size) {
		ZFS_EXIT(zfsvfs);
		return (EFAULT);
	}
	orig_off = off;

	/*
	 * If we already own the lock, then we must be page faulting
	 * in the middle of a write to this file (i.e., we are writing
	 * to this file using data from a mapped region of the file).
	 */
	if (rw_owner(&zp->z_map_lock) != curthread) {
		rw_enter(&zp->z_map_lock, RW_WRITER);
		need_unlock = TRUE;
	}

	/*
	 * Loop through the requested range [off, off + len] looking
	 * for pages.  If we don't find a page, we will need to create
	 * a new page and fill it with data from the file.
	 */
	while (len > 0) {
		if (plsz < PAGESIZE)
			break;
		if (pp = page_lookup(vp, off, SE_SHARED)) {
			*pl++ = pp;
			off += PAGESIZE;
			addr += PAGESIZE;
			len -= PAGESIZE;
			plsz -= PAGESIZE;
		} else {
			err = zfs_fillpage(vp, off, seg, addr, pl, plsz, rw);
			if (err)
				goto out;
			/*
			 * klustering may have changed our region
			 * to be block aligned.
			 */
			if (((pp = *pl) != 0) && (off != pp->p_offset)) {
				int delta = off - pp->p_offset;
				len += delta;
				off -= delta;
				addr -= delta;
			}
			while (*pl) {
				pl++;
				off += PAGESIZE;
				addr += PAGESIZE;
				plsz -= PAGESIZE;
				if (len > PAGESIZE)
					len -= PAGESIZE;
				else
					len = 0;
			}
		}
	}

	/*
	 * Fill out the page array with any pages already in the cache.
	 */
	while (plsz > 0) {
		pp = page_lookup_nowait(vp, off, SE_SHARED);
		if (pp == NULL)
			break;
		*pl++ = pp;
		off += PAGESIZE;
		plsz -= PAGESIZE;
	}

	ZFS_ACCESSTIME_STAMP(zfsvfs, zp);
out:
	/*
	 * We can't grab the range lock for the page as reader which would
	 * stop truncation as this leads to deadlock. So we need to recheck
	 * the file size.
	 */
	if (orig_off >= zp->z_phys->zp_size)
		err = EFAULT;
	if (err) {
		/*
		 * Release any pages we have previously locked.
		 */
		while (pl > pl0)
			page_unlock(*--pl);
	}

	*pl = NULL;

	if (need_unlock)
		rw_exit(&zp->z_map_lock);

	ZFS_EXIT(zfsvfs);
	return (err);
}
#endif /* !__APPLE__ */

#ifndef __APPLE__
/*
 * Request a memory map for a section of a file.  This code interacts
 * with common code and the VM system as follows:
 *
 *	common code calls mmap(), which ends up in smmap_common()
 *
 *	this calls VOP_MAP(), which takes you into (say) zfs
 *
 *	zfs_map() calls as_map(), passing segvn_create() as the callback
 *
 *	segvn_create() creates the new segment and calls VOP_ADDMAP()
 *
 *	zfs_addmap() updates z_mapcnt
 */
static int
zfs_map(vnode_t *vp, offset_t off, struct as *as, caddr_t *addrp,
    size_t len, uchar_t prot, uchar_t maxprot, uint_t flags, cred_t *cr)
{
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	segvn_crargs_t	vn_a;
	int		error;

	ZFS_ENTER(zfsvfs);

	if (vp->v_flag & VNOMAP) {
		ZFS_EXIT(zfsvfs);
		return (ENOSYS);
	}

	if (off < 0 || len > MAXOFFSET_T - off) {
		ZFS_EXIT(zfsvfs);
		return (ENXIO);
	}

	if (vp->v_type != VREG) {
		ZFS_EXIT(zfsvfs);
		return (ENODEV);
	}

	/*
	 * If file is locked, disallow mapping.
	 */
	if (MANDMODE((mode_t)zp->z_phys->zp_mode) && vn_has_flocks(vp)) {
		ZFS_EXIT(zfsvfs);
		return (EAGAIN);
	}

	as_rangelock(as);
	if ((flags & MAP_FIXED) == 0) {
		map_addr(addrp, len, off, 1, flags);
		if (*addrp == NULL) {
			as_rangeunlock(as);
			ZFS_EXIT(zfsvfs);
			return (ENOMEM);
		}
	} else {
		/*
		 * User specified address - blow away any previous mappings
		 */
		(void) as_unmap(as, *addrp, len);
	}

	vn_a.vp = vp;
	vn_a.offset = (u_offset_t)off;
	vn_a.type = flags & MAP_TYPE;
	vn_a.prot = prot;
	vn_a.maxprot = maxprot;
	vn_a.cred = cr;
	vn_a.amp = NULL;
	vn_a.flags = flags & ~MAP_TYPE;
	vn_a.szc = 0;
	vn_a.lgrp_mem_policy_flags = 0;

	error = as_map(as, *addrp, len, segvn_create, &vn_a);

	as_rangeunlock(as);
	ZFS_EXIT(zfsvfs);
	return (error);
}
#endif /* !__APPLE__ */

#ifndef __APPLE__
/* ARGSUSED */
static int
zfs_addmap(vnode_t *vp, offset_t off, struct as *as, caddr_t addr,
    size_t len, uchar_t prot, uchar_t maxprot, uint_t flags, cred_t *cr)
{
	uint64_t pages = btopr(len);

	atomic_add_64(&VTOZ(vp)->z_mapcnt, pages);
	return (0);
}
#endif /* !__APPLE__ */

#ifndef __APPLE__
/*
 * The reason we push dirty pages as part of zfs_delmap() is so that we get a
 * more accurate mtime for the associated file.  Since we don't have a way of
 * detecting when the data was actually modified, we have to resort to
 * heuristics.  If an explicit msync() is done, then we mark the mtime when the
 * last page is pushed.  The problem occurs when the msync() call is omitted,
 * which by far the most common case:
 *
 * 	open()
 * 	mmap()
 * 	<modify memory>
 * 	munmap()
 * 	close()
 * 	<time lapse>
 * 	putpage() via fsflush
 *
 * If we wait until fsflush to come along, we can have a modification time that
 * is some arbitrary point in the future.  In order to prevent this in the
 * common case, we flush pages whenever a (MAP_SHARED, PROT_WRITE) mapping is
 * torn down.
 */
/* ARGSUSED */
static int
zfs_delmap(vnode_t *vp, offset_t off, struct as *as, caddr_t addr,
    size_t len, uint_t prot, uint_t maxprot, uint_t flags, cred_t *cr)
{
	uint64_t pages = btopr(len);

	ASSERT3U(VTOZ(vp)->z_mapcnt, >=, pages);
	atomic_add_64(&VTOZ(vp)->z_mapcnt, -pages);

	if ((flags & MAP_SHARED) && (prot & PROT_WRITE) &&
	    vn_has_cached_data(vp))
		(void) VOP_PUTPAGE(vp, off, len, B_ASYNC, cr);

	return (0);
}
#endif /* !__APPLE__ */

#ifndef __APPLE__
/*
 * Free or allocate space in a file.  Currently, this function only
 * supports the `F_FREESP' command.  However, this command is somewhat
 * misnamed, as its functionality includes the ability to allocate as
 * well as free space.
 *
 *	IN:	vp	- vnode of file to free data in.
 *		cmd	- action to take (only F_FREESP supported).
 *		bfp	- section of file to free/alloc.
 *		flag	- current file open mode flags.
 *		offset	- current file offset.
 *		cr	- credentials of caller [UNUSED].
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	vp - ctime|mtime updated
 */
/* ARGSUSED */
static int
zfs_space(vnode_t *vp, int cmd, flock64_t *bfp, int flag,
    offset_t offset, cred_t *cr, caller_context_t *ct)
{
	znode_t		*zp = VTOZ(vp);
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	uint64_t	off, len;
	int		error;

	ZFS_ENTER(zfsvfs);

top:
	if (cmd != F_FREESP) {
		ZFS_EXIT(zfsvfs);
		return (EINVAL);
	}

	if (error = convoff(vp, bfp, 0, offset)) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	if (bfp->l_len < 0) {
		ZFS_EXIT(zfsvfs);
		return (EINVAL);
	}

	off = bfp->l_start;
	len = bfp->l_len; /* 0 means from off to end of file */

	do {
		error = zfs_freesp(zp, off, len, flag, TRUE);
		/* NB: we already did dmu_tx_wait() if necessary */
	} while (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT);

	ZFS_EXIT(zfsvfs);
	return (error);
}
#endif /* !__APPLE__ */

#ifndef __APPLE__
static int
zfs_fid(vnode_t *vp, fid_t *fidp)
{
	znode_t		*zp = VTOZ(vp);
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	uint32_t	gen = (uint32_t)zp->z_phys->zp_gen;
	uint64_t	object = zp->z_id;
	zfid_short_t	*zfid;
	int		size, i;

	ZFS_ENTER(zfsvfs);

	size = (zfsvfs->z_parent != zfsvfs) ? LONG_FID_LEN : SHORT_FID_LEN;
	if (fidp->fid_len < size) {
		fidp->fid_len = size;
		ZFS_EXIT(zfsvfs);
		return (ENOSPC);
	}

	zfid = (zfid_short_t *)fidp;

	zfid->zf_len = size;

	for (i = 0; i < sizeof (zfid->zf_object); i++)
		zfid->zf_object[i] = (uint8_t)(object >> (8 * i));

	/* Must have a non-zero generation number to distinguish from .zfs */
	if (gen == 0)
		gen = 1;
	for (i = 0; i < sizeof (zfid->zf_gen); i++)
		zfid->zf_gen[i] = (uint8_t)(gen >> (8 * i));

	if (size == LONG_FID_LEN) {
		uint64_t	objsetid = dmu_objset_id(zfsvfs->z_os);
		zfid_long_t	*zlfid;

		zlfid = (zfid_long_t *)fidp;

		for (i = 0; i < sizeof (zlfid->zf_setid); i++)
			zlfid->zf_setid[i] = (uint8_t)(objsetid >> (8 * i));

		/* XXX - this should be the generation number for the objset */
		for (i = 0; i < sizeof (zlfid->zf_setgen); i++)
			zlfid->zf_setgen[i] = 0;
	}

	ZFS_EXIT(zfsvfs);
	return (0);
}
#endif /* !__APPLE__ */
	
#ifndef __APPLE__
static int
zfs_pathconf(vnode_t *vp, int cmd, ulong_t *valp, cred_t *cr)
{
	znode_t		*zp, *xzp;
	zfsvfs_t	*zfsvfs;
	zfs_dirlock_t	*dl;
	int		error;

	switch (cmd) {
	case _PC_LINK_MAX:
		*valp = ULONG_MAX;
		return (0);

	case _PC_FILESIZEBITS:
		*valp = 64;
		return (0);

	case _PC_XATTR_EXISTS:
		zp = VTOZ(vp);
		zfsvfs = zp->z_zfsvfs;
		ZFS_ENTER(zfsvfs);
		*valp = 0;
		error = zfs_dirent_lock(&dl, zp, "", &xzp,
		    ZXATTR | ZEXISTS | ZSHARED);
		if (error == 0) {
			zfs_dirent_unlock(dl);
			if (!zfs_dirempty(xzp))
				*valp = 1;
			VN_RELE(ZTOV(xzp));
		} else if (error == ENOENT) {
			/*
			 * If there aren't extended attributes, it's the
			 * same as having zero of them.
			 */
			error = 0;
		}
		ZFS_EXIT(zfsvfs);
		return (error);

	case _PC_ACL_ENABLED:
		*valp = _ACL_ACE_ENABLED;
		return (0);

	case _PC_MIN_HOLE_SIZE:
		*valp = (ulong_t)SPA_MINBLOCKSIZE;
		return (0);

	default:
		return (fs_pathconf(vp, cmd, valp, cr));
	}
}
#endif /* !__APPLE__ */
	
#ifndef __APPLE__
/*ARGSUSED*/
static int
zfs_getsecattr(vnode_t *vp, vsecattr_t *vsecp, int flag, cred_t *cr)
{
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	int error;

	ZFS_ENTER(zfsvfs);
	error = zfs_getacl(zp, vsecp, cr);
	ZFS_EXIT(zfsvfs);

	return (error);
}
#endif /* !__APPLE__ */

#ifndef __APPLE__
/*ARGSUSED*/
static int
zfs_setsecattr(vnode_t *vp, vsecattr_t *vsecp, int flag, cred_t *cr)
{
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	int error;

	ZFS_ENTER(zfsvfs);
	error = zfs_setacl(zp, vsecp, cr);
	ZFS_EXIT(zfsvfs);
	return (error);
}
#endif /* !__APPLE__ */

#ifdef __APPLE__
static int
zfs_vnop_revoke(__unused struct vnop_revoke_args *ap)
{
	return vn_revoke(ap->a_vp, ap->a_flags, ap->a_context);
}
#endif /* __APPLE__ */

#ifdef __APPLE__
static int
zfs_vnop_blktooff(__unused struct vnop_blktooff_args *ap)
{
	return (ENOTSUP);
}
#endif /* __APPLE__ */

#ifdef __APPLE__
static int
zfs_vnop_offtoblk(__unused struct vnop_offtoblk_args *ap)
{
	return (ENOTSUP);
}
#endif /* __APPLE__ */

#ifdef __APPLE__
static int
zfs_vnop_blockmap(__unused struct vnop_blockmap_args *ap)
{
	return (ENOTSUP);
}
#endif /* __APPLE__ */

#ifdef __APPLE__
static int
zfs_vnop_strategy(__unused struct vnop_strategy_args *ap)
{
	return (ENOTSUP);
}
#endif /* __APPLE__ */

#ifdef __APPLE__
static int
zfs_vnop_select(__unused struct vnop_select_args *ap)
{
	return (1);
}
#endif /* __APPLE__ */

#ifndef __APPLE__
/*
 * Predeclare these here so that the compiler assumes that
 * this is an "old style" function declaration that does
 * not include arguments => we won't get type mismatch errors
 * in the initializations that follow.
 */
static int zfs_inval();
static int zfs_isdir();
#endif /* !__APPLE__ */

static int
#ifdef __APPLE__
zfs_inval(__unused void *ap)
#else
zfs_inval()
#endif /* __APPLE__ */
{
	return (EINVAL);
}

static int
#ifdef __APPLE__
zfs_isdir(__unused void *ap)
#else
zfs_isdir()
#endif /* __APPLE__ */
{
	return (EISDIR);
}

#define VOPFUNC int (*)(void *)

extern int zfs_vnop_readdirattr(struct vnop_readdirattr_args *ap);

/*
 * Directory vnode operations template
 */
#ifdef __APPLE__
int (**zfs_dvnodeops) (void *);
struct vnodeopv_entry_desc zfs_dvnodeops_template[] = {
	{&vnop_default_desc, 	(VOPFUNC)vn_default_error },
	{&vnop_lookup_desc,	(VOPFUNC)zfs_vnop_lookup},
	{&vnop_create_desc,	(VOPFUNC)zfs_vnop_create},
	{&vnop_whiteout_desc,	(VOPFUNC)zfs_vnop_whiteout},
	{&vnop_mknod_desc,	(VOPFUNC)zfs_vnop_mknod},
	{&vnop_open_desc,	(VOPFUNC)zfs_vnop_open},
	{&vnop_close_desc,	(VOPFUNC)zfs_vnop_close},
	{&vnop_access_desc,	(VOPFUNC)zfs_vnop_access},
	{&vnop_getattr_desc,	(VOPFUNC)zfs_vnop_getattr},
	{&vnop_setattr_desc,	(VOPFUNC)zfs_vnop_setattr},
	{&vnop_read_desc,	(VOPFUNC)zfs_isdir},
	{&vnop_write_desc,	(VOPFUNC)zfs_isdir},
	{&vnop_ioctl_desc,	(VOPFUNC)zfs_vnop_ioctl},
	{&vnop_select_desc,	(VOPFUNC)zfs_isdir},
	{&vnop_fsync_desc,	(VOPFUNC)zfs_vnop_fsync},
	{&vnop_remove_desc,	(VOPFUNC)zfs_vnop_remove},
	{&vnop_link_desc,	(VOPFUNC)zfs_vnop_link},
	{&vnop_rename_desc,	(VOPFUNC)zfs_vnop_rename},
	{&vnop_mkdir_desc,	(VOPFUNC)zfs_vnop_mkdir},
	{&vnop_rmdir_desc,	(VOPFUNC)zfs_vnop_rmdir},
	{&vnop_symlink_desc,	(VOPFUNC)zfs_vnop_symlink},
	{&vnop_readdir_desc,	(VOPFUNC)zfs_vnop_readdir},
	{&vnop_inactive_desc,	(VOPFUNC)zfs_vnop_inactive},
	{&vnop_reclaim_desc,	(VOPFUNC)zfs_vnop_reclaim},
	{&vnop_pathconf_desc,	(VOPFUNC)zfs_vnop_pathconf},
	{&vnop_revoke_desc,	(VOPFUNC)zfs_vnop_revoke},
	{&vnop_getxattr_desc,	(VOPFUNC)zfs_vnop_getxattr},
	{&vnop_setxattr_desc,	(VOPFUNC)zfs_vnop_setxattr},
	{&vnop_removexattr_desc,(VOPFUNC)zfs_vnop_removexattr},
	{&vnop_listxattr_desc,	(VOPFUNC)zfs_vnop_listxattr},
	{&vnop_readdirattr_desc, (VOPFUNC)zfs_vnop_readdirattr},
	{NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc zfs_dvnodeop_opv_desc =
{ &zfs_dvnodeops, zfs_dvnodeops_template };
#else /* OpenSolaris */
/*
 * Directory vnode operations template
 */
vnodeops_t *zfs_dvnodeops;
const fs_operation_def_t zfs_dvnodeops_template[] = {
	VOPNAME_OPEN,		{ .vop_open = zfs_open },
	VOPNAME_CLOSE,		{ .vop_close = zfs_close },
	VOPNAME_READ,		{ .error = zfs_isdir },
	VOPNAME_WRITE,		{ .error = zfs_isdir },
	VOPNAME_IOCTL,		{ .vop_ioctl = zfs_ioctl },
	VOPNAME_GETATTR,	{ .vop_getattr = zfs_getattr },
	VOPNAME_SETATTR,	{ .vop_setattr = zfs_setattr },
	VOPNAME_ACCESS,		{ .vop_access = zfs_access },
	VOPNAME_LOOKUP,		{ .vop_lookup = zfs_lookup },
	VOPNAME_CREATE,		{ .vop_create = zfs_create },
	VOPNAME_REMOVE,		{ .vop_remove = zfs_remove },
	VOPNAME_LINK,		{ .vop_link = zfs_link },
	VOPNAME_RENAME,		{ .vop_rename = zfs_rename },
	VOPNAME_MKDIR,		{ .vop_mkdir = zfs_mkdir },
	VOPNAME_RMDIR,		{ .vop_rmdir = zfs_rmdir },
	VOPNAME_READDIR,	{ .vop_readdir = zfs_readdir },
	VOPNAME_SYMLINK,	{ .vop_symlink = zfs_symlink },
	VOPNAME_FSYNC,		{ .vop_fsync = zfs_fsync },
	VOPNAME_INACTIVE,	{ .vop_inactive = zfs_inactive },
	VOPNAME_FID,		{ .vop_fid = zfs_fid },
	VOPNAME_SEEK,		{ .vop_seek = zfs_seek },
	VOPNAME_PATHCONF,	{ .vop_pathconf = zfs_pathconf },
	VOPNAME_GETSECATTR,	{ .vop_getsecattr = zfs_getsecattr },
	VOPNAME_SETSECATTR,	{ .vop_setsecattr = zfs_setsecattr },
	VOPNAME_VNEVENT, 	{ .vop_vnevent = fs_vnevent_support },
	NULL,			NULL
};
#endif /* __APPLE__ */

/*
 * Regular file vnode operations template
 */
#ifdef __APPLE__
int (**zfs_fvnodeops) (void *);
struct vnodeopv_entry_desc zfs_fvnodeops_template[] = {
	{&vnop_default_desc, 	(VOPFUNC)vn_default_error },
	{&vnop_whiteout_desc,	(VOPFUNC)zfs_vnop_whiteout},
	{&vnop_open_desc,	(VOPFUNC)zfs_vnop_open},
	{&vnop_close_desc,	(VOPFUNC)zfs_vnop_close},
	{&vnop_access_desc,	(VOPFUNC)zfs_vnop_access},
	{&vnop_getattr_desc,	(VOPFUNC)zfs_vnop_getattr},
	{&vnop_setattr_desc,	(VOPFUNC)zfs_vnop_setattr},
	{&vnop_read_desc,	(VOPFUNC)zfs_vnop_read},
	{&vnop_write_desc,	(VOPFUNC)zfs_vnop_write},
	{&vnop_ioctl_desc,	(VOPFUNC)zfs_vnop_ioctl},
	{&vnop_select_desc,	(VOPFUNC)zfs_vnop_select},
	{&vnop_fsync_desc,	(VOPFUNC)zfs_vnop_fsync},
	{&vnop_inactive_desc,	(VOPFUNC)zfs_vnop_inactive},
	{&vnop_reclaim_desc,	(VOPFUNC)zfs_vnop_reclaim},
	{&vnop_pathconf_desc,	(VOPFUNC)zfs_vnop_pathconf},
	{&vnop_pagein_desc,	(VOPFUNC)zfs_vnop_pagein},
	{&vnop_pageout_desc,	(VOPFUNC)zfs_vnop_pageout},
	{&vnop_mmap_desc,	(VOPFUNC)zfs_vnop_mmap},
	{&vnop_blktooff_desc,	(VOPFUNC)zfs_vnop_blktooff},
	{&vnop_offtoblk_desc,	(VOPFUNC)zfs_vnop_offtoblk},
	{&vnop_blockmap_desc,	(VOPFUNC)zfs_vnop_blockmap},
	{&vnop_strategy_desc,	(VOPFUNC)zfs_vnop_strategy},
	{&vnop_allocate_desc,   (VOPFUNC)zfs_vnop_allocate},
	{&vnop_revoke_desc,	(VOPFUNC)zfs_vnop_revoke},
	{&vnop_exchange_desc,	(VOPFUNC)zfs_vnop_exchange},
	{&vnop_getxattr_desc,	(VOPFUNC)zfs_vnop_getxattr},
	{&vnop_setxattr_desc,	(VOPFUNC)zfs_vnop_setxattr},
	{&vnop_removexattr_desc,(VOPFUNC)zfs_vnop_removexattr},
	{&vnop_listxattr_desc,	(VOPFUNC)zfs_vnop_listxattr},
	{&vnop_getnamedstream_desc,	(VOPFUNC)zfs_vnop_getnamedstream},
	{&vnop_makenamedstream_desc,	(VOPFUNC)zfs_vnop_makenamedstream},
	{&vnop_removenamedstream_desc,	(VOPFUNC)zfs_vnop_removenamedstream},
	{NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc zfs_fvnodeop_opv_desc =
{ &zfs_fvnodeops, zfs_fvnodeops_template };
#else /* OpenSolaris */
vnodeops_t *zfs_fvnodeops;
const fs_operation_def_t zfs_fvnodeops_template[] = {
	VOPNAME_OPEN,		{ .vop_open = zfs_open },
	VOPNAME_CLOSE,		{ .vop_close = zfs_close },
	VOPNAME_READ,		{ .vop_read = zfs_read },
	VOPNAME_WRITE,		{ .vop_write = zfs_write },
	VOPNAME_IOCTL,		{ .vop_ioctl = zfs_ioctl },
	VOPNAME_GETATTR,	{ .vop_getattr = zfs_getattr },
	VOPNAME_SETATTR,	{ .vop_setattr = zfs_setattr },
	VOPNAME_ACCESS,		{ .vop_access = zfs_access },
	VOPNAME_LOOKUP,		{ .vop_lookup = zfs_lookup },
	VOPNAME_RENAME,		{ .vop_rename = zfs_rename },
	VOPNAME_FSYNC,		{ .vop_fsync = zfs_fsync },
	VOPNAME_INACTIVE,	{ .vop_inactive = zfs_inactive },
	VOPNAME_FID,		{ .vop_fid = zfs_fid },
	VOPNAME_SEEK,		{ .vop_seek = zfs_seek },
	VOPNAME_FRLOCK,		{ .vop_frlock = zfs_frlock },
	VOPNAME_SPACE,		{ .vop_space = zfs_space },
	VOPNAME_GETPAGE,	{ .vop_getpage = zfs_getpage },
	VOPNAME_PUTPAGE,	{ .vop_putpage = zfs_putpage },
	VOPNAME_MAP,		{ .vop_map = zfs_map },
	VOPNAME_ADDMAP,		{ .vop_addmap = zfs_addmap },
	VOPNAME_DELMAP,		{ .vop_delmap = zfs_delmap },
	VOPNAME_PATHCONF,	{ .vop_pathconf = zfs_pathconf },
	VOPNAME_GETSECATTR,	{ .vop_getsecattr = zfs_getsecattr },
	VOPNAME_SETSECATTR,	{ .vop_setsecattr = zfs_setsecattr },
	VOPNAME_VNEVENT,	{ .vop_vnevent = fs_vnevent_support },
	NULL,			NULL
};
#endif /* __APPLE__ */

/*
 * Symbolic link vnode operations template
 */
#ifdef __APPLE__
int (**zfs_symvnodeops) (void *);
struct vnodeopv_entry_desc zfs_symvnodeops_template[] = {
	{&vnop_default_desc, 	(VOPFUNC)vn_default_error },
	{&vnop_open_desc,	(VOPFUNC)zfs_vnop_open},
	{&vnop_close_desc,	(VOPFUNC)zfs_vnop_close},
	{&vnop_access_desc,	(VOPFUNC)zfs_vnop_access},
	{&vnop_getattr_desc,	(VOPFUNC)zfs_vnop_getattr},
	{&vnop_setattr_desc,	(VOPFUNC)zfs_vnop_setattr},
	{&vnop_ioctl_desc,	(VOPFUNC)zfs_vnop_ioctl},
	{&vnop_readlink_desc,	(VOPFUNC)zfs_vnop_readlink},
	{&vnop_inactive_desc,	(VOPFUNC)zfs_vnop_inactive},
	{&vnop_reclaim_desc,	(VOPFUNC)zfs_vnop_reclaim},
	{&vnop_pathconf_desc,	(VOPFUNC)zfs_vnop_pathconf},
	{&vnop_revoke_desc,	(VOPFUNC)zfs_vnop_revoke},
	{&vnop_getxattr_desc,	(VOPFUNC)zfs_vnop_getxattr},
	{&vnop_setxattr_desc,	(VOPFUNC)zfs_vnop_setxattr},
	{&vnop_removexattr_desc,(VOPFUNC)zfs_vnop_removexattr},
	{&vnop_listxattr_desc,	(VOPFUNC)zfs_vnop_listxattr},
	{NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc zfs_symvnodeop_opv_desc =
{ &zfs_symvnodeops, zfs_symvnodeops_template };
#else /* OpenSolaris */
vnodeops_t *zfs_symvnodeops;
const fs_operation_def_t zfs_symvnodeops_template[] = {
	VOPNAME_GETATTR,	{ .vop_getattr = zfs_getattr },
	VOPNAME_SETATTR,	{ .vop_setattr = zfs_setattr },
	VOPNAME_ACCESS,		{ .vop_access = zfs_access },
	VOPNAME_RENAME,		{ .vop_rename = zfs_rename },
	VOPNAME_READLINK,	{ .vop_readlink = zfs_readlink },
	VOPNAME_INACTIVE,	{ .vop_inactive = zfs_inactive },
	VOPNAME_FID,		{ .vop_fid = zfs_fid },
	VOPNAME_PATHCONF,	{ .vop_pathconf = zfs_pathconf },
	VOPNAME_VNEVENT,	{ .vop_vnevent = fs_vnevent_support },
	NULL,			NULL
};
#endif /* __APPLE__ */

/*
 * Extended attribute directory vnode operations template
 *	This template is identical to the directory vnodes
 *	operation template except for restricted operations:
 *		VOP_MKDIR()
 *		VOP_SYMLINK()
 * Note that there are other restrictions embedded in:
 *	zfs_create()	- restrict type to VREG
 *	zfs_link()	- no links into/out of attribute space
 *	zfs_rename()	- no moves into/out of attribute space
 */
#ifdef __APPLE__
int (**zfs_xdvnodeops) (void *);
struct vnodeopv_entry_desc zfs_xdvnodeops_template[] = {
	{&vnop_default_desc, 	(VOPFUNC)vn_default_error },
	{&vnop_lookup_desc,	(VOPFUNC)zfs_vnop_lookup},
	{&vnop_create_desc,	(VOPFUNC)zfs_vnop_create},
	{&vnop_whiteout_desc,	(VOPFUNC)zfs_vnop_whiteout},
	{&vnop_mknod_desc,	(VOPFUNC)zfs_inval},
	{&vnop_open_desc,	(VOPFUNC)zfs_vnop_open},
	{&vnop_close_desc,	(VOPFUNC)zfs_vnop_close},
	{&vnop_access_desc,	(VOPFUNC)zfs_vnop_access},
	{&vnop_getattr_desc,	(VOPFUNC)zfs_vnop_getattr},
	{&vnop_setattr_desc,	(VOPFUNC)zfs_vnop_setattr},
	{&vnop_read_desc,	(VOPFUNC)zfs_vnop_read},
	{&vnop_write_desc,	(VOPFUNC)zfs_vnop_write},
	{&vnop_ioctl_desc,	(VOPFUNC)zfs_vnop_ioctl},
	{&vnop_select_desc,	(VOPFUNC)zfs_vnop_select},
	{&vnop_fsync_desc,	(VOPFUNC)zfs_vnop_fsync},
	{&vnop_remove_desc,	(VOPFUNC)zfs_vnop_remove},
	{&vnop_link_desc,	(VOPFUNC)zfs_vnop_link},
	{&vnop_rename_desc,	(VOPFUNC)zfs_vnop_rename},
	{&vnop_mkdir_desc,	(VOPFUNC)zfs_inval},
	{&vnop_rmdir_desc,	(VOPFUNC)zfs_vnop_rmdir},
	{&vnop_symlink_desc,	(VOPFUNC)zfs_inval},
	{&vnop_readdir_desc,	(VOPFUNC)zfs_vnop_readdir},
	{&vnop_inactive_desc,	(VOPFUNC)zfs_vnop_inactive},
	{&vnop_reclaim_desc,	(VOPFUNC)zfs_vnop_reclaim},
	{&vnop_pathconf_desc,	(VOPFUNC)zfs_vnop_pathconf},
	{NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc zfs_xdvnodeop_opv_desc =
{ &zfs_xdvnodeops, zfs_xdvnodeops_template };
#else /* OpenSolaris */
vnodeops_t *zfs_xdvnodeops;
const fs_operation_def_t zfs_xdvnodeops_template[] = {
	VOPNAME_OPEN,		{ .vop_open = zfs_open },
	VOPNAME_CLOSE,		{ .vop_close = zfs_close },
	VOPNAME_IOCTL,		{ .vop_ioctl = zfs_ioctl },
	VOPNAME_GETATTR,	{ .vop_getattr = zfs_getattr },
	VOPNAME_SETATTR,	{ .vop_setattr = zfs_setattr },
	VOPNAME_ACCESS,		{ .vop_access = zfs_access },
	VOPNAME_LOOKUP,		{ .vop_lookup = zfs_lookup },
	VOPNAME_CREATE,		{ .vop_create = zfs_create },
	VOPNAME_REMOVE,		{ .vop_remove = zfs_remove },
	VOPNAME_LINK,		{ .vop_link = zfs_link },
	VOPNAME_RENAME,		{ .vop_rename = zfs_rename },
	VOPNAME_MKDIR,		{ .error = zfs_inval },
	VOPNAME_RMDIR,		{ .vop_rmdir = zfs_rmdir },
	VOPNAME_READDIR,	{ .vop_readdir = zfs_readdir },
	VOPNAME_SYMLINK,	{ .error = zfs_inval },
	VOPNAME_FSYNC,		{ .vop_fsync = zfs_fsync },
	VOPNAME_INACTIVE,	{ .vop_inactive = zfs_inactive },
	VOPNAME_FID,		{ .vop_fid = zfs_fid },
	VOPNAME_SEEK,		{ .vop_seek = zfs_seek },
	VOPNAME_PATHCONF,	{ .vop_pathconf = zfs_pathconf },
	VOPNAME_GETSECATTR,	{ .vop_getsecattr = zfs_getsecattr },
	VOPNAME_SETSECATTR,	{ .vop_setsecattr = zfs_setsecattr },
	VOPNAME_VNEVENT,	{ .vop_vnevent = fs_vnevent_support },
	NULL,			NULL
};
#endif /* __APPLE__ */

/*
 * Error vnode operations template
 */
#ifdef __APPLE__
int (**zfs_evnodeops) (void *);
struct vnodeopv_entry_desc zfs_evnodeops_template[] = {
	{&vnop_default_desc, 	(VOPFUNC)vn_default_error },
	{&vnop_inactive_desc,	(VOPFUNC)zfs_vnop_inactive},
	{&vnop_reclaim_desc,	(VOPFUNC)zfs_vnop_reclaim},
	{&vnop_pathconf_desc,	(VOPFUNC)zfs_vnop_pathconf},
	{NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc zfs_evnodeop_opv_desc =
{ &zfs_evnodeops, zfs_evnodeops_template };

#else /* OpenSolaris */
vnodeops_t *zfs_evnodeops;
const fs_operation_def_t zfs_evnodeops_template[] = {
	VOPNAME_INACTIVE,	{ .vop_inactive = zfs_inactive },
	VOPNAME_PATHCONF,	{ .vop_pathconf = zfs_pathconf },
	NULL,			NULL
};
#endif /* __APPLE__ */
