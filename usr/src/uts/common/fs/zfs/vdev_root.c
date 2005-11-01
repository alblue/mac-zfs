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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/zfs_context.h>
#include <sys/spa.h>
#include <sys/vdev_impl.h>
#include <sys/zio.h>
#include <sys/fs/zfs.h>

/*
 * Virtual device vector for the pool's root vdev.
 */

static int
vdev_root_open(vdev_t *vd, uint64_t *asize, uint64_t *ashift)
{
	vdev_t *cvd;
	int c, error;
	int lasterror = 0;

	if (vd->vdev_children == 0) {
		vd->vdev_stat.vs_aux = VDEV_AUX_BAD_LABEL;
		return (EINVAL);
	}

	for (c = 0; c < vd->vdev_children; c++) {
		cvd = vd->vdev_child[c];

		if ((error = vdev_open(cvd)) != 0) {
			lasterror = error;
			continue;
		}

		*asize += cvd->vdev_asize;
		*ashift = MAX(*ashift, cvd->vdev_ashift);
	}

	if (lasterror)
		vd->vdev_stat.vs_aux = VDEV_AUX_NO_REPLICAS;

	return (lasterror);
}

static void
vdev_root_close(vdev_t *vd)
{
	int c;

	for (c = 0; c < vd->vdev_children; c++)
		vdev_close(vd->vdev_child[c]);
}

static void
vdev_root_state_change(vdev_t *vd, int faulted, int degraded)
{
	if (faulted > 0)
		vdev_set_state(vd, VDEV_STATE_CANT_OPEN, VDEV_AUX_NO_REPLICAS);
	else if (degraded != 0)
		vdev_set_state(vd, VDEV_STATE_DEGRADED, VDEV_AUX_NONE);
	else
		vdev_set_state(vd, VDEV_STATE_HEALTHY, VDEV_AUX_NONE);
}

vdev_ops_t vdev_root_ops = {
	vdev_root_open,
	vdev_root_close,
	vdev_default_asize,
	NULL,			/* io_start - not applicable to the root */
	NULL,			/* io_done - not applicable to the root */
	vdev_root_state_change,
	VDEV_TYPE_ROOT,		/* name of this vdev type */
	B_FALSE			/* not a leaf vdev */
};