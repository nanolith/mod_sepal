/*-
 * Copyright (c) 2025 Justin Handville
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY JUSTIN HANDVILLE AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/device.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/mutex.h>

MODULE(MODULE_CLASS_SECMODEL, sepal, NULL);

dev_type_open(sepal_open);
dev_type_close(sepal_close);
dev_type_ioctl(sepal_ioctl);

static struct cdevsw sepal_cdevsw = {
	.d_open = sepal_open,
	.d_close = sepal_close,
	.d_read = noread,
	.d_write = nowrite,
	.d_ioctl = sepal_ioctl,
	.d_stop = nostop,
	.d_tty = notty,
	.d_poll = nopoll,
	.d_mmap = nommap,
	.d_kqfilter = nokqfilter,
	.d_discard = nodiscard,
	.d_flag = D_OTHER | D_MPSAFE,
};

struct sepal_softc {
	kmutex_t lock;
	int devrefcnt;
	int procrefcnt;
};

static struct sepal_softc sc;

static int
sepal_has_refcnts()
{
	int retval = 0;

	mutex_enter(&sc.lock);
	/* open device count. */
	retval |= sc.devrefcnt;
	/* policy monitored process count. */
	retval |= sc.procrefcnt;
	mutex_exit(&sc.lock);

	return retval;
}

static void
sepal_incr_devrefcnt()
{
	mutex_enter(&sc.lock);
	++sc.devrefcnt;
	mutex_exit(&sc.lock);
}

static void
sepal_decr_devrefcnt()
{
	mutex_enter(&sc.lock);
	--sc.devrefcnt;
	mutex_exit(&sc.lock);
}

int
sepal_open(dev_t self __unused, int flag __unused, int mode __unused,
    struct lwp *l __unused)
{
	sepal_incr_devrefcnt();

	return 0;
}

int
sepal_close(dev_t self __unused, int flag __unused, int mode __unused,
    struct lwp *l __unused)
{
	sepal_decr_devrefcnt();

	return 0;
}

int
sepal_ioctl(dev_t self __unused, u_long cmd, void *data, int flag,
    struct lwp *l __unused)
{
	switch (cmd) {
	default:
		return ENOTTY;
	}
}

/* TODO - replace major with a statically defined value in the kernel. */
static int cmajor = 400;
static int bmajor = -1;

static int
sepal_mod_init()
{
	int retval;

	/* attach the sepal device. */
	retval = devsw_attach("sepal", NULL, &bmajor, &sepal_cdevsw, &cmajor);
	if (0 != retval) {
		retval = ENXIO;
		goto done;
	}

	/* set up global module structure. */
	memset(&sc, 0, sizeof(sc));
	mutex_init(&sc.lock, MUTEX_DEFAULT, IPL_NONE);

	/* success. */
	retval = 0;
	goto done;

done:
	return retval;
}

static int
sepal_mod_fini()
{
	int retval;

	if (0 != sepal_has_refcnts()) {
		retval = EBUSY;
		goto done;
	}
	mutex_destroy(&sc.lock);
	devsw_detach(NULL, &sepal_cdevsw);

	/* success. */
	retval = 0;
	goto done;

done:
	return retval;
}

static int
sepal_modcmd(modcmd_t cmd, void *arg __unused)
{
	int retval;

	switch (cmd) {
	case MODULE_CMD_INIT:
		retval = sepal_mod_init();
		if (0 != retval)
			return retval;

		return 0;

	case MODULE_CMD_FINI:
		retval = sepal_mod_fini();
		if (0 != retval)
			return retval;

		return 0;

	default:
		return ENOTTY;
	}
}
