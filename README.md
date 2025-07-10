mod\_sepal
==========

![Image of the calyx of Hibiscus sabdariffa](sepal.png)

`mod_sepal` uses `kauth` to provide a capabilities based policy filter for
processes on NetBSD 10.x. This filter can be used to effectively sandbox
processes by limiting the system calls they are allowed to perform and the
filesystem details they are allowed to access.

The design of this module is influenced heavily by pledge/unveil on OpenBSD and
capsicum on FreeBSD.

This module provides a control device, `/dev/sepal_policy`, which can be used to
control the policy for the given process. Policies can be implemented globally
or per-descriptor. The common design is to make global policy highly
restrictive, then add back special rules for individual descriptors.

`mod_sepal` is a work in progress at this point, and is not ready for production
use.
