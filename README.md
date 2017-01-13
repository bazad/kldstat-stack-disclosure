## kldstat-stack-disclosure

kldstat-stack-disclosure is a proof-of-concept exploit for a large (almost 2KB)
kernel stack disclosure in the kldstat system call that allows recovery of the
kernel stack guard. The issue is in the function sys_kldstat, which fails to
properly initialize the name and pathname arrays in the kld_file_stat structure
that is copied out to user space.

This exploit targets FreeBSD 11.0-RELEASE-p1 amd64.
