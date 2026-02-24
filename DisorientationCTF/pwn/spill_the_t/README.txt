This executable is dynamically linked to a specific version of libc.

One way to test this locally is to use a tool like patchelf to make sure the executable is being run with the same libraries that our server is using, e.g.,
patchelf --set-interpreter ${PWD}/ld-2.31.so --set-rpath ${PWD} vuln
