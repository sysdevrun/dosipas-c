"""PlatformIO pre-build script for the `native` environments.

Makes libmbedcrypto available to the host build by running
tools/fetch_mbedtls.sh (download + cmake build, idempotent) and adding its
include and library paths. Override the version with MBEDTLS_TAG=v2.28.10 or
point MBEDTLS_ROOT at an existing install (include/ and lib/libmbedcrypto.a).
"""
import os
import subprocess

Import("env")  # noqa: F821  (PlatformIO SCons global)

project_dir = env["PROJECT_DIR"]
tag = os.environ.get("MBEDTLS_TAG", "v3.6.4")
root = os.environ.get("MBEDTLS_ROOT") or os.path.join(project_dir, ".deps", f"mbedtls-{tag}")

if not os.path.isfile(os.path.join(root, "lib", "libmbedcrypto.a")):
    print(f"dosipas-c: fetching and building mbedTLS {tag} into {root}")
    subprocess.check_call(["sh", os.path.join(project_dir, "tools", "fetch_mbedtls.sh"), tag, root])

env.Append(
    CPPPATH=[os.path.join(root, "include")],
    LIBPATH=[os.path.join(root, "lib")],
    LIBS=["mbedcrypto"],
)
print(f"dosipas-c: using mbedTLS from {root}")
