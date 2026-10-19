/*
 * main() for the coverage builds: run LLVMFuzzerTestOneInput on every file given on the
 * command line (directories are walked one level deep).
 *
 * SPDX-License-Identifier: MIT
 */
#define _DEFAULT_SOURCE
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void run_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return;
    uint8_t *buf = malloc(1 << 20);
    size_t n = fread(buf, 1, 1 << 20, f);
    fclose(f);
    LLVMFuzzerTestOneInput(buf, n);
    free(buf);
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        struct stat st;
        if (stat(argv[i], &st) != 0) continue;
        if (!S_ISDIR(st.st_mode)) { run_file(argv[i]); continue; }
        DIR *d = opendir(argv[i]);
        struct dirent *e;
        char path[4096];
        while (d && (e = readdir(d))) {
            if (e->d_name[0] == '.') continue;
            snprintf(path, sizeof path, "%s/%s", argv[i], e->d_name);
            run_file(path);
        }
        if (d) closedir(d);
    }
    return 0;
}
