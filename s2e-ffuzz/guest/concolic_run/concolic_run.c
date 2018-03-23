#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "s2e.h"

#define MAX_TESTCASES 100
#define MAX_TESTCASES_DEFAULT 10

int file_exists(const char *filename)
{
    struct stat st;
    int rc = 0;

    rc = stat(filename, &st);
    if (rc == -1) {
        return 0;
    }

    if (st.st_size > 0) {
        return 1;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    uint32_t id;
    const char *get_cmd_fmt = "./s2eget concrete-inputs/%d.xml";
    const char *test_cmd_fmt = "./cb-test --debug --timeout 1 --directory %s --cb %s --xml %d.xml > /dev/null";
    char cwd[128] = {0};
    char buffer[128];
    int max;

    if (argc < 2) {
        printf("usage: %s <cb> [<max_testcases>]\n", argv[0]);
        return 1;
    }

    char *pcwd = getcwd(cwd, sizeof(cwd));
    if (!pcwd) {
        printf("Could not get current working directory\n");
        return 1;
    }

    max = MAX_TESTCASES_DEFAULT;
    if (argc == 3) {
        max = atoi(argv[2]);
        if (max <= 0 || max > MAX_TESTCASES) {
            printf("Invalid maximum number of test cases, using default of %d\n", MAX_TESTCASES_DEFAULT);
            max = MAX_TESTCASES_DEFAULT;
        }
    }

    printf("Running at most %d testcases\n", max);
    s2e_make_symbolic(&id, sizeof(id), "id");
    if (id >= 0 && id < max) {
        printf("ID %d\n", id);
        // Get file
        snprintf(buffer, sizeof(buffer), get_cmd_fmt, id);
        system(buffer);

        // Check that we got it (not empty)
        snprintf(buffer, sizeof(buffer), "%d.xml", id);
        if (!file_exists(buffer)) {
            s2e_kill_state(0, "no file");
        }

        // Run cb-test
        snprintf(buffer, sizeof(buffer), test_cmd_fmt, cwd, argv[1], id);
        system(buffer);

        s2e_kill_state(0, "Done");
    }

    printf("Done");
}
