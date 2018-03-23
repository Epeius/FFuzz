#define _GNU_SOURCE 1 /* For strdup */

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "s2e.h"

char **filenames;
unsigned filenames_count;

/* Searches for files ending in .xml in the given directory,
 * appending their names to the global vector 'filenames'.
 */
void get_input_file_list(const char *dir_name)
{
    DIR *dpdf;
    struct dirent *epdf;
    static const char *input_ext = ".xml";
    unsigned i = 0;

    filenames_count = 0;

    dpdf = opendir(dir_name);
    if (dpdf != NULL) {
        while ((epdf = readdir(dpdf))) {
            if (strstr(epdf->d_name, input_ext)) {
                filenames_count++;
            }
        }
    }

    filenames = (char **)malloc(sizeof(char *) * filenames_count);

    dpdf = opendir(dir_name);
    if (dpdf != NULL) {
        while ((epdf = readdir(dpdf))) {
            if (strstr(epdf->d_name, input_ext)) {
                filenames[i++] = strdup(epdf->d_name);
            }
        }
    }
}

int main(int argc, char *argv[])
{
    int id;

    if (argc < 2) {
        fprintf(stderr, "Forks a state for each xml file in a directory\n");
        fprintf(stderr, "and prints the filename on stdout.\n");
        fprintf(stderr, "usage: %s <directory>\n", argv[0]);
        return 1;
    }

    // Fork a state for each file
    get_input_file_list(argv[1]);

    if (filenames_count == 0) {
        s2e_printf("choose_file: no files to fork\n");
        return -1;
    }

    s2e_printf("choose_file: found %d files to fork\n", filenames_count);

    s2e_begin_atomic();
    //id = s2e_fork(filenames_count - 1, "file_id");
    id = s2e_range(0, filenames_count, "file_id");
    s2e_end_atomic();

    s2e_printf("choose_file: path %d filename %s\n", s2e_get_path_id(), filenames[id]);
    printf("%s", filenames[id]);
    return 0;
}
