/**
 * Copyright 2015 - CodeTickler
 * Proprietary and confidential
 */

#include <s2e.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <rawmonitor.h>

#include <cgc_monitor.h>
#include <cgc_interface.h>

#ifdef _WIN32
#include <windows.h>
#define SLEEP(x) Sleep((x) * 1000)
#else
#define SLEEP(x) sleep(x)
#endif

typedef int (*cmd_handler_t)(const char **args);

typedef struct _cmd_t {
    char *name;
    cmd_handler_t handler;
    unsigned args_count;
    char *description;
} cmd_t;


static int handler_concolic(const char **args)
{
    struct S2E_CGCMON_COMMAND cmd = { 0 };

    cmd.version = S2E_CGCMON_COMMAND_VERSION;
    cmd.currentPid = getpid();
    strncpy(cmd.currentName, "cgccmd", sizeof(cmd.currentName));

    int enable = !strcmp(args[0], "on");
    if (enable) {
        cmd.Command = CONCOLIC_ON;
    } else {
        cmd.Command = CONCOLIC_OFF;
    }

    s2e_begin_atomic();
    s2e_disable_all_apic_interrupts();
    int ret = s2e_invoke_plugin("CGCMonitor", &cmd, sizeof(cmd));
    s2e_enable_all_apic_interrupts();
    s2e_end_atomic();

    return ret;
}

static int handler_set_seed_id(const char **args)
{
    struct S2E_CGCINT_COMMAND cmd = { 0 };
    cmd.Command = SET_SEED_ID;
    cmd.SeedId = strtoll(args[0], NULL, 10);

    s2e_begin_atomic();
    s2e_disable_all_apic_interrupts();
    int ret = s2e_invoke_plugin("CGCInterface", &cmd, sizeof(cmd));
    s2e_enable_all_apic_interrupts();
    s2e_end_atomic();

    return ret;
}

#define COMMAND(c, args, desc) { #c, handler_##c, args, desc }

static cmd_t s_commands[] = {
    COMMAND(concolic, 1, "Turns on/off concolic execution on the current path (cb-test specific)"),
    COMMAND(set_seed_id, 1, "Sets the seed id for the current path"),
    { NULL, NULL, 0, NULL }
};

static void print_commands(void)
{
    unsigned i = 0;
    printf("%-15s  %s %s\n\n", "Command name", "Argument count", "Description");
    while(s_commands[i].handler) {
        printf("%-15s  %d              %s\n", s_commands[i].name,
               s_commands[i].args_count, s_commands[i].description);
        ++i;
    }
}

static int find_command(const char *cmd)
{
    unsigned i = 0;
    while(s_commands[i].handler) {
        if (!strcmp(s_commands[i].name, cmd)) {
            return i;
        }
        ++i;
    }
    return -1;
}

int main(int argc, const char **argv)
{
    if (argc < 2) {
        print_commands();
        return -1;
    }

    const char *cmd = argv[1];
    int cmd_index = find_command(cmd);

    if (cmd_index == -1) {
        printf("Command %s not found\n", cmd);
        return -1;
    }

    argc -= 2;
    ++argv;
    ++argv;

    if (argc != s_commands[cmd_index].args_count) {
        printf("Invalid number of arguments supplied (received %d, expected %d)\n",
               argc, s_commands[cmd_index].args_count);
        return -1;
    }

    return s_commands[cmd_index].handler(argv);
}
