/* SYNTHETIC DEMONSTRATION DATA — NOT BENCHMARK DATA */
/* Category: Vulnerability Requiring Callee Context */
/* The target function 'dispatch_user_command' looks like a generic dispatcher, */
/* but delegates execution to downstream callee 'execute_system_subcommand' which executes unsanitized commands. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* DOWNSTREAM CALLEE SINK */
void execute_system_subcommand(const char *cmd_string) {
    /* Dangerous sink: command injection vector */
    system(cmd_string);
}

/* TARGET FUNCTION: Appears to merely format a command string */
void dispatch_user_command(const char *action, const char *argument) {
    char full_cmd[512];
    snprintf(full_cmd, sizeof(full_cmd), "/usr/bin/service_%s %s", action, argument);
    /* Danger is revealed only by inspecting what execute_system_subcommand does with full_cmd */
    execute_system_subcommand(full_cmd);
}

int main(int argc, char **argv) {
    if (argc > 2) {
        dispatch_user_command(argv[1], argv[2]);
    }
    return 0;
}
