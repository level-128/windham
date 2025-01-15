//
// Created by level-128 on 5/11/24.
//

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../main.c"

#define MAX_ARGS 100

#define exec_test_command(X) execute_command_line(X, device_, 0)

#define exec_test_error_command(X) execute_command_line(X, device_, 1)


void execute_command_line(const char * command_line, const char * replace, int is_error) {
	char * argv[MAX_ARGS];
	int    argc = 0;
	char * processed_input;
	char * temp_input  = strdup(command_line);
	char * percent_pos = strstr(temp_input, "%");

	if (percent_pos != NULL) {
		*percent_pos    = '\0';
		processed_input = malloc(strlen(command_line) + strlen(replace));
		sprintf(processed_input, "%s%s%s", temp_input, replace, percent_pos + 1);
	} else {
		processed_input = strdup(temp_input);
	}
	printf("TEST: %s\n", processed_input);

	argv[argc++] = strdup("windham");

	char * token = strtok(processed_input, " ");
	while (token != NULL && argc < MAX_ARGS) {
		argv[argc++] = strdup(token);
		token        = strtok(NULL, " ");
	}


	if (!setjmp(exit_jmp)) {
		main_(argc, argv);
		if (is_error == 0) {
			printf("DONE: %s\n", processed_input);
		} else {
			printf("TEST NPASS, no error for: %s\n", processed_input);
			exit(1);
		}
	} else {
		if (is_error == 1) {
			printf("DONE: %s\n", processed_input);
		} else {
			printf("TEST NPASS, error for: %s\n", processed_input);
			exit(1);
		}
	}

	for (int i = 0; i < argc; i++) {
		free(argv[i]);
	}
	free(temp_input);
	free(processed_input);
}
