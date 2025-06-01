//
// Created by level-128 on 5/11/24.
//

#pragma once

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
	if (is_error) {
		printf("TESTERR: %s\n", processed_input);
	} else {
		printf("TEST: %s\n", processed_input);
	}

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
			printf("!!! TEST NPASS, no error for: %s\n", processed_input);
			exit(1);
		}
	} else {
		if (is_error == 1) {
			printf("DONE: %s\n", processed_input);
		} else {
			printf("!!! TEST NPASS, error for: %s\n", processed_input);
			exit(1);
		}
	}

	for (int i = 0; i < argc; i++) {
		free(argv[i]);
	}
	free(temp_input);
	free(processed_input);
}

void create_new_device(char * device) {
	int my_device = open(device, O_RDWR | O_CREAT, 0777);
	if (my_device < 0) {
		perror(device);
		__builtin_trap();
	}
	for (int i = 0; i < sizeof(Data); i+=8) {
		size_t ibts = write(my_device, (unsigned char [8] ){170, 170, 170, 170, 170, 170, 170, 170},
			8);
		if (ibts != 8) {
			__builtin_trap();
		}
	}
	ftruncate(my_device, 8*1024*1024);
	close(my_device);
}

void find_four_target(char * device) {
	bool has_4_fe = false;
	int fd = open(device, O_RDONLY);

	unsigned char memory[sizeof(Data)];
	read(fd, &memory, sizeof(Data));
	close(fd);

	for (size_t i = 0; i < sizeof(Data) - 3; ++i) {
		if (memory[i]     == 170 &&
			 memory[i + 1] == 170 &&
			 memory[i + 2] == 170 &&
			 memory[i + 3] == 170) {
			const void *address = &memory[i];
			printf("located 4 0xFEs at %p\n", address);
			i += 4;
			has_4_fe = true;
			 }
	}
	if (has_4_fe) {
		print_error("header has uninited region.");
	}
}
