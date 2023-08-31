//
// Created by level-128 on 8/31/23.
//

#include "test_enclib.c"
#include "test_backend.c"

int main(){
	init_random_generator("/dev/urandom");
	test_enclib();
	test_backend();
}