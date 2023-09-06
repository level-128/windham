
#include "test_enclib.c"
#include "test_backend.c"
#include "test_mapper.c"

int main(){
	init_random_generator("/dev/urandom");
//	test_enclib();
	test_backend();
//	test_mapper();



}