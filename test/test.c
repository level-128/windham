#include "test_enclib.c"
#include "test_backend.c"
#include "test_mapper.c"


int main(int argc, char * argv[]){
	init_random_generator("/dev/urandom");
	get_system_info();
	test_enclib();
	test_mapper(argc == 2 ? argv[1] : NULL);
	test_backend(argc == 2 ? argv[1] : NULL);

}