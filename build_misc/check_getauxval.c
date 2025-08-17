#include <stddef.h>
#include <sys/auxv.h>

int main(){
    char * auxval = (char *)getauxval(AT_EXECFN);
    if (auxval == NULL) {
        return 1;
    }
    return 0;
}