#include <mntent.h>
int main(void) {
	FILE *fp = setmntent("/dev/null", "r");
	if (fp) endmntent(fp);
	return 0;
}
