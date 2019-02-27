#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

int main(int argc, char** argv)
{
	char buf[32];
	int i, rc, fd, exitcode = 0;
	uid_t uid;
	gid_t gid;
	struct statbuf sb;

	if (argc != 4) {
		fprintf(stderr, "Usage: %s DIR UID GID\n", argv[0]);
		return 1;
	}

	rc = chdir(argv[1]);
	if (rc) {
		perror("chdir");
		return 1;
	}

	// need to change group before user, as changing user will
	// drop the capability to change user/group
	gid = atoi(argv[3]);
	rc = setegid(gid);
	if (rc) {
		perror("setgid");
		return 1;
	}

	uid = atoi(argv[2]);
	rc = seteuid(uid);
	if (rc) {
		perror("setuid");
		return 1;
	}


	// never fails
	umask(0);

	for (i = 0; i < 07777+1; i++) {
		snprintf(buf, sizeof(buf), "f%04o", i);
		fd = open(buf, O_CREAT|O_EXCL|O_RDONLY, (mode_t)i);
		if (fd < 0) {
			perror("open");
			fprintf(stderr, "%s creation failed\n", buf);
			exitcode = 1;
			continue;
		}
		rc = close(fd);
		if (rc) {
			perror("close");
			fprintf(stderr, "%s closing failed\n", buf);
			exitcode = 1;
			continue;
		}
	}

	return exitcode;
}
