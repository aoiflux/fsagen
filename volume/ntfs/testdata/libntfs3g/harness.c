/*
 * harness applies a script of directory operations to an NTFS image with
 * libntfs-3g, so that TestIndexMatchesLibntfs3g and
 * TestReparseIndexMatchesLibntfs3g can compare fsagen's indexes with
 * libntfs-3g's. Each line of the script is "d path" (make a directory),
 * "f path" (make an empty file), "s path" (make a symlink to "t") or
 * "r path" (remove one). Paths are absolute, with '/', in UTF-8.
 *
 *   harness image script
 *
 * Build it against libntfs-3g 2022.10.3 (Ubuntu's ntfs-3g-dev):
 *
 *   gcc -I/usr/include harness.c /usr/lib/x86_64-linux-gnu/libntfs-3g.a -o harness
 */
#include <errno.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include <ntfs-3g/types.h>
#include <ntfs-3g/volume.h>
#include <ntfs-3g/inode.h>
#include <ntfs-3g/dir.h>
#include <ntfs-3g/reparse.h>
#include <ntfs-3g/unistr.h>

/* The reparse data CreateSymbolicLinkW writes for a relative symlink to
 * "t": the tag, the data's length, the substitute name after the print
 * name, the relative flag, then the print and substitute names. */
static const char symlink_t[] = {
	0x0c, 0x00, 0x00, (char)0xa0, 0x10, 0x00, 0x00, 0x00,
	0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00,
	0x01, 0x00, 0x00, 0x00, 't', 0x00, 't', 0x00,
};

static ntfs_inode *parent_of(ntfs_volume *vol, char *path, char **leaf)
{
	char *slash = strrchr(path, '/');
	ntfs_inode *dir;
	*leaf = slash + 1;
	if (slash == path)
		return ntfs_pathname_to_inode(vol, NULL, "/");
	*slash = 0;
	dir = ntfs_pathname_to_inode(vol, NULL, path);
	*slash = '/';
	return dir;
}

int main(int argc, char **argv)
{
	ntfs_volume *vol;
	FILE *script;
	char line[1024];
	int n = 0;

	if (argc != 3) {
		fprintf(stderr, "usage: harness image script\n");
		return 2;
	}
	setlocale(LC_ALL, "C.UTF-8");
	vol = ntfs_mount(argv[1], 0);
	if (!vol) {
		perror("mount");
		return 1;
	}
	script = fopen(argv[2], "r");
	if (!script) {
		perror("script");
		return 1;
	}
	while (fgets(line, sizeof(line), script)) {
		char *path = line + 2, *leaf;
		ntfschar *uname = NULL;
		int ulen;
		ntfs_inode *dir, *ni;
		u64 mref;

		n++;
		line[strcspn(line, "\n")] = 0;
		dir = parent_of(vol, path, &leaf);
		if (!dir) {
			fprintf(stderr, "line %d: no parent: %s\n", n, strerror(errno));
			return 1;
		}
		ulen = ntfs_mbstoucs(leaf, &uname);
		if (ulen < 0) {
			perror("name");
			return 1;
		}
		switch (line[0]) {
		case 'd':
		case 'f':
			/* 0x100 is a descriptor mkntfs makes: a 72-byte
			 * $STANDARD_INFORMATION and no $SECURITY_DESCRIPTOR,
			 * as fsagen writes a record. */
			ni = ntfs_create(dir, const_cpu_to_le32(0x100), uname, ulen,
					 line[0] == 'd' ? S_IFDIR : S_IFREG);
			if (!ni || ntfs_inode_close(ni)) {
				fprintf(stderr, "line %d: create: %s\n", n, strerror(errno));
				return 1;
			}
			if (ntfs_inode_close(dir)) {
				perror("close");
				return 1;
			}
			break;
		case 's':
			/* The directory is closed first: closing the link
			 * brings its entry's $FILE_NAME up to date, reading
			 * the directory's index from disk. */
			ni = ntfs_create(dir, const_cpu_to_le32(0x100), uname, ulen, S_IFREG);
			if (!ni || ntfs_set_ntfs_reparse_data(ni, symlink_t, sizeof(symlink_t), 0) || ntfs_inode_close(dir) || ntfs_inode_close(ni)) {
				fprintf(stderr, "line %d: symlink: %s\n", n, strerror(errno));
				return 1;
			}
			break;
		case 'r':
			/* Look the object up in the directory already open: a
			 * second open of the directory, as a lookup of the whole
			 * path makes, leaves libntfs-3g's inode cache holding a
			 * copy of its record that the removal makes stale. */
			mref = ntfs_inode_lookup_by_name(dir, uname, ulen);
			ni = mref == (u64)-1 ? NULL : ntfs_inode_open(vol, MREF(mref));
			if (!ni) {
				fprintf(stderr, "line %d: no such object: %s\n", n, strerror(errno));
				return 1;
			}
			if (ntfs_delete(vol, path, ni, dir, uname, ulen)) {
				fprintf(stderr, "line %d: delete: %s\n", n, strerror(errno));
				return 1;
			}
			break;
		default:
			fprintf(stderr, "line %d: unknown operation\n", n);
			return 1;
		}
		free(uname);
	}
	if (ntfs_umount(vol, FALSE)) {
		perror("umount");
		return 1;
	}
	return 0;
}
