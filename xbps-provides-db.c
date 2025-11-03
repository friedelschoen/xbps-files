#include <errno.h>
#include <git2.h>
#include <linux/limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xbps.h>

#define UNUSED __attribute__((unused))

static const char* reference_str = "refs/heads/xbps-files";

struct sb {
	char*  data;
	size_t len;
	size_t cap;
};

static void sb_free(struct sb* b) {
	free(b->data);
	b->data = NULL;
	b->len = b->cap = 0;
}

static void sb_reserve(struct sb* b, size_t need) {
	if (b->len + need + 1 <= b->cap) return;
	size_t nc = b->cap ? b->cap : 1024;
	while (b->len + need + 1 > nc) nc *= 2;
	char* p = realloc(b->data, nc);
	if (!p) {
		fprintf(stderr, "oom\n");
		exit(EXIT_FAILURE);
	}
	b->data = p;
	b->cap  = nc;
}

static void sb_append(struct sb* b, const char* s, size_t n) {
	sb_reserve(b, n);
	memcpy(b->data + b->len, s, n);
	b->len += n;
	b->data[b->len] = '\0';
}

static void sb_append_line(struct sb* b, const char* filestr, const char* tgt, const char* typestr) {
	char line[PATH_MAX * 2];
	int  m = snprintf(line, sizeof(line), "%s%s%s (%s)\n",
	                  filestr, tgt ? " -> " : "", tgt ? tgt : "", typestr);
	if (m < 0) return;
	size_t n = (size_t) m;
	if (n >= sizeof(line)) n = sizeof(line) - 1;
	sb_append(b, line, n);
}

struct ffdata {
	const char*      repouri; /* alleen-lezen set per repo-ownedby callback */
	git_repository*  repo;    /* gedeeld; alleen gebruiken onder gitmtx */
	pthread_mutex_t  gitmtx;  /* beschermt repo-toegang en result_append */
	git_treebuilder* tb;
	git_tree*        prev_tree;
	git_reference*   prev_ref;
	int              idx, total;
	bool             inserted;
};

static void match_files_into_sb(xbps_dictionary_t pkg_filesd, xbps_dictionary_keysym_t key, struct sb* b) {
	xbps_array_t array;
	const char*  keyname = xbps_dictionary_keysym_cstring_nocopy(key);
	const char*  typestr = NULL;

	if (strcmp(keyname, "files") == 0)
		typestr = "regular file";
	else if (strcmp(keyname, "links") == 0)
		typestr = "link";
	else if (strcmp(keyname, "conf_files") == 0)
		typestr = "configuration file";
	else
		return;

	array = xbps_dictionary_get_keysym(pkg_filesd, key);
	for (unsigned int i = 0; i < xbps_array_count(array); i++) {
		xbps_object_t obj     = xbps_array_get(array, i);
		const char *  filestr = NULL, *tgt = NULL;

		xbps_dictionary_get_cstring_nocopy(obj, "file", &filestr);
		if (!filestr) continue;
		xbps_dictionary_get_cstring_nocopy(obj, "target", &tgt);

		sb_append_line(b, filestr, tgt, typestr);
	}
}

static int repo_match_cb(struct xbps_handle* xhp, xbps_object_t obj,
                         const char* key UNUSED, void* arg, bool* done UNUSED) {
	struct ffdata* ffd    = arg;
	const char*    pkgver = NULL;
	char           bfile[PATH_MAX];

	/* zet repo-uri in pkg object zodat xbps_pkg_path_or_url werkt */
	xbps_dictionary_set_cstring_nocopy(obj, "repository", ffd->repouri);
	xbps_dictionary_get_cstring_nocopy(obj, "pkgver", &pkgver);

	git_oid blob_id;
	bool    exist = 0;
	if (ffd->prev_tree) {
		const git_tree_entry* entry;

		entry = git_tree_entry_byname(ffd->prev_tree, pkgver);
		if (entry) {
			git_oid_cpy(&blob_id, git_tree_entry_id(entry));
			exist = 1;
		}
	}

	if (!exist) {
		int r = xbps_pkg_path_or_url(xhp, bfile, sizeof(bfile), obj);
		if (r < 0) {
			xbps_error_printf("could not get package path: %s\n", strerror(-r));
			return -r;
		}

		xbps_dictionary_t filesd = xbps_archive_fetch_plist(bfile, "/files.plist");
		if (!filesd) {
			xbps_error_printf("%s: couldn't fetch files.plist from %s: %s\n",
			                  pkgver, bfile, strerror(errno));
			return EINVAL;
		}

		/* lokale builder voor dit pakket (thread-local) */
		struct sb b = { 0 };

		xbps_array_t files_keys = xbps_dictionary_all_keys(filesd);
		for (unsigned int i = 0; i < xbps_array_count(files_keys); i++) {
			match_files_into_sb(filesd, xbps_array_get(files_keys, i), &b);
		}
		xbps_object_release(files_keys);
		xbps_object_release(filesd);

		/* maak blob + append resultaat onder lock (repo is niet thread-safe) */
		pthread_mutex_lock(&ffd->gitmtx);

		int gr = git_blob_create_frombuffer(&blob_id, ffd->repo,
		                                    b.data ? b.data : "", b.len);
		if (gr != 0) {
			const git_error* ge = git_error_last();
			fprintf(stderr, "git: blob create failed for %s: %s\n",
			        pkgver, ge && ge->message ? ge->message : "unknown");
			pthread_mutex_unlock(&ffd->gitmtx);
			sb_free(&b);
			return EIO;
		}

		sb_free(&b);
		ffd->inserted = 1;
	} else {
		pthread_mutex_lock(&ffd->gitmtx);
	}

	ffd->idx++;
	fprintf(stderr, "\r\033[2K%.1f%% %s", 100.0 * ffd->idx / ffd->total, pkgver);


	int gr;
	gr = git_treebuilder_insert(NULL, ffd->tb,
	                            pkgver,
	                            &blob_id,
	                            GIT_FILEMODE_BLOB);
	if (gr != 0) {
		const git_error* ge = git_error_last();
		fprintf(stderr, "git: tree insert failed for %s: %s\n", pkgver, ge && ge->message ? ge->message : "unknown");
		/* je kunt hier desnoods 'continue' doen; we failen hard: */
	}

	pthread_mutex_unlock(&ffd->gitmtx);

	return 0;
}

static int repo_ownedby_cb(struct xbps_repo* repo, void* arg, bool* done UNUSED) {
	struct ffdata* ffd = arg;
	ffd->repouri       = repo->uri;
	ffd->idx           = 0;
	ffd->total         = xbps_dictionary_count(repo->idx);

	xbps_array_t allkeys = xbps_dictionary_all_keys(repo->idx);
	int          rv      = xbps_array_foreach_cb_multi(repo->xhp, allkeys, repo->idx,
	                                                   repo_match_cb, ffd);
	xbps_object_release(allkeys);
	return rv;
}

static void get_previous_tree(struct ffdata* ffd) {
	git_object* prevobj;

	ffd->prev_tree = NULL;

	if (git_reference_lookup(&ffd->prev_ref, ffd->repo, reference_str) != 0)
		return;

	if (git_reference_peel(&prevobj, ffd->prev_ref, GIT_OBJECT_COMMIT) != 0)
		return;

	git_commit_tree(&ffd->prev_tree, (git_commit*) prevobj);
}

int main(int argc, char** argv) {
	if (argc != 2) {
		fprintf(stderr, "usage: %s <gitdir>\n", argv[0]);
		return 1;
	}

	int            rv   = 0;
	git_tree*      tree = NULL;
	git_signature* sig  = NULL;
	git_oid        tree_id, commit_id;
	int            gr = 0;


	/* libgit2 init + bare repo openen/aanmaken */
	if (git_libgit2_init() <= 0) {
		fprintf(stderr, "git: failed to init libgit2\n");
		return 1;
	}

	struct ffdata ffd;
	memset(&ffd, 0, sizeof ffd);
	pthread_mutex_init(&ffd.gitmtx, NULL);

	if (git_repository_open_bare(&ffd.repo, argv[1]) != 0) {
		int gr = git_repository_init(&ffd.repo, argv[1], /*bare=*/1);
		if (gr != 0) {
			const git_error* ge = git_error_last();
			fprintf(stderr, "git: cannot open or init bare repo at %s: %s\n",
			        argv[1], ge && ge->message ? ge->message : "unknown");
			pthread_mutex_destroy(&ffd.gitmtx);
			git_libgit2_shutdown();
			return 1;
		}
	}

	get_previous_tree(&ffd);

	/* xbps init */
	struct xbps_handle xh;
	memset(&xh, 0, sizeof xh);
	xh.flags = XBPS_FLAG_REPOS_MEMSYNC;

	if ((rv = xbps_init(&xh)) != 0) {
		xbps_error_printf("Failed to initialize libxbps: %s\n", strerror(rv));
		goto out;
	}

	if (git_treebuilder_new(&ffd.tb, ffd.repo, NULL) != 0) {
		const git_error* ge = git_error_last();
		fprintf(stderr, "git: treebuilder new failed: %s\n",
		        ge && ge->message ? ge->message : "unknown");
		goto out;
	}

	/* iterate alle repos/pakketten (callbacks kunnen parallel lopen) */
	rv = xbps_rpool_foreach(&xh, repo_ownedby_cb, &ffd);
	fprintf(stderr, "\n");
	xbps_end(&xh);

	if (rv) {
		fprintf(stderr, "error while iterating over repositories: %d\n", rv);
		goto out;
	}

	if (!ffd.inserted) {
		fprintf(stderr, "nothing written\n");
		goto out;
	}

	if (git_treebuilder_write(&tree_id, ffd.tb) != 0) {
		const git_error* ge = git_error_last();
		fprintf(stderr, "git: tree write failed: %s\n",
		        ge && ge->message ? ge->message : "unknown");
		goto out;
	}

	if (git_tree_lookup(&tree, ffd.repo, &tree_id) != 0) {
		const git_error* ge = git_error_last();
		fprintf(stderr, "git: tree lookup failed: %s\n",
		        ge && ge->message ? ge->message : "unknown");
		goto out;
	}

	if (git_signature_now(&sig, "xbps-files", "noreply@example") != 0) {
		fprintf(stderr, "git: signature_now failed\n");
		goto out;
	}

	gr = git_commit_create_v(&commit_id, ffd.repo,
	                         NULL,
	                         sig, sig, NULL,
	                         "xbps filelist snapshot", tree,
	                         0 /* nparents */);
	if (gr != 0) {
		const git_error* ge = git_error_last();
		fprintf(stderr, "git: commit failed: %s\n",
		        ge && ge->message ? ge->message : "unknown");
		rv = 1;
	} else {
		char oidstr[GIT_OID_HEXSZ + 1];
		git_oid_tostr(oidstr, sizeof oidstr, &commit_id);
		printf("commit %s written to %s\n", oidstr, reference_str);

		if (ffd.prev_ref) {
			git_reference* out;
			gr = git_reference_set_target(&out, ffd.prev_ref, &commit_id, "set tip to newest tree");
			if (gr != 0) {
				const git_error* ge = git_error_last();
				fprintf(stderr, "git: set target failed: %s\n",
				        ge && ge->message ? ge->message : "unknown");
			}
		}
	}

	git_repository_set_head(ffd.repo, reference_str);

out:
	/* opruimen gedeelde state */
	if (ffd.tb) git_treebuilder_free(ffd.tb);
	if (tree) git_tree_free(tree);
	if (sig) git_signature_free(sig);
	if (ffd.repo) git_repository_free(ffd.repo);
	pthread_mutex_destroy(&ffd.gitmtx);
	git_libgit2_shutdown();

	return rv;
}
