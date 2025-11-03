/* xbps-filesgrep.c
 * Sync (optioneel) naar ~/.cache/xbps-files.git en grep over blobs in refs/heads/xbps-files
 * Licentie: BSD-2-Clause (zoals je eerdere bestand)
 */

#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <git2.h>
#include <limits.h>
#include <regex.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static void die(const char* fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	exit(EXIT_FAILURE);
}

static bool path_exists(const char* p) {
	struct stat st;
	return stat(p, &st) == 0;
}

static void ensure_parent_dirs(const char* path) {
	/* maakt ~/.cache als nodig; simpel: alleen dat niveau */
	const char* home = getenv("HOME");
	if (!home || !*home) die("HOME is niet gezet");
	char cache[PATH_MAX];
	snprintf(cache, sizeof cache, "%s/.cache", home);
	if (!path_exists(cache)) {
		if (mkdir(cache, 0700) != 0 && errno != EEXIST)
			die("mkdir %s: %s", cache, strerror(errno));
	}
}

/* Bouw pad naar ~/.cache/xbps-files.git */
static void cache_path(char* out, size_t outsz) {
	const char* home = getenv("HOME");
	if (!home || !*home) die("HOME is niet gezet");
	snprintf(out, outsz, "%s/.cache/xbps-files.git", home);
}

static void git_check(int code, const char* what) {
	if (code == 0) return;
	const git_error* ge = git_error_last();
	die("git: %s failed: %s", what, ge && ge->message ? ge->message : "unknown");
}

/* Clone als niet bestaat; anders fetch ff op branch refs/heads/xbps-files */
static void sync_repo(const char* remote_url, const char* local_path) {
	if (!remote_url || !*remote_url)
		die("-S vereist een remote URL");

	if (!path_exists(local_path)) {
		ensure_parent_dirs(local_path);
		git_clone_options copts = GIT_CLONE_OPTIONS_INIT;
		copts.bare              = 1;
		/* we willen alleen branch xbps-files */
		git_fetch_options fopts               = GIT_FETCH_OPTIONS_INIT;
		copts.fetch_opts                      = fopts;
		copts.checkout_opts.checkout_strategy = GIT_CHECKOUT_NONE;
		/* tip: specify branch */
		copts.checkout_branch = "xbps-files";

		git_repository* repo = NULL;
		/* libgit2 clone haalt refs binnen; maar met bare + no checkout */
		git_check(git_clone(&repo, remote_url, local_path, &copts), "clone");
		if (repo) git_repository_free(repo);
		return;
	}

	git_repository* repo = NULL;
	git_check(git_repository_open_bare(&repo, local_path), "open_bare");

	/* remote 'origin' aanmaken of updaten */
	git_remote* origin = NULL;
	int         rc     = git_remote_lookup(&origin, repo, "origin");
	if (rc == GIT_ENOTFOUND) {
		git_check(git_remote_create(&origin, repo, "origin", remote_url), "remote_create");
	} else {
		git_check(rc, "remote_lookup");
		/* updaten naar nieuw URL, voor het geval */
		git_check(git_remote_set_url(repo, "origin", remote_url), "remote_set_url");
	}

	/* fetch alleen onze branch naar dezelfde lokale ref */
	git_fetch_options fopts = GIT_FETCH_OPTIONS_INIT;
	git_strarray      sarr  = {
		      .strings = (char*[]){ "+refs/heads/xbps-files:refs/heads/xbps-files" },
		      .count   = 1,
	};

	git_check(git_remote_fetch(origin, &sarr, &fopts, NULL), "fetch");

	/* HEAD symbolisch naar refs/heads/xbps-files als dat nog niet zo is */
	git_reference* head = NULL;
	rc                  = git_repository_head(&head, repo);
	if (rc == 0) {
		/* ok, al gezet */
		git_reference_free(head);
	} else if (rc == GIT_EUNBORNBRANCH || rc == GIT_ENOTFOUND) {
		git_check(git_repository_set_head(repo, "refs/heads/xbps-files"), "set_head");
	} else {
		git_check(rc, "repository_head");
	}

	git_remote_free(origin);
	git_repository_free(repo);
}

/* Grep flags */
struct grep_opts {
	bool        fixed;
	bool        icase;
	const char* pattern;
};

/* simpele line-iteratie over blob-buffer */
static void grep_blob(const char* pkgver, const char* buf, size_t len,
                      const struct grep_opts* go, regex_t* re) {
	const char *p = buf, *end = buf + len;
	while (p < end) {
		const char* nl = memchr(p, '\n', (size_t) (end - p));
		size_t      l  = nl ? (size_t) (nl - p) : (size_t) (end - p);

		int match = 0;
		if (go->fixed) {
			if (go->icase) {
				/* case-insensitive substring search */
				/* naive: kopieer naar tijdelijke buffer in lower-case */
				char* hay = malloc(l + 1);
				if (!hay) return;
				for (size_t i = 0; i < l; i++) hay[i] = (char) tolower((unsigned char) p[i]);
				hay[l]        = '\0';
				size_t pl     = strlen(go->pattern);
				char*  needle = malloc(pl + 1);
				if (!needle) {
					free(hay);
					return;
				}
				for (size_t i = 0; i < pl; i++) needle[i] = (char) tolower((unsigned char) go->pattern[i]);
				needle[pl] = '\0';
				match      = (strstr(hay, needle) != NULL);
				free(needle);
				free(hay);
			} else {
				match = (memmem(p, l, go->pattern, strlen(go->pattern)) != NULL);
			}
		} else {
			/* regex */
			char tmp;
			/* ensure line is NUL-terminated for regexec; temporarily replace */
			char* line = (char*) p;
			tmp        = line[l];
			if (nl)
				*(char*) nl = '\0';
			else
				((char*) line)[l] = '\0';
			match = (regexec(re, line, 0, NULL, 0) == 0);
			if (nl)
				*(char*) nl = '\n';
			else
				((char*) line)[l] = tmp;
		}

		if (match) {
			fwrite(pkgver, 1, strlen(pkgver), stdout);
			fputs(": ", stdout);
			fwrite(p, 1, l, stdout);
			fputc('\n', stdout);
		}

		if (!nl) break;
		p = nl + 1;
	}
}

/* Loop alle blobs in tree van refs/heads/xbps-files en grep */
static void grep_repo_cached(const char* local_path, const struct grep_opts* go) {
	git_repository* repo = NULL;
	git_check(git_repository_open_bare(&repo, local_path), "open_bare");

	/* resolve branch ref */
	git_reference* ref = NULL;
	int            rc  = git_reference_lookup(&ref, repo, "refs/heads/xbps-files");
	if (rc == GIT_ENOTFOUND) die("branch refs/heads/xbps-files niet gevonden; sync eerst (-S)");
	git_check(rc, "reference_lookup");

	git_oid coid;
	git_check(git_reference_name_to_id(&coid, repo, "refs/heads/xbps-files"), "name_to_id");

	git_commit* commit = NULL;
	git_check(git_commit_lookup(&commit, repo, &coid), "commit_lookup");

	git_tree* tree = NULL;
	git_check(git_commit_tree(&tree, commit), "commit_tree");

	regex_t re;
	int     cflags = REG_NOSUB;
	if (go->icase) cflags |= REG_ICASE;
	if (!go->fixed) {
		int rr = regcomp(&re, go->pattern, cflags);
		if (rr != 0) {
			char errbuf[256];
			regerror(rr, &re, errbuf, sizeof errbuf);
			die("regex compile error: %s", errbuf);
		}
	}

	size_t n = git_tree_entrycount(tree);
	for (size_t i = 0; i < n; i++) {
		const git_tree_entry* te = git_tree_entry_byindex(tree, i);
		if (!te) continue;
		if (git_tree_entry_type(te) != GIT_OBJECT_BLOB) continue;

		const char* pkgver = git_tree_entry_name(te);
		git_oid     boid   = *git_tree_entry_id(te);

		git_blob* blob = NULL;
		if (git_blob_lookup(&blob, repo, &boid) != 0) continue;

		const void* buf = git_blob_rawcontent(blob);
		size_t      len = git_blob_rawsize(blob);

		grep_blob(pkgver, (const char*) buf, len, go, go->fixed ? NULL : &re);

		git_blob_free(blob);
	}

	if (!go->fixed) regfree(&re);
	git_tree_free(tree);
	git_commit_free(commit);
	git_reference_free(ref);
	git_repository_free(repo);
}

int main(int argc, char** argv) {
	int              opt_sync   = 0;
	const char*      remote_url = NULL;
	struct grep_opts go         = { 0 };

	/* Opties: -S <remote> -F -i ; pattern is laatste arg */
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-S") == 0) {
			if (i + 1 >= argc) die("gebruik: -S <remote-url>");
			opt_sync   = 1;
			remote_url = argv[++i];
		} else if (strcmp(argv[i], "-F") == 0) {
			go.fixed = true;
		} else if (strcmp(argv[i], "-i") == 0) {
			go.icase = true;
		} else if (argv[i][0] == '-') {
			die("onbekende optie: %s", argv[i]);
		} else {
			go.pattern = argv[i];
			/* alles na pattern negeren */
			break;
		}
	}

	if (!go.pattern) {
		fprintf(stderr,
		        "usage: %s [-S <remote-url>] [-F] [-i] <pattern>\n"
		        "  -S <remote-url>  Clone/fetch naar ~/.cache/xbps-files.git (branch xbps-files)\n"
		        "  -F               Fixed-string i.p.v. regex\n"
		        "  -i               Case-insensitive\n",
		        argv[0]);
		return 2;
	}

	char local[PATH_MAX];
	cache_path(local, sizeof local);

	if (git_libgit2_init() <= 0) die("git: init failed");

	if (opt_sync) {
		sync_repo(remote_url, local);
	} else {
		if (!path_exists(local))
			die("cache-repo %s bestaat niet; run met -S eerst", local);
	}

	grep_repo_cached(local, &go);

	git_libgit2_shutdown();
	return 0;
}
