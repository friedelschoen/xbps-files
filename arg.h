#pragma once

#define SHIFT (argc--, argv++)

#define ARGBEGIN                                                  \
	for (SHIFT; *argv && *argv[0] == '-'; SHIFT, ((void) argc)) { \
		if ((*argv)[1] == '-' && (*argv)[2] == '\0') {            \
			SHIFT;                                                \
			break;                                                \
		}                                                         \
		for (char *opt = *argv + 1; *opt; opt++) {

#define ARGEND \
	}          \
	}

#define OPT          (*opt)
#define ARGF         (argv[1] ? (SHIFT, *argv) : NULL)
#define EARGF(usage) (argv[1] ? (SHIFT, *argv) : (printf("'-%c' requires an argument\n", *opt), usage, ""))
