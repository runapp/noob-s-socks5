#ifndef _GETOPT_INT_H
#define _GETOPT_INT_H	1

#include "getopt.h"

extern int _getopt_internal (int ___argc, char **___argv,
			     const char *__shortopts,
			     const struct option *__longopts, int *__longind,
			     int __long_only, int __posixly_correct);

enum __ord
  {
    REQUIRE_ORDER, PERMUTE, RETURN_IN_ORDER
  };

struct _getopt_data
{
  int optind;
  int opterr;
  int optopt;
  char *optarg;

  int __initialized;

  char *__nextchar;

  enum __ord __ordering;

  int __first_nonopt;
  int __last_nonopt;
};

#define _GETOPT_DATA_INITIALIZER	{ 1, 1 }

extern int _getopt_internal_r (int ___argc, char **___argv,
			       const char *__shortopts,
			       const struct option *__longopts, int *__longind,
			       int __long_only, struct _getopt_data *__data,
			       int __posixly_correct);

extern int _getopt_long_r (int ___argc, char **___argv,
			   const char *__shortopts,
			   const struct option *__longopts, int *__longind,
			   struct _getopt_data *__data);

extern int _getopt_long_only_r (int ___argc, char **___argv,
				const char *__shortopts,
				const struct option *__longopts,
				int *__longind,
				struct _getopt_data *__data);

#endif /* getopt_int.h */
