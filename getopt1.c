#include "getopt.h"
#include "getopt_int.h"

int
getopt_long (int argc, char *__getopt_argv_const *argv, const char *options,
	     const struct option *long_options, int *opt_index)
{
  return _getopt_internal (argc, (char **) argv, options, long_options,
			   opt_index, 0, 0);
}

int
_getopt_long_r (int argc, char **argv, const char *options,
		const struct option *long_options, int *opt_index,
		struct _getopt_data *d)
{
  return _getopt_internal_r (argc, argv, options, long_options, opt_index,
			     0, d, 0);
}

int
getopt_long_only (int argc, char *__getopt_argv_const *argv,
		  const char *options,
		  const struct option *long_options, int *opt_index)
{
  return _getopt_internal (argc, (char **) argv, options, long_options,
			   opt_index, 1, 0);
}

int
_getopt_long_only_r (int argc, char **argv, const char *options,
		     const struct option *long_options, int *opt_index,
		     struct _getopt_data *d)
{
  return _getopt_internal_r (argc, argv, options, long_options, opt_index,
			     1, d, 0);
}
