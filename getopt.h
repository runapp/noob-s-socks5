
#ifndef _GETOPT_H
#define _GETOPT_H 1

#ifdef __cplusplus 
#define __THROW throw()
extern "C" {
#else
#define __THROW
#endif
#define __nonnull(...)

#ifndef __getopt_argv_const
# define __getopt_argv_const const
#endif

extern char* optarg;
extern int optind;
extern int opterr;
extern int optopt;
extern int getopt(int ___argc, char* const* ___argv, const char* __shortopts)
__THROW __nonnull((2, 3));


struct option
{
	const char* name;
	/* has_arg can't be an enum because some compilers complain about
	   type mismatches in all the code that assumes it is an int.  */
	int has_arg;
	int* flag;
	int val;
};

/* Names for the values of the 'has_arg' field of 'struct option'.  */

#define no_argument		0
#define required_argument	1
#define optional_argument	2

extern int getopt_long(int ___argc, char* __getopt_argv_const* ___argv,
	const char* __shortopts,
	const struct option* __longopts, int* __longind)
	__THROW __nonnull((2, 3));
extern int getopt_long_only(int ___argc, char* __getopt_argv_const* ___argv,
	const char* __shortopts,
	const struct option* __longopts, int* __longind)
	__THROW __nonnull((2, 3));


#ifdef __cplusplus
} // extern "C" {
#endif

#endif /* getopt.h */
