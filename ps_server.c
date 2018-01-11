#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <signal.h>
#include <getopt.h>
#include <pwd.h>
#include <ctype.h>
#include <time.h>
#include <fcntl.h>
#include <ucontext.h>
#include "tree.h"

//define constants
#define FALSE 1
#define TRUE 0
#define PATH "/proc/"

//create globals
int exit_flag = FALSE;
int s_sock;
int c_sock;
FILE *out_file;
char *sock_path;

/******************************************************************************
 *When a user hits the exit flag, this function will run, closing any open    *
 *sockets, and file descriptors                                               *
 ******************************************************************************/

void exit_program(int return_value)
{
	if (s_sock > 0)
		close(s_sock);
	if (c_sock > 0)
		close(c_sock);
	if (out_file != 0)
		fclose(out_file);
	exit(return_value);
}

/**************************************************************************
 *This function fetches the directory for the process so that get_process *
 *Can find the proper process                                             *
 **************************************************************************/

char *get_directory(char *name)
{
	char *temp_file = calloc(PATH_MAX, sizeof(char));
	int path_len = strnlen(PATH, PATH_MAX);
	int name_len = strnlen(name, PATH_MAX);
	int total_len = path_len + name_len + 1;

	//build path for the process
	strncpy(temp_file, PATH, path_len);
	strncat(temp_file, name, total_len);

	return temp_file;
}

/**************************************************************************
 *This function takes a path and returns true if the file is owned by the *
 *specified user, and returns false otherwise                             *
 *This was taken from the stat man pages                                  *
 **************************************************************************/

int check_file_owner(char *file, char *user)
{
	struct stat statbuf;
	struct passwd *pass = NULL;

	stat(file, &statbuf);
	pass = getpwuid(statbuf.st_uid);
	if (pass != NULL) {

		//Strncpy
		if ((strncmp(pass->pw_name, user, PATH_MAX)) == 0)
			return TRUE;
	}

	return FALSE;
}

/**************************************************************************
 *This function takes a line from the status file from a process and will *
 *clean it, returning the name of the process                             *
 **************************************************************************/

char *clean_process_name(char *line)
{

	char *process_name = calloc(PATH_MAX, sizeof(char));
	char *token;

	//strip the newline character and get process name
	line[strnlen(line, PATH_MAX) - 1] = '\0';
	token = strtok(line, "\t");

	while (token != NULL) {

		if ((strncmp(token, "Name:", PATH_MAX) != 0))
			strncpy(process_name, token, strnlen(token, PATH_MAX));

		token = strtok(NULL, "\t");
	}

	return process_name;
}

/******************************************************************************
 *Takes a file path and gets the name of the process from the /proc/ directory*
 *Syntax for this function is from:                                           *
 *https://www.stackoverflow/questions/3501338/c-read-file-line-by-line        *
 ******************************************************************************/

char *fetch_name(char *file_path)
{
	char *process = NULL;
	char *line = NULL;

	strncat(file_path, "/status", PATH_MAX);
	FILE *file = fopen(file_path, "r");
	size_t len = 0;
	ssize_t read = NULL;

	//Grab the name of the process, stored in the status file
	read = getline(&line, &len, file);
	if (read)
		process = clean_process_name(line);
	else
		exit_program(FALSE);

	fclose(file);
	free(line);
	return process;
}

/******************************************************************************
 *This function accepts a file and a user and checks the file to see if it is *
 *a valid file and see if it is a process                                     *
 ******************************************************************************/

int is_file_valid(struct dirent *file, char *user)
{

	if (file != NULL) {
		if (file->d_type == 4 && isdigit(file->d_name[0]))
			return TRUE;
		else
			return FALSE;
	} else
		return FALSE;

}

/******************************************************************************
 *Get the processes owned by the user.                                        *
 *                                                                            *
 ******************************************************************************/

void get_processes(struct node **tree, char *user)
{
	if (!user)
		exit_program(FALSE);

	char *file_name;
	char *leaf_name;
	//open directory
	struct dirent *file;
	DIR *proc = opendir(PATH);

	file = readdir(proc);

	while ((file = readdir(proc))) {

		if (is_file_valid(file, user) == TRUE) {
			//Get file name
			file_name = get_directory(file->d_name);
			if (check_file_owner(file_name, user) == TRUE) {

				leaf_name = fetch_name(file_name);

				//add to the tree
				if (*tree == NULL)
					*tree = create_leaf(leaf_name);
				else
					insert_leaf(tree, leaf_name);
				free(leaf_name);
			}
			free(file_name);
		}
	}
	closedir(proc);
	free(file);
}

/****************************************************************************
 * this function handles the Signal by setting the flag to TRUE so the      *
 * server can gracefully exit                                               *
 ****************************************************************************/

void handle_signal(int signal, siginfo_t *si, void *arg)
{
	printf("Exiting...\n");
	exit_flag = TRUE;
}

/****************************************************************************
 * this function gets the local time                                        *
 * This code was taken from the following:                                  *
 * https://stackoverflow.com/questions/5141960/get-the-current-time-in-c    *
 ****************************************************************************/

char *get_local_time()
{
	time_t rawtime;
	struct tm *timeinfo;

	time(&rawtime);
	timeinfo = localtime(&rawtime);
	return asctime(timeinfo);

}

/***************************************************************************
 * This function will write the user and the number of processes they're   *
 * running to the specified log file                                       *
 ***************************************************************************/

void write_to_file(char *user, struct node *tree)
{
	int number_of_processes = 0;

	number_of_processes = get_process_count(tree);
	fprintf(out_file, "USER %s [%d]", user, number_of_processes);
	fprintf(out_file, "\n");

}

/****************************************************************************
 * This function handles the opts for the program                           *
 * it is not working 100% yet, still needs to account                       *
 * for runing the program without an argument -v or without                 *
 * an argument                                                              *
 ****************************************************************************/

int handle_opts(int argc, char **argv)
{
	int opts = 0;
	char *log_file = NULL;
	char *time = NULL;

	//getopt -v
	opts = getopt(argc, argv, "v:");
	if (opts != -1) {
		if (argc != 4) {
			printf("Usage: ./ps_server [-v filename] server_name");
			printf("\n");
			exit(FALSE);
		} else {

			log_file = argv[2];
			time = get_local_time();
			sock_path = argv[3];

			out_file = fopen(log_file, "awb");
			if (!out_file)
				exit(FALSE);

			fprintf(out_file, "PS Server logging started %s", time);
			time = NULL;
			return TRUE;
		}
	} else {
		//IF -v is not set, check for servername
		if (argc != 2) {
			printf("Usage: ./ps_server [-v filename] server_name");
			printf("\n");
			exit(FALSE);
		} else {
			sock_path = argv[1];
		}

	}
	return FALSE;
}

/****************************************************************************
 * This function strips the newline character from the entered username     *
 *                                                                          *
 ****************************************************************************/

char *strip_new_line(char *user)
{
	int len = strnlen(user, PATH_MAX) - 1;

	user[len] = '\0';
	return user;
}

/****************************************************************************
 * This function initiates the listening of the server                      *
 *                                                                          *
 ****************************************************************************/

int start_to_listen(int backlog)
{
	int rc;

	rc = listen(s_sock, backlog);
	if (rc == -1) {
		close(s_sock);
		exit(FALSE);
	}
	printf("socket listening...\n");
	return rc;
}

/****************************************************************************
 * This function recieves the username from the client                      *
 *                                                                          *
 ****************************************************************************/

char *receive_data(char *buf)
{
	int bytes_rec;
	char *user;

	bytes_rec = recv(c_sock, buf, PATH_MAX, 0);
	if (bytes_rec == -1)
		exit_program(FALSE);
	else {
		user = strip_new_line(buf);
		printf("USER = %s\n", user);
		return user;
	}
	return NULL;
}

/****************************************************************************
 * This function writes the data to the client, if -v is set it will        *
 * log to the log file. It also frees the tree                              *
 ****************************************************************************/

void handle_data(struct node *tree, int v_flag, char *user)
{
	if (v_flag == TRUE)                       //Write to logfile
		write_to_file(user, tree);

	print_tree(tree, c_sock, v_flag);         //Send the data back
	destroy_tree(tree);
	close(c_sock);
}


/****************************************************************************
 * This function initiates the signal handler for SIGINT using sigaction    *
 *                                                                          *
 ****************************************************************************/

void set_up_signal(struct sigaction sa)
{
	memset(&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = handle_signal;
	sigaction(SIGINT, &sa, NULL);

}

int main(int argc, char **argv)
{

	struct sigaction sa;
	int rc, v_flag;
	unsigned int len;
	int backlog   = 10;
	char *user = NULL;
	struct sockaddr_un s_sockaddr;
	struct sockaddr_un c_sockaddr;
	char *buf = malloc(sizeof(char) * PATH_MAX);

	out_file = NULL;
	set_up_signal(sa);
	v_flag = handle_opts(argc, argv);
	memset(buf, 0, PATH_MAX);
	memset(&s_sockaddr, 0, sizeof(struct sockaddr_un));
	memset(&c_sockaddr, 0, sizeof(struct sockaddr_un));

	s_sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s_sock == -1)
		exit_program(FALSE);

	s_sockaddr.sun_family = AF_UNIX;
	strcpy(s_sockaddr.sun_path, sock_path);
	len = sizeof(s_sockaddr);

	unlink(sock_path);
	rc = bind(s_sock, (struct sockaddr *) &s_sockaddr, len);
	if (rc == -1)
		exit_program(FALSE);

	while (exit_flag == FALSE) {

		struct node *tree = NULL;

		rc = start_to_listen(backlog);
		c_sock = accept(s_sock, (struct sockaddr *) &c_sockaddr, &len);
		if (c_sock == -1) {
			free(buf);
			exit_program(FALSE);
		}

		len = sizeof(c_sockaddr);
		rc = getpeername(c_sock, (struct sockaddr *) &c_sockaddr, &len);
		if (rc == 1) {
			free(buf);
			exit_program(FALSE);
		}
		user = receive_data(buf);
		get_processes(&tree, user);
		handle_data(tree, v_flag, user);

		memset(buf,  0, PATH_MAX);
		memset(user, 0, PATH_MAX);
	}

	return 0;
}
