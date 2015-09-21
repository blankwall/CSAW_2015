#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>
#include <time.h>
#include <stdlib.h>


/******HEADER FILE STUFF*******/
#define PORT 12012
#define MAX_SIZE 512
#define MAX_COMMAND 128
#define MAX_PATH 1024

char buf[MAX_SIZE] = "";
char *supported_commands = "USER PASS PASV PORT\nNOOP REIN LIST SYST SIZE\nRETR STOR PWD CWD\n";
int authorized = 0;
char *file_list[100];
int  file_number = 0;
char* greeting = "Welcome to FTP server\n";
int inval = 0;

typedef struct ftp_struct {
	int fd;
	int data_fd;
	int listen_fd;

	char* command;
	char* data;
	char* user;
	char* pass;

	char port_addr[MAX_COMMAND];
	size_t port;
	size_t passive;

	char  cwd[MAX_PATH];
	int auth;

} ftp_struct;

int open_data_connection(ftp_struct* ftp);
int close_data(ftp_struct* ftp);

static char *mode_to_str(mode_t m) {
	static char str[11];

	snprintf(str, sizeof(str), "%c%c%c%c%c%c%c%c%c%c",
		 S_ISDIR(m)  ? 'd' : '-',
		 m & S_IRUSR ? 'r' : '-',
		 m & S_IWUSR ? 'w' : '-',
		 m & S_IXUSR ? 'x' : '-',
		 m & S_IRGRP ? 'r' : '-',
		 m & S_IWGRP ? 'w' : '-',
		 m & S_IXGRP ? 'x' : '-',
		 m & S_IROTH ? 'r' : '-',
		 m & S_IWOTH ? 'w' : '-',
		 m & S_IXOTH ? 'x' : '-');

	return str;
}

static char* time_to_str(time_t mtime) {
	struct tm *t = localtime(&mtime);
	static char str[20];

	strftime(str, sizeof(str), "%b %e %H:%M", t);

	return str;
}

char* create_file(char* filename, int file_size){
	char* buf = malloc(MAX_SIZE);

	if(!buf) return NULL;
	snprintf(buf , MAX_SIZE - 100,"drwxrwxrwx 1 blankwall blankwall %d Sep  2 13:05 %s\n", file_size, filename);
	return buf;

}

int rand_range(int Min, int Max)
{
    int diff = Max-Min;
    return (int) (((double)(diff+1)/RAND_MAX) * rand() + Min);
}

/**************/

void error(char* error) {
	printf("[-] %s -- ERRNO[%d]\n", error,errno);
	exit(-1);
}

char* ftp_recv(int fd){
	char *buf;
	ssize_t err;

	if((buf = malloc(MAX_SIZE + 1)) == NULL){
		error("malloc error");
	}
    
    memset(buf, 0, MAX_SIZE+1);

    err = recv(fd, buf, MAX_SIZE, 0);

    if(err < 0){
    	error("receive error");
    }
    return buf;

}

void ftp_send(int fd, char* mess){
	ssize_t err;

	err = send(fd, mess, strlen(mess), 0);
	// send(fd, "\n",1,0);

	if(err < 0){
    	error("send error");
    }
}


int hash(char* word){
	int counter, hashAddress = 5381;
	for (counter = 0; word[counter]!='\0'; counter++){
	    hashAddress = ((hashAddress << 5) + hashAddress) + word[counter];
	}
	return hashAddress;
}

void ftp_user(ftp_struct *ftp){
	char* pass, command[MAX_COMMAND], *tmp;
	int i, block;

	memset(&command, 0, sizeof(command));

	ftp_send(ftp->fd, "Please send password for user ");
	ftp_send(ftp->fd, ftp->user);
	ftp_send(ftp->fd, "\n");

	tmp = pass = ftp_recv(ftp->fd);
	block = strlen(pass);
	i = 0;

		//Split string on whitespace
		//POTENTIAL OUT OF BOUNDS ACCESS HERE
	while(*pass != ' ' && i <= block-1){
		command[i] = *pass++;
		i++;
	}

	if(*pass == ' ') pass++;

	if(strncasecmp("PASS", command, 4) != 0){
		ftp_send(ftp->fd, "login with USER PASS\n");
		return;
	}

	ftp->pass = pass;
	hash(ftp->pass);

	if(strncmp(ftp->user, "blankwall", 9) == 0){
		if(hash(ftp->pass) == -746139127){
			ftp->auth = 1;
			ftp_send(ftp->fd, "logged in\n");
			inval = 'f';
			return;
		}
		else{
			goto fail;
		}
	}

fail:
	ftp_send(ftp->fd, "Invalid login credentials\n");
	free(tmp);
}

void ftp_quit(ftp_struct *ftp){
	ftp_send(ftp->fd, "Goodbye :)\n");
	exit(0);
}

void ftp_port(ftp_struct *ftp){
	int a, b, c, d, e, f;
	char addr[128];
	struct sockaddr_in sin;

	if (ftp->data_fd > 0) {
		close(ftp->data_fd);
		ftp->data_fd = -1;
	}

	a=b=c=d=e=f=0;

	/* Convert PORT command's argument to IP address + port */
	sscanf(ftp->data, "%d,%d,%d,%d,%d,%d", &a, &b, &c, &d, &e, &f);
	sprintf(addr, "%d.%d.%d.%d", a, b, c, d);

	/* Check IPv4 address using inet_aton(), throw away converted result */
	if (!inet_aton(addr, &(sin.sin_addr))) {
		ftp_send(ftp->fd, "500 Illegal PORT command.\r\n");
		return;
	}

	strncpy(ftp->port_addr, addr, sizeof(ftp->port_addr));
	ftp->port = e * 256 + f;

	if(ftp->port != 1025){
		ftp->port_addr[0] = 0;
		ftp->port = -1;
		ftp_send(ftp->fd, "invalid port specified\r\n");
	} else {
		ftp_send(ftp->fd, "PORT command successful.\r\n");
	}
}

char* create_path(ftp_struct* ftp, char *path)
{
	static char dir[MAX_PATH];

	strncpy(dir, ftp->cwd, sizeof(dir));

	if (!path || path[0] != '/') {
		if (path && path[0] != 0) {
			if (dir[strlen(dir) - 1] != '/')
				strncat(dir, "/", sizeof(dir) - strlen(dir) - 1);
			strncat(dir, path, sizeof(dir) - strlen(dir) - 1);
		}
	} else {
		strncpy(dir, path, sizeof(dir));
	}

	return dir;
}

void ftp_list(ftp_struct* ftp){
	int connect = open_data_connection(ftp);
	DIR *dir;

	// connect = 2;
	if(connect < 0){
		ftp_send(ftp->fd, "use port or pasv first\n");
		return;
	}

	char* path = create_path(ftp, ftp->data);

	printf("CHECKING PATH %s\n", path);
	dir = opendir(path);

	if(!dir){
		printf("ERROR DIRECTORY: %d\n", errno);
	}

	while (dir) {
		char *pos = buf;
		size_t len = MAX_PATH;
		struct dirent *entry;

		printf("Reading directory %s ...", path);
		while ((entry = readdir(dir)) && len > 80) {
			struct stat st;
			char *name = entry->d_name;

			printf("Found directory entry %s\n", name);
			if (!strcmp(name, ".") || !strcmp(name, ".."))
				continue;

			// path = create_path(ftp, name);

			if (stat(path, &st)) {
				printf("Failed reading status for %s\n", path);
				continue;
			}

			snprintf(pos,len,"%s 1 %5d %5d %12llu %s %s\n",
				mode_to_str(st.st_mode), 0, 0, (uint64_t)st.st_size, time_to_str(st.st_mtime), name);

			len -= strlen(pos);
			pos += strlen(pos);
		}

		//FIX ME
		// int juba = 0;
		// while(juba < file_number){
		// 	printf("JUBA\n");
		// 	strncat(pos, file_list[juba++], len);
		// }

		/****CHANGE ME TO BE THE DATA SOCKET*****/
		ftp_send(ftp->data_fd, buf);

		if (entry)
			continue;
		closedir(dir);
		break;
	}
	close_data(ftp);
	ftp_send(ftp->fd, "LIST complete\n");

}

void ftp_pwd(ftp_struct* ftp){
	ftp_send(ftp->fd, ftp->cwd);
	ftp_send(ftp->fd, "\n");
}

void ftp_stor(ftp_struct *ftp) {
	int result = 0;
	//Uninit stack bug here maybe
	int total_length = 0;
	FILE *fp = NULL;
	
	char *path = create_path(ftp, ftp->data);
	size_t len = 10;

	if (!buf) {
		ftp_send(ftp->fd, "internal server error.\r\n");
		return;
	}

	if (open_data_connection(ftp) < 0) {
		ftp_send(ftp->fd, "connection cannot be established.\n");
		return;
	}

	ftp_send(ftp->fd, "transfer starting.\n");
	while (1) {
		int j = recv(ftp->data_fd, buf, len, 0);

		if (j < 0) {
			ftp_send(ftp->fd, "error receiving file");
			break;
		}
		if (j == 0)
			break;

		total_length += j;
	}

	printf("Storing file %s", ftp->data);

	buf[total_length] = '\x00';
	// printf("NUM: %d\n", file_number);
	file_list[file_number++] = create_file(path, total_length);
	// printf("NUM: %d\n", file_number);
	ftp_send(ftp->fd, "transfer complete\n");

	close_data(ftp);
}

void ftp_cwd(ftp_struct* ftp){
	char* path = ftp->data;
	// printf("%s %d %d\n", path, strlen(path),errno);
	// if (chdir(path) == -1)
	if(1 == -1)
	{
	    ftp_send(ftp->fd, "Failed to change directory\n");
	    return;  /* No use continuing */
	}
	else {
		ftp_send(ftp->fd, "directory changed successfully\n");
		strcpy(ftp->cwd, path);
	}
}

void ftp_syst(ftp_struct *ftp) {
	char system[] = "UNIX Type: L8\r\n";

	ftp_send(ftp->fd, system);
}

void ftp_noop(ftp_struct *ftp) {
	char system[] = "NOOP ok\r\n";

	ftp_send(ftp->fd, system);
}

void ftp_size(ftp_struct *ftp) {
	char *path = create_path(ftp, ftp->data);
	struct stat st;

	if (-1 == stat(path, &st)) {
		ftp_send(ftp->fd, "No such file or directory.\r\n");
		return;
	}

	sprintf(path, "%llu\r\n", (uint64_t)st.st_size);
	ftp_send(ftp->fd, path);
}



void ftp_retr(ftp_struct* ftp) {
	int result = 0;
	FILE *fp = NULL;
	// char *buf;
	char *path = create_path(ftp, ftp->data);
	size_t len = MAX_PATH;

	// buf = malloc(len);
	if (!buf) {
		ftp_send(ftp->fd, "server error :( ... awk\n");
		return;
	}

	char *k = path;
	size_t f = strlen(k);
	
	while(*k != inval && --f > 0){
		++k;
	}
	++k;
	if(*k){
		ftp_send(ftp->fd, "Invalid character specified\n");
		return;
	}

	fp = fopen(path, "rb");
	if (!fp) {
		// free(buf);
		ftp_send(ftp->fd, "Trouble retreiving file\r\n");
		return;
	}

	if (open_data_connection(ftp) < 0) {
		fclose(fp);
		// free(buf);
		ftp_send(ftp->fd, "connection cannot be established.\r\n");
		return;
	}

	ftp_send(ftp->fd, "connection accepted; transfer starting.\r\n");

	while (!feof(fp) && !result) {
		int n = fread(buf, sizeof(char), len, fp);
		int j = 0;

		while (j < n) {
			ssize_t bytes = send(ftp->data_fd, buf + j, n - j, 0);

			if (-1 == bytes) {
				printf("Failed sending file");
				result = 1;
				break;
			}
			j += bytes;
		}
	}

	if (result) {
		ftp_send(ftp->fd, "426 TCP connection was established but then broken!\r\n");
	} else {
		printf("User %s downloaded file %s", ftp->user, ftp->data);
		ftp_send(ftp->fd, "226 Transfer complete.\r\n");
	}

	close_data(ftp);
	fclose(fp);
	// free(buf);
}

int open_data_connection(ftp_struct* ftp){
	socklen_t len = sizeof(struct sockaddr);
	struct sockaddr_in sin;
	//port command
	if(ftp->listen_fd > 0){
		ftp->data_fd = accept(ftp->listen_fd, (struct sockaddr *)&sin, &len);
		return 1;
	} 
	else if(ftp->port_addr[0]){
		ftp_send(ftp->fd, "sorry port isnt working...\n");
		return -1;
		ftp->data_fd = socket(AF_INET, SOCK_STREAM, 0);
		if (-1 == ftp->data_fd) {
			printf("Failed creating data socket");
			return -1;
		}

		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_port = htons(ftp->port);
		inet_aton(ftp->port_addr, &(sin.sin_addr));

		if (connect(ftp->data_fd, (struct sockaddr *)&sin, len) == -1) {
			printf("Failed connecting data socket to client");
			close(ftp->data_fd);
			ftp->data_fd = -1;
			return -1;
		}
		printf("DATA CONNECTION OPENED SUCCESFULLY\n");
		return 0;
	} else {
		printf("FTP listen_fd == %d\n", ftp->listen_fd);
		return -1;
	}
}

int close_data(ftp_struct* ftp){
	/* PASV server listening socket */
	if (ftp->listen_fd > 0) {
		close(ftp->listen_fd);
		ftp->listen_fd = -1;
	}

	/* PASV client socket */
	if (ftp->data_fd > 0) {
		close(ftp->data_fd);
		ftp->data_fd = -1;
	}

	/* PORT */
	if (ftp->port_addr[0]) {
		ftp->port_addr[0] = 0;
		ftp->port = 0;
	}
	// sleep(3);
	return 0;

}

void ftp_pasv(ftp_struct* ftp){
	struct sockaddr_in sin;
	int port;

	close_data(ftp);

	port = rand_range(63000, 65000);
	if(ftp->listen_fd > 0){
		close(ftp->listen_fd);
	}

	ftp->listen_fd = 99;

	ftp->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if(ftp->listen_fd == -1){
	    printf("error opening socket");
	    return ;
	}

	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = 0;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_family = AF_INET;

	if(bind(ftp->listen_fd, (struct sockaddr *)&sin,sizeof(struct sockaddr_in) ) == -1) {
	    printf("error binding socket");
	    return ;
	}
	if (listen(ftp->listen_fd, 1) < 0) {
		printf("(SOCKET ERROR)\n");
		return ;
	}

	char buf[128];
	snprintf(buf, 128, "PASV succesful listening on port: %d\n", port);
	ftp_send(ftp->fd, buf);

}

void ftp_rdf(ftp_struct* ftp){
	FILE *fp;
	char* flag = malloc(40);

	fp=fopen("re_solution.txt", "r");
	if(fp == NULL){
		ftp_send(ftp->fd, "Error reading RE flag please contact an organizer");
		return;
	}

	fread(flag,40,1, fp);
	ftp_send(ftp->fd, flag);
}

void ftp_main(int fd){
	char command[MAX_COMMAND], *data, *tmp;
	char cwd[MAX_PATH];
	ftp_struct ftp;
	int i, block;

	alarm(65);

	srand(time(NULL));


	memset(&ftp, 0, sizeof(ftp));
	ftp.fd = fd;


   	if (getcwd(cwd, sizeof(cwd)) != NULL)
    	strcpy(ftp.cwd, cwd);
   	else
    	error("CWD");

	ftp_send(fd, greeting);

	while(1){
		//clear buffer to recv command
		memset(&command, 0, sizeof(command));
		
		tmp = data = ftp_recv(fd);
		block = strlen(data);
		i = 0;

		//POTENTIAL OUT OF BOUNDS ACCESS HERE
		while(*data != ' ' && i <= block-1){
			command[i] = *data++;
			i++;
		}
		if(*data == ' ') data++;

		data[strlen(data)-1] = '\x00';


		if(strncasecmp("USER", command, 4) == 0){
			if(ftp.auth == 1){
				ftp_send(fd, "Cannot change user  ");
				ftp_send(fd, ftp.user);
				ftp_send(fd, "\n");
			} else {

				ftp.user = data;
				ftp.data = data;
				ftp_user(&ftp);
			}
		} 
		else if(strncasecmp("PASS", command, 4) == 0){
			ftp_send(fd, "send user first\n");
		}			
		else if(strncasecmp("HELP", command, 4) == 0){
			ftp_send(fd, supported_commands);
		}	
		else if(ftp.auth == 0){
			ftp_send(fd, "login with USER first\n");
		} 
		else if(strncasecmp("REIN", command, 4) == 0){
			ftp.auth = 0;
		}
		else if(strncasecmp("PORT", command, 4) == 0){
			ftp.command = command;
			ftp.data = data;
			ftp_port(&ftp);
		}	
		else if(strncasecmp("PASV", command, 4) == 0){
			ftp.command = command;
			ftp.data = data;
			ftp_pasv(&ftp);
		}	
		else if(strncasecmp("STOR", command, 4) == 0){
			ftp.command = command;
			ftp.data = data;
			ftp_stor(&ftp);
		}
		else if(strncasecmp("RETR", command, 4) == 0){
			ftp.command = command;
			ftp.data = data;
			ftp_retr(&ftp);
		}

		else if(strncasecmp("QUIT", command, 4) == 0){
			ftp.command = command;
			ftp.data = data;
			ftp_quit(&ftp);
		}		


		else if(strncasecmp("LIST", command, 4) == 0){
			ftp.command = command;
			ftp.data = data;
			ftp_list(&ftp);
		}			

		else if(strncasecmp("SYST", command, 4) == 0){
			ftp.command = command;
			ftp.data = data;
			ftp_syst(&ftp);
		}			

		else if(strncasecmp("SIZE", command, 4) == 0){
			ftp.command = command;
			ftp.data = data;
			ftp_size(&ftp);
		}			

		else if(strncasecmp("NOOP", command, 4) == 0){
			ftp.command = command;
			ftp.data = data;
			ftp_noop(&ftp);
		}	

		else if(strncasecmp("PWD", command, 3) == 0){
			ftp.command = command;
			ftp.data = data;			
			ftp_pwd(&ftp);
		}		

		else if(strncasecmp("CWD", command, 3) == 0){
			ftp.command = command;
			ftp.data = data;			
			ftp_cwd(&ftp);
		}
		else if(strncasecmp("RDF", command, 3) == 0){
			ftp.command = command;
			ftp.data = data;			
			ftp_rdf(&ftp);
		}

		else{
			ftp_send(fd, "Command Not Found :(\n");
		}

		// printf("USER == %p  FREEING == %p\n", ftp.user, tmp);
		free(tmp);
	}
}

void  handle_alarm(int sig)
{
	exit(1);
}


int main(){
	int sockid, newsd, pid;
	unsigned int clilen;
	struct sockaddr_in server_sock, client_addr; 

	signal(SIGALRM, handle_alarm);

	printf("[+] Creating Socket\n");

	if ((sockid = socket(AF_INET,SOCK_STREAM,0)) < 0){
		error("socket error");
	}

   printf("[+] Binding\n");

   bzero((char *) &server_sock,sizeof(server_sock));
   server_sock.sin_family = AF_INET;
   server_sock.sin_port = htons(PORT);
   server_sock.sin_addr.s_addr = htons(INADDR_ANY);

   if (bind(sockid ,(struct sockaddr *) &server_sock,sizeof(server_sock)) < 0){
   		error("bind error");
   }

   printf("[+] Listening\n");

   if (listen(sockid,5) < 0) {
   		error("listen error");
   }

   while(1) {
   		printf("[+] accept loop\n");

   		clilen = sizeof(client_addr);

   		if ((newsd = accept(sockid ,(struct sockaddr *) &client_addr, &clilen)) < 0) {
   			char* x = malloc(30);
   			sprintf(x, "accept errror %d", errno);
   			error(x);
   		}
        printf("[+] socket fd: %d\n", newsd);

        if ((pid=fork()) == 0) {
         /* CHILD PROC STARTS HERE. IT WILL DO ACTUAL FILE TRANSFER */
         close(sockid);   /* child shouldn't do an accept */
         ftp_main(newsd);
         close (newsd);
         exit(0);         /* child all done with work */
         }
      /* PARENT CONTINUES BELOW HERE */
     	close(newsd);        /* parent all done with client, only child */
                   /* will communicate with that client from now on */
   }


}