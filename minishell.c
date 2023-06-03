/*************************************************************
* Program: minishell.c
*
* Description: 
        minishell.c reimplements the visual layout on the linux terminal 
        with changed actions on 'cd', 'stat' and 'll'.The shell is equipped
        to handle and ignore signal interrupt (ctrl and c). For commands 
        besides 'cd', 'stat', 'll', and exit, the program forks and directs 
        a child process to implement the default linux action via an execvp 
        syscall
*
* Author: Matthew Kearney
*
* Date: 
    * Created:  March 28 2023
    * Modified: June 3 2023
*
* Compiler: GNU Compiler Collection [makefile available]
**************************************************************/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>   //for errno
#include <string.h>  //string funcs
#include <sys/wait.h>  
#include <sys/types.h>  //pwd
#include <pwd.h>
#include <limits.h>   //for max pathlen
#include <signal.h>   //ctrl + c handling
#include <dirent.h>
#include <sys/stat.h>
#include <grp.h>     //groupname
#include <time.h>    //ctime()


#define GRN "\x1b[32m"
#define BLUE "\x1b[34;1m"
#define DEFAULT "\x1b[0m"


/* print_pwd() uses passwd struct to print the cwd */
void print_pwd(){
    uid_t uid = getuid();
    struct passwd *pwd = getpwuid(uid);  //user information struct, passwd
    char cwd[4096]; 

    if (pwd == NULL) { //struct cannot be opened
        fprintf(stderr,  "Error: Cannot get passwd entry. %s.\n", strerror(errno));
        return;
    }

    if (getcwd(cwd, sizeof(cwd)) == NULL) { //can't get cwd
        fprintf(stderr,  "Error: Cannot get current working directory. %s.\n", strerror(errno));
        return;
    }

    printf("%s[%s]%s> ", BLUE, cwd, DEFAULT);
    return;
}

/* cd to the path given */
void cd_path(char *path){
    if( chdir(path) == -1){
        fprintf(stderr, "Error: Cannot change directory to %s. %s.\n", path, strerror(errno));
    }
}

/* cd to the home directory*/
void cd_home(){
    uid_t uid = getuid();
    struct passwd *pwd = getpwuid(uid);  
    cd_path(pwd->pw_dir);
}

volatile __sig_atomic_t interrupted = 0; //initially set to false

/* signal handler function, passed to sa.sa_handler from signal.h */ 
void handle_interruption(int sig){
    if(sig==SIGINT){ //ctrl c
        printf("\n");
        interrupted = 1;
    }
}


/* main() implements the while loop to 
    -print the pwd
    -ask for user input
    -execute accordingly */
int main(){

    /* struct sigaction gives information for signal interruptions */
    struct sigaction sa;
    sa.sa_handler = handle_interruption;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags=0;
    sigaction(SIGINT, &sa, NULL);

    while(1){
        /* print the pwd before getting user input*/
        print_pwd();  //


        /* store user input */
        char input[4096]; //
        if (fgets(input, 4096, stdin) == NULL && (interrupted ==0)){
                fprintf(stderr,  "Error: Failed to read from stdin. %s.\n", strerror(errno));  
        }//input has user command


        /* parse the user input into args** */
        int num_words = 0; //word counter (
        char *args[4096];  // *args[] == char**

        char *tok = strtok(input, " ");
        if (tok == NULL){ //no first argument (command) provided (unnecessary but helpful)
            fprintf(stderr,  "Error: Failed to read from stdin. %s.\n", strerror(errno));
        } else {
            args[num_words]=tok;  //args[0] = first word
            num_words++; //args[1]...
            while((tok = strtok(NULL, " ")) != NULL){ 
                args[num_words]=tok; //args[1]= second word
                num_words++;   //therefore num_words = number of spaces +1
            }
            args[num_words]=NULL; 
               
        }

        
        /* get rid of "\n" in user input, so we can evaluate it */
        size_t idx = strcspn(args[num_words-1], "\n");
        if (idx < (size_t) strlen(args[num_words-1])){
            args[num_words-1][idx] = '\0';
        }


        /* check if interrupted, if so, then don't do anything in this iteration... */
        if(interrupted){
            interrupted=0;
            continue;
        }
        

        /* Evaluate the commands; exit, cd, other (exec) */
        if(strcmp(args[0], "exit") == 0){
            return EXIT_SUCCESS;
        } //not exiting, so check cd

        /* execute cd command */
        if(strcmp(args[0], "cd")==0){
            if(num_words>2){
                fprintf(stderr, "Error: Too many arguments to cd.\n");
                continue;
            } 

            if (args[1]==NULL  || strcmp(args[1], "~")==0) {
                cd_home();
                continue;
            }

            if(args[1] != NULL && strcmp(args[1], "~")!=0){
                cd_path(args[1]);
                continue;
            }
        }
        
    

        

        /* give file information for all args provided  */
        if(strcmp(args[0], "stat")==0){
        
        	if(num_words<2){
        		fprintf(stderr, "Error: missing operand for stat. \n");
        		continue;
        	} 

        	struct stat file;
        	
        	for(int i = 1; i < num_words-1; i++){	
        		int result = lstat(args[i], &file);
        	
        		if(result == 0){
                    char f_type;
                    
        			char *file_type;
        			if (S_ISREG(file.st_mode)){
        				file_type = "regular file";
                        f_type = '-';
        			} else if (S_ISDIR(file.st_mode)){
                        f_type = 'd';
        				file_type = "directory";
        			} else if (S_ISCHR(file.st_mode)){
                        f_type ='c';
        				file_type = "character device";
        			} else if (S_ISBLK(file.st_mode)){
                        f_type='b';
        				file_type = "block device";
        			} else if (S_ISFIFO(file.st_mode)){
                        f_type='p';
        				file_type = "pipe";
        			} else if (S_ISLNK(file.st_mode)){
                        f_type='l';
        				file_type = "symbolic link";
        			} else if (S_ISSOCK(file.st_mode)){
                        f_type = 's';
        				file_type = "socket";
        			}
                    char permissions[11];
                    int mode = file.st_mode & 0777;
                   
                    permissions[0]=f_type,
                    permissions[1] =  (mode & S_IRUSR) ? 'r' : '-';
                    permissions[2] =  (mode & S_IWUSR) ? 'w' : '-';
                    permissions[3] =  (mode & S_IXUSR) ? 'x' : '-';
                    permissions[4] =  (mode & S_IRGRP) ? 'r' : '-';
                    permissions[5] =  (mode & S_IWGRP) ? 'w' : '-';
                    permissions[6] =  (mode & S_IXGRP) ? 'x' : '-';
                    permissions[7] =  (mode & S_IROTH) ? 'r' : '-';
                    permissions[8] =  (mode & S_IWOTH) ? 'w' : '-';
                    permissions[9] =  (mode & S_IXOTH) ? 'x' : '-';
                    permissions[10] = '\0';
                    //store permissions in char[]

                    uid_t uid = getuid();
                    gid_t gid = getgid();

                    struct passwd *usr = getpwuid(uid);
                    struct group *grp = getgrgid(gid);

                    char* username = usr->pw_name;
                    char* groupname = grp->gr_name;
        		
                    //print out file information...
        			printf("  File: %s\n", args[i]);
        			printf("  Size: %ld\tBlocks: %ld\tIO Block: %ld\t%s\n", file.st_size, file.st_blocks, file.st_blksize, file_type);
        			printf("Device: %lxh/%ldd\tInode: %lu\tLinks: %ld\n", file.st_dev, file.st_dev, file.st_ino, file.st_nlink); 
        			printf("Access: (%o/%s)\tUid: ( %d/ %s)\tGid: ( %d/ %s)\n", file.st_mode & 0777, permissions, file.st_uid, username, file.st_gid, groupname); 
                    printf("Access: %s", ctime(&file.st_atime));
                    printf("Modify: %s", ctime(&file.st_mtime));
                    printf("Change: %s", ctime(&file.st_mtime));
                    printf(" Birth: %s", ctime(&file.st_ctime));
        		} else {
        		
        			fprintf(stderr, "Error: operand for stat is not existent. \n");
        		}
        	continue;
        	}
        }

        /* implements ll command (ls -l) */
        if(strcmp(args[0], "ll")==0){
            // printf("implement ll");
            if(num_words > 2){
                fprintf(stderr, "Error: Too many arguments provided to ll. \n");
                continue;
            } else {

                if(args[1]==NULL){ //ll no args 
                    args[1]=".";
                } 

                struct stat arg_info;

                if(stat(args[1], &arg_info)==0 && S_ISDIR(arg_info.st_mode)){
                    DIR* dir;
                    struct dirent *ent;
                    

                    if( (dir = opendir(args[1])) != NULL ){

                        while((ent = readdir(dir)) != NULL){ //traverse through all items in directory...
                            struct stat file;
                            if(stat(ent->d_name, &file)==0){

                                int result = lstat(ent->d_name, &file);
                                if(result == 0){
                                    char f_type;
                    
        			                
        			                if (S_ISREG(file.st_mode)){
                                        f_type = '-';
        			                } else if (S_ISDIR(file.st_mode)){
                                        f_type = 'd';
        			                } else if (S_ISCHR(file.st_mode)){
                                        f_type ='c';
        			                } else if (S_ISBLK(file.st_mode)){
                                        f_type='b';
        			                } else if (S_ISFIFO(file.st_mode)){
                                        f_type='p';
        			                } else if (S_ISLNK(file.st_mode)){
                                        f_type='l';
        			                } else if (S_ISSOCK(file.st_mode)){
                                        f_type = 's';
        			                }
                                    char permissions[11];
                                    int mode = file.st_mode & 0777;
                   
                                    permissions[0] = f_type,
                                    permissions[1] =  (mode & S_IRUSR) ? 'r' : '-';
                                    permissions[2] =  (mode & S_IWUSR) ? 'w' : '-';
                                    permissions[3] =  (mode & S_IXUSR) ? 'x' : '-';
                                    permissions[4] =  (mode & S_IRGRP) ? 'r' : '-';
                                    permissions[5] =  (mode & S_IWGRP) ? 'w' : '-';
                                    permissions[6] =  (mode & S_IXGRP) ? 'x' : '-';
                                    permissions[7] =  (mode & S_IROTH) ? 'r' : '-';
                                    permissions[8] =  (mode & S_IWOTH) ? 'w' : '-';
                                    permissions[9] =  (mode & S_IXOTH) ? 'x' : '-';
                                    permissions[10] = '\0';

                                    uid_t uid = getuid();
                                    gid_t gid = getgid();

                                    struct passwd *usr = getpwuid(uid);
                                    struct group *grp = getgrgid(gid);

                                    char* username = usr->pw_name;
                                    char* groupname = grp->gr_name;

                                    char* time = ctime(&file.st_mtime);
                                    size_t idx1 = strcspn(time, "\n");
                                    if (idx1 < (size_t) strlen(time)){
                                        time[idx1] = '\0';
                                    }

                                    printf("%s%s  ", DEFAULT, permissions);
                                    printf("%ld  ", file.st_nlink);
                                    printf("%s  ", username);
                                    printf("%s  ", groupname);
                                    printf("%ld  ", file.st_size);
                                    printf("%s  ", time);
                                }

                                


                                if (S_ISREG(file.st_mode)){
                                    printf("%s%s\n", DEFAULT, ent->d_name);
                                } else  {
                                    printf("%s%s\n", GRN, ent->d_name);
                                }
                            }
                        }
                        closedir(dir);
                        continue;

                    }
                } else if (!S_ISDIR(arg_info.st_mode)){
                    if(ENOENT == errno){
                        fprintf(stderr, "Error: Directory doesn't exist.\n");
                        continue;
                    }
                    fprintf(stderr, "Error: Not a directory. \n");
                    continue;
                }
            }
        }


        //exec!!
        else {
            pid_t pid, wpid;
            int status;

            pid = fork(); //invoke the child process
            if (pid == 0) {
            
                if (execvp(args[0], args) == -1) {
                    if(args[0] == NULL){
                        interrupted = 1;
                        exit(EXIT_FAILURE);
                    }

                    fprintf(stderr, "Error: exec() failed. %s.\n", strerror(errno));
                    exit(EXIT_FAILURE);
                }
            } else if (pid < 0) {
            //error forking
        
                fprintf(stderr, "Error: fork() failed. %s.\n", strerror(errno));
            } else { //parent process waits for child process to return
            
                do {
                    wpid = waitpid(pid, &status, WUNTRACED);
                    if(wpid == 0){
                        fprintf(stderr,  "Error: wait() failed. %s.\n", strerror(errno));
                    }
                }    while (!WIFEXITED(status) && !WIFSIGNALED(status));
            }
                //child process will exec() the given command and the parent process
                // waits for child process to return to continue the prompt
        }
        interrupted = 0;
    }
}

