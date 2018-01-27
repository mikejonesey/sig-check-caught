#include <stdio.h>
#include <string.h>

void getStatus(char *javapid){
    char tstatus_txt[4096];
    char tstatus_path[256];
    char binarySigCaught[100];
    int binSigLen=0;
    memset(tstatus_txt, 0, sizeof(tstatus_txt));
    memset(tstatus_path, 0, sizeof(tstatus_path));
    memset(binarySigCaught, 0, sizeof(binarySigCaught));
    FILE *f_tstatus;

    strcpy(tstatus_path, "/proc/");
    strcat(tstatus_path, javapid);
    strcat(tstatus_path, "/status");

    f_tstatus = fopen(tstatus_path, "r");
    if (f_tstatus) {
        while (fgets(tstatus_txt, sizeof(tstatus_txt), f_tstatus)) {
            if(strstr(tstatus_txt,"SigCgt:")){
                int charpos=7;
                while(tstatus_txt[charpos]!='\0'){
                    switch(tstatus_txt[charpos]){
                        case '0': strcat(binarySigCaught,"0000"); break;
                        case '1': strcat(binarySigCaught,"0001"); break;
                        case '2': strcat(binarySigCaught,"0010"); break;
                        case '3': strcat(binarySigCaught,"0011"); break;
                        case '4': strcat(binarySigCaught,"0100"); break;
                        case '5': strcat(binarySigCaught,"0101"); break;
                        case '6': strcat(binarySigCaught,"0110"); break;
                        case '7': strcat(binarySigCaught,"0111"); break;
                        case '8': strcat(binarySigCaught,"1000"); break;
                        case '9': strcat(binarySigCaught,"1001"); break;
                        case 'A': strcat(binarySigCaught,"1010"); break;
                        case 'B': strcat(binarySigCaught,"1011"); break;
                        case 'C': strcat(binarySigCaught,"1100"); break;
                        case 'D': strcat(binarySigCaught,"1101"); break;
                        case 'E': strcat(binarySigCaught,"1110"); break;
                        case 'F': strcat(binarySigCaught,"1111"); break;
                        case 'a': strcat(binarySigCaught,"1010"); break;
                        case 'b': strcat(binarySigCaught,"1011"); break;
                        case 'c': strcat(binarySigCaught,"1100"); break;
                        case 'd': strcat(binarySigCaught,"1101"); break;
                        case 'e': strcat(binarySigCaught,"1110"); break;
                        case 'f': strcat(binarySigCaught,"1111"); break;
                    }
                    charpos++;
                }
                binarySigCaught[(charpos-1)*4]='\0';
                binSigLen=strlen(binarySigCaught);
                //printf("BinSig: %s\n", binarySigCaught);
                if(binarySigCaught[binSigLen-1]=='1')
                    printf("SIGHUP ");
                if(binarySigCaught[binSigLen-2]=='1')
                    printf("SIGINT ");
                if(binarySigCaught[binSigLen-3]=='1')
                    printf("SIGQUIT ");
                if(binarySigCaught[binSigLen-4]=='1')
                    printf("SIGILL ");
                if(binarySigCaught[binSigLen-5]=='1')
                    printf("SIGTRAP ");
                if(binarySigCaught[binSigLen-6]=='1')
                    printf("SIGABRT ");
                if(binarySigCaught[binSigLen-7]=='1')
                    printf("SIGBUS ");
                if(binarySigCaught[binSigLen-8]=='1')
                    printf("SIGFPE ");
                if(binarySigCaught[binSigLen-9]=='1')
                    printf("SIGKILL ");
                if(binarySigCaught[binSigLen-10]=='1')
                    printf("SIGUSR1 ");
                if(binarySigCaught[binSigLen-11]=='1')
                    printf("SIGSEGV ");
                if(binarySigCaught[binSigLen-12]=='1')
                    printf("SIGUSR2 ");
                if(binarySigCaught[binSigLen-13]=='1')
                    printf("SIGPIPE ");
                if(binarySigCaught[binSigLen-14]=='1')
                    printf("SIGALRM ");
                if(binarySigCaught[binSigLen-15]=='1')
                    printf("SIGTERM ");
                if(binarySigCaught[binSigLen-16]=='1')
                    printf("SIGSTKFLT ");
                if(binarySigCaught[binSigLen-17]=='1')
                    printf("SIGCHLD ");
                if(binarySigCaught[binSigLen-18]=='1')
                    printf("SIGCONT ");
                if(binarySigCaught[binSigLen-19]=='1')
                    printf("SIGSTOP ");
                if(binarySigCaught[binSigLen-20]=='1')
                    printf("SIGTSTP ");
                if(binarySigCaught[binSigLen-21]=='1')
                    printf("SIGTTIN ");
                if(binarySigCaught[binSigLen-22]=='1')
                    printf("SIGTTOU ");
                if(binarySigCaught[binSigLen-23]=='1')
                    printf("SIGURG ");
                if(binarySigCaught[binSigLen-24]=='1')
                    printf("SIGXCPU ");
                if(binarySigCaught[binSigLen-25]=='1')
                    printf("SIGXFSZ ");
                if(binarySigCaught[binSigLen-26]=='1')
                    printf("SIGVTALRM ");
                if(binarySigCaught[binSigLen-27]=='1')
                    printf("SIGPROF ");
                if(binarySigCaught[binSigLen-28]=='1')
                    printf("SIGWINCH ");
                if(binarySigCaught[binSigLen-29]=='1')
                    printf("SIGIO ");
                if(binarySigCaught[binSigLen-30]=='1')
                    printf("SIGPWR ");
                if(binarySigCaught[binSigLen-31]=='1')
                    printf("SIGSYS ");
                if(binarySigCaught[binSigLen-34]=='1')
                    printf("SIGRTMIN ");
                if(binarySigCaught[binSigLen-35]=='1')
                    printf("SIGRTMIN+1 ");
                if(binarySigCaught[binSigLen-36]=='1')
                    printf("SIGRTMIN+2 ");
                if(binarySigCaught[binSigLen-37]=='1')
                    printf("SIGRTMIN+3 ");
                if(binarySigCaught[binSigLen-38]=='1')
                    printf("SIGRTMIN+4 ");
                if(binarySigCaught[binSigLen-39]=='1')
                    printf("SIGRTMIN+5 ");
                if(binarySigCaught[binSigLen-40]=='1')
                    printf("SIGRTMIN+6 ");
                if(binarySigCaught[binSigLen-41]=='1')
                    printf("SIGRTMIN+7 ");
                if(binarySigCaught[binSigLen-42]=='1')
                    printf("SIGRTMIN+8 ");
                if(binarySigCaught[binSigLen-43]=='1')
                    printf("SIGRTMIN+9 ");
                if(binarySigCaught[binSigLen-44]=='1')
                    printf("SIGRTMIN+10 ");
                if(binarySigCaught[binSigLen-45]=='1')
                    printf("SIGRTMIN+11 ");
                if(binarySigCaught[binSigLen-46]=='1')
                    printf("SIGRTMIN+12 ");
                if(binarySigCaught[binSigLen-47]=='1')
                    printf("SIGRTMIN+13 ");
                if(binarySigCaught[binSigLen-48]=='1')
                    printf("SIGRTMIN+14 ");
                if(binarySigCaught[binSigLen-49]=='1')
                    printf("SIGRTMIN+15 ");
                if(binarySigCaught[binSigLen-50]=='1')
                    printf("SIGRTMAX-14 ");
                if(binarySigCaught[binSigLen-51]=='1')
                    printf("SIGRTMAX-13 ");
                if(binarySigCaught[binSigLen-52]=='1')
                    printf("SIGRTMAX-12 ");
                if(binarySigCaught[binSigLen-53]=='1')
                    printf("SIGRTMAX-11 ");
                if(binarySigCaught[binSigLen-54]=='1')
                    printf("SIGRTMAX-10 ");
                if(binarySigCaught[binSigLen-55]=='1')
                    printf("SIGRTMAX-9 ");
                if(binarySigCaught[binSigLen-56]=='1')
                    printf("SIGRTMAX-8 ");
                if(binarySigCaught[binSigLen-57]=='1')
                    printf("SIGRTMAX-7 ");
                if(binarySigCaught[binSigLen-58]=='1')
                    printf("SIGRTMAX-6 ");
                if(binarySigCaught[binSigLen-59]=='1')
                    printf("SIGRTMAX-5 ");
                if(binarySigCaught[binSigLen-60]=='1')
                    printf("SIGRTMAX-4 ");
                if(binarySigCaught[binSigLen-61]=='1')
                    printf("SIGRTMAX-3 ");
                if(binarySigCaught[binSigLen-62]=='1')
                    printf("SIGRTMAX-2 ");
                if(binarySigCaught[binSigLen-63]=='1')
                    printf("SIGRTMAX-1 ");
                if(binarySigCaught[binSigLen-64]=='1')
                    printf("SIGRTMAX ");
                break;
            }
        }
        fclose(f_tstatus);
        printf("\n");
    } else{
        //failed to open status file...
        //strcpy(threads[i][7],tstatus_path);
    }
}

int main(int argc, char **argv) {
    if(argc>2 && argv[1] && strcmp(argv[1],"-p") == 0){
        //printf("Checking for Signals Caught by pid: %s\n",argv[2]);
        getStatus(argv[2]);
    }else{
        printf("Usage:\nsig_check_caught -p [PID]\n");
    }
    return 0;
}