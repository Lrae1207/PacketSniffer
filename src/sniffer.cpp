//http://yuba.stanford.edu/~casado/pcap/section1.html
// I now realize that I may need a variety of different versions of this file as there are many
// different operating systems that use different methods of socket programming
#include <pcap.h>
#include <fstream>
#include <sys/socket.h>
#include <sys/types.h>

int writeToFile() {
    
}

int main(int argc, char *argv[]) {
    // Command format is: argv[1] <filename> <media identifier(im not sure what yet)> 
    if (argc != 3) {
        exit(1);
    }

    // Main file that will be written to
    std::ofstream datafile(argv[1]);
    // Make a backup file in case of data corruption
    std::ofstream backup(argv[1]);

    
    
    return 0;
}