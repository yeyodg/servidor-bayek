#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>

#define PORT_IN 12166
#define PORT_OUT 12167
#define NUM_THREADS 5
#define BUFFER_SIZE 2048
#define BUFFER_ANSWER 100
#define h_addr h_addr_list[0]
