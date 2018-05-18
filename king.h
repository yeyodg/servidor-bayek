#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <fcntl.h>

// Librerias de GPG
#include <gpgme.h>
#include <locale.h>

#define OPTION 0
#define REALM 1
#define KEY 2
#define ARGC 3
#define SIGN "sign"
#define ADD "add"
#define ASK "ask"
#define ENTER "enter"
#define START "start"
#define FPR_SIZE 100
#define IP_SIZE 15
#define TABLE "table"

#define fail_if_gpgme_err(err)                            \
    if (err)                                              \
    {                                                     \
        fprintf(stderr, "%s:%d: %s: %s\n",                \
                __FILE__, __LINE__, gpgme_strsource(err), \
                gpgme_strerror(err));                     \
        exit(__LINE__);                                   \
    }

#define fail_err()                                    \
    {                                                 \
        fprintf(stderr, "%s:%d: %s\n",                \
                __FILE__, __LINE__, strerror(errno)); \
        exit(__LINE__);                               \
    }

char phrase[50];

/* 
    Esta funcion inicializa GPGME y verifica que wwse cumplan los requerimientos
    para funcionar    
*/
void init_gpgme();

/* 
    Crea e inicializa el contexto para trabajar con el protocolo y el pinentry
    deseado
*/
void create_context(gpgme_ctx_t *ctx);

/* 
    Maneja el callback de solicitud de phrase
*/
void passphrase_cb(void *hook, const char *uid_hint,
                   const char *passphrase_info, int prev_was_bad,
                   int fd);

/* 
    Firma la clave en el archivo con el nombre del socket y la retorna
*/
void sign_and_return(int socket);

/* 
    Verifica si la clave recibida está firmada por un miembro de la base de 
    datosde confianza
*/
void ask_for_signature(int socket);

/* 
    Agrega a un miembro a la base de datos de confianza
*/
void add_to_db(int socket, char *ip, char *sender_ip);

/* 
    Envia la base de datos al miembro que la solicita
*/
void enter_to_db(int socket, char *sender_ip);

/* 
    Crea el archivo de la base de datos, agrega el fingerprint y la ip a la
    base de datos
*/
void start_db(int socket, char *name, char *sender_ip, char *ip);

/* 
    Verifica si la clave con el fingerprint fpr es valida 
    Retorna: 0 si no es valida, 1 si lo es
*/
int valid_key(char *fpr);

/* Imprime la clave key */
void show_key(gpgme_key_t key);

/* 
    Importa la clave que llega por el socket y crea un archivo que contendrá la
    clave cuyo nombre es el numero del socket
*/
int import_from_file(gpgme_ctx_t ctx, int socket, char *fpr);

/* Envia la clave recibida a todas las direcciones en la base de datos */
void broadcast_key(gpgme_ctx_t ctx, char *key_fpr, char *key_ip);

/* Exporta la clave con el fingerprint fpr por el socket socket */
void export_key(gpgme_ctx_t ctx, char *fpr, int socket);

/* Muestra los errores en la consola */
void print_err();

/* 
    Busca la palabra object en la base de datos
    Retorna: 1 si la encontró, 0 en caso contrario
 */
int find_in_db(char *object);

int port;
