/*Funciones que manejan GPGME para el server*/
#ifndef FILE_KING_SEEN
#define FILE_KING_SEEN
#include "king.h"
#endif

/*Funciones que manejan la conexion*/
#ifndef FILE_SOCKETS_SEEN
#define FILE_SOCKETS_SEEN
#include "sockets.h"
#endif

int main(int argc, char const *argv[])
{
    printf("Por favor escribe la frase secreta de tu clave:\n");
    fflush(stdin);
    scanf("%s", &phrase);
    system("clear");
    printf("You are running the SERVER...\n");
    char buffer[BUFFER_SIZE], option[ARGC][50], name[10];
    int bytes = 0, c, prev, arg, fd, i, first, offset, op = 1;
    int server_socket, client_socket;
    struct sockaddr_in server, client;

    socklen_t longc;

    port = PORT_IN;
    /* Inicializar GPG_ME */
    init_gpgme();

    /*Inicializar las variables del socket*/
    bzero((char *)&server, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = INADDR_ANY;

    /*Crear el socket*/
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        fail_err();
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &op, sizeof(op));
    printf("[%d] Socket...\n", port);

    /*Asignar PORT al socket*/
    if ((bind(server_socket, (struct sockaddr *)&server, sizeof(server))) < 0)
        fail_err();
    printf("Bind...\n");

    /*Escuchar peticiones*/
    if ((listen(server_socket, NUM_THREADS)) < 0)
        fail_err();
    printf("Listen...\n");

    /*Aceptar solicitudes*/
    longc = sizeof(client);
    while (1)
    {
        first = 1;
        arg = 2;
        /* Aceptar solicitudes en el socket */
        if ((client_socket = accept(server_socket, (struct sockaddr *)&client,
                                    &longc)) < 0)
            fail_err();
        printf("\n[%d]Accept...\n", client_socket);
        printf("Conecting with %s:%d\n", inet_ntoa(client.sin_addr),
               htons(client.sin_port));

        /* Vaciar el buffer */
        memset(buffer, 0, BUFFER_SIZE);
        memset(name, 0, 10);
        sprintf(name, "%d", client_socket);
        
        /*Leer*/
        do
        {
            memset(buffer, 0, BUFFER_SIZE);

            if ((bytes = read(client_socket, buffer, BUFFER_SIZE)) < 0)
                fail_err();
            if (bytes != BUFFER_SIZE)
                buffer[bytes] = '\0';
            prev = 0;
            c = 0;
            if (first)
            {
                for (i = 0; i < arg; i++)
                {
                    prev = c;
                    while (buffer[c] != ' ' && buffer[c] != '\0')
                        c++;
                    memcpy(option[i], (buffer + prev), (c - prev));
                    option[i][c] = '\0';
                    if (i == OPTION)
                    {
                        if (!strcmp(option[OPTION], ENTER) || !strcmp(option[OPTION], START))
                            ++arg;
                        else if ((fd = open(name, O_CREAT | O_WRONLY, S_IRWXU)) < 0)
                            fail_err();
                    }
                    c++;
                }
                first = 0;
                if (arg == 2)
                {
                    if (write(fd, buffer + c, bytes - c) < 0)
                        fail_err();
                }
            }
            else
            {
                if (write(fd, buffer, bytes) < 0)
                    fail_err();
            }
        } while (bytes == BUFFER_SIZE);
        if (fd)
            close(fd);

        /* Manejar la solicitud entrante */
        printf("%s", inet_ntoa(client.sin_addr));
        if (!strcmp(option[OPTION], SIGN))
            sign_and_return(client_socket);
        else if (!strcmp(option[OPTION], ASK))
            ask_for_signature(client_socket);
        else if (!strcmp(option[OPTION], ADD))
            add_to_db(client_socket, option[REALM], inet_ntoa(client.sin_addr));
        else if (!strcmp(option[OPTION], ENTER))
            enter_to_db(client_socket, inet_ntoa(client.sin_addr));
        else if (!strcmp(option[OPTION], START))
            start_db(client_socket, option[KEY], inet_ntoa(client.sin_addr), option[REALM]);
        close(client_socket);
    }
    return 0;
}
