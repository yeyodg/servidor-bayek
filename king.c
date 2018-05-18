#ifndef FILE_CLIENTE_SEEN
#define FILE_CLIENTE_SEEN
#include "king.h"
#endif

/*Funciones que manejan la conexion*/
#ifndef FILE_SOCKETS_SEEN
#define FILE_SOCKETS_SEEN
#include "sockets.h"
#endif

void init_gpgme()
{
    gpgme_error_t err = 0;
    /*Activando el debug*/
    gpgme_set_global_flag("debug", 0);
    /* Inicializa el ambiente local */
    setlocale(LC_ALL, "");
    gpgme_check_version(NULL);
    err = gpgme_engine_check_version(GPGME_PROTOCOL_OPENPGP);
    fail_if_gpgme_err(err);
    err = gpgme_set_engine_info(GPGME_PROTOCOL_OPENPGP, NULL, NULL);
    fail_if_gpgme_err(err);
    gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL));
#ifdef LC_MESSAGES
    gpgme_set_locale(NULL, LC_MESSAGES, setlocale(LC_MESSAGES, NULL));
#endif
}

void create_context(gpgme_ctx_t *ctx)
{
    gpgme_error_t err;
    err = gpgme_new(ctx);
    fail_if_gpgme_err(err);
    /* Seleccionar el protocolo */
    err = gpgme_set_protocol(*ctx, GPGME_PROTOCOL_OPENPGP);
    fail_if_gpgme_err(err);
    /* Configurar el pinentry */
    err = gpgme_set_pinentry_mode(*ctx, GPGME_PINENTRY_MODE_LOOPBACK);
    fail_if_gpgme_err(err);

    gpgme_set_armor(ctx, 1);
}

void passphrase_cb(void *hook, const char *uid_hint,
                   const char *passphrase_info, int prev_was_bad,
                   int fd)
{
    gpgme_error_t err;
    if (gpgme_io_writen(fd, phrase, strlen(phrase)) < 0)
        err = gpgme_error(GPG_ERR_GENERAL);
    fail_if_gpgme_err(err);
}

int import_from_file(gpgme_ctx_t ctx, int socket, char *fpr)
{
    int fd, bytes = 0;
    char file[10], buffer[BUFFER_SIZE];
    gpgme_error_t err;
    gpgme_data_t key_stream;
    gpgme_import_result_t import_result;

    sprintf(file, "%d", socket);
    memset(buffer, 0, BUFFER_SIZE);
    /* Obtener la clave en el archivo */
    err = gpgme_data_new_from_file(&key_stream, file, 1);
    fail_if_gpgme_err(err);
    /* Importar la clave */
    err = gpgme_op_import(ctx, key_stream);
    fail_if_gpgme_err(err);
    import_result = gpgme_op_import_result(ctx);
    /* Si se importó */
    if (import_result->imported)
        strcpy(fpr, import_result->imports->fpr);
    else
    {
        unlink(file);
        gpgme_data_release(key_stream);
        return -1;
    }
    unlink(file);
    gpgme_data_release(key_stream);
    return 0;
}

void sign_and_return(int socket)
{
    /* Variables de GPGME */
    gpgme_error_t err;
    gpgme_data_t key_stream, key_to_export, prueba;

    gpgme_key_t key;
    char buffer[BUFFER_SIZE], fpr[FPR_SIZE];
    int bytes = 0, fd;
    gpgme_ctx_t ctx;
    create_context(&ctx);
    /* Importar la clave */
    memset(fpr, 0, FPR_SIZE);
    if (import_from_file(ctx, socket, fpr))
    {
        strcpy(buffer, "Error: Clave no importada\n");
        if (write(socket, buffer, strlen(buffer)) < 0)
            fail_err();
        close(socket);
        return;
    }
    /* Obtener la clave importada */
    err = gpgme_set_keylist_mode(ctx, GPGME_KEYLIST_MODE_SIGS);
    fail_if_gpgme_err(err);
    err = gpgme_op_keylist_start(ctx, fpr, 0);
    fail_if_gpgme_err(err);
    err = gpgme_op_keylist_next(ctx, &key);
    fail_if_gpgme_err(err);
    /* Si la clave es valida */
    if (key->uids->validity == GPGME_VALIDITY_FULL ||
        key->uids->validity == GPGME_VALIDITY_ULTIMATE)
    {
        /* Configurar la frase para acceder a la clave */
        gpg_error_t (*passfunc)(void *hook, const char *uid_hint,
                                const char *passphrase_info,
                                int prev_was_bad, int fd);
        passfunc = passphrase_cb;
        gpgme_set_passphrase_cb(ctx, passfunc, NULL);
        /* Firmar */
        err = gpgme_op_keysign(ctx, key, NULL, 0, GPGME_KEYSIGN_NOEXPIRE);
        fail_if_gpgme_err(err);

        export_key(ctx, fpr, socket);
    }
    else
    {
        strcpy(buffer, "Error: Clave no valida\n");
        /* Envia el error */
        if (write(socket, buffer, strlen(buffer)) < 0)
            fail_err();
    }
    /* Elimina la clave importada */
    err = gpgme_op_delete_ext(ctx, key, GPGME_DELETE_FORCE);
    fail_if_gpgme_err(err);
    gpgme_release(ctx);
}

void export_key(gpgme_ctx_t ctx, char *fpr, int socket)
{
    gpgme_err_code_t err;
    gpgme_data_t key_to_export;
    int bytes = 0;
    char buffer[BUFFER_SIZE];

    /* Crea el data objet que almacenará la clave */
    err = gpgme_data_new(&key_to_export);
    fail_if_gpgme_err(err);

    /* Almacena la clave en el data object */
    err = gpgme_op_export(ctx, fpr, 0, key_to_export);
    fail_if_gpgme_err(err);

    /* Mueve la posicion de lectura al principio del objeto */
    if (gpgme_data_seek(key_to_export, 0, SEEK_SET) < 0)
        fail_err();
    do
    {
        /* Copia lo que está en key_to_export en el buffer para enviarlo */
        bytes = gpgme_data_read(key_to_export, (void *)buffer, BUFFER_SIZE);
        /* Envia el buffer */
        if (write(socket, buffer, bytes) < 0)
            fail_err();
    } while (bytes == BUFFER_SIZE);
    gpgme_data_release(key_to_export);
}

void show_key(gpgme_key_t key)
{
    gpgme_key_sig_t signature;
    printf("%s:", key->subkeys->keyid);
    if (key->uids && key->uids->name)
        printf(" %s", key->uids->name);
    if (key->uids && key->uids->email)
        printf(" <%s>", key->uids->email);
    printf(" [%d]\n", key->owner_trust);
    if (key->uids && key->uids->signatures)
        signature = key->uids->signatures;
    while (signature)
    {
        printf("Signed by: %s\n", signature->uid);
        signature = signature->next;
    }
    printf("Validity: %d\n", key->uids->validity);
}

int find_in_db(char *object)
{
    int fd, bytes, count = 0;
    char buffer[BUFFER_SIZE];
    /* Abrir la base de datos */
    if ((fd = open(TABLE, O_CREAT | O_RDONLY, S_IRWXU)) < 0)
        fail_err();
    do
    {
        lseek(fd, -1 * count, SEEK_CUR);
        bytes = read(fd, buffer, BUFFER_SIZE);
        /* Buscar object en buffer */
        if (strstr(buffer, object) != NULL)
        {
            close(fd);
            return 1;
        }
        while (buffer[bytes - count] != ' ')
            count++;
        count++;
    } while (bytes == BUFFER_SIZE);
    close(fd);
    return 0;
}

void add_to_db(int socket, char *ip, char *sender_ip)
{
    /* Variables de GPGME */
    gpgme_error_t err;
    gpgme_key_t key;
    gpgme_ctx_t ctx;
    create_context(&ctx);
    FILE *file;
    int fd, bytes = 0, found = 0, count = 0;
    char buffer[BUFFER_SIZE], fpr[FPR_SIZE];

    memset(buffer, 0, BUFFER_SIZE);

    /* Importar la clave */
    memset(fpr, 0, FPR_SIZE);
    if (import_from_file(ctx, socket, fpr))
    {
        strcpy(buffer, "Error: Clave no importada\n");
        if (write(socket, buffer, strlen(buffer)) < 0)
            fail_err();
        close(socket);
        return;
    }

    /* Si se recibe la clave de la misma maquina */
    if (!strcmp(sender_ip, "127.0.0.1"))
    {
        /* Se envia a los otros reyes */
        //broadcast_key(ctx, fpr, ip);
        found = 1;
    }
    else
    {
        /* Preguntar si el que la envió está en la base de datos */
        found = find_in_db(sender_ip);
    }
    if (found)
    {
        /*
            Guardar el fingerprint de la clave importada y la direccion en
            la base de datos de las claves
        */
        strcat(fpr, " ");
        strcat(fpr, ip);
        strcat(fpr, "\n");

        /* Abrir o crear la base de datos */
        if ((fd = open(TABLE, O_WRONLY | O_APPEND)) < 0)
            fail_err();
        /* Escribir en la base de datos */
        if ((write(fd, fpr, strlen(fpr))) < 0)
            fail_err();

        if ((write(socket, "Ok\n", 3)) < 0)
            fail_err();
        close(fd);
    }
    gpgme_release(ctx);
}

void ask_for_signature(int socket)
{
    /* Variables de GPGME */
    gpgme_error_t err;
    gpgme_key_sig_t signature, aux_signature;
    gpgme_key_t key, key_imported;
    gpgme_ctx_t ctx;
    char buffer[BUFFER_ANSWER], fpr[FPR_SIZE], signature_name[10][30];
    int bytes = 0, fd, valida = 1, i;

    create_context(&ctx);

    memset(fpr, 0, FPR_SIZE);
    memset(buffer, 0, BUFFER_ANSWER);

    /* Importar la clave */
    if (import_from_file(ctx, socket, fpr))
    {
        strcpy(buffer, "Error: Clave no importada\n");
        if (write(socket, buffer, strlen(buffer)) < 0)
            fail_err();
        close(socket);
        return;
    }

    /* Obtener la clave importada */
    err = gpgme_set_keylist_mode(ctx, GPGME_KEYLIST_MODE_SIGS);
    fail_if_gpgme_err(err);
    err = gpgme_op_keylist_start(ctx, fpr, 0);
    fail_if_gpgme_err(err);
    err = gpgme_op_keylist_next(ctx, &key_imported);
    fail_if_gpgme_err(err);
    /* Guarda las firmas de la clave importada */
    signature = key_imported->uids->signatures;
    int filas = 0;
    while (signature)
    {
        strcpy(signature_name[filas], signature->email);
        signature = signature->next;
        filas++;
    }

    /* Elimina la clave importada */
    err = gpgme_op_delete_ext(ctx, key_imported, GPGME_DELETE_FORCE);
    fail_if_gpgme_err(err);
    err = gpgme_op_keylist_end(ctx);
    fail_if_gpgme_err(err);
    err = gpgme_op_keylist_start(ctx, NULL, 0);
    fail_if_gpgme_err(err);

    /* Leer todas las claves importadas */
    while (!gpgme_op_keylist_next(ctx, &key))
    {
        /* Si la clave tiene firmas */
        if (key->uids && key->uids->email && key_imported->uids &&
            key_imported->uids->signatures)
        {
            if (find_in_db(key->fpr))
            {
                /* Me muevo en las firmas de la clave importada */
                for (i = 0; i < filas; i++)
                {
                    /* Si conozco la firma */
                    if (!strcmp(signature_name[i], key->uids->email))
                    {
                        strcpy(buffer, "Conocida\n");
                        if (write(socket, buffer, strlen(buffer)) < 0)
                            fail_err();
                        close(socket);
                    }
                    if (!strcmp(buffer, "Conocida\n"))
                        break;
                }
                if (!strcmp(buffer, "Conocida\n"))
                    break;
            }
        }
    }
    if (strcmp(buffer, "Conocida\n"))
    {
        strcpy(buffer, "No la conozco\n");
        if (write(socket, buffer, strlen(buffer)) < 0)
            fail_err();
        close(socket);
    }
    gpgme_release(ctx);
}

void broadcast_key(gpgme_ctx_t ctx, char *key_fpr, char *key_ip)
{
    FILE *file;
    int server_socket, bytes;
    struct sockaddr_in client;
    struct hostent *server;
    char fpr[FPR_SIZE], ip[IP_SIZE], buffer[BUFFER_SIZE];
    
    memset(ip, 0, IP_SIZE);
    memset(fpr, 0, FPR_SIZE);
    gpgme_err_code_t err;
    gpgme_data_t key_to_export;

    /* Crear el data objet que almacenará la clave */
    err = gpgme_data_new(&key_to_export);
    fail_if_gpgme_err(err);

    /* Almacenar la clave en el data object */
    err = gpgme_op_export(ctx, fpr, 0, key_to_export);
    fail_if_gpgme_err(err);

    bzero((char *)&client, sizeof((char *)&client));
    client.sin_family = AF_INET;
    client.sin_port = htons(PORT_IN);

    /* Abrir la base de datos */
    if ((file = fopen(TABLE, "r")) != NULL)
    {
        while (!feof(file))
        {
            fscanf(file, "%s %s", fpr, ip);
            if (strlen(fpr) && strlen(ip))
            {
                printf("%s - %s\n", fpr, ip);
                if (strcmp(ip, "127.0.0.1"))
                {
                    server = gethostbyname(ip);
                    bcopy((char *)server->h_addr, (char *)&client.sin_addr.s_addr,
                          sizeof(server->h_length));
                    memset(buffer, 0, BUFFER_SIZE);
                    /*Crear server_socket*/
                    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
                        print_err();

                    /*Hacer socket*/
                    if (connect(server_socket, (struct sockaddr *)&client,
                                sizeof(client)) < 0)
                        print_err();
                    else
                    {
                        strcpy(buffer, "add ");
                        strcat(buffer, ip);

                        if ((write(server_socket, buffer, strlen(buffer))) < 0)
                            print_err();
                        /* Mueve la posicion de lectura al principio del objeto */
                        if (gpgme_data_seek(key_to_export, 0, SEEK_SET) < 0)
                            fail_err();
                        do
                        {
                            /* Copia lo que está en key_to_export en el buffer para enviarlo */
                            bytes = gpgme_data_read(key_to_export, (void *)buffer, BUFFER_SIZE);
                            /* Envia el buffer */
                            if (write(server_socket, buffer, bytes) < 0)
                                print_err();
                        } while (bytes == BUFFER_SIZE);
                    }
                }
            }
        }
        fclose(file);
    }
    gpgme_data_release(key_to_export);
}

void print_err()
{
    fprintf(stderr, "%s:%d: %s\n",
            __FILE__, __LINE__, strerror(errno));
}

void enter_to_db(int socket, char *sender_ip)
{
    /* Variables de GPGME */
    gpgme_error_t err;
    gpgme_key_t key;
    gpgme_ctx_t ctx;
    create_context(&ctx);
    FILE *file;
    int fd, bytes = 0, found = 0, count = 0;
    char buffer[BUFFER_SIZE], fpr[FPR_SIZE];

    memset(buffer, 0, BUFFER_SIZE);

    /* Importar la clave */
    memset(fpr, 0, FPR_SIZE);
    if (import_from_file(ctx, socket, fpr))
    {
        strcpy(buffer, "Clave no importada");
        if (write(socket, buffer, strlen(buffer)) < 0)
            fail_err();
        close(socket);
        return;
    }

    /* Si se recibe la clave de la misma maquina */
    if (!strcmp(sender_ip, "127.0.0.1"))
    {
        strcpy(buffer, "Error: No valido\n");
        if (write(socket, buffer, strlen(buffer)) < 0)
            fail_err();
        close(socket);
        return;
    }
    else
    {
        if ((fd = open(TABLE, O_CREAT | O_RDONLY | O_APPEND, S_IRWXU)) < 0)
            fail_err();
        do
        {
            lseek(fd, -1 * count, SEEK_CUR);
            count = 0;
            bytes = read(fd, buffer, BUFFER_SIZE);
            if (strstr(buffer, sender_ip) != NULL)
            {
                found = 1;
                break;
            }
            while (buffer[bytes - count] != ' ')
                count++;
            count++;
        } while (bytes == BUFFER_SIZE);
        close(fd);
    }
    if (found)
    {
        if ((fd = open(TABLE, O_RDONLY)) < 0)
            fail_err();
        do
        {
            if ((bytes = read(fd, buffer, BUFFER_SIZE)) < 0)
                fail_err();
            if (write(socket, buffer, bytes) < 0)
                fail_err();
        } while (bytes == BUFFER_SIZE);
        close(fd);
    }
    gpgme_release(ctx);
}

void start_db(int socket, char *name, char *sender_ip, char *ip)
{
    gpgme_error_t err;
    gpgme_key_t key;
    gpgme_ctx_t ctx;
    create_context(&ctx);
    int fd = 0;
    char buffer[BUFFER_SIZE];

    memset(buffer, 0, BUFFER_SIZE);

    err = gpgme_op_keylist_start(ctx, name, 0);
    fail_if_gpgme_err(err);

    err = gpgme_op_keylist_next(ctx, &key);
    fail_if_gpgme_err(err);

    strcpy(buffer, key->fpr);
    strcat(buffer, " ");
    strcat(buffer, ip);
    strcat(buffer, "\n");
    /* Si se recibe la peticion de la misma maquina */
    if (strcmp(sender_ip, "127.0.0.1"))
    {
        strcpy(buffer, "Error: La base de datos se debe crear desde la maquina local\n");
        if (write(socket, buffer, strlen(buffer)) < 0)
            fail_err();
        close(socket);
        return;
    }
    if ((fd = open(TABLE, O_CREAT | O_WRONLY | O_EXCL, S_IRWXU)) < 0)
    {
        strcpy(buffer, "Error: La base de datos ya existe\n");
        if (write(socket, buffer, strlen(buffer)) < 0)
            fail_err();
        close(socket);
        return;
    }
    if (write(fd, buffer, strlen(buffer)) < 0)
        fail_err();
    close(fd);
    strcpy(buffer, "La base de datos fue creada\n");
    if (write(socket, buffer, strlen(buffer)) < 0)
        fail_err();

    close(socket);
    gpgme_release(ctx);
}