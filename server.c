#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
 
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/****************************************
        Author: Anthony Korzam
        with a little help from
        Professor Wood's courses

****************************************/

#define BACKLOG 10     // how many pending connections queue will hold

/*
        Prints error and exits program.
        To be used with argument handling.
*/
void
error(char *format, ...) {
	va_list valist;
	va_start(valist, format);
	vfprintf(stderr, format, valist);
	/* Clean memory */
	va_end(valist);

	exit(-1);
}

int
main(int arc, char** argv) {
	char* server_port = "5000";

	char* cert_file = "server.crt";
	char* key_file = "server.key";

	// Command Line generation of Diffie-Hellman parameters
	// openssl dhparam -out dh_param_2048.pem 2048
	char* dh_file = "dh_param_2048_server.pem";

	DH *dh_2048 = NULL;
	FILE *paramfile;

	int err;
        int sockfd;
	int yes = 1;

	struct addrinfo hints;
	struct addrinfo *server;

	const SSL_METHOD *ssl_meth;
	SSL_CTX *ctx;

        /* Load encryption & hashing algorithms for the SSL program */
	SSL_library_init();
	/* Load the error strings for SSL & CRYPTO APIs */
	SSL_load_error_strings();

	/* Use SSLv3 for the connection */
	ssl_meth = SSLv23_server_method();
	/* Create a new context--stores configuration for SSL */
	ctx = SSL_CTX_new(ssl_meth);
	if (!ctx)
		error("Error creating SSL context.\n");

	printf("Setting the local certificates and keys...\n");
        /* Set the local certificates and keys */
	err = SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM);
	if (err <= 0) {
		ERR_print_errors_fp(stderr);
		SSL_CTX_free(ctx);
		error("Error setting the certificate file.\n");
	}

	err = SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM);
	if (err <= 0) {
		ERR_print_errors_fp(stderr);
		SSL_CTX_free(ctx);
		error("Error setting the private key file.\n");
	}

        /* Verify private key and public crt combination. */
	if (!SSL_CTX_check_private_key(ctx)) {
		SSL_CTX_free(ctx);
		error("Error, private key does not match public key.\n");
	}
	printf("Setting Diffie-Hellman parameters...\n");

	/* Set up ephemeral DH parameters. */
	paramfile = fopen(dh_file, "r");
	if (!paramfile) {
		SSL_CTX_free(ctx);
		error("Error opening Diffie-Hellman parameters.\n");
	}

	dh_2048 = PEM_read_DHparams(paramfile, NULL, NULL, NULL);
	err = fclose(paramfile);
	if (err) {
		SSL_CTX_free(ctx);
		error("Error closing file stream.\n");
	}
	if (!dh_2048) {
		SSL_CTX_free(ctx);
		error("Error reading Diffie-Hellman parameters.\n");
	}
	err = SSL_CTX_set_tmp_dh(ctx, dh_2048);
	if (err != 1) {
		SSL_CTX_free(ctx);
		error("Error setting Diffie-Hellman into SSL context\n");
	}


	/*--- Standard TCP server setup and connection ---*/

	printf("Creating TCP/IP socket...\n");

	/* The hints struct is used to specify what kind of server info
	   we are looking for */
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM; /* or SOCK_DGRAM */
        hints.ai_flags = AI_PASSIVE;

        /* getaddrinfo() gives us back a server address we can connect to.
           The first parameter is NULL since we want an address on this host.
           It actually gives us a linked list of addresses, but we'll just
	   use the first. */
	err = getaddrinfo(NULL, server_port, &hints, &server);
        if (err != 0) {
		SSL_CTX_free(ctx);
		error("Error getting address information.\n");
	}
        /* Now we can create the socket and bind it to the local IP and port */
        sockfd = socket(server->ai_family, server->ai_socktype, server->ai_protocol);
        if (sockfd == -1) {
		freeaddrinfo(server);
		SSL_CTX_free(ctx);
		error("Error opening socket.\n");
	}
        /* Get rid of "Address already in use" error messages */
        err = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
	if (err == -1) {
		freeaddrinfo(server);
		SSL_CTX_free(ctx);
		error("Error with setsockopt.\n");
	}

	err = bind(sockfd, server->ai_addr, server->ai_addrlen);
        if (err == -1) {
		close(sockfd);
		freeaddrinfo(server);
		SSL_CTX_free(ctx);
		error("Error binding socket for server\n");
        }

	printf("Listening for connections.\n");
        err = listen(sockfd, BACKLOG);
	if (err == -1) {
		close(sockfd);
		freeaddrinfo(server);
		SSL_CTX_free(ctx);
		error("Error binding socket for server; errno=%d\n", errno);
	}

	while (1) {
		SSL *ssl;
                socklen_t addr_size;
                int clientfd;
		int imindex;
		int ipaddr;
		int bytes_read = 0;
		struct sockaddr_storage client_addr;
		char* msg = "Got it!";
		char buffer[256];

		// Zero out our buffer for easier debugging
		memset(&buffer, 0, sizeof(buffer));

                addr_size = sizeof client_addr;
                clientfd = accept(sockfd, (struct sockaddr *)&client_addr, &addr_size);

		// Print ip address
		printf("TCP connection from ");
		for (imindex = 2; imindex < 6; imindex++){
			ipaddr = (int)(((struct sockaddr *)&client_addr)->sa_data[imindex]);
			ipaddr = (ipaddr+256)%256;
			printf("%d.",ipaddr);
		}
		printf("\n");
		//end

		ssl = SSL_new(ctx);
		/* Add the connection socket to the SSL state */
		SSL_set_fd(ssl, clientfd);

		err = SSL_accept(ssl);
		if (err < 1) {
			ERR_print_errors_fp(stderr);

			SSL_free(ssl);
			close(clientfd);
			close(sockfd);
			freeaddrinfo(server);
			exit(-1);
		}

		/* Print out connection details */
		printf("SSL connection on socket %x, Version: %s, Cipher: %s\n",
		       clientfd,
		       SSL_get_version(ssl),
		       SSL_get_cipher(ssl));

		bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
		
		if (bytes_read < 0) {
			ERR_print_errors_fp(stderr);
			err = SSL_get_error(ssl, bytes_read);
			
			error("Error #%d in sslread\n",err);
			/********************************/
			/* If err=6 it means the client */
			/* issued an SSL_shutdown. You */
			/* must respond with a shutdown */
			/* to complete a graceful */
			/* shutdown */
			/********************************/
			
			if (err == 6)
				SSL_shutdown(ssl);
			
			SSL_free(ssl);
			close(clientfd);
			close(sockfd);
			freeaddrinfo(server);
			exit(-1);
		}

		if (bytes_read > 0)
			printf("Read: %s\n", buffer);
				
		err = SSL_write(ssl, msg, strlen(msg) + 1);
		if (err < 0) {
			printf("sslerror:%d\n", SSL_get_error(ssl, err));
			ERR_print_errors_fp(stderr);

			SSL_free(ssl);
			close(clientfd);
			close(sockfd);
			freeaddrinfo(server);
			exit(-1);
		}

		err = SSL_shutdown(ssl);
		if (err < 0)
			printf("Error in SSL shutdown\n");
		else if (err == 1)
			printf("Client exited gracefully\n");

		/* close connections & clean up */
		SSL_free(ssl);
		close(clientfd);
	}
	SSL_CTX_free(ctx);
	freeaddrinfo(server);
        close(sockfd);
	return 0;
}
