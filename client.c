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

	exit(0);
}

int
main(int arc, char** argv) {
	char* server_port = "5000";
	char* server_ip = "127.0.0.1";

	char* cert_file = "client.crt";
	char* key_file = "client.key";

	// Command Line generation of Diffie-Hellman parameters
	// openssl dhparam -out dh_param_2048.pem 2048
	char* dh_file = "dh_param_2048_client.pem";

	DH *dh_2048 = NULL;
	FILE *paramfile;

	int err;
        int sockfd;

	struct addrinfo hints;
	struct addrinfo *server;

	const SSL_METHOD *ssl_meth;
	SSL_CTX *ctx;

        /* Load encryption & hashing algorithms for the SSL program */
	SSL_library_init();
	/* Load the error strings for SSL & CRYPTO APIs */
	SSL_load_error_strings();

	/* Use SSLv3 for the connection */
	ssl_meth = SSLv23_client_method();
	/* Create a new context--stores configuration for SSL */
	ctx = SSL_CTX_new(ssl_meth);
	if (!ctx)
		error("Error creating SSL context.\n");

	printf("Setting the local certificates and keys...\n");
        /* Set the local certificates and keys */
	err = SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM);
	if (err <= 0) {
		ERR_print_errors_fp(stderr);
		fprintf(stderr, "Error setting the certificate file.\n");
		goto out;
	}

	err = SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM);
	if (err <= 0) {
		ERR_print_errors_fp(stderr);
		fprintf(stderr, "Error setting the private key file.\n");
		goto out;
	}

        /* Verify private key and public crt combination. */
	if (!SSL_CTX_check_private_key(ctx)) {		
		fprintf(stderr,
			"Error, private key does not match public key.\n");
		goto out;
	}

	/* Set up ephemeral DH parameters. */
	paramfile = fopen(dh_file, "r");

	if (!paramfile) {
		fprintf(stderr, "Error opening Diffie-Hellman parameters.\n");
		goto out;
	}
	dh_2048 = PEM_read_DHparams(paramfile, NULL, NULL, NULL);

	err = fclose(paramfile);
	if (err) {
		fprintf(stderr, "Error closing file stream.\n");
		goto out;
	}

	if (!dh_2048) {
		fprintf(stderr, "Error reading Diffie-Hellman parameters.\n");
		goto out;
	}
	err = SSL_CTX_set_tmp_dh(ctx, dh_2048);
	if (err != 1) {
		fprintf(stderr,
			"Error setting Diffie-Hellman into SSL context\n");
		goto out;
	}


	/*--- Standard TCP server setup and connection ---*/

	printf("Creating TCP/IP socket...\n");
	{
		SSL *ssl;
		int bytes = 0;
		char *msg = "Hello!";
		char buf[256];

		memset(&buf, 0, sizeof(buf));
		/* The hints struct is used to specify what kind of server info
		 * we are looking for. */
		memset(&hints, 0, sizeof hints);
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM; /* or SOCK_DGRAM */
		
		/* getaddrinfo() gives us back a server address we can connect to.
		   It actually gives us a linked list of addresses, but we'll just
		   use the first. */
		err = getaddrinfo(server_ip, server_port, &hints, &server);
		if (err) {
			fprintf(stderr, "Error getting address information.\n");
			goto out;
		}
		/* Now we can create the socket and connect */
		sockfd = socket(server->ai_family, server->ai_socktype, server->ai_protocol);
		if (sockfd == -1) {		
			fprintf(stderr, "Error opening socket.\n");
			freeaddrinfo(server);
			goto out;
		}
		
		err = connect(sockfd, server->ai_addr, server->ai_addrlen);
		if (err == -1) {
			fprintf(stderr, "Error on connect.\n");
			close(sockfd);
			freeaddrinfo(server);
			goto out;
		}
		
		ssl = SSL_new(ctx);
		if (!ssl) {
			fprintf(stderr,
				"Error creating a new SSL structure.\n");
			ERR_print_errors_fp(stderr);
			close(sockfd);
			freeaddrinfo(server);
			goto out;
		}
		SSL_set_fd(ssl, sockfd); /* set connection to SSL state */
		
		err = SSL_connect(ssl);
		if (err < 1) {
			err = SSL_get_error(ssl,err);
			printf("SSL error #%d in accept.\n", err);
			ERR_print_errors_fp(stderr);

			SSL_free(ssl);
			close(sockfd);
			freeaddrinfo(server);
			goto out;
		}
		
		/* Print out connection details */
		printf("SSL connection on socket %x, Version: %s, Cipher: %s\
\n", sockfd, SSL_get_version(ssl), SSL_get_cipher(ssl));
		
		err = SSL_write(ssl, msg, strlen(msg) + 1);
		if (err < 0) {
			printf("sslerror:%d\n", SSL_get_error(ssl, err));
			ERR_print_errors_fp(stderr);
			
			SSL_free(ssl);
			close(sockfd);
			freeaddrinfo(server);
			goto out;
		}
		
		while(bytes <= 0)
			bytes = SSL_read(ssl, buf, sizeof(buf) - 1);
		
		printf("Received: %s\n", buf);
		
		err = SSL_shutdown(ssl);
		if (err < 0)
			printf("Error in SSL shutdown\n");
		else if (err == 1)
			printf("Client exited gracefully\n");
		
		/* close connection & clean up */
		SSL_free(ssl);
		close(sockfd);
		freeaddrinfo(server);
	}
out:
	SSL_CTX_free(ctx);
	return 0;
}
