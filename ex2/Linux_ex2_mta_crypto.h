#ifndef LINUX_EX2_MTA_CRYPTO_H
#define LINUX_EX2_MTA_CRYPTO_H
#include <stdio.h>
#include <mta_crypt.h>
#include <mta_rand.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sched.h>

// assert macro
#define assert_if(errnum) if (errnum != 0){ printf("Error in line #%u: %m\n", __LINE__); exit(EXIT_FAILURE);}

#define TRUE 1
#define FALSE 0
#define MAX_DATA_LENGTH 200
#define CLOCK_REALTIME 0

// input params flags
#define DECRYPTERS_FLAG "--num-of-decrypters"
#define DECRYPTERS_FLAG_SHORTCUT "-n"
#define PASSWORD_FLAG "--password-length"
#define PASSWORD_FLAG_SHORTCUT "-l"
#define TIMEOUT_FLAG "--timeout"
#define TIMEOUT_FLAG_SHORTCUT "-t"
 
 struct decrypter_guess
{
    char decrypted_data[MAX_DATA_LENGTH];
    unsigned int decrypter_id;
};

struct decrypter_guess_list
{
    struct decrypter_guess_node * head;
    struct decrypter_guess_node * tail;
};

struct decrypter_guess_node
{
    struct decrypter_guess * plain_data_guess;
    struct decrypter_guess_node * next;
};

unsigned int g_new_password_required = TRUE;
char g_encrypted_data[MAX_DATA_LENGTH] = {0};
unsigned int g_encrypted_data_length;
unsigned int g_key_length;
unsigned int g_plain_data_length;
unsigned int g_is_contains_timeout = FALSE;
unsigned int g_timeout;

// mutexes:
pthread_mutex_t g_current_encrypted_data_mutex;
pthread_mutex_t g_plain_data_guess_list_mutex;

// condition variables:
pthread_cond_t g_new_encrypted_data_cv;
pthread_cond_t g_empty_list_cv;

// functions:

// main thread functions:
void handle_threads_sched_params(pthread_attr_t * decrypter_thread_attr);
void initialize_global_variables(int plain_data_length, int timeout);
void initialize_decrypter_thread_attribute(pthread_attr_t * encrypter_thread_attr);
void create_pthread_decrypters_array(pthread_t *decrypters, int arr_size, pthread_attr_t * decrypter_thread_attr);

// encrypter functions:
void *encrypter_start(void *ptr);
void generate_and_encrypt_new_password(char *password);
void handle_plain_data_guess(char * password);
void new_password_iteration(char * password);
void new_password_iteration_with_no_time_limit(char * password);
void new_password_iteration_with_time_limit(char * password);

// decrypter functions:
void * decrypter_start(void * ptr);
void decrypt_to_printable_data(char * plain_data, unsigned int thread_id);
void send_plain_data_guess_to_server(unsigned int thread_id, char * plain_data);

// data functions:
int is_printable_string(char * data, unsigned int size);
void get_printable_rand_data(char * data, unsigned int requested_data_length);
int check_input_params_validation(int num_of_consumers, int plain_data_length, int timeout);

// list functions:
unsigned int is_decrypter_guess_list_is_an_empty_list();
struct decrypter_guess_node * create_new_decrypter_guess_node(unsigned int thread_id, char * plain_data);
void insert_decrypter_guess_node_to_tail(struct decrypter_guess_node *new_node);
void make_decrypter_guess_list_an_empty_list();
void free_decrypter_guess_nodes(struct decrypter_guess_node *plain_data_guess_node);
void handle_guesses_list_after_timeout();

#endif //LINUX_EX2_MTA_CRYPTO_H
