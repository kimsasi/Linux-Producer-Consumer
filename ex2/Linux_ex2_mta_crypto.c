#include "Linux_ex2_mta_crypto.h"

struct decrypter_guess_list * g_plain_data_guess_list = NULL;

int main(int argc, char *argv[])
{
    int i, num_of_decrypters, plain_data_length, timeout = 0, is_valid;

    // extract program parameters
    for(i = 1; i < argc - 1; i++)
    {
        if(strcmp(argv[i], DECRYPTERS_FLAG) == 0 || strcmp(argv[i], DECRYPTERS_FLAG_SHORTCUT) == 0)
        {
            num_of_decrypters = (atoi(argv[i + 1]));
        }
        else if(strcmp(argv[i], PASSWORD_FLAG) == 0 || strcmp(argv[i], PASSWORD_FLAG_SHORTCUT) == 0)
        {
            plain_data_length = (atoi(argv[i + 1]));
        }
        else if(strcmp(argv[i], TIMEOUT_FLAG) == 0 || strcmp(argv[i], TIMEOUT_FLAG_SHORTCUT) == 0)
        {
            g_is_contains_timeout = TRUE;
            timeout = (atoi(argv[i + 1]));
        }
    }

    is_valid = check_input_params_validation(num_of_decrypters, plain_data_length, timeout);

    if(is_valid == FALSE)
    {
        // invalid input params
        exit(1);
    }

    initialize_global_variables(plain_data_length, timeout);
    
    pthread_attr_t decrypter_thread_attr;
    handle_threads_sched_params(&decrypter_thread_attr);

    pthread_t decrypters[num_of_decrypters];
    pthread_t encrypter;

    // create the threads
    pthread_create(&encrypter, NULL, encrypter_start, NULL);
    create_pthread_decrypters_array(decrypters, num_of_decrypters, &decrypter_thread_attr);

    pthread_exit(0);
}

/*--------------------------------------------------------*/
void initialize_global_variables(int plain_data_length, int timeout)
{
    // initialize valid global params
    g_plain_data_length = plain_data_length;
    g_key_length = g_plain_data_length / 8;
    g_timeout = timeout;

    // initialize mutexes
    pthread_mutex_init(&g_current_encrypted_data_mutex, NULL);
    pthread_mutex_init(&g_plain_data_guess_list_mutex, NULL);

    // initialize condition variables
    pthread_cond_init(&g_new_encrypted_data_cv, NULL);
    pthread_cond_init(&g_empty_list_cv, NULL);
}

/*--------------------------------------------------------*/
/* This function gets the main inpur params and an indication for their validation. */
int check_input_params_validation(int num_of_decrypters, int plain_data_length, int timeout)
{
    int is_valid = TRUE;

    if(plain_data_length % 8 != 0 || plain_data_length <= 0)
    {
        is_valid = FALSE;
        printf("Invalid password length. The password length must be a positive multiplication of 8.\n");
    }
    if(num_of_decrypters <= 0)
    {
        is_valid = FALSE;
        printf("The decrypters number must be a positive number.\n");
    }
    if(g_is_contains_timeout == TRUE && timeout <= 0)
    {
        printf("The timeout parameter must be a positive number.\n");
    }

    return is_valid;
}

/*--------------------------------------------------------*/
void handle_threads_sched_params(pthread_attr_t * decrypter_thread_attr)
{
    int res;
    struct sched_param max_prio = {sched_get_priority_max(SCHED_RR)};

    // Set Round-Robin policy and highest priority to main thread	
    res = pthread_setschedparam(pthread_self(), SCHED_RR, &max_prio);
    assert_if(res);
    
    initialize_decrypter_thread_attribute(decrypter_thread_attr);
}

/*--------------------------------------------------------*/
void initialize_decrypter_thread_attribute(pthread_attr_t * decrypter_thread_attr)
{
    int res;
    struct sched_param max_prio = {sched_get_priority_max(SCHED_OTHER)};

    // initialize attribute
    res = pthread_attr_init(decrypter_thread_attr);
	assert_if(res);

    // set attribute scheduling policy to time-sharing
    res = pthread_attr_setschedpolicy(decrypter_thread_attr, SCHED_OTHER);
    assert_if(res);
    
    // set attribute priority to max  priority
    res = pthread_attr_setschedparam(decrypter_thread_attr, &max_prio);
	assert_if(res);

    // set attribute schedule params explicitly 
    res = pthread_attr_setinheritsched(decrypter_thread_attr, PTHREAD_EXPLICIT_SCHED);
    assert_if(res);
}

/*--------------------------------------------------------*/
/* The encrypter's thread execute function. */ 
 void *encrypter_start(void *ptr)
{
    char password[MAX_DATA_LENGTH];

    make_decrypter_guess_list_an_empty_list();

    while(TRUE)
    {
        generate_and_encrypt_new_password(password);            // new encrypted data
        pthread_cond_broadcast(&g_new_encrypted_data_cv);       // broadcast to the decrypters
        new_password_iteration(password);                        
    }

    pthread_exit(0);
}

/*--------------------------------------------------------*/
void new_password_iteration(char * password)
{
    if (g_is_contains_timeout == TRUE)
    {
        new_password_iteration_with_time_limit(password);
    }
    else
    {
        new_password_iteration_with_no_time_limit(password);
    }   
}

/*--------------------------------------------------------*/
void new_password_iteration_with_time_limit(char * password)
{
    struct timespec timespec_timeout;

    clock_gettime(CLOCK_REALTIME, &timespec_timeout);
    timespec_timeout.tv_sec += g_timeout;

    while(g_new_password_required == FALSE)
    {
        // password has not been decrypted and timeout has not expired yet

        int timeout_res = 0;

        pthread_mutex_lock(&g_plain_data_guess_list_mutex);

        while(is_decrypter_guess_list_is_an_empty_list() == TRUE && timeout_res != ETIMEDOUT)
        {
            // the guesses list is empty and timeout has not expired yet
            timeout_res = pthread_cond_timedwait(&g_empty_list_cv, &g_plain_data_guess_list_mutex, &timespec_timeout);
        }
        pthread_mutex_unlock(&g_plain_data_guess_list_mutex);


        if(timeout_res == ETIMEDOUT)
        {
            // the time is up
            printf("[SERVER]\t\t[ERROR]\tNo password received during the configured timeout period (%u seconds), regenerating password\n", g_timeout);
            pthread_mutex_lock(&g_current_encrypted_data_mutex);
            g_new_password_required = TRUE;
            pthread_mutex_unlock(&g_current_encrypted_data_mutex);
            handle_guesses_list_after_timeout();
        }
        else
        {
            // check the head of decrypter guesses list
            handle_plain_data_guess(password);
        }
    }
}

/*--------------------------------------------------------*/
void new_password_iteration_with_no_time_limit(char * password)
{
    while(g_new_password_required == FALSE)
    {
        // password has not been decrypted

        pthread_mutex_lock(&g_plain_data_guess_list_mutex);

        while(is_decrypter_guess_list_is_an_empty_list() == TRUE)
        {
            // the guesses list is empty
            pthread_cond_wait(&g_empty_list_cv, &g_plain_data_guess_list_mutex);
        }
        pthread_mutex_unlock(&g_plain_data_guess_list_mutex);

        // check the head of decrypter guesses list
        handle_plain_data_guess(password);
    }
}

/*--------------------------------------------------------*/
/* The function checks the current decrypter guess and handles it.*/
void handle_plain_data_guess(char *password)
{
    pthread_mutex_lock(&g_plain_data_guess_list_mutex);
    struct decrypter_guess_node * previous_head = g_plain_data_guess_list->head;    // save previous list head
    pthread_mutex_unlock(&g_plain_data_guess_list_mutex);

    if (strcmp(previous_head->plain_data_guess->decrypted_data, password) == 0)
    {
        // current guess is correct 
        printf("[SERVER]\t\t[OK]\tPassword decrypted successfully by client #%u, received(%s), is (%s)\n",
               previous_head->plain_data_guess->decrypter_id, previous_head->plain_data_guess->decrypted_data, password);

        pthread_mutex_lock(&g_current_encrypted_data_mutex);
        g_new_password_required = TRUE;
        pthread_mutex_unlock(&g_current_encrypted_data_mutex);

        pthread_mutex_lock(&g_plain_data_guess_list_mutex);
        g_plain_data_guess_list->head = g_plain_data_guess_list->tail = NULL;   // set the list head to NULL 
        pthread_mutex_unlock(&g_plain_data_guess_list_mutex);
    }
    else
    {
        // current guess is incorrect
        printf("[SERVER]\t\t[ERROR]\tWrong password received from client #%u(%s), should be (%s)\n", previous_head->plain_data_guess->decrypter_id, previous_head->plain_data_guess->decrypted_data, password);

        pthread_mutex_lock(&g_plain_data_guess_list_mutex);
        g_plain_data_guess_list->head = g_plain_data_guess_list->head->next;    // set the list head to the next guess 
        previous_head->next = NULL;                                             // disconnect the previous head from the list
        pthread_mutex_unlock(&g_plain_data_guess_list_mutex);
    }

    free_decrypter_guess_nodes(previous_head);
}

/*--------------------------------------------------------*/
/* The function handles the decrypters guesses list after the time is up with no correct guess. */
void handle_guesses_list_after_timeout()
{
    pthread_mutex_lock(&g_plain_data_guess_list_mutex);
    if(is_decrypter_guess_list_is_an_empty_list() == FALSE)
    {
        struct decrypter_guess_node * previous_head = g_plain_data_guess_list->head;    // save the previous list head
        g_plain_data_guess_list->head = g_plain_data_guess_list->tail = NULL;           // set the list head to NULL 
        pthread_mutex_unlock(&g_plain_data_guess_list_mutex);
        free_decrypter_guess_nodes(previous_head);                                      // free outside the lock
    }
    else
    {
        pthread_mutex_unlock(&g_plain_data_guess_list_mutex);
    }
}

/*--------------------------------------------------------*/
/* This function creates the decrypters threads. */
void create_pthread_decrypters_array(pthread_t *decrypters, int arr_size, pthread_attr_t * decrypter_thread_attr)
{
    int i, res;

    for (i = 0; i < arr_size; i++)
    {
        int *thread_id = (int *) malloc(sizeof(int));
        *thread_id = i + 1;

        // Execute the decrypter thread with the attributes
        res = pthread_create(&decrypters[i], decrypter_thread_attr, decrypter_start, thread_id);
        assert_if(res);
    }
}

/*--------------------------------------------------------*/
/* This function generates and encryptes a new password. */
void generate_and_encrypt_new_password(char *password)
{
    char key[MAX_DATA_LENGTH], encrypted_data[MAX_DATA_LENGTH];; 
    unsigned int encrypted_data_length;

    // initialize data
    bzero(password, MAX_DATA_LENGTH);
    bzero(key, MAX_DATA_LENGTH);
    bzero(encrypted_data, MAX_DATA_LENGTH);

    get_printable_rand_data(password, g_plain_data_length + 1);     // get a random password 
    MTA_get_rand_data(key, g_key_length);                           // get a random key


    MTA_CRYPT_RET_STATUS ret_status = MTA_encrypt(key, g_key_length, password, g_plain_data_length,
                                 encrypted_data, &encrypted_data_length);

    if(ret_status != MTA_CRYPT_RET_OK)
    {
        printf("Oops! Something went wrong.\n");
        exit(1);
    }

    // update the global variables
    pthread_mutex_lock(&g_current_encrypted_data_mutex);
    memcpy(g_encrypted_data, encrypted_data, sizeof(char) * (encrypted_data_length + 1));
    g_encrypted_data_length = encrypted_data_length;
    g_new_password_required = FALSE;
    pthread_mutex_unlock(&g_current_encrypted_data_mutex);

    printf("[SERVER]\t\t[INFO]\tNew password generated: %s, key: %s, After encryption: %s\n", encrypted_data, key, password);
}

/*--------------------------------------------------------*/
/* The decrypter's thread execute function. */ 
 void *decrypter_start(void *ptr)
{
    unsigned int thread_id = *((int *) ptr);
    char plain_data[MAX_DATA_LENGTH];

    while(TRUE)
    {
        decrypt_to_printable_data(plain_data, thread_id);
        send_plain_data_guess_to_server(thread_id, plain_data);
    }

    pthread_exit(0);
}

/*--------------------------------------------------------*/
/* This function decrypts the encrypted data until it is printable. */
void decrypt_to_printable_data(char * plain_data, unsigned int thread_id)
{
    char key[MAX_DATA_LENGTH], encrypted_data[MAX_DATA_LENGTH];
    unsigned int plain_data_length, num_of_iterations = 0;
    MTA_CRYPT_RET_STATUS ret_status;

    do
    {
        // initialize data
        bzero(key, MAX_DATA_LENGTH);
        bzero(plain_data, MAX_DATA_LENGTH);
        bzero(encrypted_data, MAX_DATA_LENGTH);

        pthread_mutex_lock(&g_current_encrypted_data_mutex);
        while(g_new_password_required == TRUE)
        {
            // waiting for a new password
            pthread_cond_wait(&g_new_encrypted_data_cv, &g_current_encrypted_data_mutex);
            num_of_iterations = 0;
        }
        pthread_mutex_unlock(&g_current_encrypted_data_mutex);

        MTA_get_rand_data(key, g_key_length);

        // save the encrypted data global variables in a local variables
        pthread_mutex_lock(&g_current_encrypted_data_mutex);
        memcpy(encrypted_data, g_encrypted_data, sizeof(char) * g_encrypted_data_length + 1);
        unsigned int encrypted_data_length = g_encrypted_data_length;
        pthread_mutex_unlock(&g_current_encrypted_data_mutex);

        ret_status = MTA_decrypt(key, g_key_length, encrypted_data, encrypted_data_length, plain_data,
                                 &plain_data_length);
        if(ret_status != MTA_CRYPT_RET_OK)
        {
            printf("Oops! Something went wrong.\n");
            exit(1);
        }

        ++num_of_iterations;
    } while(is_printable_string(plain_data, plain_data_length) == FALSE);

    printf("[CLIENT #%u]\t\t[INFO]\tAfter decryption(%s), key guessed(%s), sending to server after %u iterations\n",
           thread_id, plain_data, key, num_of_iterations);

}
/*--------------------------------------------------------*/
/* This function sends the decrypter guess to the encrypter. */
void send_plain_data_guess_to_server(unsigned int thread_id, char *plain_data)
{
    struct decrypter_guess_node * new_guess = create_new_decrypter_guess_node(thread_id, plain_data);

    pthread_mutex_lock(&g_plain_data_guess_list_mutex);
    insert_decrypter_guess_node_to_tail(new_guess);
    pthread_mutex_unlock(&g_plain_data_guess_list_mutex);
}

/*--------------------------------------------------------*/
/* This function gets an array of characters and returns an indication if it is printable. */
int is_printable_string(char *data, unsigned int size)
{
    int is_printable = TRUE;
    int i;

    for (i = 0; i < size && is_printable != FALSE; i++)
    {
        is_printable = isprint(data[i]);
    }

    return is_printable;
}

/*--------------------------------------------------------*/
/* This function gets a requested length and returns (by an output param) an array
   of random and printable characters in the requested length. */
void get_printable_rand_data(char *data, unsigned int requested_data_length)
{
    int index = 0;

    while (index < requested_data_length - 1)
    {
        char rand_char = MTA_get_rand_char();

        if (isprint(rand_char) != FALSE)
        {
            data[index] = rand_char;
            index++;
        }
    }

    data[requested_data_length - 1] = '\0';
}

/*--------------------------------------------------------*/
/* This function allocates the plain data guess list and sets
 * the head and the tail of the list to NULL. */
void make_decrypter_guess_list_an_empty_list()
{
    g_plain_data_guess_list = (struct decrypter_guess_list *) malloc(sizeof(struct decrypter_guess_list));
    g_plain_data_guess_list->head = g_plain_data_guess_list->tail = NULL;
}

/*--------------------------------------------------------*/
/* This function returns an indication for an empty list. */
unsigned int is_decrypter_guess_list_is_an_empty_list()
{
    return g_plain_data_guess_list->head == NULL;
}

/*--------------------------------------------------------*/
/* This function gets a single decryper guess data and returns a new decrypter guess node. */
struct decrypter_guess_node * create_new_decrypter_guess_node(unsigned int thread_id, char * plain_data)
{
    struct decrypter_guess_node *new_node = (struct decrypter_guess_node *) malloc(sizeof(struct decrypter_guess_node));
    new_node->plain_data_guess = (struct decrypter_guess *)malloc(sizeof (struct decrypter_guess));
    strcpy(new_node->plain_data_guess->decrypted_data, plain_data);
    new_node->plain_data_guess->decrypter_id = thread_id;
    new_node->next = NULL;

    return new_node;
}

/*--------------------------------------------------------*/
/* This function gets a decryper guess node and inserts it to the tail of the list. */
void insert_decrypter_guess_node_to_tail(struct decrypter_guess_node *new_node)
{
    if (g_plain_data_guess_list->head != NULL)
    {
        // The guess list is not empty
        g_plain_data_guess_list->tail->next = new_node;
        g_plain_data_guess_list->tail = g_plain_data_guess_list->tail->next;
    }
    else
    {
        // It is the first guess in the list
        g_plain_data_guess_list->head = new_node;
        g_plain_data_guess_list->tail = new_node;
        pthread_cond_signal(&g_empty_list_cv);
    }
}

/*--------------------------------------------------------*/
/* This function gets a single decryper guess node and releases all the
   following nodes. */
void free_decrypter_guess_nodes(struct decrypter_guess_node *plain_data_guess_node)
{
    while (plain_data_guess_node != NULL)
    {
        free(plain_data_guess_node->plain_data_guess);
        struct decrypter_guess_node *temp = plain_data_guess_node;
        plain_data_guess_node = plain_data_guess_node->next;
        free(temp);
    }
}