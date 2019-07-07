// gluttony.c ~ Author: Lilith Wyatt (https://github.com/Thiefyface)
//            ~ Refer to the License.txt for BSD 3-clause licensing info <3   

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <fcntl.h>
#include <signal.h>
#include <limits.h>



// sockets
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

// dynamorio includes
#include <dr_api.h>
#include <dr_tools.h>
#include <drmgr.h>
#include <hashtable.h>
#include <drtable.h>

//nolors
#define RED     "\033[31m"
#define ORANGE  "\033[91m"
#define GREEN   "\033[92m"
#define LIME    "\033[99m"
#define YELLOW  "\033[93m"
#define BLUE    "\033[94m"
#define PURPLE  "\033[95m"
#define CYAN    "\033[96m"
#define CLEAR   "\033[00m"

#define FALSE 0
#define TRUE 1

#define HASH_INTPTR 0
#define HASH_STRING 1
#define HASH_STRING_NOCASE 2
#define HASH_CUSTOM 3


#ifdef WINDOWS
# define SYS_MAX_ARGS 9
# define DIR_CHAR '\\'
#else
# define SYS_MAX_ARGS 3
# define DIR_CHAR '/'
#endif

static bool DEBUG;

typedef struct {
    reg_t param[SYS_MAX_ARGS];
    reg_t reg_xcx;
    bool repeat;
} per_thread_t;

static int tcls_idx;

static void exit_event(void);
static void module_loaded_event(void *drcontext, const module_data_t *info, bool loaded);
static void module_unloaded_event(void *drcontext, const module_data_t *info);

static dr_emit_flags_t analyze_hash_ops(void *drcontext, void *tag, instrlist_t *bb,
                            bool for_trace, bool translating, void **user_data);

static dr_emit_flags_t insert_hash_ops(void *drcontext, void *tag, instrlist_t *bb,
                            instr_t *instr, bool for_trace, 
                            bool translating, void *user_data);

static void signal_event(void *drcontext, dr_siginfo_t *siginfo);

//static void event_thread_context_init(void *drcontext, bool new_depth);
//static void event_thread_context_exit(void *drcontext, bool process_exit);
static unsigned long old_bb;

// <hashtablies.>
#define HSIZE 16
static hashtable_t bbxor_hashtable; // Any bb pairs added here will generate a 
                                    // new fuzzer case.


static hashtable_t bbtrace_bitmap;  // This is where we import into for persistance
                                    // And where we add to at the beginning of starting
                                    // the program. Just serves to not generate fuzz cases
                                    // for BB's that will always run.  

static app_pc prev_bb_addr;

static void hash_ops(app_pc addr, app_pc last_addr, app_pc *prev_bb_addr, 
                    hashtable_t *bbxor_hashtable, hashtable_t *bbtrace_hashtable, 
                    void * seen_table, unsigned long baseaddr);
static void baseline_hash_ops(app_pc addr, app_pc last_addr, hashtable_t *bbtrace_bitmap);
static void hash_ops_add(void);
static void hash_ops_del(void);

static size_t alloc_count;
static void *hash_lock;
// </hashtablies.>

 

// All this for persistance.
static byte *persist_base_addr;
static char savedir[1024];
static char savedir_full[4096];
static char seen_backup[4096];
static char unseen_backup[4096];
static void *seen_table;
static void *unseen_table;
static unsigned long seen_counter;
static unsigned long unseen_counter;

#define BB_TABLE_SIZE 0x10000

typedef struct {
    unsigned long addr_prev;
    unsigned long addr_curr; 
} bb_pair; 


// <module stuff>
static void *module_lock;
static size_t page_size;
typedef struct _module_store {
    unsigned long start;
    unsigned long end;
    bool loaded;
    module_data_t *info;
    unsigned long size;
    byte *bitmap;
} module_store;

#define MAX_MOD 256
static module_store module_array[MAX_MOD];
static unsigned int mod_count;
// </module stuff>

// <socket_fun>
static void *fuzzer_comms(void);
static pid_t comms_pid;
#define DEFAULT_ADDR "127.0.0.1" 
#define DEFAULT_PORT 61601

static char fuzzer_addr[16];
static unsigned short fuzzer_port;

typedef struct{
    byte type;
    ssize_t length;
    byte *msg;
} fuzzer_msg;

//
static dr_signal_action_t feedback_signal_handler(void *drcontext, dr_siginfo_t *info);
static void fuzzer_signal_handler(int sig);
static bool is_fork; 
//

static int init_interproc_socket(bool bindflag);
static int connect_feedback_socket(const char *addr,unsigned short port);
static int do_fuzzer_handshake(void);

static struct sockaddr_un unixaddr;
static int inter_srv_sock; // these belong to parent 
static int inter_cli_sock; //

static byte *interproc_buff; // buffer for each, dr_global_alloc(MAX_MSG_LEN)
static int inter_comms_sock; // belong to child
static int fuzzer_socket;
static void *socket_lock;

// 2 second timeout.
static struct timeval timeout;     

static int handle_fuzzer_msg(byte *msg);
static byte *create_msg(byte num, unsigned int msg_len, byte *contents);

// Fuzzer Message Handlers
static int heartbeat(unsigned int len, byte *msg);
static void init_new_trace(unsigned int len, byte *msg);
static void init_previous_trace(unsigned int len, byte *msg);
static void fuzz_case(unsigned int len, byte *msg);
static void end_of_fuzz_case(unsigned int len, byte *msg);
static void send_results_n_cleanup(unsigned int len, byte *msg);
static void start_feedback(unsigned int len, byte *msg);
static void stop_feedback(unsigned int len, byte *msg);
static void keepalive(unsigned int len, byte *msg);

static unsigned int keepalive_timer; 
static bool queued_flag;

static void (*msg_handler)(unsigned int len, byte *msg);
#define MAX_MSG_LEN 0x00100000
#define MIN_MSG_LEN 0x5

static void sendmsg_addqueue(void);
static void sendmsg_crashnoti(void);
static void sendmsg_sessionstats(void);

static bool feedback_flag;
static bool bbtrace_flag;
// </socket_fun>
static void usage();   
    

typedef enum {
    ERROR,
    STR,
    LONG,
    INT,
    SHORT,
    BYTE,
    BOOL
} ret_type;


// Client mode variables/functions
static bool clientside;
static bool syscall_connect_cb(void *drcontext, int sysnum);
static bool syscall_connect_filter(void *drcontext, int sysnum);
static void fork_loop(void);
static bool fork_flag;
static void event_thread_init(void *drcontext);
static void event_thread_exit(void *drcontext);


// =========================End Defines================================== 

static int dumb_argparse(int argc, const char * argv[], 
                  void *ret_val, ret_type type, unsigned int ret_len,
                  char *target_arg); 

static void dr_color_printf(char *msg, char *color){
    dr_printf("%s%s%s",color,msg,CLEAR);
}


DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
    dr_color_printf("[^_^] MutiTrace Init\n",GREEN);
    if (dumb_argparse(argc,argv,NULL,BOOL,0x0,"--help") == 0){
        usage();
        return; 
    } 
    
    if (dumb_argparse(argc,argv,(void *)&fuzzer_port,SHORT,2,"--fuzzerport") < 0){
        fuzzer_port = DEFAULT_PORT;
    }
    
    if (dumb_argparse(argc,argv,(void *)fuzzer_addr,STR,15,"--fuzzerip") < 0){
        strncpy((char *)fuzzer_addr,DEFAULT_ADDR,strlen(DEFAULT_ADDR)); 
    }

    if (dumb_argparse(argc,argv,(void *)&DEBUG,BOOL,1,"--debug") == 0){
        DEBUG = true;  
    } else {
        DEBUG = false;
    }
    
    dumb_argparse(argc,argv,(void *)savedir,STR,768,"--savedir");

    if (dumb_argparse(argc,argv,(void *)&clientside,BOOL,1,"--client") == 0){
        clientside = true;
    } else {
        clientside = false;
    }

    unsigned int seen_size = 0x10000;
    unsigned int unseen_size = 0x10000;
    unsigned long fsize = 0;
    unsigned long mapsize = 0;

    unsigned int savedir_len = strlen(savedir); 

    // Create tables for persistance.
    seen_table = drtable_create(BB_TABLE_SIZE,sizeof(bb_pair),0x0,true,NULL); 
    unseen_table = drtable_create(BB_TABLE_SIZE,sizeof(bb_pair),0x0,true,NULL); 
    dr_printf("Seen_table: 0x%lx\n");

    if (savedir_len > 0){
        if (*(char *)savedir != '/'){ 
            dr_get_current_directory(savedir_full,2048);
            savedir_full[strlen(savedir_full)] = DIR_CHAR;
            strncat(savedir_full,savedir,sizeof(savedir));
        } else {
            strncpy(savedir_full,savedir,sizeof(savedir));
        }


        savedir[savedir_len] = DIR_CHAR;

        strncpy(seen_backup,savedir_full,3072); 
        seen_backup[strlen(seen_backup)] = DIR_CHAR;
        strncat(seen_backup,"seen_table.bin",14);

        strncpy(unseen_backup,savedir_full,3072); 
        unseen_backup[strlen(unseen_backup)] = DIR_CHAR;
        strncat(unseen_backup,"unseen_table.bin",16);

        // start importing the seen/unseen backups if they exist.
        file_t f1 = dr_open_file(seen_backup, DR_FILE_READ);
        file_t f2 = dr_open_file(unseen_backup, DR_FILE_READ);
        dr_printf("seen_backup: %s, unseen_backup: %s\n",seen_backup,unseen_backup);
        dr_printf("invalid or invalid? 0x%x 0x%x\n",f1,f2);

        // [ (endbb,startbb),(endbb,startbb)....]
        // [ (endbb,startbb),(endbb,startbb)....] (non-taken paths)
        
        
        unsigned int i = 0;
        if (f1 != INVALID_FILE){
            dr_file_size(f1,&fsize); 

            if (fsize % sizeof(bb_pair) != 0){
                dr_printf("[?.?] Potentially corrupted bb_pair seen_table.\n"); 
                DR_ASSERT(false); 
            }
            mapsize = fsize;

            if ((fsize/sizeof(bb_pair)) > BB_TABLE_SIZE){
                dr_printf("[?.?] Importing too huge seen_table. Too huge.\n"); 
                DR_ASSERT(false); 
            }

            byte * tmpbuff = (byte *)dr_global_alloc(fsize);
            dr_read_file(f1,tmpbuff,fsize);

            if (tmpbuff == NULL){
                dr_close_file(f1);
                dr_printf("[?.?] Could not alloc space for seentable, aborting\n"); 
                DR_ASSERT(false); 
            }

            dr_printf("Mapped seen_table to 0x%lx!\n",tmpbuff);

            for (i=0;i<(fsize/sizeof(bb_pair));i+=sizeof(bb_pair)){
                    bb_pair *tmp_bb_pair = drtable_alloc(seen_table,1,NULL);
                    memcpy(tmp_bb_pair,tmpbuff+i,sizeof(bb_pair));
                    if (DEBUG){
                        dr_printf("[!.!] Adding 0x%lx, 0x%lx into seen_table!\n",tmp_bb_pair->addr_curr,tmp_bb_pair->addr_prev);
                    }
                }    
            dr_printf("[!.!] Loaded 0x%x entries into seen_table!\n",i);
            dr_global_free(tmpbuff,fsize);
        } 
        dr_close_file(f1);

        if (f2 != INVALID_FILE){
            dr_file_size(f2,&fsize); 
            if (fsize % sizeof(bb_pair) != 0){
                dr_printf("[?.?] Potentially corrupted bb_pair unseen_table.\n"); 
                DR_ASSERT(false); 
            }

            if ((fsize/sizeof(bb_pair)) > BB_TABLE_SIZE){
                dr_printf("[?.?] Importing too huge unseen_table. Too huge.\n"); 
                DR_ASSERT(false); 
            }

            byte *tmpbuff = (byte *)dr_global_alloc(fsize);
            if (tmpbuff == NULL){

                dr_close_file(f2);
                dr_printf("[?.?] Could not alloc space for seentable, aborting\n"); 
                DR_ASSERT(false); 
            }
            dr_read_file(f2,tmpbuff,fsize);


            for (i=0;i<(fsize/sizeof(bb_pair));i+=sizeof(bb_pair)){
                bb_pair *tmp_bb_pair = drtable_alloc(unseen_table,1,NULL);
                memcpy(tmp_bb_pair,tmpbuff+i,sizeof(bb_pair));
            }    
            dr_global_free(tmpbuff,fsize);
        } 

    } else { // use a default backup location (savedir_len <= 0){
        dr_get_current_directory(savedir_full,2048);
        savedir_full[strlen(savedir_full)] = DIR_CHAR;

        strncpy(seen_backup,savedir_full,3072); 
        seen_backup[strlen(seen_backup)] = DIR_CHAR;
        strncat(seen_backup,"seen_table.bin",14);

        strncpy(unseen_backup,savedir_full,3072); 
        unseen_backup[strlen(unseen_backup)] = DIR_CHAR;
        strncat(unseen_backup,"unseen_table.bin",16);
    }

    dr_printf("[!_!] persist_base_addr => 0x%lx\n",module_array[0].start); 
    dr_printf("Connecting to fuzzer@(%s,%d)\n",fuzzer_addr,fuzzer_port);

    comms_pid = fork();
    if (comms_pid == 0){ //child proc == network manager
        signal(SIGUSR1,fuzzer_signal_handler); 
        signal(SIGUSR2,fuzzer_signal_handler); 
        signal(SIGPIPE,fuzzer_signal_handler); 
        is_fork = true;
        comms_pid = getppid();
        sleep(1); // Verify that we don't connect too fast.
        inter_comms_sock = init_interproc_socket(false); 
        fuzzer_comms(); // => fuzzer client loop 
        return;
    }

    if (!drmgr_init())
        DR_ASSERT(false);

    interproc_buff = (byte *)dr_global_alloc(MAX_MSG_LEN+8);
    if (interproc_buff == NULL){
        DR_ASSERT(false);
        exit(-1); 
    }
    memset(interproc_buff,0x0,MAX_MSG_LEN+8);
    interproc_buff+=0x8;

    feedback_flag = FALSE;
    bbtrace_flag = TRUE;

    drmgr_register_signal_event(feedback_signal_handler);
    // bind mode (accepted connections => inter_cli_sock 
    inter_srv_sock = init_interproc_socket(true);

    // fuzzer socket timeout
    timeout.tv_sec = 2;     
    timeout.tv_usec = 0;
    queued_flag = false;

    page_size = dr_page_size();

    module_lock = dr_mutex_create();
    hash_lock = dr_mutex_create();
    socket_lock = dr_mutex_create();

    hashtable_init(&bbxor_hashtable, HSIZE, HASH_INTPTR, FALSE); 
    hashtable_init(&bbtrace_bitmap, HSIZE, HASH_INTPTR, FALSE); 
    if (DEBUG){
        dr_printf("[^_^] Hash tables initialized 0x%lx, 0x%lx\n",&bbtrace_bitmap,&bbxor_hashtable);
    }

    /*
    if (!dr_register_persist_rw(event_persist_rw_size, event_persist_rw, event_resurrect_rw)){
        dr_printf("[x.x] Could not enable persistance for hashtables!\n");
        DR_ASSERT(false);
    }
    // Persistance flags that will be needed:
    // hashtable_persist_flags_t 
    // DR_HASHPERS_PAYLOAD_IS_POINTER  (persist/resurrect)
    // DR_HASHPERS_CLONE_PAYLOAD       (resurrect)
    // DR_HASHPERS_REBASE_KEY          (all) Rebase keys on reload.... 
    */

    prev_bb_addr = 0x0;

    // register all the things.
    drmgr_register_module_load_event(module_loaded_event);    
    if (DEBUG){
        dr_color_printf("[^_^] Gluttony module loaded event register'ed \n",GREEN);
    }

    drmgr_register_module_unload_event(module_unloaded_event);    
    if (DEBUG){
        dr_color_printf("[^_^] Gluttony module loaded event register'ed \n",GREEN);
    }

    dr_register_exit_event(exit_event);
    
    /*
    tcls_idx = drmgr_register_cls_field(event_thread_context_init,
                                        event_thread_context_exit);
    DR_ASSERT(tcls_idx != -1);

    */
    if (clientside) {
        fork_flag = false;
        dr_register_filter_syscall_event(syscall_connect_filter);
        drmgr_register_pre_syscall_event(syscall_connect_cb);
        dr_printf("[!.!] Registered connect syscall hooks!\n");
    } 

    //drmgr_register_thread_init_event(event_thread_init);
    //drmgr_register_thread_exit_event(event_thread_exit);

    drmgr_register_bb_instrumentation_event(analyze_hash_ops,insert_hash_ops,NULL);
    dr_color_printf("[^_^] MutiTrace Init Finished\n",GREEN);
    dr_printf("\n\n");
}


/*
static size_t event_persist_rw_size(void *drcontext, void *perscxt, size_t file_offs, 
                                    void **user_data OUT){

    static hashtable_t bbxor_hashtable;
    static hashtable_t bbtrace_bitmap; //Determine where recv loop is

    //return hashtable_persist_size(drcontext,

}

static bool event_persist_rw(void *drcontext, void *perscxt, file_t fd, void *user_data){


}
*/

/*
#ifndef WINDOWS
static int sysnum_execve = IF_X64_ELSE(59, 11);
#endif
*/


static void exit_event(void){
    if (!is_fork){
        feedback_flag = FALSE;
        
        dr_printf("[^_^] Unique trans_BB count == %d\n",alloc_count);
        dr_mutex_destroy(module_lock);
        dr_mutex_destroy(hash_lock);
        dr_mutex_destroy(socket_lock);
        hash_ops_del();

        kill(comms_pid,SIGINT); 
        close(inter_srv_sock);
        close(inter_cli_sock);

        if (strlen(savedir_full)){ 
            dr_create_dir(savedir_full);

            file_t f1;
            f1 = dr_open_file(seen_backup, DR_FILE_WRITE_OVERWRITE);
            dr_printf("[!.!] Attempting to dump to %s\n",seen_backup);
            
            if (f1 == INVALID_FILE){
                dr_printf("[!.!] %s was an invalid file\n",seen_backup); 
            } else {
                drtable_dump_entries(seen_table,f1);
                dr_close_file(f1);
            }

            file_t f2;
            f2 = dr_open_file(unseen_backup, DR_FILE_WRITE_OVERWRITE);
            dr_printf("[!.!] Attempting to dump to %s\n",unseen_backup);
            if (f2 == INVALID_FILE){
                dr_printf("[!.!] %s was an invalid file\n",unseen_backup); 
            }
            drtable_dump_entries(unseen_table,f2);
            dr_close_file(f2);
        }
        
    }
    dr_color_printf("[!.!] MutiTrace Exit\n",GREEN);
    /*
    drmgr_unregister_cls_field(event_thread_context_init,
                               event_thread_context_exit,   
                               tcls_idx);
    */
}

/*
static void event_thread_context_init(void *drcontext, bool new_depth){
    per_thread_t *data;
   dr_printf("new thread context id=0x%x\n", dr_get_thread_id(drcontext));
    
    if (new_depth){
        data = (per_thread_t *)dr_thread_alloc(drcontext, sizeof(per_thread_t)); 
        drmgr_set_cls_field(drcontext, tcls_idx, data);
    } else {
        data = (per_thread_t *)dr_thread_alloc(drcontext, sizeof(per_thread_t)); 
    }
    
    memset(data,0,sizeof(*data)); 
}
    
static void event_thread_context_exit(void *drcontext, bool thread_exit){
    dr_printf("Resuming thread context 0x%lx\n", dr_get_thread_id(drcontext));
    if (thread_exit){
        per_thread_t *data = (per_thread_t *) drmgr_get_cls_field(drcontext, tcls_idx);
        dr_thread_free(drcontext,data,sizeof(per_thread_t));
    }
}
*/

static bool load_bbtrace_from_seen(ptr_uint_t idx, void *bb_inp, void *bbtrace_hashtable){
    bb_pair *bb = (bb_pair *)bb_inp;
    if (DEBUG){
        dr_printf(" inp bb_pair: 0x%lx, 0x%lx, 0x%lx\n",bb,bb->addr_curr,bb->addr_prev);
    } 
    unsigned long* init;
    unsigned long key = (bb->addr_curr + module_array[0].start); 

    init = dr_global_alloc(sizeof(unsigned long));
    hashtable_add(bbtrace_hashtable,(void *)key,init);
    if (DEBUG){
        dr_printf("[^_^] Loaded persistant bb entry: (orig)0x%lx => 0x%lx\n",bb->addr_curr,key);
    }
    // continues iteration
    return true; 
}


static void module_loaded_event(void *drcontext, const module_data_t *info, bool loaded){

    int i = 0;  

    size_t offs;
    const char *mod_name = dr_module_preferred_name(info);
    
    if ((strncmp(mod_name,"libdynamorio.so",15) == 0) || \
        (strncmp(mod_name,"libgluttony.so",14) == 0) ) {
        // Dont tread on our own feet
        return; 
    }

    dr_mutex_lock(module_lock); 
    for (i=0; i < mod_count; i++){
        if ( strncmp(info->full_path, module_array[i].info->full_path,strlen(module_array[i].info->full_path)) == 0 ){
            module_array[i].loaded = TRUE;
        } 
    }
    
    if (i == mod_count && i < MAX_MOD){
        module_array[i].info   = dr_copy_module_data(info); 
        module_array[i].loaded = TRUE;
        module_array[i].start   = (unsigned long)info->start;
        module_array[i].end    = (unsigned long)info->end;
    
        module_array[i].size   = module_array[i].end-module_array[i].start;
        module_array[i].bitmap = (byte*) malloc(module_array[i].size);
        mod_count++;
    }

    if (DEBUG){
        dr_printf("%s[>.>] Module Loaded: %s (%s) 0x%lx-0x%lx\n%s",CYAN, mod_name, info->full_path, module_array[i].start, module_array[i].end, CLEAR);
    }

    // first module load should be our exe => load hashtable entries from the seen_table.
    if (mod_count == 1 && (strlen(savedir_full) > 0) ){
        drtable_iterate(seen_table, (void *)&bbtrace_bitmap, load_bbtrace_from_seen);  
        if (DEBUG){    
            dr_printf("[!.!] Size of seen_table: 0x%lx\n",drtable_num_entries(seen_table)); 
        }
    }
    

    dr_mutex_unlock(module_lock);
    
}

static void module_unloaded_event(void *drcontext, const module_data_t *info){ 
    const char *mod_name = dr_module_preferred_name(info);
    if (DEBUG){
        dr_printf("%s[>.>] Module Unloaded: %s!%s\n",ORANGE,mod_name,CLEAR);
    }
}


static dr_emit_flags_t analyze_hash_ops(void *drcontext, void *tag, instrlist_t *bb,
                            bool for_trace, bool translating, void **user_data){

}

static dr_emit_flags_t insert_hash_ops(void *drcontext, void *tag, instrlist_t *bb,
                            instr_t *instr, bool for_trace, 
                            bool translating, void *user_data){

    app_pc curr_addr = instr_get_app_pc(instr);

    instr_t *bb_first_instr = instrlist_first_app(bb);
    app_pc bb_first_addr = instr_get_app_pc(bb_first_instr);

    instr_t *bb_last_instr = instrlist_last_app(bb); 
    app_pc bb_last_addr = instr_get_app_pc(bb_last_instr);

    if (feedback_flag == TRUE){
    //if (TRUE){
        if (curr_addr == bb_first_addr) {
            if (bb_first_addr == NULL){
                dr_printf("Bad bb found! (f:0x%08lx, l:0x%08lx)\n",bb_first_addr,bb_last_addr);
                return DR_EMIT_DEFAULT;
            }
    
            // check to see if it belongs to the executable in question or not:
            // // Assumption that the exe is always the first module loaded. Is this the same for windows?
            // // Is this always true for linux?
            if (((unsigned long)curr_addr < module_array[0].start)  
            || ((unsigned long) curr_addr > module_array[0].end)){
                /*
                if (DEBUG){
                    dr_printf("Lib bb found! Ignoring. (f:0x%08lx, l:0x%08lx)\n",bb_first_addr,bb_last_addr);
                }    
                */
                //#! make this better TODO
                //return DR_EMIT_DEFAULT;
            } 
            
            if (DEBUG){
                dr_printf("Good bb found! (f:0x%08lx, l:0x%08lx)\n",bb_first_addr,bb_last_addr);
            }
            // prev_bb_addr is going to have to be callback-local-storage... :/ #!TODO 
            dr_insert_clean_call(drcontext, bb, instr, (void *)hash_ops, false, 7, 
                                OPND_CREATE_INTPTR(bb_first_addr), 
                                OPND_CREATE_INTPTR(bb_last_addr),
                                OPND_CREATE_INTPTR(&prev_bb_addr),
                                OPND_CREATE_INTPTR(&bbxor_hashtable),
                                OPND_CREATE_INTPTR(&bbtrace_bitmap),
                                OPND_CREATE_INTPTR(seen_table),
                                OPND_CREATE_INT64(module_array[0].start)); 
            // dr_mutex_lock(bb_count_lock);
            // bb_count++;
            // dr_mutex_unlock(bb_count_lock);
        }
    } else if (bbtrace_flag == TRUE && curr_addr == bb_first_addr) {
            // for baseline, we add regardless if in our exe or another module.
            unsigned long key = ((unsigned long)bb_first_addr^(unsigned long)bb_last_addr); 
             
            unsigned long *value = hashtable_lookup(&bbtrace_bitmap,(void *)key); 
            if (value == NULL){
                
                if (DEBUG){
                    dr_printf("Inserting new bb baseline op: 0x%lx\n",bb_first_addr);
                }
                dr_insert_clean_call(drcontext, bb, instr, (void *)baseline_hash_ops, false, 3, 
                                    OPND_CREATE_INTPTR(bb_first_addr), 
                                    OPND_CREATE_INTPTR(bb_last_addr),
                                    OPND_CREATE_INTPTR(&bbtrace_bitmap));
            }
    } else {
        //When would this occur?

    }  

    return DR_EMIT_DEFAULT;
}

static void hash_ops_del(void){
   dr_nonheap_free(hash_ops,page_size); 
}

// This call is inserted at the beginnning of all basic blocks.
static void baseline_hash_ops(app_pc addr, app_pc last_addr, hashtable_t *bbtrace_bitmap){

    void *drcontext = dr_get_current_drcontext();
    char msg[256]; 

    unsigned long key = 0x0;
    unsigned long *value;
    unsigned long *init; 

    
    dr_mutex_lock(hash_lock);

    key = ((unsigned long)addr^(unsigned long)last_addr); 

    value = hashtable_lookup(bbtrace_bitmap,(void *)key); 
    
    if (value == NULL){
    
        //dr_printf("New BB to baseline! 0x%lx\n",key);
        init = dr_global_alloc(sizeof(unsigned long));
        if (init == NULL){
            dr_printf("[x.x] OOM! Alloc count=0x%lx\n",alloc_count);
            DR_ASSERT(false);
        } else {
            alloc_count++;
        }
        
        *init = 0x1;
        hashtable_add(bbtrace_bitmap,(void *)key,init);
        //dr_snprintf(msg,sizeof(msg),"(0x%lx) \n",value,"Baseline (new bb)",key);
        //dr_printf("(0x%lx) Baseline (new transition)\n",key);
        //send(comms_socket,msg,strlen(msg),0x0);
    }     
    dr_mutex_unlock(hash_lock);
}


// This call is inserted at the beginnning of all basic blocks.
static void hash_ops(app_pc addr, app_pc last_addr, app_pc *prev_bb_addr, 
                    hashtable_t *bbxor_hashtable, hashtable_t *bbtrace_hashtable, 
                    void *seen_table, unsigned long baseaddr){

    void *drcontext = dr_get_current_drcontext();
    char msg[256]; 

    unsigned long key = 0x0;
    unsigned long *value;
    unsigned long *init; 
    int ret = 0x0;
    byte q[0x9] = "\x80\x00\x00\x00\x00";

    dr_mutex_lock(hash_lock);
        
    // If the basic block is inside the baseline hashtable, we don't really care.
    value = hashtable_lookup(bbtrace_hashtable,(void *)addr); 
    if (value != NULL){
        dr_mutex_unlock(hash_lock);
        return;
    }

    //dr_printf("allocate, seen_table: 0x%lx, magic? 0x%lx\n", seen_table, (long *)seen_table);
    bb_pair *bb = drtable_alloc(seen_table, 1, NULL);
    bb->addr_prev = (unsigned long)last_addr-baseaddr;
    bb->addr_curr = (unsigned long)addr-baseaddr;

    key = (*(unsigned long *)prev_bb_addr) ^ ((unsigned long)addr>>1); 
    value = hashtable_lookup(bbxor_hashtable,(void *)key); 
    if (value != NULL){
        dr_mutex_unlock(hash_lock);
        return; 
    } 
    

    init = dr_global_alloc(sizeof(unsigned long));
    if (init == NULL){
        dr_printf("[x.x] OOM! Alloc count=0x%lx\n",alloc_count);
        DR_ASSERT(false);
    } else {
        alloc_count++;
    }
    
    *init = 0x1;
    hashtable_add(bbtrace_hashtable,(void *)addr,init);
    hashtable_add(bbxor_hashtable,(void *)key,init);

    //dr_snprintf(msg,sizeof(msg),"(0x%lx) %s:0x%lx -> 0x%lx (key:0x%lx)\n",value,"Boop (new transition)",*prev_bb_addr, addr, key);

    //dr_printf("(0x%lx) %s:0x%lx -> 0x%lx (key:0x%lx)\n",value,"Boop (new transition)",*prev_bb_addr, addr, key);
    // queue msg if not already queued.
    if (!queued_flag){
        if (DEBUG){
            dr_printf("(0x%lx) %s:0x%lx -> 0x%lx (key:0x%lx)\n",value,"Boop (new transition)",*prev_bb_addr, addr, key);
            dr_printf("Queue fuzzer msg being sent: 0x%x 0x%x 0x%x\n",q[0],q[4],q[8]);
        }
        
        ret = send(inter_cli_sock,q,0x5,0x0);
        kill(comms_pid,SIGUSR1); 
        queued_flag = true;
        if (DEBUG){ 
            dr_printf("[F.F] Did the queue stuff. (bytes sent: 0x%x)\n",ret);
        }
        //exit(-1); 
    }

    
    dr_mutex_unlock(hash_lock);
    //prev_bb_addr => last bb's last instr
    // last addr => last instr of curr bb.
    *prev_bb_addr = last_addr;
}

//
// Comms_Socket Protocol (tlv)
// [msg_id][length][contents...]
// <msg_id>   - 1 byte 
// <length>   - 4 bytes
// <contents> - <length> bytes 

// ~~~~~~~ Start unix socket wrapper functions ~~~~~~~~ 
// The feedback portion of the code does not directly talk
// the the fuzzer via the comms_socket, there is a unix 
// socket pair inbetween. During setup, we fork() to have
// a child process handle the direct fuzzer comms such that
// the child can handle recieving of data. Thus, we can 
// launch an interrupt signal (SIGUSR1) to notify the 
// feedback portion that there's data to be read/parsed.
//
// The entire reason for this extra functionality is so that
// we don't have to end up polling/doing extra inside of each
// basic block (would would undoubtly add severe costs to runtime) 

// This function is the network handler child's SIGUSR1 Handler.
// really good example: http://dynamorio.org/docs/samples/signal.c
static void fuzzer_signal_handler(int sig){
    byte signal_buff[MAX_MSG_LEN+8];
    byte * signal_ptr = signal_buff;
    ssize_t msg_len; 
    dr_printf("[n_n] Fuzzer signal handler recv! sig:%d\n",sig);

    if (sig == SIGPIPE){ 
        // 
        //* how do we know which socket is raising SIGPIPE? */
        // if there wasn't a successful heartbeat write/read, reconnect.
        // do_fuzzer_handshake();        

    } else if (sig == SIGUSR1 || sig == SIGUSR2) {
        msg_len = recv(inter_comms_sock,signal_ptr,0x5,0x0); // msg should be on wire 
        //dr_printf("fuzzer_signal_handler SIGUSR1 got %d bytes\n",msg_len);

        if (msg_len == 5){  
            fuzzer_msg fmsg;
            fmsg.type = *signal_ptr;                                     //  1     4   <len>
            fmsg.length = *((unsigned int *)(signal_ptr+1));              //[type][len][contents] 
            //dr_printf("%s[n~n] NetworkHandler=>Fuzzer: 0x%x, len:%d\n%s",PURPLE,fmsg.type,fmsg.length,CLEAR);

            if (fmsg.length > 0x0 && fmsg.length < (MAX_MSG_LEN-8)){
                msg_len += recv(inter_comms_sock,signal_ptr+5,fmsg.length,0x0); // msg should be on wire, if any 
            }
            
            if (msg_len > -1 &&  msg_len == (fmsg.length-5)){ 
                //dr_printf("%sSending to fuzzer (sigHandle): 0x%x (%d bytes)\n%s",PURPLE,*signal_ptr,msg_len,CLEAR); 
                msg_len = send(fuzzer_socket,signal_ptr,fmsg.length+5,0x0); 
            } else { 
                //dr_printf("[?.?] Incomplete data from intercomms socket?\n");
            }

            if (msg_len == -1){
                dr_color_printf("[O.O] NetworkHandler=>Fuzzer failed!!!\n",RED);
                do_fuzzer_handshake();
                //kill(comms_pid,SIGKILL); 
            } else {
                dr_printf("[^_^] Sent 0x%x bytes!\n",msg_len);
                //#!exit(-1);
            }         
            //return DR_SIGNAL_SUPPRESS;
            
        } else {
            dr_printf("Signal but no msg... :(\n");
            //return DR_SIGNAL_SUPPRESS;
        }
    } else if (sig == SIGINT) {
        dr_printf("[F.F] Recieved Ctrl+C. Exiting!\n");
        feedback_flag = false;
        //return DR_SIGNAL_DELIVER;
    }

}


// This is the Feedback's signal handler.
static dr_signal_action_t feedback_signal_handler(void *drcontext, dr_siginfo_t *info){
    int msg_len;
    byte op_len[5]; 

    if (info->sig == SIGUSR2) {
        // SIGUSR2 handler notifies the Feedback thread that there's
        // data on the unix socket to be read and handled. 
        //dr_color_printf("[F.F] SIGUSR2 heard by Feedback\n",CYAN);
        //dr_printf("0x%x 0x%x 0x%x 0x%x 0x%x\n",op_len[0],op_len[1],op_len[2],op_len[3],op_len[4]);
        msg_len = recv(inter_cli_sock,&op_len,0x5,0x0);  
        
        if (msg_len >= 5){ 
            byte opcode = op_len[0];
            int len = op_len[1];
            if (DEBUG){
                dr_printf("[^_^] Feedback recved data!(len:0x%x)\n",msg_len);
                dr_printf("0x%x 0x%x 0x%x 0x%x 0x%x\n",op_len[0],op_len[1],op_len[2],op_len[3],op_len[4]);
                dr_printf("Opcode: 0x%x, len: 0x%x\n",opcode,len); 
            }
            // dr_printf("[>_>] First 12 bytes: 0x%x 0x%x 0x%x 0x%x\n",*(signal_buff),*(signal_buff+1),*(signal_buff+2),*(signal_buff+3));

            if (len < 0x0 || len >= MAX_MSG_LEN){
                dr_printf("[>.>] Invalid length given:0x%x\n",len);
                return DR_SIGNAL_SUPPRESS;
            }

            if (len > 0x0){
                byte *signal_buff = (byte *)dr_global_alloc(len);

                if (signal_buff == NULL){ 
                    dr_printf("Could not allocate 0x%x bytes\n",len);
                    return DR_SIGNAL_SUPPRESS;
                } else {
                    send(inter_cli_sock,"fin\0",4, 0x0);
                    dr_printf("[^_^] Size 0x%x buff alloc'ed at 0x%lx\n",len,signal_buff);
                }

                msg_len = recv(inter_cli_sock,op_len,len,0x0);  
                if (msg_len != len){
                    dr_printf("size mismatch. len:0x%x,actual input:0x%x\n",len,msg_len);
                    send(inter_cli_sock,"fin\0",4, 0x0);
                    return DR_SIGNAL_SUPPRESS;
                }

                handle_fuzzer_msg(signal_buff);
            } else {
                handle_fuzzer_msg(op_len);                 
            }

            //
            if (DEBUG){
                dr_printf("[f.f] sending fin from feedback=>network_handler\n"); 
            }
            send(inter_cli_sock,"fin\0",4, 0x0);
        }
        return DR_SIGNAL_SUPPRESS;

    } else if (info->sig == SIGUSR1){
        dr_printf("[F_F] Feedback still running!\n");
        return DR_SIGNAL_SUPPRESS;

    } else if (info->sig == SIGSEGV) {
        // Crash detected, notify the fuzzer.
        byte crash[0x10] = "\x8F\x00\x00\x00\x04";
        send(inter_cli_sock,crash,0x5,0x0);
        dr_color_printf("[F.F] Feedback detected crash!\n",RED);
        // Restart the process...?    
    } else if (info->sig == SIGABRT) {
        // Crash detected, notify the fuzzer.
        byte crash[0x10] = "\x8F\x00\x00\x00\x04";
        send(inter_cli_sock,crash,0x5,0x0);
        dr_color_printf("[F.F] Feedback detected crash!\n",RED);
    } else if (info->sig == SIGPIPE) {
        // odds are the remote fuzzer socket died, try connecting again 
        if (DEBUG){
            dr_printf("[F~F] Sigpipe \n");
        }
    } else if (info->sig == SIGINT){
        // ctrl-c... 
        if (fork_flag == false){
            dr_printf("[F.F] Killing fork loop\n");
            fork_flag = true; 
        }

    } else {
        dr_printf("[F.F] Got signal:(%d)\n",info->sig);
    }
    return DR_SIGNAL_DELIVER;
}

//
// ~~~~~~~ Start outbound socket message definitions and utilities ~~~~~~~
//--------------------------------------------------------------------
// 0x80 | ORelay->Fuzzer    | Gluttony: Yo, that testcase was cool. 
//      | (no contents)     | Fuzzer: Okay, saving it and adding to the queue.
// 
// 0x84 | ORelay->Fuzzer    | Gluttony: Sending fuzzer my stuff.
//      | (no contents)     | 
//
// 0x8F | ORelay->Fuzzer    | Gluttony: prog pooped/detected a crash, save that. 
//      | (no contents)     | Fuzzer: Okay, saving it. 
//--------------------------------------------------------------------
//

// Used by feedback to send data to the ORelay intermediary.
static size_t relay_fuzzer_msg(byte msgnum, unsigned int msg_len, byte *contents){
    if (DEBUG){
        dr_printf("Entered relay_fuzzer_msg 0x%x,%d,0x%lx\n",msgnum,msg_len,contents);
    }
    int ret = 0x0;
    int retry = 0x0;
    
    if ((msgnum == 0x0) || (msg_len >= MAX_MSG_LEN) || (msg_len < MIN_MSG_LEN)){
        dr_color_printf("Trying to send malformd msg, abort!\n",RED);
        dr_printf("ARGS | 0x%x | 0x%lx | 0x%x\n");
        return -1;
    }

    byte *msg = (byte *)dr_global_alloc(msg_len);
    memset(msg,0,msg_len);

    if (msg == NULL){
        dr_printf("%s[x.x] OOM! alloc_size:0x%lx\n%s",RED,msg_len,CLEAR);
        return -1;
    }
    
    memset(msg,0x0,msg_len);
    *msg = msgnum; 
    *(msg+0x1) = msg_len;

    if ((msg_len > 5) && (contents != NULL)){
        memcpy((msg+0x5),contents,msg_len);
    }
    
    ret = send(inter_cli_sock,msg,msg_len,0x0);
    if (ret < 0){
        return ret;
    }

    kill(comms_pid,SIGUSR2); 

    while (ret = recv(inter_cli_sock,msg,0x4,0x0) < 0){
        if (strncmp(msg,"fin\0",0x3) == 0){
            break;
        } 
        dr_printf("relay_fuzzer_msg got bad/no fin\n");
        retry++;
        sleep(2);
        if (retry == 4){
            return -1;
        }
    }

    dr_global_free(msg,msg_len);
    return ret;
}


// ORelay => Fuzzer
static void sendmsg_addqueue(void){
    byte msg_num = 0x80; 
    unsigned int msg_len = 0x5;
    byte *contents = NULL;

    if (relay_fuzzer_msg(msg_num,msg_len,contents) == -1){
        dr_printf("%sCould not send msg(0x%x,0x%x,0x%x)%s\n",RED,msg_num,msg_len,contents);
    } else {
       // dr_printf("%sSent msg(0x%x,0x%x,0x%x)%s\n",PURPLE,msg_num,msg_len,contents);
    }
}

// ORelay => Fuzzer
static void sendmsg_crashnoti(void){
    byte msg_num = 0x84; 
    unsigned int msg_len = 0x5;
    byte *contents = NULL;

    if (relay_fuzzer_msg(msg_num,msg_len,contents) == -1){
        dr_printf("%sCould not send msg(0x%x,0x%x,0x%x)%s\n",RED,msg_num,msg_len,contents);
    }
}

// ORelay => Fuzzer 
// Called on close to update the fuzzer of what all has happened.
static void sendmsg_sessionstats(void){
    byte msg_num = 0x8F; 
    char *contents = "herpderp\n";
    char msg[256];
    unsigned int msg_len = strlen(contents)+0x5;

    //TODO: Actually send useful stuff here
    if (relay_fuzzer_msg(msg_num,msg_len,contents) == -1){
        dr_printf("%sCould not send msg(0x%x,0x%x,0x%x)%s\n",RED,msg_num,msg_len,contents);
    }
}

// assuming ipv4, sorry.
static int connect_feedback_socket(const char *ipv4_addr,unsigned short port){

    struct sockaddr_in dst_addr;
    unsigned int comms_socket;
    char msg[256];
    
    comms_socket = socket(AF_INET,SOCK_STREAM,0);
    if (comms_socket == -1){
        dr_color_printf("[x.x] Unable to init socket, abort\n",RED);
        exit(-1);
    }

    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port  = ((port & 0xff) << 8) + ((port & 0xff00) >> 0x8);
    if (inet_aton(ipv4_addr,(struct in_addr *)&dst_addr.sin_addr) != 1){
        dr_color_printf("[x.x] Invalid IP provided, abort\n",RED);
        exit(-1);
    }

    if (setsockopt(comms_socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0){
        dr_color_printf("[xox] fuzzer socket timeout not set, aborting!\n",RED);
        dr_printf("Error: %s\n",strerror(errno));
        close(fuzzer_socket);
        exit(-1);
    } 

    size_t prevlen = 0;
    while (connect(comms_socket,(struct sockaddr *)&dst_addr,sizeof(dst_addr)) < 0){
        if (prevlen == 0){
            prevlen = snprintf(msg,sizeof(msg),"%s[x.x] Fuzzer socket status: DISCONNECTED (%s:%d)!\n%s",RED,ipv4_addr,port,CLEAR);
            dr_printf(msg);
        }
        sleep(2);   
        /* backspaces no work? [;-;]
        memset(msg,0x8,prevlen);
        dr_printf(msg);
        */
    }

    dr_printf("%s[^_^] Socket connected to endpoint %s:%hu%s\n",GREEN,ipv4_addr,port,CLEAR);

    return comms_socket;
}

#define SOCKPATH "interproc_sock"
static int init_interproc_socket(bool bindflag){
    byte j;
    int i;
    unsigned int interproc_sock;
    interproc_sock = socket(AF_UNIX,SOCK_STREAM,0x0);

    if (interproc_sock == -1){
        dr_color_printf("[x.x] Unable to interproc socket, abort\n",RED);
        exit(-1);
    }
    
    memset(&unixaddr,0,sizeof(unixaddr));
    unixaddr.sun_family = AF_UNIX;
    strcpy(unixaddr.sun_path,SOCKPATH);

    // Parent thread (Feedback)
    if (bindflag){
        unlink(SOCKPATH);
        if (bind(interproc_sock,(struct sockaddr*)&unixaddr,sizeof(unixaddr)) == -1){
            dr_color_printf("[x.x] Unable to bind to interproc! Abort!\n",RED);
            exit(-1);
        } 
        listen(interproc_sock,1);
        inter_cli_sock = accept(interproc_sock,NULL,NULL);
        //dr_printf("[^_^] interproc_cli_sock : %d, interproc_sock : %d\n",inter_cli_sock, interproc_sock);
        return interproc_sock;

    } else { //child
        if (connect(interproc_sock,(struct sockaddr*)&unixaddr,sizeof(unixaddr)) == -1){
            dr_color_printf("[x.x] Unable to connect to interproc! Abort!\n",RED);
            exit(-1);
        } 

        dr_printf("[^_^] Interproc connected! (fd:%d) \n",interproc_sock); 
        return interproc_sock;
    }
}



static int do_fuzzer_handshake(void){
    char init_msg[8] = "boop";
    char init_resp[8];

    memset(init_resp,0,sizeof(init_resp));

    fuzzer_socket = connect_feedback_socket(fuzzer_addr,fuzzer_port);
    if (fuzzer_socket == -1){
        dr_color_printf("[xox] Fuzzer socket not connected.\n",RED);
        return -1;
    }

    if (DEBUG){
        dr_printf("Sending init_msg %s",init_msg);
    }

    if (send(fuzzer_socket,&init_msg,strlen(init_msg),0x0) != 0x4){
        dr_color_printf("[xox] fuzzer socket can't send! aborting!\n",RED);
        close(fuzzer_socket);
        return -1;
    }

    if (DEBUG){
        dr_printf("do_fuzzer_handshake recv\n");
    }

    if (recv(fuzzer_socket,&init_resp,4,0x0) < 0x4){
        dr_color_printf("[xox] fuzzer socket can't recv! aborting!\n",RED);
        close(fuzzer_socket);
        return -1;
    }

    if (strncmp(init_resp,"doop",0x4) != 0){
        dr_color_printf("[xox] Bad init msg, aborting!\n",RED);
        dr_printf("Bad msg: %s\n",init_resp);
        close(fuzzer_socket);
        return -1;
    }
 
    dr_color_printf("[!-!] Fuzzer/Comms handshake successful!\n",GREEN);
    return 0;
}

/// MAX_MSG_LEN 0x00100000
/// MIN_MSG_LEN 0x5
static void *fuzzer_comms(void){
    //dr_color_printf("[^_^] Entered fuzzer_comms thread!\n",GREEN);
    int recv_msg_len;
    fuzzer_msg fmsg;
    fmsg.msg = (byte *)dr_global_alloc(MAX_MSG_LEN + 8);
    byte * outbound_buff = (byte *)dr_global_alloc(MAX_MSG_LEN + 8);
    
    int handshake_status = do_fuzzer_handshake();

    while (handshake_status == -1){
        sleep(1); 
        handshake_status = do_fuzzer_handshake(); 
    } 
    
    byte keepalive_msg[0x5] = "\xF0\x00\x00\x00\x00";
    byte op_len[0x5];
    byte *op_len_ptr = op_len;

    ssize_t intercomms_size = 0;
    struct timeval tv;
    tv.tv_sec = 1;  // Network Handler recv timeout 
    tv.tv_usec = 0;
    setsockopt(fuzzer_socket, SOL_SOCKET, SO_RCVTIMEO,(struct timeval *)&tv,sizeof(struct timeval));
    setsockopt(inter_comms_sock, SOL_SOCKET, SO_RCVTIMEO,(struct timeval *)&tv,sizeof(struct timeval));

    // main processing loop.
    // need some sort of logging since all stdoutput (and DR_ASSERT) seem not working...)
    while (true){
        if (DEBUG){
            dr_printf("[N.N] Network handler waiting for packets\n");
        }
        recv_msg_len = recv(fuzzer_socket,op_len_ptr,0x5,0x0);         
        if (DEBUG && recv_msg_len > 0){
            dr_printf("[N.N] Network handler got packets %d bytes\n",recv_msg_len);
        }

        if (recv_msg_len == 0){ // socket closed => reconnect
            sleep(3);
            dr_printf("Attempting to reconnect to feedback socket\n");
            do_fuzzer_handshake();
            setsockopt(fuzzer_socket, SOL_SOCKET, SO_RCVTIMEO,(struct timeval *)&tv,sizeof(struct timeval));
        } else if (recv_msg_len == -1){
            if (errno == EINTR){ // interrupted by signal during recv, w/e, restart loop.
                continue;
            }
        }
    
        
        
        // This recv's messages from the outside fuzzer.
        if (recv_msg_len == 0x5){
            fmsg.type = *op_len_ptr;                               //  1     4   <len>
            fmsg.length = *((unsigned int *)(op_len_ptr+1));         //[type][len][contents] 

            if (fmsg.length > 0x0 && fmsg.length < MAX_MSG_LEN){
                recv_msg_len = recv(fuzzer_socket,fmsg.msg,fmsg.length,0x0);         
            } else {
                recv_msg_len = 0;
            }

            if (fmsg.length != recv_msg_len || recv_msg_len < 0x0){  
                dr_printf("%s[>_>] Bad msg len given, ignoring (#byts:0x%x,<len>:0x%x)\n%s",RED,recv_msg_len,fmsg.length,CLEAR); 
                dr_printf("0x%x...\n",*(long *)fmsg.msg);
                continue;
            }
            
            *(fmsg.msg) = fmsg.type; 
            *(fmsg.msg+0x1) = fmsg.length;
            //dr_printf("t: 0x%x, l: 0x%x v: 0x%x\n",fmsg.type, fmsg.length, *fmsg.msg);
            
            if (DEBUG){
                dr_printf("%s[n-n] Notify pid %d, MsgLen:%d\n%s",ORANGE,comms_pid,fmsg.length,CLEAR);
            }

            //#! THis is the poopy code. Signal handler fine, but when we actually don't use a signal,
            // srsly, it's really bad. 
            send(inter_comms_sock,fmsg.msg,fmsg.length+5,0x0);
            kill(comms_pid,SIGUSR2); // notifies feedback that there's a message.
            int tmp;
        }

        // theres a chance that there's something else on the wire besides a 'fin\0' at this point. 
        // Wait till fin before passing anything else to feedback.
        intercomms_size = recv(inter_comms_sock,outbound_buff,MAX_MSG_LEN,0x0);  
        char * buff_loc = strstr(outbound_buff,"fin\0");
        if (intercomms_size == 4 && buff_loc == (char *)outbound_buff){
            continue;
        }
        unsigned int retry_count = 0;
        unsigned int send_len = 0;

        while ((intercomms_size > 0) && (buff_loc == 0)){
            //dr_printf("got intersock stuff: len(%d), 0x%lx\n",intercomms_size,*(int *)outbound_buff);
            // its not finding the fin...
            //dr_printf("Entered fin loop\n");
            if (intercomms_size > 0){
                dr_printf("%sSending to fuzzer: 0x%x (%d bytes)\n%s",PURPLE,*outbound_buff,intercomms_size,CLEAR); 
                send_len = send(fuzzer_socket,outbound_buff,intercomms_size,0x0); 
                 
                if (send_len < 0){
                    dr_printf("Attempting to reconnect to feedback socket\n");
                    do_fuzzer_handshake();
                    setsockopt(fuzzer_socket, SOL_SOCKET, SO_RCVTIMEO,(struct timeval *)&tv,sizeof(struct timeval));
                    sleep(3);    
                }
            }
            // if send fails, socket closed => reconnect.
            intercomms_size = recv(inter_comms_sock,outbound_buff,MAX_MSG_LEN,0x0);  
            if (intercomms_size > -1){  
                buff_loc = strstr(outbound_buff,"fin\0");
            }
            if (retry_count++ > 10){
                break;
            }
        }       

        if (intercomms_size > 0){
            dr_printf("%sSending to fuzzer: 0x%x (%d bytes)\n%s",PURPLE,*outbound_buff,intercomms_size,CLEAR); 
            send(fuzzer_socket,outbound_buff,intercomms_size,0x0); 
        }
        
    }
    
    DR_ASSERT(false);
    dr_color_printf("Exiting fuzzer_comms thread!\n",GREEN);
    close(fuzzer_socket);
}


// ~~~~~~ Start Inbound socket message definitions and utilities ~~~~~~~~
//msg_id| Message Direction | Explination
//--------------------------------------------------------------------
// 0x1  | Fuzzer->ORelay    | Fuzzer: Sending first/unfuzzed testcase. 
//      | (no contents)     | Gluttony: Get baseline for BB trace 
//
// 0x2  | Fuzzer->ORelay    | Resume previous session instead of new. 
//      | contents: sess_id |  
//
// 0x3  | Fuzzer->ORelay    | Fuzzer: Sending fuzzed test case.
//      | (no contents)     | Gluttony: Check for new paths/Significant increases  
//
// 0x4  | Fuzzer->ORelay    | Fuzzer: Send me your stuff, then shutdown. 
//      | contents: stuff   | 
//
// 0x5  | 
//
// 0x6  | Start Feedback
//
// ?opcode to shift the persistant hashtable to the baseline hashtable?


static void *get_msg_handler(byte msg_num){
    switch (msg_num){
        case 0x1:
            return &init_new_trace;
        case 0x2:
            return &init_previous_trace;
        case 0x3:
            return &fuzz_case;
        case 0x4:
            return &end_of_fuzz_case;
        case 0x5:
            return &send_results_n_cleanup; 
        case 0x6: 
            return &start_feedback;
        case 0x7:
            return &stop_feedback;
        case 0x8:
            return &keepalive;
    default:
        return NULL; 
    }
}

// Checking of size/content len vs lenght given occurs in the comms_thread
// that calls this function.
static int handle_fuzzer_msg(byte *msg){
    if (msg == 0x0 || *msg == 0x0){
        return -1;
    } 
    //dr_printf("[^_^] Entered handle_fuzzer_msg! msg:0x%08lx\n",*msg);

    fuzzer_msg fmsg; 
    fmsg.type = *msg;            //[type][len][contents] 
    fmsg.length = *(msg+1);

    /*
        dr_printf("fmsg->length:0x%x\n",fmsg.length);
        dr_printf("fmsg->length:0x%x\n",*(msg+1));
    */

    if (fmsg.length > 0x0){
        fmsg.msg = msg+0x5; 
    } else {
        fmsg.msg = msg+1; // just point it towards null bytes. 
    }

    
    if (DEBUG) {
        dr_printf("[^_^] Got unix from comms: 0x%x, len:%d, msg:0x%08lx\n",fmsg.type,fmsg.length,*fmsg.msg);
        dr_printf("[>_>] First 12 bytes: 0x%x 0x%x 0x%x 0x%x\n",*(interproc_buff),*(interproc_buff+1),*(interproc_buff+2),*(interproc_buff+3));
    }

    if (fmsg.type == 0x0){
        dr_color_printf("NULL msg recieved, ignoring.\n",YELLOW);
        return -1;
    }

    msg_handler = get_msg_handler(fmsg.type);

    if (msg_handler == NULL){
        dr_printf("%sBAD msg recieved (0x%x), ignoring.\n%s",YELLOW,fmsg,CLEAR);
        return -1;
    }

    msg_handler(fmsg.length,fmsg.msg);
}

// These callbacks are only hit by the parent thread.
// static hashtable_t bbxor_hashtable;

static int heartbeat(unsigned int len, byte *msg){
    if (DEBUG){
        dr_printf("[D.D] Entered Heartbeat\n"); 
    }

    if (len == 0x0 && *(unsigned int *)msg == 0x0){
        return 0; 
    }
    return -1;
    
}


// Initializes the BB tracing. 
// Starts from scratch with hashtable.  
static void init_new_trace(unsigned int len,byte *msg){
    // Clears out the current persistant hash table, if any.
    // Waits "start_feedback" message before sending updates 
    // to the fuzzer.   
    if (DEBUG){
        dr_printf("[D.D] Entered init_new\n");
    }

    if (feedback_flag == true){     
        hashtable_clear(&bbxor_hashtable);         
        feedback_flag = false;
    }

    // start calibrating to find the start point of our BB's
    // In order to minimize size, only start tracing once we 
    // recieve this packet.
    bbtrace_flag = true;
    sendmsg_addqueue();
}

// Initializes BB tracing.
// Attempt to load up a persitant hashtable.
// If ont found, then use init_new_trace instead.
static void init_previous_trace(unsigned int len,byte *msg){
    if (DEBUG){
        dr_printf("[D.D] Entered init_prev\n");
    }
    // not entirely sure if this can be done entirely with the "persistant" feature of hashtables/etc.
    // might need to export to some sort of file format.
}

static void fuzz_case(unsigned int len,byte *msg){
    if (DEBUG){
        dr_printf("[D.D] Entered fuzz_case: %d\n",*((unsigned int *)msg));
    }
    queued_flag   = FALSE;
    bbtrace_flag = FALSE;
    feedback_flag = TRUE;
    if (len != 0x0){   
        dr_printf("[F_F] bad length on fuzz_case packet!(0x%x), expected: 0x0\n",len);   
        return;
    }
}

/* Do we need this?? */
static void end_of_fuzz_case(unsigned int len,byte *msg){
    if (DEBUG){
        dr_printf("[D.D] Entered eof_fuzzcase\n");
    }
    // What do I want to do here?
    // Clear out the perRun hashtable collecting?
    // What purpose does it serve?
        // To keep track of the iterations of each basic block.
        // The Main hashtable keeps track of the max. 
        // What if we hit something that gets less iterations? is that necessarily worse? Should we also keep track of those?
    // We should evaluate the given case at this point by comparing with the persistant table. 

          
}

static void send_results_n_cleanup(unsigned int len,byte *msg){
    void *drcontext = dr_get_current_drcontext();
    int fd; 
    if (DEBUG){
        dr_printf("[D.D] Entered send_results_n_cleanup\n");
    }
    // What do I want here?
    // We send a summary of the persistant bitmap's data. 
    //hashtable_persist(

}

// So we can limit the size of the hashtable/tracking.
static void start_feedback(unsigned int len, byte *msg){
    if (DEBUG){
        dr_printf("[D.D] Entered start_feedback\n");
    }
    if (feedback_flag == FALSE){
        feedback_flag = TRUE;
        bbtrace_flag = FALSE;
    }
}

static void stop_feedback(unsigned int len, byte *msg){
    if (DEBUG){
        dr_printf("[D.D] Entered stop_feedback\n");
    }
    feedback_flag = false;
}


static void keepalive(unsigned int len, byte *msg){
    if (DEBUG){
        dr_printf("[D.D] Entered keepalive()\n");
    }
    keepalive_timer = 4; 
}

//#!TODO: add coverage cases for ID'ing/verifying a specific fuzz case
static void start_coverage_trace(unsigned int len, byte *msg){

}
static void stop_coverage_trace(unsigned int len, byte *msg){

}


static int dumb_argparse(int argc, const char * argv[], 
                  void *ret_val, ret_type type, unsigned int ret_len,
                  char *target_arg){ 

    int i = 0; 

    if (argc == 0 || argv == NULL){
        return -1;
    }
                
    unsigned int target_len = strlen(target_arg);    
    if (!target_len){
        dr_printf("[>_>] Invalid commandline args given\n");
        DR_ASSERT(false);
    }

    if (!type){
        dr_printf("[>_>] Invalid type provided\n");
        DR_ASSERT(false);
    }

    for (i=0; i < argc; i++){
        if (strncmp(target_arg,argv[i],target_len) == 0){
            if (type == BOOL){
                return 0;
            } else {
                if (!ret_val){
                        dr_printf("[>_>] Cannot store ret_val, wtf m8.\n");
                        DR_ASSERT(false);
                }

                if (!ret_len){
                    dr_printf("[>_>] Invalid retlen.\n");
                    DR_ASSERT(false);
                }
                if (i == argc){
                    dr_printf("Value required for option %s\n",target_arg);
                    DR_ASSERT(false);
                }  
               
                if (type == STR){
                    unsigned int val_len = strlen(argv[i+1]);

                    if (val_len == 0){
                        dr_printf("Value required for option %s\n",target_arg);
                        DR_ASSERT(false);
                    }
    
                    if (val_len > ret_len){
                        dr_printf("[>_>] Insufficient space for option value (%s) [%d|%d], booooo~\n",
                                                                          target_arg,val_len,ret_len);     
                        DR_ASSERT(false);
                    }
                    strncpy(ret_val,argv[i+1],val_len);

                } else if (type == INT || type == SHORT || type == LONG){
                    char **invalid = NULL;
                    long int tmp_value = strtol(argv[i+1],invalid,0);
                    if (tmp_value == LONG_MIN || tmp_value == LONG_MAX){
                        dr_printf("[>_>] Option %s underflow||overflow. c'mon now.\n",target_arg);  
                        DR_ASSERT(false);
                    }
                    if (invalid != NULL){
                        dr_printf("[>_>] Invalid INT value %c in option %s\n",*invalid,target_arg);
                        DR_ASSERT(false);
                    }
    
                    memset(ret_val,0x0,sizeof(ret_val));
                    if (type == INT){
                        int value = (int)tmp_value;
                        memcpy(ret_val,&value,sizeof(value));
                    } else if (type == SHORT) {
                        short value = (short)tmp_value;
                        memcpy(ret_val,&value,sizeof(value));
                    } else if (type == LONG) {
                        long value = tmp_value;
                        memcpy(ret_val,&value,sizeof(value));
                    } else if (type == BYTE) {
                        char value = (char)tmp_value;
                        memcpy(ret_val,&value,sizeof(value));
                    } 
                    

                    return 0;
                } 

            } 
            // option == switch, we good.
            return 0;
        }
    }
    // option just wasn't found ¯\_(ツ)_/¯
    return -1;
}


static bool syscall_connect_filter(void *drcontext, int sysnum){
    dr_printf("[D.D] entered sysall_filter(tid0x%lx): %d\n",dr_get_thread_id(drcontext),sysnum); 
    if (DEBUG){
        dr_printf("[D.D] entered sysall_filter(tid0x%lx): %d\n",dr_get_thread_id(drcontext),sysnum); 
    }
    if (sysnum & (SYS_connect | SYS_socket | SYS_accept | SYS_open | SYS_sendmsg
                | SYS_read |SYS_clone))
    {
        return true;
    } else {
        return false;
    }
}

// We use this filtering everything except network connects.
// (i.e. ignore unix sockets) 
static bool syscall_connect_cb(void *drcontext, int sysnum){
    /*
    Syscalls we care about:
    41  sys_socket(int family,int type,int protocol);     
    42  sys_connect(int fd,struct sockaddr *uservaddr, int addrlen); 
    43  sys_accept(int fd,struct sockaddr *upeer_sockaddr, int *upeer_addrlen); 
    */
    byte *p1 = (byte *) dr_syscall_get_param(drcontext, 0);
    byte *p2 = (byte *) dr_syscall_get_param(drcontext, 1);
    byte *p3 = (byte *) dr_syscall_get_param(drcontext, 2);

    // clone(child_stack=0x7fa5d6d0ddf0, 
    // flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, 
    // parent_tidptr=0x7fa5d6d0e9d0,    
    // tls=0x7fa5d6d0e700, 
    // child_tidptr=0x7fa5d6d0e9d0) = 11052 

    if (sysnum == SYS_connect){
        char addr[20] = "";
        char ip_addr[20] = "";
        char port[8] = "";
        if (dr_safe_read(p2,16,addr,NULL)){

        //dr_snprintf(msg,sizeof(msg),"(0x%lx) \n",value,"Baseline (new bb)",key);
            dr_snprintf(ip_addr,16,"%d.%d.%d.%d",addr[4],addr[5],addr[6],addr[7]);
            dr_snprintf(port,5,"%hu",(addr[2]<<8)+addr[3]);
            
            if (*(short *)addr == 2){ //af_inet
                dr_printf("[>.>] Connect(0x%lx,0x%lx,0x%lx)\n",p1,p2,p3);
                dr_printf("[___] AF_INET(%s:%s)\n",ip_addr,port);
                dr_printf("Attempting fork!\n"); 
                fork_loop(); 
            }
            
        }    
    } else if (sysnum == SYS_socket){
        if ((long)p1 == 2){ //AF_INET 
            dr_printf("[>.>] AF_INET Socket(0x%lx,0x%lx,0x%lx)\n",p1,p2,p3);
        } else if ((long)p1 == 2){ //AF_INET6 
            dr_printf("[>.>] AF_INET6 Socket(0x%lx,0x%lx,0x%lx)\n",p1,p2,p3);
        }
    } else if (sysnum == SYS_accept){
        dr_printf("[>.>] Accept(0x%lx,0x%lx,0x%lx)\n",p1,p2,p3);
    } else if (sysnum == SYS_open){
        char filename[64] = ""; 
        if (dr_safe_read(p1,60,filename,NULL)){
            dr_printf("Open on %s\n",filename);
        }
    } else if (sysnum == SYS_sendmsg){
        dr_printf("sendmsg(fd:%d)\n",p1);
    } else if (sysnum == SYS_read){
        dr_printf("read on fd:%d\n",p1); 
    } else if (sysnum == SYS_clone){
        dr_printf("clone occurring!\n");
    }
    return true; // ret true => passthrough, ret false => stop syscall. 
}


static void fork_loop(){
    pid_t child;
    // begin fork_loop
    while (fork_flag == true){
        dr_printf("[^_^] spawning new!\n");
        child = fork();
        if (child > 0){
            dr_printf("Hope I have dr, lol (parent)\n");
            waitpid(child,NULL,0);
        } else {
            dr_printf("Also hope I have dr, lol (child)\n");
            break;
        }
    }
}



static void event_thread_init(void *drcontext){
    dr_printf("[1.1] New thread spawned!!! (0x%lx)\n",dr_get_thread_id(drcontext));
}

static void event_thread_exit(void *drcontext){
    dr_printf("[1.1] New thread died!!!\n");
}

static void usage(){    
    dr_color_printf("Gluttony Feedback <(^_^)>\n",CYAN);
    dr_printf("usage: drrun\n");
}

