/*
  Copyright 2013 Google LLC All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/*
   american fuzzy lop - fuzzer code
   --------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

*/

#define AFL_MAIN
#include "android-ashmem.h"
#define MESSAGES_TO_STDOUT

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define _FILE_OFFSET_BITS 64

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "hash.h"
#include "chat-llm.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <ctype.h>
#include <fcntl.h>
#include <termios.h>
#include <dlfcn.h>
#include <sched.h>

#include <sys/wait.h>
#include <sys/time.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <sys/capability.h>

#include "aflnet.h"
#include <graphviz/gvc.h>
#include <math.h>

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
#include <sys/sysctl.h>
#endif /* __APPLE__ || __FreeBSD__ || __OpenBSD__ */

/* For systems that have sched_setaffinity; right now just Linux, but one
   can hope... */

#ifdef __linux__
#define HAVE_AFFINITY 1
#endif /* __linux__ */

/* A toggle to export some variables when building as a library. Not very
   useful for the general public. */

#ifdef AFL_LIB
#define EXP_ST
#else
#define EXP_ST static
#endif /* ^AFL_LIB */

/* Lots of globals, but mostly for the status UI and other things where it
   really makes no sense to haul them around as function parameters. */

EXP_ST u8 *in_dir, /* Input directory with test cases  */
    *out_file,     /* File to fuzz, if any             */
    *out_dir,      /* Working & output directory       */
    *sync_dir,     /* Synchronization directory        */
    *sync_id,      /* Fuzzer ID                        */
    *use_banner,   /* Display banner                   */
    *in_bitmap,    /* Input bitmap                     */
    *doc_path,     /* Path to documentation dir        */
    *target_path,  /* Path to target binary            */
    *orig_cmdline; /* Original command line            */

EXP_ST u32 exec_tmout = EXEC_TIMEOUT; /* Configurable exec timeout (ms)   */
static u32 hang_tmout = EXEC_TIMEOUT; /* Timeout used for hang det (ms)   */

EXP_ST u64 mem_limit = MEM_LIMIT; /* Memory cap for child (MB)        */

static u32 stats_update_freq = 1; /* Stats update frequency (execs)   */

EXP_ST u8 skip_deterministic, /* Skip deterministic stages?       */
    force_deterministic,      /* Force deterministic stages?      */
    use_splicing,             /* Recombine input files?           */
    dumb_mode,                /* Run in non-instrumented mode?    */
    score_changed,            /* Scoring for favorites changed?   */
    kill_signal,              /* Signal that killed the child     */
    resuming_fuzz,            /* Resuming an older fuzzing job?   */
    timeout_given,            /* Specific timeout given?          */
    not_on_tty,               /* stdout is not a tty              */
    term_too_small,           /* terminal dimensions too small    */
    uses_asan,                /* Target uses ASAN?                */
    no_forkserver,            /* Disable forkserver?              */
    crash_mode,               /* Crash mode! Yeah!                */
    in_place_resume,          /* Attempt in-place resume?         */
    auto_changed,             /* Auto-generated tokens changed?   */
    no_cpu_meter_red,         /* Feng shui on the status screen   */
    no_arith,                 /* Skip most arithmetic ops         */
    shuffle_queue,            /* Shuffle input queue?             */
    bitmap_changed = 1,       /* Time to update bitmap?           */
    qemu_mode,                /* Running in QEMU mode?            */
    skip_requested,           /* Skip request, via SIGUSR1        */
    run_over10m,              /* Run time over 10 minutes?        */
    persistent_mode,          /* Running in persistent mode?      */
    deferred_mode,            /* Deferred forkserver mode?        */
    fast_cal;                 /* Try to calibrate faster?         */

static s32 out_fd,       /* Persistent fd for out_file       */
    dev_urandom_fd = -1, /* Persistent fd for /dev/urandom   */
    dev_null_fd = -1,    /* Persistent fd for /dev/null      */
    fsrv_ctl_fd,         /* Fork server control pipe (write) */
    fsrv_st_fd;          /* Fork server status pipe (read)   */

static s32 forksrv_pid, /* PID of the fork server           */
    child_pid = -1,     /* PID of the fuzzed program        */
    out_dir_fd = -1;    /* FD of the lock file              */

EXP_ST u8 *trace_bits; /* SHM with instrumentation bitmap  */

EXP_ST u8 virgin_bits[MAP_SIZE], /* Regions yet untouched by fuzzing */
    virgin_tmout[MAP_SIZE],      /* Bits we haven't seen in tmouts   */
    virgin_crash[MAP_SIZE];      /* Bits we haven't seen in crashes  */

static u8 var_bytes[MAP_SIZE]; /* Bytes that appear to be variable */

static s32 shm_id; /* ID of the SHM region             */

static volatile u8 stop_soon, /* Ctrl-C pressed?                  */
    clear_screen = 1,         /* Window resized?                  */
    child_timed_out;          /* Traced process timed out?        */

EXP_ST u32 queued_paths, /* Total number of queued testcases */
    queued_variable,     /* Testcases with variable behavior */
    queued_at_start,     /* Total number of initial inputs   */
    queued_discovered,   /* Items discovered during this run */
    queued_imported,     /* Items imported via -S            */
    queued_favored,      /* Paths deemed favorable           */
    queued_with_cov,     /* Paths with new coverage bytes    */
    pending_not_fuzzed,  /* Queued but not done yet          */
    pending_favored,     /* Pending favored paths            */
    cur_skipped_paths,   /* Abandoned inputs in cur cycle    */
    cur_depth,           /* Current path depth               */
    max_depth,           /* Max path depth                   */
    useless_at_start,    /* Number of useless starting paths */
    var_byte_count,      /* Bitmap bytes with var behavior   */
    current_entry,       /* Current queue entry ID           */
    havoc_div = 1;       /* Cycle count divisor for havoc    */

EXP_ST u64 total_crashes, /* Total number of crashes          */
    unique_crashes,       /* Crashes with unique signatures   */
    total_tmouts,         /* Total number of timeouts         */
    unique_tmouts,        /* Timeouts with unique signatures  */
    unique_hangs,         /* Hangs with unique signatures     */
    total_execs,          /* Total execve() calls             */
    slowest_exec_ms,      /* Slowest testcase non hang in ms  */
    start_time,           /* Unix start time (ms)             */
    last_path_time,       /* Time for most recent path (ms)   */
    last_crash_time,      /* Time for most recent crash (ms)  */
    last_hang_time,       /* Time for most recent hang (ms)   */
    last_crash_execs,     /* Exec counter at last crash       */
    queue_cycle,          /* Queue round counter              */
    cycles_wo_finds,      /* Cycles without any new paths     */
    trim_execs,           /* Execs done to trim input files   */
    bytes_trim_in,        /* Bytes coming into the trimmer    */
    bytes_trim_out,       /* Bytes coming outa the trimmer    */
    blocks_eff_total,     /* Blocks subject to effector maps  */
    blocks_eff_select;    /* Blocks selected as fuzzable      */

static u32 subseq_tmouts; /* Number of timeouts in a row      */

static u8 *stage_name = "init", /* Name of the current fuzz stage   */
    *stage_short,               /* Short stage name                 */
    *syncing_party;             /* Currently syncing with...        */

static s32 stage_cur, stage_max; /* Stage progression                */
static s32 splicing_with = -1;   /* Splicing with which test case?   */

static u32 master_id, master_max; /* Master instance job splitting    */

static u32 syncing_case; /* Syncing with case #...           */

static s32 stage_cur_byte, /* Byte offset of current stage op  */
    stage_cur_val;         /* Value used for stage op          */

static u8 stage_val_type; /* Value type (STAGE_VAL_*)         */

static u64 stage_finds[32], /* Patterns found per fuzz stage    */
    stage_cycles[32];       /* Execs per fuzz stage             */

static u32 rand_cnt; /* Random number counter            */

static u64 total_cal_us, /* Total calibration time (us)      */
    total_cal_cycles;    /* Total calibration cycles         */

static u64 total_bitmap_size, /* Total bit count for all bitmaps  */
    total_bitmap_entries;     /* Number of bitmaps counted        */

static s32 cpu_core_count; /* CPU core count                   */

#ifdef HAVE_AFFINITY

static s32 cpu_aff = -1; /* Selected CPU core                */

#endif /* HAVE_AFFINITY */

static FILE *plot_file; /* Gnuplot output file              */

struct queue_entry
{

  u8 *fname; /* File name for the test case      */
  u32 len;   /* Input length                     */

  u8 cal_failed,    /* Calibration failed?              */
      trim_done,    /* Trimmed?                         */
      was_fuzzed,   /* Had any fuzzing done yet?        */
      passed_det,   /* Deterministic stages passed?     */
      has_new_cov,  /* Triggers new coverage?           */
      var_behavior, /* Variable behavior?               */
      favored,      /* Currently favored?               */
      fs_redundant; /* Marked as redundant in the fs?   */

  u32 bitmap_size, /* Number of bits set in bitmap     */
      exec_cksum;  /* Checksum of the execution trace  */

  u64 exec_us,  /* Execution time (us)              */
      handicap, /* Number of queue cycles behind    */
      depth;    /* Path depth                       */

  u8 *trace_mini; /* Trace bytes, if kept             */
  u32 tc_ref;     /* Trace bytes ref count            */

  struct queue_entry *next, /* Next element, if any             */
      *next_100;            /* 100 elements ahead               */

  region_t *regions;       /* Regions keeping information of message(s) sent to the server under test */
  u32 region_count;        /* Total number of regions in this seed */
  u32 index;               /* Index of this queue entry in the whole queue */
  u32 generating_state_id; /* ID of the start at which the new seed was generated */
  u8 is_initial_seed;      /* Is this an initial seed */
  u32 unique_state_count;  /* Unique number of states traversed by this queue entry */
};

static struct queue_entry *queue, /* Fuzzing queue (linked list)      */
    *queue_cur,                   /* Current offset within the queue  */
    *queue_top,                   /* Top of the list                  */
    *q_prev100;                   /* Previous 100 marker              */

static struct queue_entry *
    top_rated[MAP_SIZE]; /* Top entries for bitmap bytes     */

struct extra_data
{
  u8 *data;    /* Dictionary token data            */
  u32 len;     /* Dictionary token length          */
  u32 hit_cnt; /* Use count in the corpus          */
};

static struct extra_data *extras; /* Extra tokens to fuzz with        */
static u32 extras_cnt;            /* Total number of tokens read      */

static struct extra_data *a_extras; /* Automatically selected extras    */
static u32 a_extras_cnt;            /* Total number of tokens available */

static u8 *(*post_handler)(u8 *buf, u32 *len);

/* Interesting values, as per config.h */

static s8 interesting_8[] = {INTERESTING_8};
static s16 interesting_16[] = {INTERESTING_8, INTERESTING_16};
static s32 interesting_32[] = {INTERESTING_8, INTERESTING_16, INTERESTING_32};

/* Fuzzing stages */

enum
{
  /* 00 */ STAGE_FLIP1,
  /* 01 */ STAGE_FLIP2,
  /* 02 */ STAGE_FLIP4,
  /* 03 */ STAGE_FLIP8,
  /* 04 */ STAGE_FLIP16,
  /* 05 */ STAGE_FLIP32,
  /* 06 */ STAGE_ARITH8,
  /* 07 */ STAGE_ARITH16,
  /* 08 */ STAGE_ARITH32,
  /* 09 */ STAGE_INTEREST8,
  /* 10 */ STAGE_INTEREST16,
  /* 11 */ STAGE_INTEREST32,
  /* 12 */ STAGE_EXTRAS_UO,
  /* 13 */ STAGE_EXTRAS_UI,
  /* 14 */ STAGE_EXTRAS_AO,
  /* 15 */ STAGE_HAVOC,
  /* 16 */ STAGE_SPLICE
};

/* Stage value types */

enum
{
  /* 00 */ STAGE_VAL_NONE,
  /* 01 */ STAGE_VAL_LE,
  /* 02 */ STAGE_VAL_BE
};

/* Execution status fault codes */

enum
{
  /* 00 */ FAULT_NONE,
  /* 01 */ FAULT_TMOUT,
  /* 02 */ FAULT_CRASH,
  /* 03 */ FAULT_ERROR,
  /* 04 */ FAULT_NOINST,
  /* 05 */ FAULT_NOBITS
};

char **use_argv; /* argument to run the target program. In vanilla AFL, this is a local variable in main. */
/* add these declarations here so we can call these functions earlier */
static u8 run_target(char **argv, u32 timeout);
static inline u32 UR(u32 limit);
static inline u8 has_new_bits(u8 *virgin_map);

/* AFLNet-specific variables & functions */

u32 server_wait_usecs = 10000;
u32 poll_wait_msecs = 1;
u32 socket_timeout_usecs = 1000;
u8 net_protocol;
u8 *net_ip;
u32 net_port;
char *response_buf = NULL;
int response_buf_size = 0;  // the size of the whole response buffer
u32 *response_bytes = NULL; // an array keeping accumulated response buffer size
                            // e.g., response_bytes[i] keeps the response buffer size
                            // once messages 0->i have been received and processed by the SUT
u32 max_annotated_regions = 0;
u32 target_state_id = 0;
u32 *state_ids = NULL;
u32 state_ids_count = 0;
u32 selected_state_index = 0;
u32 state_cycles = 0;
u32 messages_sent = 0;
EXP_ST u8 session_virgin_bits[MAP_SIZE]; /* Regions yet untouched while the SUT is still running */
EXP_ST u8 *cleanup_script;               /* script to clean up the environment of the SUT -- make fuzzing more deterministic */
EXP_ST u8 *netns_name;                   /* network namespace name to run server in */
char **was_fuzzed_map = NULL;            /* A 2D array keeping state-specific was_fuzzed information */
u32 fuzzed_map_states = 0;
u32 fuzzed_map_qentries = 0;
u32 max_seed_region_count = 0;
u32 local_port; /* TCP/UDP port number to use as source */

/* flags */
u8 use_net = 0;
u8 poll_wait = 0;
u8 server_wait = 0;
u8 socket_timeout = 0;
u8 protocol_selected = 0;
u8 terminate_child = 0;
u8 corpus_read_or_sync = 0;
u8 state_aware_mode = 0;
u8 region_level_mutation = 0;
u8 state_selection_algo = ROUND_ROBIN, seed_selection_algo = RANDOM_SELECTION;
u8 false_negative_reduction = 0;

/* Track how long we don't observe interesting seeds */
u32 uninteresting_times = 0;
/* Track how much times we ask for breaking coverage plateau */
u32 chat_times = 0;

/* Implemented state machine */
Agraph_t *ipsm;
static FILE *ipsm_dot_file;

/* Hash table/map and list */
klist_t(lms) * kl_messages;
khash_t(hs32) * khs_ipsm_paths;
khash_t(hms) * khms_states;

// M2_prev points to the last message of M1 (i.e., prefix)
// If M1 is empty, M2_prev == NULL
// M2_next points to the first message of M3 (i.e., suffix)
// If M3 is empty, M2_next point to the end of the kl_messages linked list
kliter_t(lms) * M2_prev, *M2_next;

// Function pointers pointing to Protocol-specific functions
unsigned int *(*extract_response_codes)(unsigned char *buf, unsigned int buf_size, unsigned int *state_count_ref) = NULL;
region_t *(*extract_requests)(unsigned char *buf, unsigned int buf_size, unsigned int *region_count_ref) = NULL;

// Patterns generated from the Language Model
klist_t(rang) * protocol_patterns;
// Message types of the patterns generated from the Language model
khash_t(strSet) * message_types_set;
// Protocol name kept for prompts
char *protocol_name;
// Reward fields - To be used
u32 reward_random;
u32 reward_grammar;

void setup_llm_grammars_semantics()
{

  ACTF("Getting grammars from LLM...");// 打印一条日志信息，表示开始从LLM获取语法

  khash_t(consistency_table) *const_table = kh_init(consistency_table);// kh_init(consistency_table)：初始化一个哈希表 const_table，用于存储一致性信息。
  char *first_question;
  char *templates_prompt = construct_prompt_for_templates(protocol_name, &first_question);// 构造一个提示词，用于从LLM获取模板。first_question 是第一个问题，templates_prompt 是完整的提示词。

  for (int iter = 0; iter < TEMPLATE_CONSISTENCY_COUNT; iter++)// TEMPLATE_CONSISTENCY_COUNT：循环次数，用于多次获取模板以提高一致性。
  {
    klist_t(gram) *grammar_list = kl_init(gram);

    char *templates_answer = chat_with_llm(templates_prompt, "turbo", GRAMMAR_RETRIES, 0.5);//chat_with_llm：调用LLM获取模板答案。如果失败，跳转到 free_templates_answer 标签。
    if (templates_answer == NULL)
      goto free_templates_answer;

    // printf("## Answer from LLM:\n %s\n", templates_answer);
    char *remaining_prompt = construct_prompt_for_remaining_templates(protocol_name, first_question, templates_answer);// construct_prompt_for_remaining_templates：构造一个提示词，用于获取剩余的模板。如果失败，跳转到 free_remaining 标签。
    // printf("remaining prompt is:\n %s\n", remaining_prompt);
    char *remaining_templates = chat_with_llm(remaining_prompt, "turbo", GRAMMAR_RETRIES, 0.5);
    if (remaining_templates == NULL)
      goto free_remaining;

    // printf("## Remaining templates:\n %s\n", remaining_templates);

    char *combined_templates = NULL;
    asprintf(&combined_templates, "%s\n%s", templates_answer, remaining_templates);// asprintf：将两个答案合并成一个字符串 combined_templates

    char *grammar_output_path = alloc_printf("%s/protocol-grammars/llm-grammar-output-%d", out_dir, iter);// alloc_printf 和 open：生成文件路径并打开文件，将合并后的模板写入文件。
    int grammar_output_fd = open(grammar_output_path, O_WRONLY | O_CREAT, 0600);

    ck_write(grammar_output_fd, combined_templates, strlen(combined_templates), grammar_output_path);

    close(grammar_output_fd);
    ck_free(grammar_output_path);

    extract_message_grammars(combined_templates, grammar_list);// extract_message_grammars：从合并后的模板中提取消息语法，并存储在 grammar_list 中。

    kliter_t(gram) * iter;// kl_iter 和 kh_put：遍历 grammar_list，将消息头和字段信息存储在 const_table 中
    for (iter = kl_begin(grammar_list); iter != kl_end(grammar_list); iter = kl_next(iter))
    {
      json_object *jobj = kl_val(iter);

      json_object *header = json_object_array_get_idx(jobj, 0);

      int absent;

      const char *header_str = json_object_get_string(header);

      khiter_t k = kh_put(consistency_table, const_table, header_str, &absent);
      if (absent)
      {
        khash_t(field_table) *field_table = kh_init(field_table);
        kh_value(const_table, k) = field_table;
      }

      for (int i = 1; i < json_object_array_length(jobj); i++)
      {
        const char *v = json_object_get_string(json_object_array_get_idx(jobj, i));
        khash_t(field_table) *field_table = kh_value(const_table, k);
        khiter_t field_k = kh_put(field_table, field_table, v, &absent);
        if (absent)
        {
          kh_value(field_table, field_k) = 0;
        }
        kh_value(field_table, field_k)++;
      }
    }
    kl_destroy_gram(grammar_list);// kl_destroy_gram：销毁 grammar_list

    free(combined_templates);//释放分配的内存。
    free(remaining_templates);

  free_remaining:
    free(remaining_prompt);

  free_templates_answer:
    free(templates_answer);
  }
  // ACTF("Getting semantics from RAG...");// 打印一条日志信息，表示开始从RAG获取语义
  // int pattern_index = 0;// pattern_index：模式索引，用于生成文件名
  // for (khiter_t con_t_iter = kh_begin(const_table); con_t_iter != kh_end(const_table); ++con_t_iter)
  // {
  //   if (kh_exist(const_table, con_t_iter))
  //   {
  //     pcre2_code **patterns = ck_alloc(2 * sizeof(pcre2_code *));

  //     khash_t(field_table) *field_table = kh_value(const_table, con_t_iter);

  //     json_object *header_v = json_object_new_string(kh_key(const_table, con_t_iter));// json_object_new_string 和 json_object_to_json_string：将消息头转换为JSON字符串。
  //     const char *header_str = json_object_to_json_string(header_v);

  //     char *pattern_path = alloc_printf("%s/protocol-grammars/pattern-%d", out_dir, pattern_index);
  //     pattern_index++;// alloc_printf 和 open：生成文件路径并打开文件，用于存储模式。
  //     int pattern_fd = open(pattern_path, O_WRONLY | O_CREAT, 0600);

  //     char *message_type = extract_message_pattern(header_str, field_table, patterns, pattern_fd, pattern_path);// extract_message_pattern：从消息头和字段表中提取模式，并生成正则表达式。
  //     if (message_type != NULL)
  //     {
  //       int discard;
  //       kh_put(strSet, message_types_set, message_type, &discard);// kh_put：将消息类型存储在 message_types_set 中。
  //       *kl_pushp(rang, protocol_patterns) = patterns; // kl_pushp：将模式存储在 protocol_patterns 列表中。
  //     }

  //     json_object_put(header_v);// json_object_put：释放JSON对象。
  //     close(pattern_fd);// close 和 ck_free：关闭文件并释放文件路径。
  //     ck_free(pattern_path);
  //   }
  // }

  // free(first_question);
  // free(templates_prompt);
  // for (khiter_t con_t_iter = kh_begin(const_table); con_t_iter != kh_end(const_table); ++con_t_iter) {
  //   if (kh_exist(const_table, con_t_iter)) {
  //     const char *header_str = kh_key(const_table, con_t_iter);
  //     khash_t(field_table) *field_table = kh_value(const_table, con_t_iter);

  //     // 遍历每个字段
  //     for (khiter_t field_iter = kh_begin(field_table); field_iter != kh_end(field_table); ++field_iter) {
  //       if (kh_exist(field_table, field_iter)) {
  //         const char *field_str = kh_key(field_table, field_iter);

  //         // 构造查询和文档列表
  //         const char *documents[] = {"源代码1", "源代码2", "源代码3", "源代码4"};
  //         const char *query = field_str;

  //         // 调用 RAG API 进行检索和生成
  //         char *response = perform_rerank_request(query, documents, 4);

  //         if (response) {
  //           // 解析响应，提取语义信息
  //           // 这里假设响应是一个 JSON 字符串
  //           json_object *jobj = json_tokener_parse(response);
  //           if (jobj) {
  //             json_object *reranked_docs = NULL;
  //             json_object_object_get_ex(jobj, "reranked_documents", &reranked_docs);
  //             if (reranked_docs) {
  //               int len = json_object_array_length(reranked_docs);
  //               for (int i = 0; i < len; i++) {
  //                 json_object *doc = json_object_array_get_idx(reranked_docs, i);
  //                 const char *doc_text = json_object_get_string(doc);
  //                 // 将 doc_text 存储到 field_table 中
  //                 int absent;
  //                 khiter_t sem_k = kh_put(field_table, field_table, doc_text, &absent);
  //                 if (absent) {
  //                   kh_value(field_table, sem_k) = 0;
  //                 }
  //                 kh_value(field_table, sem_k)++;
  //               }
  //             }
  //             json_object_put(jobj);
  //           }
  //           free(response);
  //         }
  //       }
  //     }
  //   }
  // }
}

range_list parse_buffer(char *buf, size_t buf_len)
{
  range_list best_decomposition;
  kv_init(best_decomposition);
  kliter_t(rang) * iter_rang;
  // Find a valid decomposition of the buffer, according to a header pattern
  for (iter_rang = kl_begin(protocol_patterns); iter_rang != kl_end(protocol_patterns); iter_rang = kl_next(iter_rang))
  {
    pcre2_code **patterns = kl_val(iter_rang);
    pcre2_code *header_pattern = patterns[0];
    pcre2_code *fields_pattern = patterns[1];

    if(header_pattern == NULL || fields_pattern == NULL) continue;

    range_list header_groups = starts_with(buf, buf_len, header_pattern);

    if (kv_size(header_groups) == 0)
    {
      continue;
    }
    else
    {
      range header_match = kv_pop(header_groups);
      char *offsetted_line = buf;
      size_t offsetted_len = buf_len;
      range_list dyn_ranges = get_mutable_ranges(offsetted_line, offsetted_len, header_match.len, fields_pattern);

      for (int i = 0; i < kv_size(dyn_ranges); i++)
      {
        kv_push(range, header_groups, kv_A(dyn_ranges, i));
      }
      kv_destroy(dyn_ranges);

      best_decomposition = header_groups;

      break;
    }
  }

  if (kv_size(best_decomposition) == 0)
  {
    // Graceful degradataion
    range v = {.start = 0, .len = buf_len, .mutable = 1};
    kv_push(range, best_decomposition, v);
  }
  return best_decomposition;
}

/* Initialize the implemented state machine as a graphviz graph */
void setup_ipsm()
{
  ipsm = agopen("g", Agdirected, 0);

  agattr(ipsm, AGNODE, "color", "black"); // Default node colr is black
  agattr(ipsm, AGEDGE, "color", "black"); // Default edge color is black

  khs_ipsm_paths = kh_init(hs32);

  khms_states = kh_init(hms);
}

/* Free memory allocated to state-machine variables */
void destroy_ipsm()
{
  agclose(ipsm);

  kh_destroy(hs32, khs_ipsm_paths);

  state_info_t *state;
  kh_foreach_value(khms_states, state, {ck_free(state->seeds); ck_free(state); });
  kh_destroy(hms, khms_states);

  ck_free(state_ids);
}

/* Get state index in the state IDs list, given a state ID */
u32 get_state_index(u32 state_id)
{
  u32 index = 0;
  for (index = 0; index < state_ids_count; index++)
  {
    if (state_ids[index] == state_id)
      break;
  }
  return index;
}

/* Expand the size of the map when a new seed or a new state has been discovered */
void expand_was_fuzzed_map(u32 new_states, u32 new_qentries)
{
  int i, j;
  // Realloc the memory
  was_fuzzed_map = (char **)ck_realloc(was_fuzzed_map, (fuzzed_map_states + new_states) * sizeof(char *));
  for (i = 0; i < fuzzed_map_states + new_states; i++)
    was_fuzzed_map[i] = (char *)ck_realloc(was_fuzzed_map[i], (fuzzed_map_qentries + new_qentries) * sizeof(char));

  // All new cells are marked as -1 -- meaning UNREACHABLE
  // Keep other cells untouched
  for (i = 0; i < fuzzed_map_states + new_states; i++)
    for (j = 0; j < fuzzed_map_qentries + new_qentries; j++)
      if ((i >= fuzzed_map_states) || (j >= fuzzed_map_qentries))
        was_fuzzed_map[i][j] = -1;

  // Update total number of states (rows) and total number of queue entries (columns) in the was_fuzzed_map
  fuzzed_map_states += new_states;
  fuzzed_map_qentries += new_qentries;
}

/* Get unique state count, given a state sequence */
u32 get_unique_state_count(unsigned int *state_sequence, unsigned int state_count)
{
  // A hash set is used so that no state is counted twice
  khash_t(hs32) * khs_state_ids;
  khs_state_ids = kh_init(hs32);

  unsigned int discard, state_id, i;
  u32 result = 0;

  for (i = 0; i < state_count; i++)
  {
    state_id = state_sequence[i];

    if (kh_get(hs32, khs_state_ids, state_id) != kh_end(khs_state_ids))
    {
      continue;
    }
    else
    {
      kh_put(hs32, khs_state_ids, state_id, &discard);
      result++;
    }
  }

  kh_destroy(hs32, khs_state_ids);
  return result;
}

/* Check if a state sequence is interesting (e.g., new state is discovered). Loop is taken into account */
u8 is_state_sequence_interesting(unsigned int *state_sequence, unsigned int state_count)
{
  // limit the loop count to only 1
  u32 *trimmed_state_sequence = NULL;
  u32 i, count = 0;
  for (i = 0; i < state_count; i++)
  {
    if ((i >= 2) && (state_sequence[i] == state_sequence[i - 1]) && (state_sequence[i] == state_sequence[i - 2]))
      continue;
    count++;
    trimmed_state_sequence = (u32 *)realloc(trimmed_state_sequence, count * sizeof(unsigned int));
    trimmed_state_sequence[count - 1] = state_sequence[i];
  }

  // Calculate the hash based on the shortened state sequence
  u32 hashKey = hash32(trimmed_state_sequence, count * sizeof(unsigned int), 0);
  if (trimmed_state_sequence)
    free(trimmed_state_sequence);

  if (kh_get(hs32, khs_ipsm_paths, hashKey) != kh_end(khs_ipsm_paths))
  {
    return 0;
  }
  else
  {
    int dummy;
    kh_put(hs32, khs_ipsm_paths, hashKey, &dummy);
    return 1;
  }
}

/* Update the annotations of regions (i.e., state sequence received from the server) */
void update_region_annotations(struct queue_entry *q)
{
  u32 i = 0;

  for (i = 0; i < messages_sent; i++)
  {
    if ((response_bytes[i] == 0) || (i > 0 && (response_bytes[i] - response_bytes[i - 1] == 0)))
    {
      q->regions[i].state_sequence = NULL;
      q->regions[i].state_count = 0;
    }
    else
    {
      unsigned int state_count;
      q->regions[i].state_sequence = (*extract_response_codes)(response_buf, response_bytes[i], &state_count);
      q->regions[i].state_count = state_count;
    }
  }
}

/* Choose a region data for region-level mutations */
u8 *choose_source_region(u32 *out_len)
{
  u8 *out = NULL;
  *out_len = 0;
  struct queue_entry *q = queue;

  // randomly select a seed
  u32 index = UR(queued_paths);
  while (index != 0)
  {
    q = q->next;
    index--;
  }

  // randomly select a region in the selected seed
  if (q->region_count)
  {
    u32 reg_index = UR(q->region_count);
    u32 len = q->regions[reg_index].end_byte - q->regions[reg_index].start_byte + 1;
    if (len <= MAX_FILE)
    {
      out = (u8 *)ck_alloc(len);
      if (out == NULL)
        PFATAL("Unable allocate a memory region to store a region");
      *out_len = len;
      // Read region data into memory. */
      FILE *fp = fopen(q->fname, "rb");
      fseek(fp, q->regions[reg_index].start_byte, SEEK_CUR);
      fread(out, 1, len, fp);
      fclose(fp);
    }
  }

  return out;
}

/* Update #fuzzs visiting a specific state */
void update_fuzzs()
{
  unsigned int state_count, i, discard;
  unsigned int *state_sequence = (*extract_response_codes)(response_buf, response_buf_size, &state_count);

  // A hash set is used so that the #paths is not updated more than once for one specific state
  khash_t(hs32) * khs_state_ids;
  khint_t k;
  khs_state_ids = kh_init(hs32);

  for (i = 0; i < state_count; i++)
  {
    unsigned int state_id = state_sequence[i];

    if (kh_get(hs32, khs_state_ids, state_id) != kh_end(khs_state_ids))
    {
      continue;
    }
    else
    {
      kh_put(hs32, khs_state_ids, state_id, &discard);
      k = kh_get(hms, khms_states, state_id);
      if (k != kh_end(khms_states))
      {
        kh_val(khms_states, k)->fuzzs++;
      }
    }
  }
  ck_free(state_sequence);
  kh_destroy(hs32, khs_state_ids);
}

/* Return the index of the "region" containing a given value */
u32 index_search(u32 *A, u32 n, u32 val)
{
  u32 index = 0;
  for (index = 0; index < n; index++)
  {
    if (val <= A[index])
      break;
  }
  return index;
}

/* Calculate state scores and select the next state */
u32 update_scores_and_select_next_state(u8 mode)
{
  u32 result = 0, i;

  if (state_ids_count == 0)
    return 0;

  u32 *state_scores = NULL;
  state_scores = (u32 *)ck_alloc(state_ids_count * sizeof(u32));
  if (!state_scores)
    PFATAL("Cannot allocate memory for state_scores");

  khint_t k;
  state_info_t *state;
  // Update the states' score
  for (i = 0; i < state_ids_count; i++)
  {
    u32 state_id = state_ids[i];

    k = kh_get(hms, khms_states, state_id);
    if (k != kh_end(khms_states))
    {
      state = kh_val(khms_states, k);
      switch (mode)
      {
      case FAVOR:
        state->score = ceil(1000 * pow(2, -log10(log10(state->fuzzs + 1) * state->selected_times + 1)) * pow(2, log(state->paths_discovered + 1)));
        break;
        // other cases are reserved
      }

      if (i == 0)
      {
        state_scores[i] = state->score;
      }
      else
      {
        state_scores[i] = state_scores[i - 1] + state->score;
      }
    }
  }

  u32 randV = UR(state_scores[state_ids_count - 1]);
  u32 idx = index_search(state_scores, state_ids_count, randV);
  result = state_ids[idx];

  if (state_scores)
    ck_free(state_scores);
  return result;
}

/* Select a target state at which we do state-aware fuzzing */
unsigned int choose_target_state(u8 mode)
{
  u32 result = 0;

  switch (mode)
  {
  case RANDOM_SELECTION: // Random state selection
    selected_state_index = UR(state_ids_count);
    result = state_ids[selected_state_index];
    break;
  case ROUND_ROBIN: // Round-robin state selection
    result = state_ids[selected_state_index];
    selected_state_index++;
    if (selected_state_index == state_ids_count)
      selected_state_index = 0;
    break;
  case FAVOR:
    /* Do ROUND_ROBIN for a few cycles to get enough statistical information*/
    if (state_cycles < 5)
    {
      result = state_ids[selected_state_index];
      selected_state_index++;
      if (selected_state_index == state_ids_count)
      {
        selected_state_index = 0;
        state_cycles++;
      }
      break;
    }

    result = update_scores_and_select_next_state(FAVOR);
    break;
  default:
    break;
  }

  return result;
}

/* Select a seed to exercise the target state */
struct queue_entry *choose_seed(u32 target_state_id, u8 mode)
{
  khint_t k;
  state_info_t *state;
  struct queue_entry *result = NULL;

  k = kh_get(hms, khms_states, target_state_id);
  if (k != kh_end(khms_states))
  {
    state = kh_val(khms_states, k);

    if (state->seeds_count == 0)
      return NULL;

    switch (mode)
    {
    case RANDOM_SELECTION: // Random seed selection
      state->selected_seed_index = UR(state->seeds_count);
      result = state->seeds[state->selected_seed_index];
      break;
    case ROUND_ROBIN: // Round-robin seed selection
      result = state->seeds[state->selected_seed_index];
      state->selected_seed_index++;
      if (state->selected_seed_index == state->seeds_count)
        state->selected_seed_index = 0;
      break;
    case FAVOR:
      if (state->seeds_count > 10)
      {
        // Do seed selection similar to AFL + take into account state-aware information
        // e.g., was_fuzzed information becomes state-aware
        u32 passed_cycles = 0;
        while (passed_cycles < 5)
        {
          result = state->seeds[state->selected_seed_index];
          if (state->selected_seed_index + 1 == state->seeds_count)
          {
            state->selected_seed_index = 0;
            passed_cycles++;
          }
          else
            state->selected_seed_index++;

          // Skip this seed with high probability if it is neither an initial seed nor a seed generated while the
          // current target_state_id was targeted
          if (result->generating_state_id != target_state_id && !result->is_initial_seed && UR(100) < 90)
            continue;

          u32 target_state_index = get_state_index(target_state_id);
          if (pending_favored)
          {
            /* If we have any favored, non-fuzzed new arrivals in the queue,
               possibly skip to them at the expense of already-fuzzed or non-favored
               cases. */
            if (((was_fuzzed_map[target_state_index][result->index] == 1) || !result->favored) && UR(100) < SKIP_TO_NEW_PROB)
              continue;

            /* Otherwise, this seed is selected */
            break;
          }
          else if (!result->favored && queued_paths > 10)
          {
            /* Otherwise, still possibly skip non-favored cases, albeit less often.
               The odds of skipping stuff are higher for already-fuzzed inputs and
               lower for never-fuzzed entries. */
            if (queue_cycle > 1 && (was_fuzzed_map[target_state_index][result->index] == 0))
            {
              if (UR(100) < SKIP_NFAV_NEW_PROB)
                continue;
            }
            else
            {
              if (UR(100) < SKIP_NFAV_OLD_PROB)
                continue;
            }

            /* Otherwise, this seed is selected */
            break;
          }
        }
      }
      else
      {
        // Do Round-robin if seeds_count of the selected state is small
        result = state->seeds[state->selected_seed_index];
        state->selected_seed_index++;
        if (state->selected_seed_index == state->seeds_count)
          state->selected_seed_index = 0;
      }
      break;
    default:
      break;
    }
  }
  else
  {
    PFATAL("AFLNet - the states hashtable has no entries for state %d", target_state_id);
  }

  return result;
}

static u64 get_cur_time(void);

/* Update state-aware variables */
void update_state_aware_variables(struct queue_entry *q, u8 dry_run)
{
  khint_t k;
  int discard, i;
  state_info_t *state;
  unsigned int state_count;

  if (!response_buf_size || !response_bytes)
    return;

  unsigned int *state_sequence = (*extract_response_codes)(response_buf, response_buf_size, &state_count);

  q->unique_state_count = get_unique_state_count(state_sequence, state_count);

  if (is_state_sequence_interesting(state_sequence, state_count))
  {
    // Save the current kl_messages to a file which can be used to replay the newly discovered paths on the ipsm
    u8 *temp_str = state_sequence_to_string(state_sequence, state_count);
    u8 *fname = alloc_printf("%s/replayable-new-ipsm-paths/id:%llu:%s:%s", out_dir, get_cur_time() / 1000, temp_str, dry_run ? basename(q->fname) : "new");
    save_kl_messages_to_file(kl_messages, fname, 1, messages_sent);
    ck_free(temp_str);
    ck_free(fname);

    u8 *responses_fname = alloc_printf("%s/responses-ipsm/id:%s", out_dir, basename(q->fname));
    save_responses_to_file(response_buf, response_buf_size, response_bytes, responses_fname, messages_sent);
    ck_free(responses_fname);

    // Update the IPSM graph
    if (state_count > 1)
    {
      unsigned int prevStateID = state_sequence[0];

      for (i = 1; i < state_count; i++)
      {
        unsigned int curStateID = state_sequence[i];
        char fromState[STATE_STR_LEN], toState[STATE_STR_LEN];
        snprintf(fromState, STATE_STR_LEN, "%d", prevStateID);
        snprintf(toState, STATE_STR_LEN, "%d", curStateID);

        // Check if the prevStateID and curStateID have been added to the state machine as vertices
        // Check also if the edge prevStateID->curStateID has been added
        Agnode_t *from, *to;
        Agedge_t *edge;
        from = agnode(ipsm, fromState, FALSE);
        if (!from)
        {
          // Add a node to the graph
          from = agnode(ipsm, fromState, TRUE);
          if (dry_run)
            agset(from, "color", "blue");
          else
            agset(from, "color", "red");

          // Insert this newly discovered state into the states hashtable
          state_info_t *newState_From = (state_info_t *)ck_alloc(sizeof(state_info_t));
          newState_From->id = prevStateID;
          newState_From->is_covered = 1;
          newState_From->paths = 0;
          newState_From->paths_discovered = 0;
          newState_From->selected_times = 0;
          newState_From->fuzzs = 0;
          newState_From->score = 1;
          newState_From->selected_seed_index = 0;
          newState_From->seeds = NULL;
          newState_From->seeds_count = 0;

          k = kh_put(hms, khms_states, prevStateID, &discard);
          kh_value(khms_states, k) = newState_From;

          // Insert this into the state_ids array too
          state_ids = (u32 *)ck_realloc(state_ids, (state_ids_count + 1) * sizeof(u32));
          state_ids[state_ids_count++] = prevStateID;

          if (prevStateID != 0)
            expand_was_fuzzed_map(1, 0);
        }

        to = agnode(ipsm, toState, FALSE);
        if (!to)
        {
          // Add a node to the graph
          to = agnode(ipsm, toState, TRUE);
          if (dry_run)
            agset(to, "color", "blue");
          else
            agset(to, "color", "red");

          // Insert this newly discovered state into the states hashtable
          state_info_t *newState_To = (state_info_t *)ck_alloc(sizeof(state_info_t));
          newState_To->id = curStateID;
          newState_To->is_covered = 1;
          newState_To->paths = 0;
          newState_To->paths_discovered = 0;
          newState_To->selected_times = 0;
          newState_To->fuzzs = 0;
          newState_To->score = 1;
          newState_To->selected_seed_index = 0;
          newState_To->seeds = NULL;
          newState_To->seeds_count = 0;

          k = kh_put(hms, khms_states, curStateID, &discard);
          kh_value(khms_states, k) = newState_To;

          // Insert this into the state_ids array too
          state_ids = (u32 *)ck_realloc(state_ids, (state_ids_count + 1) * sizeof(u32));
          state_ids[state_ids_count++] = curStateID;

          if (curStateID != 0)
            expand_was_fuzzed_map(1, 0);
        }

        // Check if an edge from->to exists
        edge = agedge(ipsm, from, to, NULL, FALSE);
        if (!edge)
        {
          // Add an edge to the graph
          edge = agedge(ipsm, from, to, "new_edge", TRUE);
          if (dry_run)
            agset(edge, "color", "blue");
          else
            agset(edge, "color", "red");
        }

        // Update prevStateID
        prevStateID = curStateID;
      }
    }

    // Update the dot file
    s32 fd;
    u8 *tmp;
    tmp = alloc_printf("%s/ipsm.dot", out_dir);
    fd = open(tmp, O_WRONLY | O_CREAT, 0600);
    if (fd < 0)
    {
      PFATAL("Unable to create %s", tmp);
    }
    else
    {
      ipsm_dot_file = fdopen(fd, "w");
      agwrite(ipsm, ipsm_dot_file);
      close(fileno(ipsm_dot_file));
      ck_free(tmp);
    }
  }

  // Update others no matter the new seed leads to interesting state sequence or not

  // Annotate the regions
  update_region_annotations(q);

  // Update the states hashtable to keep the list of seeds which help us to reach a specific state
  // Iterate over the regions & their annotated state (sub)sequences and update the hashtable accordingly
  // All seed should "reach" state 0 (initial state) so we add this one to the map first
  k = kh_get(hms, khms_states, 0);
  if (k != kh_end(khms_states))
  {
    state = kh_val(khms_states, k);
    state->seeds = (void **)ck_realloc(state->seeds, (state->seeds_count + 1) * sizeof(void *));
    state->seeds[state->seeds_count] = (void *)q;
    state->seeds_count++;

    was_fuzzed_map[0][q->index] = 0; // Mark it as reachable but not fuzzed
  }
  else
  {
    PFATAL("AFLNet - the states hashtable should always contain an entry of the initial state");
  }

  // Now update other states
  for (i = 0; i < q->region_count; i++)
  {
    unsigned int regional_state_count = q->regions[i].state_count;
    if (regional_state_count > 0)
    {
      // reachable_state_id is the last ID in the state_sequence
      unsigned int reachable_state_id = q->regions[i].state_sequence[regional_state_count - 1];

      k = kh_get(hms, khms_states, reachable_state_id);
      if (k != kh_end(khms_states))
      {
        state = kh_val(khms_states, k);
        state->seeds = (void **)ck_realloc(state->seeds, (state->seeds_count + 1) * sizeof(void *));
        state->seeds[state->seeds_count] = (void *)q;
        state->seeds_count++;
      }
      else
      {
        // XXX. This branch is supposed to be not reachable
        // However, due to some undeterminism, new state could be seen during regions' annotating process
        // even though the state was not observed before
        // To completely fix this, we should fix all causes leading to potential undeterminism
        // For now, we just add the state into the hashtable

        state_info_t *newState = (state_info_t *)ck_alloc(sizeof(state_info_t));
        newState->id = reachable_state_id;
        newState->is_covered = 1;
        newState->paths = 0;
        newState->paths_discovered = 0;
        newState->selected_times = 0;
        newState->fuzzs = 0;
        newState->score = 1;
        newState->selected_seed_index = 0;
        newState->seeds = NULL;
        newState->seeds = (void **)ck_realloc(newState->seeds, sizeof(void *));
        newState->seeds[0] = (void *)q;
        newState->seeds_count = 1;

        k = kh_put(hms, khms_states, reachable_state_id, &discard);
        kh_value(khms_states, k) = newState;

        // Insert this into the state_ids array too
        state_ids = (u32 *)ck_realloc(state_ids, (state_ids_count + 1) * sizeof(u32));
        state_ids[state_ids_count++] = reachable_state_id;

        if (reachable_state_id != 0)
          expand_was_fuzzed_map(1, 0);
      }

      was_fuzzed_map[get_state_index(reachable_state_id)][q->index] = 0; // Mark it as reachable but not fuzzed
    }
  }

  // Update the number of paths which have traversed a specific state
  // It can be used for calculating fuzzing energy
  // A hash set is used so that the #paths is not updated more than once for one specific state
  khash_t(hs32) * khs_state_ids;
  khs_state_ids = kh_init(hs32);

  for (i = 0; i < state_count; i++)
  {
    unsigned int state_id = state_sequence[i];

    if (kh_get(hs32, khs_state_ids, state_id) != kh_end(khs_state_ids))
    {
      continue;
    }
    else
    {
      kh_put(hs32, khs_state_ids, state_id, &discard);
      k = kh_get(hms, khms_states, state_id);
      if (k != kh_end(khms_states))
      {
        kh_val(khms_states, k)->paths++;
      }
    }
  }
  kh_destroy(hs32, khs_state_ids);

  // Update paths_discovered
  if (!dry_run)
  {
    k = kh_get(hms, khms_states, target_state_id);
    if (k != kh_end(khms_states))
    {
      kh_val(khms_states, k)->paths_discovered++;
    }
  }

  // Free state sequence
  if (state_sequence)
    ck_free(state_sequence);
}

/* Send (mutated) messages in order to the server under test */
int send_over_network()
{
  int n;
  u8 likely_buggy = 0;
  struct sockaddr_in serv_addr;
  struct sockaddr_in local_serv_addr;

  // Clean up the server if needed
  if (cleanup_script)
    system(cleanup_script);

  // Wait a bit for the server initialization
  usleep(server_wait_usecs);

  // Clear the response buffer and reset the response buffer size
  if (response_buf)
  {
    ck_free(response_buf);
    response_buf = NULL;
    response_buf_size = 0;
  }

  if (response_bytes)
  {
    ck_free(response_bytes);
    response_bytes = NULL;
  }

  // Create a TCP/UDP socket
  int sockfd = -1;
  if (net_protocol == PRO_TCP)
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
  else if (net_protocol == PRO_UDP)
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

  if (sockfd < 0)
  {
    PFATAL("Cannot create a socket");
  }

  // Set timeout for socket data sending/receiving -- otherwise it causes a big delay
  // if the server is still alive after processing all the requests
  struct timeval timeout;
  timeout.tv_sec = 0;
  timeout.tv_usec = socket_timeout_usecs;
  setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));

  memset(&serv_addr, '0', sizeof(serv_addr));

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(net_port);
  serv_addr.sin_addr.s_addr = inet_addr(net_ip);

  // This piece of code is only used for targets that send responses to a specific port number
  // The Kamailio SIP server is an example. After running this code, the intialized sockfd
  // will be bound to the given local port
  if (local_port > 0)
  {
    local_serv_addr.sin_family = AF_INET;
    local_serv_addr.sin_addr.s_addr = INADDR_ANY;
    local_serv_addr.sin_port = htons(local_port);

    local_serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (bind(sockfd, (struct sockaddr *)&local_serv_addr, sizeof(struct sockaddr_in)))
    {
      FATAL("Unable to bind socket on local source port");
    }
  }

  if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
  {
    // If it cannot connect to the server under test
    // try it again as the server initial startup time is varied
    for (n = 0; n < 1000; n++)
    {
      if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0)
        break;
      usleep(1000);
    }
    if (n == 1000)
    {
      close(sockfd);
      return 1;
    }
  }

  // retrieve early server response if needed
  if (net_recv(sockfd, timeout, poll_wait_msecs, &response_buf, &response_buf_size))
    goto HANDLE_RESPONSES;

  // write the request messages
  kliter_t(lms) * it;
  messages_sent = 0;

  for (it = kl_begin(kl_messages); it != kl_end(kl_messages); it = kl_next(it))
  {
    n = net_send(sockfd, timeout, kl_val(it)->mdata, kl_val(it)->msize);
    messages_sent++;

    // Allocate memory to store new accumulated response buffer size
    response_bytes = (u32 *)ck_realloc(response_bytes, messages_sent * sizeof(u32));

    // Jump out if something wrong leading to incomplete message sent
    if (n != kl_val(it)->msize)
    {
      goto HANDLE_RESPONSES;
    }

    // retrieve server response
    u32 prev_buf_size = response_buf_size;
    if (net_recv(sockfd, timeout, poll_wait_msecs, &response_buf, &response_buf_size))
    {
      goto HANDLE_RESPONSES;
    }

    // Update accumulated response buffer size
    response_bytes[messages_sent - 1] = response_buf_size;

    // set likely_buggy flag if AFLNet does not receive any feedback from the server
    // it could be a signal of a potentiall server crash, like the case of CVE-2019-7314
    if (prev_buf_size == response_buf_size)
      likely_buggy = 1;
    else
      likely_buggy = 0;
  }

HANDLE_RESPONSES:

  net_recv(sockfd, timeout, poll_wait_msecs, &response_buf, &response_buf_size);

  if (messages_sent > 0 && response_bytes != NULL)
  {
    response_bytes[messages_sent - 1] = response_buf_size;
  }

  // wait a bit letting the server to complete its remaining task(s)
  memset(session_virgin_bits, 255, MAP_SIZE);
  while (1)
  {
    if (has_new_bits(session_virgin_bits) != 2)
      break;
  }

  close(sockfd);

  if (likely_buggy && false_negative_reduction)
    return 0;

  if (terminate_child && (child_pid > 0))
    kill(child_pid, SIGTERM);

  // give the server a bit more time to gracefully terminate
  while (1)
  {
    int status = kill(child_pid, 0);
    if ((status != 0) && (errno == ESRCH))
      break;
  }

  return 0;
}
/* End of AFLNet-specific variables & functions */

/* Get unix time in milliseconds */

static u64 get_cur_time(void)
{

  struct timeval tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);
}

/* Get unix time in microseconds */

static u64 get_cur_time_us(void)
{

  struct timeval tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000000ULL) + tv.tv_usec;
}

/* Generate a random number (from 0 to limit - 1). This may
   have slight bias. */

static inline u32 UR(u32 limit)
{

  if (unlikely(!rand_cnt--))
  {

    u32 seed[2];

    ck_read(dev_urandom_fd, &seed, sizeof(seed), "/dev/urandom");

    srandom(seed[0]);
    rand_cnt = (RESEED_RNG / 2) + (seed[1] % RESEED_RNG);
  }

  return random() % limit;
}

/* Shuffle an array of pointers. Might be slightly biased. */

static void shuffle_ptrs(void **ptrs, u32 cnt)
{

  u32 i;

  for (i = 0; i < cnt - 2; i++)
  {

    u32 j = i + UR(cnt - i);
    void *s = ptrs[i];
    ptrs[i] = ptrs[j];
    ptrs[j] = s;
  }
}

#ifdef HAVE_AFFINITY

/* Build a list of processes bound to specific cores. Returns -1 if nothing
   can be found. Assumes an upper bound of 4k CPUs. */

static void bind_to_free_cpu(void)
{

  DIR *d;
  struct dirent *de;
  cpu_set_t c;

  u8 cpu_used[4096] = {0};
  u32 i;

  if (cpu_core_count < 2)
    return;

  if (getenv("AFL_NO_AFFINITY"))
  {

    WARNF("Not binding to a CPU core (AFL_NO_AFFINITY set).");
    return;
  }

  d = opendir("/proc");

  if (!d)
  {

    WARNF("Unable to access /proc - can't scan for free CPU cores.");
    return;
  }

  ACTF("Checking CPU core loadout...");

  /* Introduce some jitter, in case multiple AFL tasks are doing the same
     thing at the same time... */

  usleep(R(1000) * 250);

  /* Scan all /proc/<pid>/status entries, checking for Cpus_allowed_list.
     Flag all processes bound to a specific CPU using cpu_used[]. This will
     fail for some exotic binding setups, but is likely good enough in almost
     all real-world use cases. */

  while ((de = readdir(d)))
  {

    u8 *fn;
    FILE *f;
    u8 tmp[MAX_LINE];
    u8 has_vmsize = 0;

    if (!isdigit(de->d_name[0]))
      continue;

    fn = alloc_printf("/proc/%s/status", de->d_name);

    if (!(f = fopen(fn, "r")))
    {
      ck_free(fn);
      continue;
    }

    while (fgets(tmp, MAX_LINE, f))
    {

      u32 hval;

      /* Processes without VmSize are probably kernel tasks. */

      if (!strncmp(tmp, "VmSize:\t", 8))
        has_vmsize = 1;

      if (!strncmp(tmp, "Cpus_allowed_list:\t", 19) &&
          !strchr(tmp, '-') && !strchr(tmp, ',') &&
          sscanf(tmp + 19, "%u", &hval) == 1 && hval < sizeof(cpu_used) &&
          has_vmsize)
      {

        cpu_used[hval] = 1;
        break;
      }
    }

    ck_free(fn);
    fclose(f);
  }

  closedir(d);

  for (i = 0; i < cpu_core_count; i++)
    if (!cpu_used[i])
      break;

  if (i == cpu_core_count)
  {

    SAYF("\n" cLRD "[-] " cRST
         "Uh-oh, looks like all %u CPU cores on your system are allocated to\n"
         "    other instances of afl-fuzz (or similar CPU-locked tasks). Starting\n"
         "    another fuzzer on this machine is probably a bad plan, but if you are\n"
         "    absolutely sure, you can set AFL_NO_AFFINITY and try again.\n",
         cpu_core_count);

    FATAL("No more free CPU cores");
  }

  OKF("Found a free CPU core, binding to #%u.", i);

  cpu_aff = i;

  CPU_ZERO(&c);
  CPU_SET(i, &c);

  if (sched_setaffinity(0, sizeof(c), &c))
    PFATAL("sched_setaffinity failed");
}

#endif /* HAVE_AFFINITY */

#ifndef IGNORE_FINDS

/* Helper function to compare buffers; returns first and last differing offset. We
   use this to find reasonable locations for splicing two files. */

static void locate_diffs(u8 *ptr1, u8 *ptr2, u32 len, s32 *first, s32 *last)
{

  s32 f_loc = -1;
  s32 l_loc = -1;
  u32 pos;

  for (pos = 0; pos < len; pos++)
  {

    if (*(ptr1++) != *(ptr2++))
    {

      if (f_loc == -1)
        f_loc = pos;
      l_loc = pos;
    }
  }

  *first = f_loc;
  *last = l_loc;

  return;
}

#endif /* !IGNORE_FINDS */

/* Describe integer. Uses 12 cyclic static buffers for return values. The value
   returned should be five characters or less for all the integers we reasonably
   expect to see. */

static u8 *DI(u64 val)
{

  static u8 tmp[12][16];
  static u8 cur;

  cur = (cur + 1) % 12;

#define CHK_FORMAT(_divisor, _limit_mult, _fmt, _cast)    \
  do                                                      \
  {                                                       \
    if (val < (_divisor) * (_limit_mult))                 \
    {                                                     \
      sprintf(tmp[cur], _fmt, ((_cast)val) / (_divisor)); \
      return tmp[cur];                                    \
    }                                                     \
  } while (0)

  /* 0-9999 */
  CHK_FORMAT(1, 10000, "%llu", u64);

  /* 10.0k - 99.9k */
  CHK_FORMAT(1000, 99.95, "%0.01fk", double);

  /* 100k - 999k */
  CHK_FORMAT(1000, 1000, "%lluk", u64);

  /* 1.00M - 9.99M */
  CHK_FORMAT(1000 * 1000, 9.995, "%0.02fM", double);

  /* 10.0M - 99.9M */
  CHK_FORMAT(1000 * 1000, 99.95, "%0.01fM", double);

  /* 100M - 999M */
  CHK_FORMAT(1000 * 1000, 1000, "%lluM", u64);

  /* 1.00G - 9.99G */
  CHK_FORMAT(1000LL * 1000 * 1000, 9.995, "%0.02fG", double);

  /* 10.0G - 99.9G */
  CHK_FORMAT(1000LL * 1000 * 1000, 99.95, "%0.01fG", double);

  /* 100G - 999G */
  CHK_FORMAT(1000LL * 1000 * 1000, 1000, "%lluG", u64);

  /* 1.00T - 9.99G */
  CHK_FORMAT(1000LL * 1000 * 1000 * 1000, 9.995, "%0.02fT", double);

  /* 10.0T - 99.9T */
  CHK_FORMAT(1000LL * 1000 * 1000 * 1000, 99.95, "%0.01fT", double);

  /* 100T+ */
  strcpy(tmp[cur], "infty");
  return tmp[cur];
}

/* Describe float. Similar to the above, except with a single
   static buffer. */

static u8 *DF(double val)
{

  static u8 tmp[16];

  if (val < 99.995)
  {
    sprintf(tmp, "%0.02f", val);
    return tmp;
  }

  if (val < 999.95)
  {
    sprintf(tmp, "%0.01f", val);
    return tmp;
  }

  return DI((u64)val);
}

/* Describe integer as memory size. */

static u8 *DMS(u64 val)
{

  static u8 tmp[12][16];
  static u8 cur;

  cur = (cur + 1) % 12;

  /* 0-9999 */
  CHK_FORMAT(1, 10000, "%llu B", u64);

  /* 10.0k - 99.9k */
  CHK_FORMAT(1024, 99.95, "%0.01f kB", double);

  /* 100k - 999k */
  CHK_FORMAT(1024, 1000, "%llu kB", u64);

  /* 1.00M - 9.99M */
  CHK_FORMAT(1024 * 1024, 9.995, "%0.02f MB", double);

  /* 10.0M - 99.9M */
  CHK_FORMAT(1024 * 1024, 99.95, "%0.01f MB", double);

  /* 100M - 999M */
  CHK_FORMAT(1024 * 1024, 1000, "%llu MB", u64);

  /* 1.00G - 9.99G */
  CHK_FORMAT(1024LL * 1024 * 1024, 9.995, "%0.02f GB", double);

  /* 10.0G - 99.9G */
  CHK_FORMAT(1024LL * 1024 * 1024, 99.95, "%0.01f GB", double);

  /* 100G - 999G */
  CHK_FORMAT(1024LL * 1024 * 1024, 1000, "%llu GB", u64);

  /* 1.00T - 9.99G */
  CHK_FORMAT(1024LL * 1024 * 1024 * 1024, 9.995, "%0.02f TB", double);

  /* 10.0T - 99.9T */
  CHK_FORMAT(1024LL * 1024 * 1024 * 1024, 99.95, "%0.01f TB", double);

#undef CHK_FORMAT

  /* 100T+ */
  strcpy(tmp[cur], "infty");
  return tmp[cur];
}

/* Describe time delta. Returns one static buffer, 34 chars of less. */

static u8 *DTD(u64 cur_ms, u64 event_ms)
{

  static u8 tmp[64];
  u64 delta;
  s32 t_d, t_h, t_m, t_s;

  if (!event_ms)
    return "none seen yet";

  delta = cur_ms - event_ms;

  t_d = delta / 1000 / 60 / 60 / 24;
  t_h = (delta / 1000 / 60 / 60) % 24;
  t_m = (delta / 1000 / 60) % 60;
  t_s = (delta / 1000) % 60;

  sprintf(tmp, "%s days, %u hrs, %u min, %u sec", DI(t_d), t_h, t_m, t_s);
  return tmp;
}

/* Mark deterministic checks as done for a particular queue entry. We use the
   .state file to avoid repeating deterministic fuzzing when resuming aborted
   scans. */

static void mark_as_det_done(struct queue_entry *q)
{

  u8 *fn = strrchr(q->fname, '/');
  s32 fd;

  fn = alloc_printf("%s/queue/.state/deterministic_done/%s", out_dir, fn + 1);

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0)
    PFATAL("Unable to create '%s'", fn);
  close(fd);

  ck_free(fn);

  q->passed_det = 1;
}

/* Mark as variable. Create symlinks if possible to make it easier to examine
   the files. */

static void mark_as_variable(struct queue_entry *q)
{

  u8 *fn = strrchr(q->fname, '/') + 1, *ldest;

  ldest = alloc_printf("../../%s", fn);
  fn = alloc_printf("%s/queue/.state/variable_behavior/%s", out_dir, fn);

  if (symlink(ldest, fn))
  {

    s32 fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0)
      PFATAL("Unable to create '%s'", fn);
    close(fd);
  }

  ck_free(ldest);
  ck_free(fn);

  q->var_behavior = 1;
}

/* Mark / unmark as redundant (edge-only). This is not used for restoring state,
   but may be useful for post-processing datasets. */

static void mark_as_redundant(struct queue_entry *q, u8 state)
{

  u8 *fn;
  s32 fd;

  if (state == q->fs_redundant)
    return;

  q->fs_redundant = state;

  fn = strrchr(q->fname, '/');
  fn = alloc_printf("%s/queue/.state/redundant_edges/%s", out_dir, fn + 1);

  if (state)
  {

    fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0)
      PFATAL("Unable to create '%s'", fn);
    close(fd);
  }
  else
  {

    if (unlink(fn))
      PFATAL("Unable to remove '%s'", fn);
  }

  ck_free(fn);
}

/* Append new test case to the queue. */

static void add_to_queue(u8 *fname, u32 len, u8 passed_det)
{

  struct queue_entry *q = ck_alloc(sizeof(struct queue_entry));

  q->fname = fname;
  q->len = len;
  q->depth = cur_depth + 1;
  q->passed_det = passed_det;
  q->regions = NULL;
  q->region_count = 0;
  q->index = queued_paths;
  q->generating_state_id = target_state_id;
  q->is_initial_seed = 0;
  q->unique_state_count = 0;

  if (q->depth > max_depth)
    max_depth = q->depth;

  if (queue_top)
  {

    queue_top->next = q;
    queue_top = q;
  }
  else
    q_prev100 = queue = queue_top = q;

  queued_paths++;
  pending_not_fuzzed++;

  cycles_wo_finds = 0;

  if (!(queued_paths % 100))
  {

    q_prev100->next_100 = q;
    q_prev100 = q;
  }

  /* AFLNet: extract regions keeping client requests if needed */
  if (corpus_read_or_sync)
  {
    FILE *fp;
    unsigned char *buf;

    /* opening file for reading */
    fp = fopen(fname, "rb");

    buf = (unsigned char *)ck_alloc(len);
    u32 byte_count = fread(buf, 1, len, fp);
    fclose(fp);

    if (byte_count != len)
      PFATAL("AFLNet - Inconsistent file length '%s'", fname);
    q->regions = (*extract_requests)(buf, len, &q->region_count);
    ck_free(buf);

    // Keep track the maximal number of seed regions
    // We use this for some optimization to reduce the overhead while following the server's sequence diagram
    if ((corpus_read_or_sync == 1) && (q->region_count > max_seed_region_count))
      max_seed_region_count = q->region_count;
  }
  else
  {
    // Convert the linked list kl_messages to regions
    q->regions = convert_kl_messages_to_regions(kl_messages, &q->region_count, messages_sent);
  }

  /* save the regions' information to file for debugging purpose */
  u8 *fn = alloc_printf("%s/regions/%s", out_dir, basename(fname));
  save_regions_to_file(q->regions, q->region_count, fn);
  ck_free(fn);

  last_path_time = get_cur_time();

  // Add a new column to the was_fuzzed map
  if (fuzzed_map_states)
  {
    expand_was_fuzzed_map(0, 1);
  }
  else
  {
    // Also add a new row (for state 0) if needed
    expand_was_fuzzed_map(1, 1);
  }
}

/* Destroy the entire queue. */

EXP_ST void destroy_queue(void)
{

  struct queue_entry *q = queue, *n;

  while (q)
  {

    n = q->next;
    ck_free(q->fname);
    ck_free(q->trace_mini);
    u32 i;
    // Free AFLNet-specific data structure
    for (i = 0; i < q->region_count; i++)
    {
      if (q->regions[i].state_sequence)
        ck_free(q->regions[i].state_sequence);
    }
    if (q->regions)
      ck_free(q->regions);
    ck_free(q);
    q = n;
  }
}

/* Write bitmap to file. The bitmap is useful mostly for the secret
   -B option, to focus a separate fuzzing session on a particular
   interesting input without rediscovering all the others. */

EXP_ST void write_bitmap(void)
{

  u8 *fname;
  s32 fd;

  if (!bitmap_changed)
    return;
  bitmap_changed = 0;

  fname = alloc_printf("%s/fuzz_bitmap", out_dir);
  fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0600);

  if (fd < 0)
    PFATAL("Unable to open '%s'", fname);

  ck_write(fd, virgin_bits, MAP_SIZE, fname);

  close(fd);
  ck_free(fname);
}

/* Read bitmap from file. This is for the -B option again. */

EXP_ST void read_bitmap(u8 *fname)
{

  s32 fd = open(fname, O_RDONLY);

  if (fd < 0)
    PFATAL("Unable to open '%s'", fname);

  ck_read(fd, virgin_bits, MAP_SIZE, fname);

  close(fd);
}

/* Check if the current execution path brings anything new to the table.
   Update virgin bits to reflect the finds. Returns 1 if the only change is
   the hit-count for a particular tuple; 2 if there are new tuples seen.
   Updates the map, so subsequent calls will always return 0.

   This function is called after every exec() on a fairly large buffer, so
   it needs to be fast. We do this in 32-bit and 64-bit flavors. */

static inline u8 has_new_bits(u8 *virgin_map)
{

#ifdef WORD_SIZE_64

  u64 *current = (u64 *)trace_bits;
  u64 *virgin = (u64 *)virgin_map;

  u32 i = (MAP_SIZE >> 3);

#else

  u32 *current = (u32 *)trace_bits;
  u32 *virgin = (u32 *)virgin_map;

  u32 i = (MAP_SIZE >> 2);

#endif /* ^WORD_SIZE_64 */

  u8 ret = 0;

  while (i--)
  {

    /* Optimize for (*current & *virgin) == 0 - i.e., no bits in current bitmap
       that have not been already cleared from the virgin map - since this will
       almost always be the case. */

    if (unlikely(*current) && unlikely(*current & *virgin))
    {

      if (likely(ret < 2))
      {

        u8 *cur = (u8 *)current;
        u8 *vir = (u8 *)virgin;

        /* Looks like we have not found any new bytes yet; see if any non-zero
           bytes in current[] are pristine in virgin[]. */

#ifdef WORD_SIZE_64

        if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff) ||
            (cur[4] && vir[4] == 0xff) || (cur[5] && vir[5] == 0xff) ||
            (cur[6] && vir[6] == 0xff) || (cur[7] && vir[7] == 0xff))
          ret = 2;
        else
          ret = 1;

#else

        if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff))
          ret = 2;
        else
          ret = 1;

#endif /* ^WORD_SIZE_64 */
      }

      *virgin &= ~*current;
    }

    current++;
    virgin++;
  }

  if (ret && virgin_map == virgin_bits)
    bitmap_changed = 1;

  return ret;
}

/* Count the number of bits set in the provided bitmap. Used for the status
   screen several times every second, does not have to be fast. */

static u32 count_bits(u8 *mem)
{

  u32 *ptr = (u32 *)mem;
  u32 i = (MAP_SIZE >> 2);
  u32 ret = 0;

  while (i--)
  {

    u32 v = *(ptr++);

    /* This gets called on the inverse, virgin bitmap; optimize for sparse
       data. */

    if (v == 0xffffffff)
    {
      ret += 32;
      continue;
    }

    v -= ((v >> 1) & 0x55555555);
    v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
    ret += (((v + (v >> 4)) & 0xF0F0F0F) * 0x01010101) >> 24;
  }

  return ret;
}

#define FF(_b) (0xff << ((_b) << 3))

/* Count the number of bytes set in the bitmap. Called fairly sporadically,
   mostly to update the status screen or calibrate and examine confirmed
   new paths. */

static u32 count_bytes(u8 *mem)
{

  u32 *ptr = (u32 *)mem;
  u32 i = (MAP_SIZE >> 2);
  u32 ret = 0;

  while (i--)
  {

    u32 v = *(ptr++);

    if (!v)
      continue;
    if (v & FF(0))
      ret++;
    if (v & FF(1))
      ret++;
    if (v & FF(2))
      ret++;
    if (v & FF(3))
      ret++;
  }

  return ret;
}

/* Count the number of non-255 bytes set in the bitmap. Used strictly for the
   status screen, several calls per second or so. */

static u32 count_non_255_bytes(u8 *mem)
{

  u32 *ptr = (u32 *)mem;
  u32 i = (MAP_SIZE >> 2);
  u32 ret = 0;

  while (i--)
  {

    u32 v = *(ptr++);

    /* This is called on the virgin bitmap, so optimize for the most likely
       case. */

    if (v == 0xffffffff)
      continue;
    if ((v & FF(0)) != FF(0))
      ret++;
    if ((v & FF(1)) != FF(1))
      ret++;
    if ((v & FF(2)) != FF(2))
      ret++;
    if ((v & FF(3)) != FF(3))
      ret++;
  }

  return ret;
}

/* Destructively simplify trace by eliminating hit count information
   and replacing it with 0x80 or 0x01 depending on whether the tuple
   is hit or not. Called on every new crash or timeout, should be
   reasonably fast. */

static const u8 simplify_lookup[256] = {

    [0] = 1,
    [1 ... 255] = 128

};

#ifdef WORD_SIZE_64

static void simplify_trace(u64 *mem)
{

  u32 i = MAP_SIZE >> 3;

  while (i--)
  {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem))
    {

      u8 *mem8 = (u8 *)mem;

      mem8[0] = simplify_lookup[mem8[0]];
      mem8[1] = simplify_lookup[mem8[1]];
      mem8[2] = simplify_lookup[mem8[2]];
      mem8[3] = simplify_lookup[mem8[3]];
      mem8[4] = simplify_lookup[mem8[4]];
      mem8[5] = simplify_lookup[mem8[5]];
      mem8[6] = simplify_lookup[mem8[6]];
      mem8[7] = simplify_lookup[mem8[7]];
    }
    else
      *mem = 0x0101010101010101ULL;

    mem++;
  }
}

#else

static void simplify_trace(u32 *mem)
{

  u32 i = MAP_SIZE >> 2;

  while (i--)
  {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem))
    {

      u8 *mem8 = (u8 *)mem;

      mem8[0] = simplify_lookup[mem8[0]];
      mem8[1] = simplify_lookup[mem8[1]];
      mem8[2] = simplify_lookup[mem8[2]];
      mem8[3] = simplify_lookup[mem8[3]];
    }
    else
      *mem = 0x01010101;

    mem++;
  }
}

#endif /* ^WORD_SIZE_64 */

/* Destructively classify execution counts in a trace. This is used as a
   preprocessing step for any newly acquired traces. Called on every exec,
   must be fast. */

static const u8 count_class_lookup8[256] = {

    [0] = 0,
    [1] = 1,
    [2] = 2,
    [3] = 4,
    [4 ... 7] = 8,
    [8 ... 15] = 16,
    [16 ... 31] = 32,
    [32 ... 127] = 64,
    [128 ... 255] = 128

};

static u16 count_class_lookup16[65536];

EXP_ST void init_count_class16(void)
{

  u32 b1, b2;

  for (b1 = 0; b1 < 256; b1++)
    for (b2 = 0; b2 < 256; b2++)
      count_class_lookup16[(b1 << 8) + b2] =
          (count_class_lookup8[b1] << 8) |
          count_class_lookup8[b2];
}

#ifdef WORD_SIZE_64

static inline void classify_counts(u64 *mem)
{

  u32 i = MAP_SIZE >> 3;

  while (i--)
  {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem))
    {

      u16 *mem16 = (u16 *)mem;

      mem16[0] = count_class_lookup16[mem16[0]];
      mem16[1] = count_class_lookup16[mem16[1]];
      mem16[2] = count_class_lookup16[mem16[2]];
      mem16[3] = count_class_lookup16[mem16[3]];
    }

    mem++;
  }
}

#else

static inline void classify_counts(u32 *mem)
{

  u32 i = MAP_SIZE >> 2;

  while (i--)
  {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem))
    {

      u16 *mem16 = (u16 *)mem;

      mem16[0] = count_class_lookup16[mem16[0]];
      mem16[1] = count_class_lookup16[mem16[1]];
    }

    mem++;
  }
}

#endif /* ^WORD_SIZE_64 */

/* Get rid of shared memory (atexit handler). */

static void remove_shm(void)
{

  shmctl(shm_id, IPC_RMID, NULL);
}

/* Compact trace bytes into a smaller bitmap. We effectively just drop the
   count information here. This is called only sporadically, for some
   new paths. */

static void minimize_bits(u8 *dst, u8 *src)
{

  u32 i = 0;

  while (i < MAP_SIZE)
  {

    if (*(src++))
      dst[i >> 3] |= 1 << (i & 7);
    i++;
  }
}

/* When we bump into a new path, we call this to see if the path appears
   more "favorable" than any of the existing ones. The purpose of the
   "favorables" is to have a minimal set of paths that trigger all the bits
   seen in the bitmap so far, and focus on fuzzing them at the expense of
   the rest.

   The first step of the process is to maintain a list of top_rated[] entries
   for every byte in the bitmap. We win that slot if there is no previous
   contender, or if the contender has smaller unique state count or
   it has a more favorable speed x size factor. */

static void update_bitmap_score(struct queue_entry *q)
{

  u32 i;
  u64 fav_factor = q->exec_us * q->len;

  /* For every byte set in trace_bits[], see if there is a previous winner,
     and how it compares to us. */

  for (i = 0; i < MAP_SIZE; i++)

    if (trace_bits[i])
    {

      if (top_rated[i])
      {

        /* AFLNet check unique state count first */

        if (q->unique_state_count < top_rated[i]->unique_state_count)
          continue;

        /* Faster-executing or smaller test cases are favored. */

        if ((q->unique_state_count < top_rated[i]->unique_state_count) && (fav_factor > top_rated[i]->exec_us * top_rated[i]->len))
          continue;

        /* Looks like we're going to win. Decrease ref count for the
           previous winner, discard its trace_bits[] if necessary. */

        if (!--top_rated[i]->tc_ref)
        {
          ck_free(top_rated[i]->trace_mini);
          top_rated[i]->trace_mini = 0;
        }
      }

      /* Insert ourselves as the new winner. */

      top_rated[i] = q;
      q->tc_ref++;

      if (!q->trace_mini)
      {
        q->trace_mini = ck_alloc(MAP_SIZE >> 3);
        minimize_bits(q->trace_mini, trace_bits);
      }

      score_changed = 1;
    }
}

/* The second part of the mechanism discussed above is a routine that
   goes over top_rated[] entries, and then sequentially grabs winners for
   previously-unseen bytes (temp_v) and marks them as favored, at least
   until the next run. The favored entries are given more air time during
   all fuzzing steps. */

static void cull_queue(void)
{

  struct queue_entry *q;
  static u8 temp_v[MAP_SIZE >> 3];
  u32 i;

  if (dumb_mode || !score_changed)
    return;

  score_changed = 0;

  memset(temp_v, 255, MAP_SIZE >> 3);

  queued_favored = 0;
  pending_favored = 0;

  q = queue;

  while (q)
  {
    if (!q->is_initial_seed)
      q->favored = 0;
    q = q->next;
  }

  /* Let's see if anything in the bitmap isn't captured in temp_v.
     If yes, and if it has a top_rated[] contender, let's use it. */

  for (i = 0; i < MAP_SIZE; i++)
    if (top_rated[i] && (temp_v[i >> 3] & (1 << (i & 7))))
    {

      u32 j = MAP_SIZE >> 3;

      /* Remove all bits belonging to the current entry from temp_v. */

      while (j--)
        if (top_rated[i]->trace_mini[j])
          temp_v[j] &= ~top_rated[i]->trace_mini[j];

      top_rated[i]->favored = 1;
      queued_favored++;

      // if (!top_rated[i]->was_fuzzed) pending_favored++;
      /* AFLNet takes into account more information to make this decision */
      if ((top_rated[i]->generating_state_id == target_state_id || top_rated[i]->is_initial_seed) && (was_fuzzed_map[get_state_index(target_state_id)][top_rated[i]->index] == 0))
        pending_favored++;
    }

  q = queue;

  while (q)
  {
    mark_as_redundant(q, !q->favored);
    q = q->next;
  }
}

/* Configure shared memory and virgin_bits. This is called at startup. */

EXP_ST void setup_shm(void)
{

  u8 *shm_str;

  if (!in_bitmap)
    memset(virgin_bits, 255, MAP_SIZE);

  memset(virgin_tmout, 255, MAP_SIZE);
  memset(virgin_crash, 255, MAP_SIZE);

  shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);

  if (shm_id < 0)
    PFATAL("shmget() failed");

  atexit(remove_shm);

  shm_str = alloc_printf("%d", shm_id);

  /* If somebody is asking us to fuzz instrumented binaries in dumb mode,
     we don't want them to detect instrumentation, since we won't be sending
     fork server commands. This should be replaced with better auto-detection
     later on, perhaps? */

  if (!dumb_mode)
    setenv(SHM_ENV_VAR, shm_str, 1);

  ck_free(shm_str);

  trace_bits = shmat(shm_id, NULL, 0);

  if (!trace_bits)
    PFATAL("shmat() failed");
}

/* Load postprocessor, if available. */

static void setup_post(void)
{

  void *dh;
  u8 *fn = getenv("AFL_POST_LIBRARY");
  u32 tlen = 6;

  if (!fn)
    return;

  ACTF("Loading postprocessor from '%s'...", fn);

  dh = dlopen(fn, RTLD_NOW);
  if (!dh)
    FATAL("%s", dlerror());

  post_handler = dlsym(dh, "afl_postprocess");
  if (!post_handler)
    FATAL("Symbol 'afl_postprocess' not found.");

  /* Do a quick test. It's better to segfault now than later =) */

  post_handler("hello", &tlen);

  OKF("Postprocessor installed successfully.");
}

void get_seeds_with_messsage_types(const char *in_dir, khash_t(strSet) * message_types_set)
{
  // const char *in_dir: 指定一个目录路径，该函数将在这个目录下查找文件。
  // khash_t(strSet) * message_types_set: 这是一个哈希集合，包含了需要在文件中寻找的所有消息类型。

  struct dirent **nl_files;
  int nl_cnt = scandir(in_dir, &nl_files, NULL, alphasort); // 扫描指定目录，获取文件列表
  if (nl_cnt < 0)
  {
    printf("Error in reading the directory %s\n", in_dir); // 如果目录读取失败，打印错误信息并退出
    exit(1);
  }

  // 遍历目录以读取文件
  for (int i = 0; i < nl_cnt; i++)
  {
    char *nl_file_name = nl_files[i]->d_name; // 获取文件名
    // 跳过 . 和 .. 以及名称中包含 "enriched" 的文件
    if (strcmp(nl_file_name, ".") == 0 || strcmp(nl_file_name, "..") == 0 || strstr(nl_file_name, "enriched") != NULL)
    {
      continue;
    }
    char *nl_file_path = malloc(strlen(in_dir) + strlen(nl_file_name) + 2); // 分配内存构建文件路径
    strcpy(nl_file_path, in_dir);
    strcat(nl_file_path, "/");
    strcat(nl_file_path, nl_file_name);
    // printf("## File path: %s\n", nl_file_path); // 打印文件路径（调试用）

    FILE *nl_file = fopen(nl_file_path, "r"); // 打开文件
    if (nl_file == NULL)
    {
      printf("Error in opening the file %s\n", nl_file_path); // 如果文件打开失败，打印错误信息并退出
      exit(1);
    }

    // 将整个文件读入缓冲区
    fseek(nl_file, 0, SEEK_END); // 移动文件指针到文件末尾
    size_t fsize = ftell(nl_file); // 获取文件大小
    fseek(nl_file, 0, SEEK_SET); // 移动文件指针到文件开头
    char *nl_file_content = malloc(fsize + 1); // 分配内存以存储文件内容
    fread(nl_file_content, fsize, 1, nl_file); // 读取文件内容到缓冲区
    nl_file_content[fsize] = '\0'; // 确保字符串以 \0 结尾
    // printf("## File content:\n %s\n", nl_file_content); // 打印文件内容（调试用）
    fclose(nl_file); // 关闭文件
    free(nl_file_path); // 释放文件路径内存

    u32 region_count = 0;
    region_t *regions = (*extract_requests)(nl_file_content, fsize, &region_count); // 提取文件中的请求区域

    khash_t(strSet) *messages = duplicate_hash(message_types_set); // 复制消息类型集

    // 遍历每个请求区域
    for (int j = 0; j < region_count; j++)
    { 
      // 移除所有已观察到的消息类型
      int header_len = 0;
      while (regions[j].start_byte + header_len < regions[j].end_byte 
             && nl_file_content[regions[j].start_byte + header_len] != ' ' 
             && nl_file_content[regions[j].start_byte + header_len] != '\r' 
             && nl_file_content[regions[j].start_byte + header_len] != '\n'
             && nl_file_content[regions[j].start_byte + header_len] != '\\')
      {
        header_len++; // 计算消息头长度
      }

      char *header = ck_alloc(header_len + 1); // 分配内存存储消息头
      memcpy(header, nl_file_content + regions[j].start_byte, header_len); // 拷贝消息头
      header[header_len] = '\0'; // 确保字符串以 \0 结尾

      khiter_t k = kh_get(strSet, messages, header); // 查找消息头是否存在于消息类型集中
      if (kh_exist(messages, k))
      {
        kh_del(strSet, messages, k); // 如果存在，从消息类型集中移除
      }
      ck_free(header); // 释放消息头内存
    }

    ck_free(regions); // 释放请求区域内存

    // 如果没有缺失的消息类型，跳过增强
    if (kh_size(messages) == 0) 
    {
      kh_destroy(strSet, messages); // 销毁消息类型集
      WARNF("Message %s already has all message types. Skipping enrichment", nl_file_name); // 打印警告信息
      continue;
    }

    // 如果消息类型集超过最大增强语料库大小，随机删除多余的消息类型
    while (kh_size(messages) > MAX_ENRICHMENT_CORPUS_SIZE) 
    {
      khiter_t x = UR(kh_end(messages)); // 随机选择一个消息类型
      if (kh_exist(messages, x))
      {
        kh_del(strSet, messages, x); // 删除选中的消息类型
      }
    }

    // 生成消息类型组合
    message_set_list message_subsets = message_combinations(messages, MAX_ENRICHMENT_MESSAGE_TYPES);

    // 遍历每个消息类型组合
    for (int i = 0; i < kv_size(message_subsets); i++)
    {
      khash_t(strSet) *subset = kv_A(message_subsets, i); // 获取当前组合

      // 尝试增强序列
      char *client_request_answer = enrich_sequence(nl_file_content, subset);

      if (client_request_answer == NULL)
        continue; // 如果增强失败，跳过

      // 检查 client_request_answer 是否与 nl_file_content 相同或为空
      char *formatted_nl_file_content = format_string(nl_file_content); // 格式化原始文件内容
      char *unescaped_client_requests = unescape_string(client_request_answer); // 去除转义字符
      char *formatted_unescaped_client_requests = format_string(unescaped_client_requests); // 格式化去转义后的请求
      // printf("## Formatted answer from LLM:\n %s\n", formatted_unescaped_client_requests); // 打印格式化后的 LLM 回答（调试用）
      // printf("## Formatted file content:\n %s\n", formatted_nl_file_content); // 打印格式化后的文件内容（调试用）
      if (formatted_unescaped_client_requests == NULL || strcmp(formatted_unescaped_client_requests, formatted_nl_file_content) == 0)
      {
        printf("## Skip the same seed\n"); // 如果内容相同，跳过
        continue;
      }

      unescaped_client_requests = format_request_message(unescaped_client_requests); // 格式化请求消息

      // 在同一目录下创建文件，名称为 enriched_state_<file_name>
      char *enriched_file_name = malloc(strlen(nl_file_name) + 10 + 20); // 分配内存构建增强文件名
      strcpy(enriched_file_name, "enriched_");
      sprintf(enriched_file_name + 9, "%d_", i); // 添加索引
      strcat(enriched_file_name, nl_file_name); // 拼接文件名
      char *enriched_file_path = malloc(strlen(in_dir) + strlen(enriched_file_name) + 2); // 分配内存构建增强文件路径
      strcpy(enriched_file_path, in_dir);
      strcat(enriched_file_path, "/");
      strcat(enriched_file_path, enriched_file_name);
      // printf("## Enriched file path: %s\n", enriched_file_path); // 打印增强文件路径（调试用）

      write_new_seeds(enriched_file_path, unescaped_client_requests); // 写入新的种子文件

      free(enriched_file_name); // 释放增强文件名内存
      free(enriched_file_path); // 释放增强文件路径内存
    }

    // 释放消息类型组合内存
    for (int i = 0; i < kv_size(message_subsets); i++)
    {
      khash_t(strSet) *subset = kv_A(message_subsets, i);
      kh_destroy(strSet, subset);
    } 

    kh_destroy(strSet, messages); // 销毁消息类型集
  }
}
/* Enrich the testcases before startup */
static void enrich_testcases(void)
{
  ACTF("Enriching test cases from LLM...");

  // char *message_prompt = construct_prompt_for_protocol_message_types(protocol_name);

  // // Get protocol states
  // get_protocol_message_types(message_prompt, message_type_set);

  // free(message_prompt);

  // Get seeds to states and save them to the in_dir
  get_seeds_with_messsage_types(in_dir, message_types_set);
}

/* Read all testcases from the input directory, then queue them for testing.
   Called at startup. */

static void read_testcases(void)
{

  struct dirent **nl;
  s32 nl_cnt;
  u32 i;
  u8 *fn;

  /* AFLNet: set this flag to enable request extractions while adding new seed to the queue */
  corpus_read_or_sync = 1;

  /* Auto-detect non-in-place resumption attempts. */

  fn = alloc_printf("%s/queue", in_dir);
  if (!access(fn, F_OK))
    in_dir = fn;
  else
    ck_free(fn);

  ACTF("Scanning '%s'...", in_dir);

  /* We use scandir() + alphasort() rather than readdir() because otherwise,
     the ordering  of test cases would vary somewhat randomly and would be
     difficult to control. */

  nl_cnt = scandir(in_dir, &nl, NULL, alphasort);

  if (nl_cnt < 0)
  {

    if (errno == ENOENT || errno == ENOTDIR)

      SAYF("\n" cLRD "[-] " cRST
           "The input directory does not seem to be valid - try again. The fuzzer needs\n"
           "    one or more test case to start with - ideally, a small file under 1 kB\n"
           "    or so. The cases must be stored as regular files directly in the input\n"
           "    directory.\n");

    PFATAL("Unable to open '%s'", in_dir);
  }

  if (shuffle_queue && nl_cnt > 1)
  {

    ACTF("Shuffling queue...");
    shuffle_ptrs((void **)nl, nl_cnt);
  }

  for (i = 0; i < nl_cnt; i++)
  {

    struct stat st;

    u8 *fn = alloc_printf("%s/%s", in_dir, nl[i]->d_name);
    u8 *dfn = alloc_printf("%s/.state/deterministic_done/%s", in_dir, nl[i]->d_name);

    u8 passed_det = 0;

    free(nl[i]); /* not tracked */

    if (lstat(fn, &st) || access(fn, R_OK))
      PFATAL("Unable to access '%s'", fn);

    /* This also takes care of . and .. */

    if (!S_ISREG(st.st_mode) || !st.st_size || strstr(fn, "/README.txt"))
    {

      ck_free(fn);
      ck_free(dfn);
      continue;
    }

    if (st.st_size > MAX_FILE)
      FATAL("Test case '%s' is too big (%s, limit is %s)", fn,
            DMS(st.st_size), DMS(MAX_FILE));

    /* Check for metadata that indicates that deterministic fuzzing
       is complete for this entry. We don't want to repeat deterministic
       fuzzing when resuming aborted scans, because it would be pointless
       and probably very time-consuming. */

    if (!access(dfn, F_OK))
      passed_det = 1;
    ck_free(dfn);

    add_to_queue(fn, st.st_size, passed_det);
  }

  /* AFLNet: unset this flag to disable request extractions while adding new seed to the queue */
  corpus_read_or_sync = 0;

  free(nl); /* not tracked */

  if (!queued_paths)
  {

    SAYF("\n" cLRD "[-] " cRST
         "Looks like there are no valid test cases in the input directory! The fuzzer\n"
         "    needs one or more test case to start with - ideally, a small file under\n"
         "    1 kB or so. The cases must be stored as regular files directly in the\n"
         "    input directory.\n");

    FATAL("No usable test cases in '%s'", in_dir);
  }

  last_path_time = 0;
  queued_at_start = queued_paths;
}

/* Helper function for load_extras. */

static int compare_extras_len(const void *p1, const void *p2)
{
  struct extra_data *e1 = (struct extra_data *)p1,
                    *e2 = (struct extra_data *)p2;

  return e1->len - e2->len;
}

static int compare_extras_use_d(const void *p1, const void *p2)
{
  struct extra_data *e1 = (struct extra_data *)p1,
                    *e2 = (struct extra_data *)p2;

  return e2->hit_cnt - e1->hit_cnt;
}

/* Read extras from a file, sort by size. */

static void load_extras_file(u8 *fname, u32 *min_len, u32 *max_len,
                             u32 dict_level)
{

  FILE *f;
  u8 buf[MAX_LINE];
  u8 *lptr;
  u32 cur_line = 0;

  f = fopen(fname, "r");

  if (!f)
    PFATAL("Unable to open '%s'", fname);

  while ((lptr = fgets(buf, MAX_LINE, f)))
  {

    u8 *rptr, *wptr;
    u32 klen = 0;

    cur_line++;

    /* Trim on left and right. */

    while (isspace(*lptr))
      lptr++;

    rptr = lptr + strlen(lptr) - 1;
    while (rptr >= lptr && isspace(*rptr))
      rptr--;
    rptr++;
    *rptr = 0;

    /* Skip empty lines and comments. */

    if (!*lptr || *lptr == '#')
      continue;

    /* All other lines must end with '"', which we can consume. */

    rptr--;

    if (rptr < lptr || *rptr != '"')
      FATAL("Malformed name=\"value\" pair in line %u.", cur_line);

    *rptr = 0;

    /* Skip alphanumerics and dashes (label). */

    while (isalnum(*lptr) || *lptr == '_')
      lptr++;

    /* If @number follows, parse that. */

    if (*lptr == '@')
    {

      lptr++;
      if (atoi(lptr) > dict_level)
        continue;
      while (isdigit(*lptr))
        lptr++;
    }

    /* Skip whitespace and = signs. */

    while (isspace(*lptr) || *lptr == '=')
      lptr++;

    /* Consume opening '"'. */

    if (*lptr != '"')
      FATAL("Malformed name=\"keyword\" pair in line %u.", cur_line);

    lptr++;

    if (!*lptr)
      FATAL("Empty keyword in line %u.", cur_line);

    /* Okay, let's allocate memory and copy data between "...", handling
       \xNN escaping, \\, and \". */

    extras = ck_realloc_block(extras, (extras_cnt + 1) *
                                          sizeof(struct extra_data));

    wptr = extras[extras_cnt].data = ck_alloc(rptr - lptr);

    while (*lptr)
    {

      char *hexdigits = "0123456789abcdef";

      switch (*lptr)
      {

      case 1 ... 31:
      case 128 ... 255:
        FATAL("Non-printable characters in line %u.", cur_line);

      case '\\':

        lptr++;

        if (*lptr == '\\' || *lptr == '"')
        {
          *(wptr++) = *(lptr++);
          klen++;
          break;
        }

        if (*lptr != 'x' || !isxdigit(lptr[1]) || !isxdigit(lptr[2]))
          FATAL("Invalid escaping (not \\xNN) in line %u.", cur_line);

        *(wptr++) =
            ((strchr(hexdigits, tolower(lptr[1])) - hexdigits) << 4) |
            (strchr(hexdigits, tolower(lptr[2])) - hexdigits);

        lptr += 3;
        klen++;

        break;

      default:

        *(wptr++) = *(lptr++);
        klen++;
      }
    }

    extras[extras_cnt].len = klen;

    if (extras[extras_cnt].len > MAX_DICT_FILE)
      FATAL("Keyword too big in line %u (%s, limit is %s)", cur_line,
            DMS(klen), DMS(MAX_DICT_FILE));

    if (*min_len > klen)
      *min_len = klen;
    if (*max_len < klen)
      *max_len = klen;

    extras_cnt++;
  }

  fclose(f);
}

/* Read extras from the extras directory and sort them by size. */

static void load_extras(u8 *dir)
{

  DIR *d;
  struct dirent *de;
  u32 min_len = MAX_DICT_FILE, max_len = 0, dict_level = 0;
  u8 *x;

  /* If the name ends with @, extract level and continue. */

  if ((x = strchr(dir, '@')))
  {

    *x = 0;
    dict_level = atoi(x + 1);
  }

  ACTF("Loading extra dictionary from '%s' (level %u)...", dir, dict_level);

  d = opendir(dir);

  if (!d)
  {

    if (errno == ENOTDIR)
    {
      load_extras_file(dir, &min_len, &max_len, dict_level);
      goto check_and_sort;
    }

    PFATAL("Unable to open '%s'", dir);
  }

  if (x)
    FATAL("Dictionary levels not supported for directories.");

  while ((de = readdir(d)))
  {

    struct stat st;
    u8 *fn = alloc_printf("%s/%s", dir, de->d_name);
    s32 fd;

    if (lstat(fn, &st) || access(fn, R_OK))
      PFATAL("Unable to access '%s'", fn);

    /* This also takes care of . and .. */
    if (!S_ISREG(st.st_mode) || !st.st_size)
    {

      ck_free(fn);
      continue;
    }

    if (st.st_size > MAX_DICT_FILE)
      FATAL("Extra '%s' is too big (%s, limit is %s)", fn,
            DMS(st.st_size), DMS(MAX_DICT_FILE));

    if (min_len > st.st_size)
      min_len = st.st_size;
    if (max_len < st.st_size)
      max_len = st.st_size;

    extras = ck_realloc_block(extras, (extras_cnt + 1) *
                                          sizeof(struct extra_data));

    extras[extras_cnt].data = ck_alloc(st.st_size);
    extras[extras_cnt].len = st.st_size;

    fd = open(fn, O_RDONLY);

    if (fd < 0)
      PFATAL("Unable to open '%s'", fn);

    ck_read(fd, extras[extras_cnt].data, st.st_size, fn);

    close(fd);
    ck_free(fn);

    extras_cnt++;
  }

  closedir(d);

check_and_sort:

  if (!extras_cnt)
    FATAL("No usable files in '%s'", dir);

  qsort(extras, extras_cnt, sizeof(struct extra_data), compare_extras_len);

  OKF("Loaded %u extra tokens, size range %s to %s.", extras_cnt,
      DMS(min_len), DMS(max_len));

  if (max_len > 32)
    WARNF("Some tokens are relatively large (%s) - consider trimming.",
          DMS(max_len));

  if (extras_cnt > MAX_DET_EXTRAS)
    WARNF("More than %u tokens - will use them probabilistically.",
          MAX_DET_EXTRAS);
}

/* Helper function for maybe_add_auto() */

static inline u8 memcmp_nocase(u8 *m1, u8 *m2, u32 len)
{

  while (len--)
    if (tolower(*(m1++)) ^ tolower(*(m2++)))
      return 1;
  return 0;
}

/* Maybe add automatic extra. */

static void maybe_add_auto(u8 *mem, u32 len)
{

  u32 i;

  /* Allow users to specify that they don't want auto dictionaries. */

  if (!MAX_AUTO_EXTRAS || !USE_AUTO_EXTRAS)
    return;

  /* Skip runs of identical bytes. */

  for (i = 1; i < len; i++)
    if (mem[0] ^ mem[i])
      break;

  if (i == len)
    return;

  /* Reject builtin interesting values. */

  if (len == 2)
  {

    i = sizeof(interesting_16) >> 1;

    while (i--)
      if (*((u16 *)mem) == interesting_16[i] ||
          *((u16 *)mem) == SWAP16(interesting_16[i]))
        return;
  }

  if (len == 4)
  {

    i = sizeof(interesting_32) >> 2;

    while (i--)
      if (*((u32 *)mem) == interesting_32[i] ||
          *((u32 *)mem) == SWAP32(interesting_32[i]))
        return;
  }

  /* Reject anything that matches existing extras. Do a case-insensitive
     match. We optimize by exploiting the fact that extras[] are sorted
     by size. */

  for (i = 0; i < extras_cnt; i++)
    if (extras[i].len >= len)
      break;

  for (; i < extras_cnt && extras[i].len == len; i++)
    if (!memcmp_nocase(extras[i].data, mem, len))
      return;

  /* Last but not least, check a_extras[] for matches. There are no
     guarantees of a particular sort order. */

  auto_changed = 1;

  for (i = 0; i < a_extras_cnt; i++)
  {

    if (a_extras[i].len == len && !memcmp_nocase(a_extras[i].data, mem, len))
    {

      a_extras[i].hit_cnt++;
      goto sort_a_extras;
    }
  }

  /* At this point, looks like we're dealing with a new entry. So, let's
     append it if we have room. Otherwise, let's randomly evict some other
     entry from the bottom half of the list. */

  if (a_extras_cnt < MAX_AUTO_EXTRAS)
  {

    a_extras = ck_realloc_block(a_extras, (a_extras_cnt + 1) *
                                              sizeof(struct extra_data));

    a_extras[a_extras_cnt].data = ck_memdup(mem, len);
    a_extras[a_extras_cnt].len = len;
    a_extras_cnt++;
  }
  else
  {

    i = MAX_AUTO_EXTRAS / 2 +
        UR((MAX_AUTO_EXTRAS + 1) / 2);

    ck_free(a_extras[i].data);

    a_extras[i].data = ck_memdup(mem, len);
    a_extras[i].len = len;
    a_extras[i].hit_cnt = 0;
  }

sort_a_extras:

  /* First, sort all auto extras by use count, descending order. */

  qsort(a_extras, a_extras_cnt, sizeof(struct extra_data),
        compare_extras_use_d);

  /* Then, sort the top USE_AUTO_EXTRAS entries by size. */

  qsort(a_extras, MIN(USE_AUTO_EXTRAS, a_extras_cnt),
        sizeof(struct extra_data), compare_extras_len);
}

/* Save automatically generated extras. */

static void save_auto(void)
{

  u32 i;

  if (!auto_changed)
    return;
  auto_changed = 0;

  for (i = 0; i < MIN(USE_AUTO_EXTRAS, a_extras_cnt); i++)
  {

    u8 *fn = alloc_printf("%s/queue/.state/auto_extras/auto_%06u", out_dir, i);
    s32 fd;

    fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);

    if (fd < 0)
      PFATAL("Unable to create '%s'", fn);

    ck_write(fd, a_extras[i].data, a_extras[i].len, fn);

    close(fd);
    ck_free(fn);
  }
}

/* Load automatically generated extras. */

static void load_auto(void)
{

  u32 i;

  for (i = 0; i < USE_AUTO_EXTRAS; i++)
  {

    u8 tmp[MAX_AUTO_EXTRA + 1];
    u8 *fn = alloc_printf("%s/.state/auto_extras/auto_%06u", in_dir, i);
    s32 fd, len;

    fd = open(fn, O_RDONLY, 0600);

    if (fd < 0)
    {

      if (errno != ENOENT)
        PFATAL("Unable to open '%s'", fn);
      ck_free(fn);
      break;
    }

    /* We read one byte more to cheaply detect tokens that are too
       long (and skip them). */

    len = read(fd, tmp, MAX_AUTO_EXTRA + 1);

    if (len < 0)
      PFATAL("Unable to read from '%s'", fn);

    if (len >= MIN_AUTO_EXTRA && len <= MAX_AUTO_EXTRA)
      maybe_add_auto(tmp, len);

    close(fd);
    ck_free(fn);
  }

  if (i)
    OKF("Loaded %u auto-discovered dictionary tokens.", i);
  else
    OKF("No auto-generated dictionary tokens to reuse.");
}

/* Destroy extras. */

static void destroy_extras(void)
{

  u32 i;

  for (i = 0; i < extras_cnt; i++)
    ck_free(extras[i].data);

  ck_free(extras);

  for (i = 0; i < a_extras_cnt; i++)
    ck_free(a_extras[i].data);

  ck_free(a_extras);
}

/* Move process to the network namespace "netns_name" */

static void move_process_to_netns()
{
  const char *netns_path_fmt = "/var/run/netns/%s";
  char netns_path[272]; /* 15 for "/var/.." + 256 for netns name + 1 '\0' */
  int netns_fd;

  if (strlen(netns_name) > 256)
    FATAL("Network namespace name \"%s\" is too long", netns_name);

  sprintf(netns_path, netns_path_fmt, netns_name);

  netns_fd = open(netns_path, O_RDONLY);
  if (netns_fd == -1)
    PFATAL("Unable to open %s", netns_path);

  if (setns(netns_fd, CLONE_NEWNET) == -1)
    PFATAL("setns failed");
}

/* Spin up fork server (instrumented mode only). The idea is explained here:

   http://lcamtuf.blogspot.com/2014/10/fuzzing-binaries-without-execve.html

   In essence, the instrumentation allows us to skip execve(), and just keep
   cloning a stopped child. So, we just execute once, and then send commands
   through a pipe. The other part of this logic is in afl-as.h. */

EXP_ST void init_forkserver(char **argv)
{

  static struct itimerval it;
  int st_pipe[2], ctl_pipe[2];
  int status;
  s32 rlen;

  ACTF("Spinning up the fork server...");

  if (pipe(st_pipe) || pipe(ctl_pipe))
    PFATAL("pipe() failed");

  forksrv_pid = fork();

  if (forksrv_pid < 0)
    PFATAL("fork() failed");

  if (!forksrv_pid)
  {

    struct rlimit r;

    /* Umpf. On OpenBSD, the default fd limit for root users is set to
       soft 128. Let's try to fix that... */

    if (!getrlimit(RLIMIT_NOFILE, &r) && r.rlim_cur < FORKSRV_FD + 2)
    {

      r.rlim_cur = FORKSRV_FD + 2;
      setrlimit(RLIMIT_NOFILE, &r); /* Ignore errors */
    }

    if (mem_limit)
    {

      r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;

#ifdef RLIMIT_AS

      setrlimit(RLIMIT_AS, &r); /* Ignore errors */

#else

      /* This takes care of OpenBSD, which doesn't have RLIMIT_AS, but
         according to reliable sources, RLIMIT_DATA covers anonymous
         maps - so we should be getting good protection against OOM bugs. */

      setrlimit(RLIMIT_DATA, &r); /* Ignore errors */

#endif /* ^RLIMIT_AS */
    }

    /* Dumping cores is slow and can lead to anomalies if SIGKILL is delivered
       before the dump is complete. */

    r.rlim_max = r.rlim_cur = 0;

    setrlimit(RLIMIT_CORE, &r); /* Ignore errors */

    /* Move the process to the different namespace. */

    if (netns_name)
      move_process_to_netns();

    /* Isolate the process and configure standard descriptors. If out_file is
       specified, stdin is /dev/null; otherwise, out_fd is cloned instead. */

    setsid();

    dup2(dev_null_fd, 1);
    dup2(dev_null_fd, 2);

    if (out_file)
    {

      dup2(dev_null_fd, 0);
    }
    else
    {

      dup2(out_fd, 0);
      close(out_fd);
    }

    /* Set up control and status pipes, close the unneeded original fds. */

    if (dup2(ctl_pipe[0], FORKSRV_FD) < 0)
      PFATAL("dup2() failed");
    if (dup2(st_pipe[1], FORKSRV_FD + 1) < 0)
      PFATAL("dup2() failed");

    close(ctl_pipe[0]);
    close(ctl_pipe[1]);
    close(st_pipe[0]);
    close(st_pipe[1]);

    close(out_dir_fd);
    close(dev_null_fd);
    close(dev_urandom_fd);
    close(fileno(plot_file));

    /* This should improve performance a bit, since it stops the linker from
       doing extra work post-fork(). */

    if (!getenv("LD_BIND_LAZY"))
      setenv("LD_BIND_NOW", "1", 0);

    /* Set sane defaults for ASAN if nothing else specified. */

    setenv("ASAN_OPTIONS", "abort_on_error=1:"
                           "detect_leaks=0:"
                           "symbolize=0:"
                           "allocator_may_return_null=1",
           0);

    /* MSAN is tricky, because it doesn't support abort_on_error=1 at this
       point. So, we do this in a very hacky way. */

    setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                                                              "symbolize=0:"
                                                              "abort_on_error=1:"
                                                              "allocator_may_return_null=1:"
                                                              "msan_track_origins=0",
           0);

    execv(target_path, argv);

    /* Use a distinctive bitmap signature to tell the parent about execv()
       falling through. */

    *(u32 *)trace_bits = EXEC_FAIL_SIG;
    exit(0);
  }

  /* Close the unneeded endpoints. */

  close(ctl_pipe[0]);
  close(st_pipe[1]);

  fsrv_ctl_fd = ctl_pipe[1];
  fsrv_st_fd = st_pipe[0];

  /* Wait for the fork server to come up, but don't wait too long. */

  it.it_value.tv_sec = ((exec_tmout * FORK_WAIT_MULT) / 1000);
  it.it_value.tv_usec = ((exec_tmout * FORK_WAIT_MULT) % 1000) * 1000;

  setitimer(ITIMER_REAL, &it, NULL);

  rlen = read(fsrv_st_fd, &status, 4);

  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  /* If we have a four-byte "hello" message from the server, we're all set.
     Otherwise, try to figure out what went wrong. */

  if (rlen == 4)
  {
    OKF("All right - fork server is up.");
    return;
  }

  if (child_timed_out)
    FATAL("Timeout while initializing fork server (adjusting -t may help)");

  if (waitpid(forksrv_pid, &status, 0) <= 0)
    PFATAL("waitpid() failed");

  if (WIFSIGNALED(status))
  {

    if (mem_limit && mem_limit < 500 && uses_asan)
    {

      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the target binary crashed suddenly, before receiving any input\n"
           "    from the fuzzer! Since it seems to be built with ASAN and you have a\n"
           "    restrictive memory limit configured, this is expected; please read\n"
           "    %s/notes_for_asan.txt for help.\n",
           doc_path);
    }
    else if (!mem_limit)
    {

      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the target binary crashed suddenly, before receiving any input\n"
           "    from the fuzzer! There are several probable explanations:\n\n"

           "    - The binary is just buggy and explodes entirely on its own. If so, you\n"
           "      need to fix the underlying problem or find a better replacement.\n\n"

#ifdef __APPLE__

           "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
           "      break afl-fuzz performance optimizations when running platform-specific\n"
           "      targets. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"

#endif /* __APPLE__ */

           "    - Less likely, there is a horrible bug in the fuzzer. If other options\n"
           "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n");
    }
    else
    {

      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the target binary crashed suddenly, before receiving any input\n"
           "    from the fuzzer! There are several probable explanations:\n\n"

           "    - The current memory limit (%s) is too restrictive, causing the\n"
           "      target to hit an OOM condition in the dynamic linker. Try bumping up\n"
           "      the limit with the -m setting in the command line. A simple way confirm\n"
           "      this diagnosis would be:\n\n"

#ifdef RLIMIT_AS
           "      ( ulimit -Sv $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#else
           "      ( ulimit -Sd $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#endif /* ^RLIMIT_AS */

           "      Tip: you can use http://jwilk.net/software/recidivm to quickly\n"
           "      estimate the required amount of virtual memory for the binary.\n\n"

           "    - The binary is just buggy and explodes entirely on its own. If so, you\n"
           "      need to fix the underlying problem or find a better replacement.\n\n"

#ifdef __APPLE__

           "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
           "      break afl-fuzz performance optimizations when running platform-specific\n"
           "      targets. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"

#endif /* __APPLE__ */

           "    - Less likely, there is a horrible bug in the fuzzer. If other options\n"
           "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n",
           DMS(mem_limit << 20), mem_limit - 1);
    }

    FATAL("Fork server crashed with signal %d", WTERMSIG(status));
  }

  if (*(u32 *)trace_bits == EXEC_FAIL_SIG)
    FATAL("Unable to execute target application ('%s')", argv[0]);

  if (mem_limit && mem_limit < 500 && uses_asan)
  {

    SAYF("\n" cLRD "[-] " cRST
         "Hmm, looks like the target binary terminated before we could complete a\n"
         "    handshake with the injected code. Since it seems to be built with ASAN and\n"
         "    you have a restrictive memory limit configured, this is expected; please\n"
         "    read %s/notes_for_asan.txt for help.\n",
         doc_path);
  }
  else if (!mem_limit)
  {

    SAYF("\n" cLRD "[-] " cRST
         "Hmm, looks like the target binary terminated before we could complete a\n"
         "    handshake with the injected code. Perhaps there is a horrible bug in the\n"
         "    fuzzer. Poke <lcamtuf@coredump.cx> for troubleshooting tips.\n");
  }
  else
  {

    SAYF("\n" cLRD "[-] " cRST
         "Hmm, looks like the target binary terminated before we could complete a\n"
         "    handshake with the injected code. There are %s probable explanations:\n\n"

         "%s"
         "    - The current memory limit (%s) is too restrictive, causing an OOM\n"
         "      fault in the dynamic linker. This can be fixed with the -m option. A\n"
         "      simple way to confirm the diagnosis may be:\n\n"

#ifdef RLIMIT_AS
         "      ( ulimit -Sv $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#else
         "      ( ulimit -Sd $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#endif /* ^RLIMIT_AS */

         "      Tip: you can use http://jwilk.net/software/recidivm to quickly\n"
         "      estimate the required amount of virtual memory for the binary.\n\n"

         "    - Less likely, there is a horrible bug in the fuzzer. If other options\n"
         "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n",
         getenv(DEFER_ENV_VAR) ? "three" : "two",
         getenv(DEFER_ENV_VAR) ? "    - You are using deferred forkserver, but __AFL_INIT() is never\n"
                                 "      reached before the program terminates.\n\n"
                               : "",
         DMS(mem_limit << 20), mem_limit - 1);
  }

  FATAL("Fork server handshake failed");
}

/* Execute target application, monitoring for timeouts. Return status
   information. The called program will update trace_bits[]. */

static u8 run_target(char **argv, u32 timeout)
{

  static struct itimerval it;
  static u32 prev_timed_out = 0;
  static u64 exec_ms = 0;

  int status = 0;
  u32 tb4;

  child_timed_out = 0;

  /* After this memset, trace_bits[] are effectively volatile, so we
     must prevent any earlier operations from venturing into that
     territory. */

  memset(trace_bits, 0, MAP_SIZE);
  MEM_BARRIER();

  /* If we're running in "dumb" mode, we can't rely on the fork server
     logic compiled into the target program, so we will just keep calling
     execve(). There is a bit of code duplication between here and
     init_forkserver(), but c'est la vie. */

  if (dumb_mode == 1 || no_forkserver)
  {

    child_pid = fork();

    if (child_pid < 0)
      PFATAL("fork() failed");

    if (!child_pid)
    {

      struct rlimit r;

      if (mem_limit)
      {

        r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;

#ifdef RLIMIT_AS

        setrlimit(RLIMIT_AS, &r); /* Ignore errors */

#else

        setrlimit(RLIMIT_DATA, &r); /* Ignore errors */

#endif /* ^RLIMIT_AS */
      }

      r.rlim_max = r.rlim_cur = 0;

      setrlimit(RLIMIT_CORE, &r); /* Ignore errors */

      /* Move the process to the different namespace. */

      if (netns_name)
        move_process_to_netns();

      /* Isolate the process and configure standard descriptors. If out_file is
         specified, stdin is /dev/null; otherwise, out_fd is cloned instead. */

      setsid();

      dup2(dev_null_fd, 1);
      dup2(dev_null_fd, 2);

      if (out_file)
      {

        dup2(dev_null_fd, 0);
      }
      else
      {

        dup2(out_fd, 0);
        close(out_fd);
      }

      /* On Linux, would be faster to use O_CLOEXEC. Maybe TODO. */

      close(dev_null_fd);
      close(out_dir_fd);
      close(dev_urandom_fd);
      close(fileno(plot_file));

      /* Set sane defaults for ASAN if nothing else specified. */

      setenv("ASAN_OPTIONS", "abort_on_error=1:"
                             "detect_leaks=0:"
                             "symbolize=0:"
                             "allocator_may_return_null=1",
             0);

      setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                                                                "symbolize=0:"
                                                                "msan_track_origins=0",
             0);

      execv(target_path, argv);

      /* Use a distinctive bitmap value to tell the parent about execv()
         falling through. */

      *(u32 *)trace_bits = EXEC_FAIL_SIG;
      exit(0);
    }
  }
  else
  {

    s32 res;

    /* In non-dumb mode, we have the fork server up and running, so simply
       tell it to have at it, and then read back PID. */

    if ((res = write(fsrv_ctl_fd, &prev_timed_out, 4)) != 4)
    {

      if (stop_soon)
        return 0;
      RPFATAL(res, "Unable to request new process from fork server (OOM?)");
    }

    if ((res = read(fsrv_st_fd, &child_pid, 4)) != 4)
    {

      if (stop_soon)
        return 0;
      RPFATAL(res, "Unable to request new process from fork server (OOM?)");
    }

    if (child_pid <= 0)
      FATAL("Fork server is misbehaving (OOM?)");
  }

  /* Configure timeout, as requested by user, then wait for child to terminate. */

  it.it_value.tv_sec = (timeout / 1000);
  it.it_value.tv_usec = (timeout % 1000) * 1000;

  setitimer(ITIMER_REAL, &it, NULL);

  /* The SIGALRM handler simply kills the child_pid and sets child_timed_out. */

  if (dumb_mode == 1 || no_forkserver)
  {
    if (use_net)
      send_over_network();
    if (waitpid(child_pid, &status, 0) <= 0)
      PFATAL("waitpid() failed");
  }
  else
  {
    if (use_net)
      send_over_network();
    s32 res;

    if ((res = read(fsrv_st_fd, &status, 4)) != 4)
    {

      if (stop_soon)
        return 0;
      RPFATAL(res, "Unable to communicate with fork server (OOM?)");
    }
  }

  if (!WIFSTOPPED(status))
    child_pid = 0;

  getitimer(ITIMER_REAL, &it);
  exec_ms = (u64)timeout - (it.it_value.tv_sec * 1000 +
                            it.it_value.tv_usec / 1000);

  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  total_execs++;
// Usage: export CFLAGS="-D SHORT_BENCH" or export CFLGAS="-D LONG_BENCH"
#ifdef LONG_BENCH
  if (total_execs == 1000000)
  {
    OKF("AFLNet: Done!");
    raise(SIGINT);
  }
#elif SHORT_BENCH
  if (total_execs == 10000)
  {
    OKF("AFLNet: Done!");
    raise(SIGINT);
  }
#else
#endif

  /* Any subsequent operations on trace_bits must not be moved by the
     compiler below this point. Past this location, trace_bits[] behave
     very normally and do not have to be treated as volatile. */

  MEM_BARRIER();

  tb4 = *(u32 *)trace_bits;

#ifdef WORD_SIZE_64
  classify_counts((u64 *)trace_bits);
#else
  classify_counts((u32 *)trace_bits);
#endif /* ^WORD_SIZE_64 */

  prev_timed_out = child_timed_out;

  /* Report outcome to caller. */

  if (WIFSIGNALED(status) && !stop_soon)
  {

    kill_signal = WTERMSIG(status);

    if (child_timed_out && kill_signal == SIGKILL)
      return FAULT_TMOUT;

    if (kill_signal == SIGTERM)
      return FAULT_NONE;

    return FAULT_CRASH;
  }

  /* A somewhat nasty hack for MSAN, which doesn't support abort_on_error and
     must use a special exit code. */

  if (uses_asan && WEXITSTATUS(status) == MSAN_ERROR)
  {
    kill_signal = 0;
    return FAULT_CRASH;
  }

  if ((dumb_mode == 1 || no_forkserver) && tb4 == EXEC_FAIL_SIG)
    return FAULT_ERROR;

  /* It makes sense to account for the slowest units only if the testcase was run
  under the user defined timeout. */
  if (!(timeout > exec_tmout) && (slowest_exec_ms < exec_ms))
  {
    slowest_exec_ms = exec_ms;
  }

  return FAULT_NONE;
}

/* Write modified data to file for testing. If out_file is set, the old file
   is unlinked and a new one is created. Otherwise, out_fd is rewound and
   truncated. */

static void write_to_testcase(void *mem, u32 len)
{

  // AFLNet sends data via network so it does not need this function
}

static void show_stats(void);

/* Calibrate a new test case. This is done when processing the input directory
   to warn about flaky or otherwise problematic test cases early on; and when
   new paths are discovered to detect variable behavior and so on. */

static u8 calibrate_case(char **argv, struct queue_entry *q, u8 *use_mem,
                         u32 handicap, u8 from_queue)
{

  static u8 first_trace[MAP_SIZE];

  u8 fault = 0, new_bits = 0, var_detected = 0,
     first_run = (q->exec_cksum == 0);

  u64 start_us, stop_us;

  s32 old_sc = stage_cur, old_sm = stage_max;
  u32 use_tmout = exec_tmout;
  u8 *old_sn = stage_name;

  /* Be a bit more generous about timeouts when resuming sessions, or when
     trying to calibrate already-added finds. This helps avoid trouble due
     to intermittent latency. */

  if (!from_queue || resuming_fuzz)
    use_tmout = MAX(exec_tmout + CAL_TMOUT_ADD,
                    exec_tmout * CAL_TMOUT_PERC / 100);

  q->cal_failed++;

  stage_name = "calibration";
  stage_max = fast_cal ? 3 : CAL_CYCLES;

  /* Make sure the forkserver is up before we do anything, and let's not
     count its spin-up time toward binary calibration. */

  if (dumb_mode != 1 && !no_forkserver && !forksrv_pid)
    init_forkserver(argv);

  if (q->exec_cksum)
    memcpy(first_trace, trace_bits, MAP_SIZE);

  start_us = get_cur_time_us();

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++)
  {

    u32 cksum;

    if (!first_run && !(stage_cur % stats_update_freq))
      show_stats();

    write_to_testcase(use_mem, q->len);

    fault = run_target(argv, use_tmout);

    /* stop_soon is set by the handler for Ctrl+C. When it's pressed,
       we want to bail out quickly. */

    if (stop_soon || fault != crash_mode)
      goto abort_calibration;

    if (!dumb_mode && !stage_cur && !count_bytes(trace_bits))
    {
      fault = FAULT_NOINST;
      goto abort_calibration;
    }

    cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

    if (q->exec_cksum != cksum)
    {

      u8 hnb = has_new_bits(virgin_bits);
      if (hnb > new_bits)
        new_bits = hnb;

      if (q->exec_cksum)
      {

        u32 i;

        for (i = 0; i < MAP_SIZE; i++)
        {

          if (!var_bytes[i] && first_trace[i] != trace_bits[i])
          {

            var_bytes[i] = 1;
            stage_max = CAL_CYCLES_LONG;
          }
        }

        var_detected = 1;
      }
      else
      {

        q->exec_cksum = cksum;
        memcpy(first_trace, trace_bits, MAP_SIZE);
      }
    }
  }

  stop_us = get_cur_time_us();

  total_cal_us += stop_us - start_us;
  total_cal_cycles += stage_max;

  /* OK, let's collect some stats about the performance of this test case.
     This is used for fuzzing air time calculations in calculate_score(). */

  q->exec_us = (stop_us - start_us) / stage_max;
  q->bitmap_size = count_bytes(trace_bits);
  q->handicap = handicap;
  q->cal_failed = 0;

  total_bitmap_size += q->bitmap_size;
  total_bitmap_entries++;

  update_bitmap_score(q);

  /* If this case didn't result in new output from the instrumentation, tell
     parent. This is a non-critical problem, but something to warn the user
     about. */

  if (!dumb_mode && first_run && !fault && !new_bits)
    fault = FAULT_NOBITS;

abort_calibration:

  if (new_bits == 2 && !q->has_new_cov)
  {
    q->has_new_cov = 1;
    queued_with_cov++;
  }

  /* Mark variable paths. */

  if (var_detected)
  {

    var_byte_count = count_bytes(var_bytes);

    if (!q->var_behavior)
    {
      mark_as_variable(q);
      queued_variable++;
    }
  }

  stage_name = old_sn;
  stage_cur = old_sc;
  stage_max = old_sm;

  if (!first_run)
    show_stats();

  return fault;
}

/* Examine map coverage. Called once, for first test case. */

static void check_map_coverage(void)
{

  u32 i;

  if (count_bytes(trace_bits) < 100)
    return;

  for (i = (1 << (MAP_SIZE_POW2 - 1)); i < MAP_SIZE; i++)
    if (trace_bits[i])
      return;

  WARNF("Recompile binary with newer version of afl to improve coverage!");
}

/* Perform dry run of all test cases to confirm that the app is working as
   expected. This is done only for the initial inputs, and only once. */

static void perform_dry_run(char **argv)
{

  struct queue_entry *q = queue;
  u32 cal_failures = 0;
  u8 *skip_crashes = getenv("AFL_SKIP_CRASHES");

  while (q)
  {

    u8 *use_mem;
    u8 res;
    s32 fd;

    q->is_initial_seed = 1;

    u8 *fn = strrchr(q->fname, '/') + 1;

    ACTF("Attempting dry run with '%s'...", fn);

    fd = open(q->fname, O_RDONLY);
    if (fd < 0)
      PFATAL("Unable to open '%s'", q->fname);

    use_mem = ck_alloc_nozero(q->len);

    if (read(fd, use_mem, q->len) != q->len)
      FATAL("Short read from '%s'", q->fname);

    close(fd);

    /* AFLNet construct the kl_messages linked list for this queue entry*/
    kl_messages = construct_kl_messages(q->fname, q->regions, q->region_count);

    res = calibrate_case(argv, q, use_mem, 0, 1);
    ck_free(use_mem);

    /* Update state-aware variables (e.g., state machine, regions and their annotations */
    if (state_aware_mode)
      update_state_aware_variables(q, 1);

    /* save the seed to file for replaying */
    u8 *fn_replay = alloc_printf("%s/replayable-queue/%s", out_dir, basename(q->fname));
    save_kl_messages_to_file(kl_messages, fn_replay, 1, messages_sent);
    ck_free(fn_replay);

    /* AFLNet delete the kl_messages */
    delete_kl_messages(kl_messages);

    if (stop_soon)
      return;

    if (res == crash_mode || res == FAULT_NOBITS)
      SAYF(cGRA "    len = %u, map size = %u, exec speed = %llu us\n" cRST,
           q->len, q->bitmap_size, q->exec_us);

    switch (res)
    {

    case FAULT_NONE:

      if (q == queue)
        check_map_coverage();

      if (crash_mode)
        FATAL("Test case '%s' does *NOT* crash", fn);

      break;

    case FAULT_TMOUT:

      if (timeout_given)
      {

        /* The -t nn+ syntax in the command line sets timeout_given to '2' and
           instructs afl-fuzz to tolerate but skip queue entries that time
           out. */

        if (timeout_given > 1)
        {
          WARNF("Test case results in a timeout (skipping)");
          q->cal_failed = CAL_CHANCES;
          cal_failures++;
          break;
        }

        SAYF("\n" cLRD "[-] " cRST
             "The program took more than %u ms to process one of the initial test cases.\n"
             "    Usually, the right thing to do is to relax the -t option - or to delete it\n"
             "    altogether and allow the fuzzer to auto-calibrate. That said, if you know\n"
             "    what you are doing and want to simply skip the unruly test cases, append\n"
             "    '+' at the end of the value passed to -t ('-t %u+').\n",
             exec_tmout,
             exec_tmout);

        FATAL("Test case '%s' results in a timeout", fn);
      }
      else
      {

        SAYF("\n" cLRD "[-] " cRST
             "The program took more than %u ms to process one of the initial test cases.\n"
             "    This is bad news; raising the limit with the -t option is possible, but\n"
             "    will probably make the fuzzing process extremely slow.\n\n"

             "    If this test case is just a fluke, the other option is to just avoid it\n"
             "    altogether, and find one that is less of a CPU hog.\n",
             exec_tmout);

        FATAL("Test case '%s' results in a timeout", fn);
      }

    case FAULT_CRASH:

      if (crash_mode)
        break;

      if (skip_crashes)
      {
        WARNF("Test case results in a crash (skipping)");
        q->cal_failed = CAL_CHANCES;
        cal_failures++;
        break;
      }

      if (mem_limit)
      {

        SAYF("\n" cLRD "[-] " cRST
             "Oops, the program crashed with one of the test cases provided. There are\n"
             "    several possible explanations:\n\n"

             "    - The test case causes known crashes under normal working conditions. If\n"
             "      so, please remove it. The fuzzer should be seeded with interesting\n"
             "      inputs - but not ones that cause an outright crash.\n\n"

             "    - The current memory limit (%s) is too low for this program, causing\n"
             "      it to die due to OOM when parsing valid files. To fix this, try\n"
             "      bumping it up with the -m setting in the command line. If in doubt,\n"
             "      try something along the lines of:\n\n"

#ifdef RLIMIT_AS
             "      ( ulimit -Sv $[%llu << 10]; /path/to/binary [...] <testcase )\n\n"
#else
             "      ( ulimit -Sd $[%llu << 10]; /path/to/binary [...] <testcase )\n\n"
#endif /* ^RLIMIT_AS */

             "      Tip: you can use http://jwilk.net/software/recidivm to quickly\n"
             "      estimate the required amount of virtual memory for the binary. Also,\n"
             "      if you are using ASAN, see %s/notes_for_asan.txt.\n\n"

#ifdef __APPLE__

             "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
             "      break afl-fuzz performance optimizations when running platform-specific\n"
             "      binaries. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"

#endif /* __APPLE__ */

             "    - Least likely, there is a horrible bug in the fuzzer. If other options\n"
             "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n",
             DMS(mem_limit << 20), mem_limit - 1, doc_path);
      }
      else
      {

        SAYF("\n" cLRD "[-] " cRST
             "Oops, the program crashed with one of the test cases provided. There are\n"
             "    several possible explanations:\n\n"

             "    - The test case causes known crashes under normal working conditions. If\n"
             "      so, please remove it. The fuzzer should be seeded with interesting\n"
             "      inputs - but not ones that cause an outright crash.\n\n"

#ifdef __APPLE__

             "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
             "      break afl-fuzz performance optimizations when running platform-specific\n"
             "      binaries. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"

#endif /* __APPLE__ */

             "    - Least likely, there is a horrible bug in the fuzzer. If other options\n"
             "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n");
      }

      FATAL("Test case '%s' results in a crash", fn);

    case FAULT_ERROR:

      FATAL("Unable to execute target application ('%s')", argv[0]);

    case FAULT_NOINST:

      FATAL("No instrumentation detected");

    case FAULT_NOBITS:

      useless_at_start++;

      if (!in_bitmap && !shuffle_queue)
        WARNF("No new instrumentation output, test case may be useless.");

      break;
    }

    if (q->var_behavior)
      WARNF("Instrumentation output varies across runs.");

    q = q->next;
  }

  if (cal_failures)
  {

    if (cal_failures == queued_paths)
      FATAL("All test cases time out%s, giving up!",
            skip_crashes ? " or crash" : "");

    WARNF("Skipped %u test cases (%0.02f%%) due to timeouts%s.", cal_failures,
          ((double)cal_failures) * 100 / queued_paths,
          skip_crashes ? " or crashes" : "");

    if (cal_failures * 5 > queued_paths)
      WARNF(cLRD "High percentage of rejected test cases, check settings!");
  }

  OKF("All test cases processed.");
}

/* Helper function: link() if possible, copy otherwise. */

static void link_or_copy(u8 *old_path, u8 *new_path)
{

  s32 i = link(old_path, new_path);
  s32 sfd, dfd;
  u8 *tmp;

  if (!i)
    return;

  sfd = open(old_path, O_RDONLY);
  if (sfd < 0)
    PFATAL("Unable to open '%s'", old_path);

  dfd = open(new_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (dfd < 0)
    PFATAL("Unable to create '%s'", new_path);

  tmp = ck_alloc(64 * 1024);

  while ((i = read(sfd, tmp, 64 * 1024)) > 0)
    ck_write(dfd, tmp, i, new_path);

  if (i < 0)
    PFATAL("read() failed");

  ck_free(tmp);
  close(sfd);
  close(dfd);
}

static void nuke_resume_dir(void);

/* Create hard links for input test cases in the output directory, choosing
   good names and pivoting accordingly. */

static void pivot_inputs(void)
{

  struct queue_entry *q = queue;
  u32 id = 0;

  ACTF("Creating hard links for all input files...");

  while (q)
  {

    u8 *nfn, *rsl = strrchr(q->fname, '/');
    u32 orig_id;

    if (!rsl)
      rsl = q->fname;
    else
      rsl++;

      /* If the original file name conforms to the syntax and the recorded
         ID matches the one we'd assign, just use the original file name.
         This is valuable for resuming fuzzing runs. */

#ifndef SIMPLE_FILES
#define CASE_PREFIX "id:"
#else
#define CASE_PREFIX "id_"
#endif /* ^!SIMPLE_FILES */

    if (!strncmp(rsl, CASE_PREFIX, 3) &&
        sscanf(rsl + 3, "%06u", &orig_id) == 1 && orig_id == id)
    {

      u8 *src_str;
      u32 src_id;

      resuming_fuzz = 1;
      nfn = alloc_printf("%s/queue/%s", out_dir, rsl);

      /* Since we're at it, let's also try to find parent and figure out the
         appropriate depth for this entry. */

      src_str = strchr(rsl + 3, ':');

      if (src_str && sscanf(src_str + 1, "%06u", &src_id) == 1)
      {

        struct queue_entry *s = queue;
        while (src_id-- && s)
          s = s->next;
        if (s)
          q->depth = s->depth + 1;

        if (max_depth < q->depth)
          max_depth = q->depth;
      }
    }
    else
    {

      /* No dice - invent a new name, capturing the original one as a
         substring. */

#ifndef SIMPLE_FILES

      u8 *use_name = strstr(rsl, ",orig:");

      if (use_name)
        use_name += 6;
      else
        use_name = rsl;
      nfn = alloc_printf("%s/queue/id:%06u,orig:%s", out_dir, id, use_name);

#else

      nfn = alloc_printf("%s/queue/id_%06u", out_dir, id);

#endif /* ^!SIMPLE_FILES */
    }

    /* Pivot to the new queue entry. */

    link_or_copy(q->fname, nfn);
    ck_free(q->fname);
    q->fname = nfn;

    /* Make sure that the passed_det value carries over, too. */

    if (q->passed_det)
      mark_as_det_done(q);

    q = q->next;
    id++;
  }

  if (in_place_resume)
    nuke_resume_dir();
}

#ifndef SIMPLE_FILES

/* Construct a file name for a new test case, capturing the operation
   that led to its discovery. Uses a static buffer. */

static u8 *describe_op(u8 hnb)
{

  static u8 ret[256];

  if (syncing_party)
  {

    sprintf(ret, "sync:%s,src:%06u", syncing_party, syncing_case);
  }
  else
  {

    sprintf(ret, "src:%06u", current_entry);

    if (splicing_with >= 0)
      sprintf(ret + strlen(ret), "+%06u", splicing_with);

    sprintf(ret + strlen(ret), ",op:%s", stage_short);

    if (stage_cur_byte >= 0)
    {

      sprintf(ret + strlen(ret), ",pos:%u", stage_cur_byte);

      if (stage_val_type != STAGE_VAL_NONE)
        sprintf(ret + strlen(ret), ",val:%s%+d",
                (stage_val_type == STAGE_VAL_BE) ? "be:" : "",
                stage_cur_val);
    }
    else
      sprintf(ret + strlen(ret), ",rep:%u", stage_cur_val);
  }

  if (hnb == 2)
    strcat(ret, ",+cov");

  return ret;
}

#endif /* !SIMPLE_FILES */

/* Write a message accompanying the crash directory :-) */

static void write_crash_readme(void)
{

  u8 *fn = alloc_printf("%s/replayable-crashes/README.txt", out_dir);
  s32 fd;
  FILE *f;

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  ck_free(fn);

  /* Do not die on errors here - that would be impolite. */

  if (fd < 0)
    return;

  f = fdopen(fd, "w");

  if (!f)
  {
    close(fd);
    return;
  }

  fprintf(f, "Command line used to find this crash:\n\n"

             "%s\n\n"

             "If you can't reproduce a bug outside of afl-fuzz, be sure to set the same\n"
             "memory limit. The limit used for this fuzzing session was %s.\n\n"

             "Need a tool to minimize test cases before investigating the crashes or sending\n"
             "them to a vendor? Check out the afl-tmin that comes with the fuzzer!\n\n"

             "Found any cool bugs in open-source tools using afl-fuzz? If yes, please drop\n"
             "me a mail at <lcamtuf@coredump.cx> once the issues are fixed - I'd love to\n"
             "add your finds to the gallery at:\n\n"

             "  http://lcamtuf.coredump.cx/afl/\n\n"

             "Thanks :-)\n",

          orig_cmdline, DMS(mem_limit << 20)); /* ignore errors */

  fclose(f);
}

/* Check if the result of an execve() during routine fuzzing is interesting,
   save or queue the input test case for further analysis if so. Returns 1 if
   entry is saved, 0 otherwise. */

static u8 save_if_interesting(char **argv, void *mem, u32 len, u8 fault)
{

  u8 *fn = "";
  u8 hnb;
  // s32 fd;
  u8 keeping = 0, res;

  if (fault == crash_mode)
  {

    /* Keep only if there are new bits in the map, add to queue for
       future fuzzing, etc. */

    if (!(hnb = has_new_bits(virgin_bits)))
    {
      if (crash_mode)
        total_crashes++;
      return 0;
    }

#ifndef SIMPLE_FILES

    fn = alloc_printf("%s/queue/id:%06u,%s", out_dir, queued_paths,
                      describe_op(hnb));

#else

    fn = alloc_printf("%s/queue/id_%06u", out_dir, queued_paths);

#endif /* ^!SIMPLE_FILES */

    u32 full_len = save_kl_messages_to_file(kl_messages, fn, 0, messages_sent);

    /* We use the actual length of all messages (full_len), not the len of the mutated message subsequence (len)*/
    add_to_queue(fn, full_len, 0);

    if (state_aware_mode)
      update_state_aware_variables(queue_top, 0);

    /* save the seed to file for replaying */
    u8 *fn_replay = alloc_printf("%s/replayable-queue/%s", out_dir, basename(queue_top->fname));
    save_kl_messages_to_file(kl_messages, fn_replay, 1, messages_sent);
    ck_free(fn_replay);

    if (hnb == 2)
    {
      queue_top->has_new_cov = 1;
      queued_with_cov++;
    }

    queue_top->exec_cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

    /* Try to calibrate inline; this also calls update_bitmap_score() when
       successful. */

    res = calibrate_case(argv, queue_top, mem, queue_cycle - 1, 0);

    if (res == FAULT_ERROR)
      FATAL("Unable to execute target application");

    /*fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);
    ck_write(fd, mem, len, fn);
    close(fd);*/

    keeping = 1;
  }

  switch (fault)
  {

  case FAULT_TMOUT:

    /* Timeouts are not very interesting, but we're still obliged to keep
       a handful of samples. We use the presence of new bits in the
       hang-specific bitmap as a signal of uniqueness. In "dumb" mode, we
       just keep everything. */

    total_tmouts++;

    if (unique_hangs >= KEEP_UNIQUE_HANG)
      return keeping;

    if (!dumb_mode)
    {

#ifdef WORD_SIZE_64
      simplify_trace((u64 *)trace_bits);
#else
      simplify_trace((u32 *)trace_bits);
#endif /* ^WORD_SIZE_64 */

      if (!has_new_bits(virgin_tmout))
        return keeping;
    }

    unique_tmouts++;

    /* Before saving, we make sure that it's a genuine hang by re-running
       the target with a more generous timeout (unless the default timeout
       is already generous). */

    if (exec_tmout < hang_tmout)
    {

      u8 new_fault;
      write_to_testcase(mem, len);
      new_fault = run_target(argv, hang_tmout);

      /* A corner case that one user reported bumping into: increasing the
         timeout actually uncovers a crash. Make sure we don't discard it if
         so. */

      if (!stop_soon && new_fault == FAULT_CRASH)
        goto keep_as_crash;

      if (stop_soon || new_fault != FAULT_TMOUT)
        return keeping;
    }

#ifndef SIMPLE_FILES

    fn = alloc_printf("%s/replayable-hangs/id:%06llu,%s", out_dir,
                      unique_hangs, describe_op(0));

#else

    fn = alloc_printf("%s/replayable-hangs/id_%06llu", out_dir,
                      unique_hangs);

#endif /* ^!SIMPLE_FILES */

    unique_hangs++;

    last_hang_time = get_cur_time();

    break;

  case FAULT_CRASH:

  keep_as_crash:

    /* This is handled in a manner roughly similar to timeouts,
       except for slightly different limits and no need to re-run test
       cases. */

    total_crashes++;

    if (unique_crashes >= KEEP_UNIQUE_CRASH)
      return keeping;

    if (!dumb_mode)
    {

#ifdef WORD_SIZE_64
      simplify_trace((u64 *)trace_bits);
#else
      simplify_trace((u32 *)trace_bits);
#endif /* ^WORD_SIZE_64 */

      if (!has_new_bits(virgin_crash))
        return keeping;
    }

    if (!unique_crashes)
      write_crash_readme();

#ifndef SIMPLE_FILES

    fn = alloc_printf("%s/replayable-crashes/id:%06llu,sig:%02u,%s", out_dir,
                      unique_crashes, kill_signal, describe_op(0));

#else

    fn = alloc_printf("%s/replayable-crashes/id_%06llu_%02u", out_dir, unique_crashes,
                      kill_signal);

#endif /* ^!SIMPLE_FILES */

    unique_crashes++;

    last_crash_time = get_cur_time();
    last_crash_execs = total_execs;

    break;

  case FAULT_ERROR:
    FATAL("Unable to execute target application");

  default:
    return keeping;
  }

  /* If we're here, we apparently want to save the crash or hang
     test case, too. */

  save_kl_messages_to_file(kl_messages, fn, 1, messages_sent);

  /*fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", fn);
  ck_write(fd, mem, len, fn);
  close(fd);*/

  ck_free(fn);

  return keeping;
}

/* When resuming, try to find the queue position to start from. This makes sense
   only when resuming, and when we can find the original fuzzer_stats. */

static u32 find_start_position(void)
{

  static u8 tmp[4096]; /* Ought to be enough for anybody. */

  u8 *fn, *off;
  s32 fd, i;
  u32 ret;

  if (!resuming_fuzz)
    return 0;

  if (in_place_resume)
    fn = alloc_printf("%s/fuzzer_stats", out_dir);
  else
    fn = alloc_printf("%s/../fuzzer_stats", in_dir);

  fd = open(fn, O_RDONLY);
  ck_free(fn);

  if (fd < 0)
    return 0;

  i = read(fd, tmp, sizeof(tmp) - 1);
  (void)i; /* Ignore errors */
  close(fd);

  off = strstr(tmp, "cur_path          : ");
  if (!off)
    return 0;

  ret = atoi(off + 20);
  if (ret >= queued_paths)
    ret = 0;
  return ret;
}

/* The same, but for timeouts. The idea is that when resuming sessions without
   -t given, we don't want to keep auto-scaling the timeout over and over
   again to prevent it from growing due to random flukes. */

static void find_timeout(void)
{

  static u8 tmp[4096]; /* Ought to be enough for anybody. */

  u8 *fn, *off;
  s32 fd, i;
  u32 ret;

  if (!resuming_fuzz)
    return;

  if (in_place_resume)
    fn = alloc_printf("%s/fuzzer_stats", out_dir);
  else
    fn = alloc_printf("%s/../fuzzer_stats", in_dir);

  fd = open(fn, O_RDONLY);
  ck_free(fn);

  if (fd < 0)
    return;

  i = read(fd, tmp, sizeof(tmp) - 1);
  (void)i; /* Ignore errors */
  close(fd);

  off = strstr(tmp, "exec_timeout      : ");
  if (!off)
    return;

  ret = atoi(off + 20);
  if (ret <= 4)
    return;

  exec_tmout = ret;
  timeout_given = 3;
}

/* Update stats file for unattended monitoring. */

static void write_stats_file(double bitmap_cvg, double stability, double eps)
{

  static double last_bcvg, last_stab, last_eps;
  static struct rusage usage;

  u8 *fn = alloc_printf("%s/fuzzer_stats", out_dir);
  s32 fd;
  FILE *f;

  fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);

  if (fd < 0)
    PFATAL("Unable to create '%s'", fn);

  ck_free(fn);

  f = fdopen(fd, "w");

  if (!f)
    PFATAL("fdopen() failed");

  /* Keep last values in case we're called from another context
     where exec/sec stats and such are not readily available. */

  if (!bitmap_cvg && !stability && !eps)
  {
    bitmap_cvg = last_bcvg;
    stability = last_stab;
    eps = last_eps;
  }
  else
  {
    last_bcvg = bitmap_cvg;
    last_stab = stability;
    last_eps = eps;
  }

  fprintf(f, "start_time        : %llu\n"
             "last_update       : %llu\n"
             "fuzzer_pid        : %u\n"
             "cycles_done       : %llu\n"
             "execs_done        : %llu\n"
             "execs_per_sec     : %0.02f\n"
             "paths_total       : %u\n"
             "paths_favored     : %u\n"
             "paths_found       : %u\n"
             "paths_imported    : %u\n"
             "max_depth         : %u\n"
             "cur_path          : %u\n" /* Must match find_start_position() */
             "pending_favs      : %u\n"
             "pending_total     : %u\n"
             "variable_paths    : %u\n"
             "stability         : %0.02f%%\n"
             "bitmap_cvg        : %0.02f%%\n"
             "unique_crashes    : %llu\n"
             "unique_hangs      : %llu\n"
             "last_path         : %llu\n"
             "last_crash        : %llu\n"
             "last_hang         : %llu\n"
             "execs_since_crash : %llu\n"
             "exec_timeout      : %u\n" /* Must match find_timeout() */
             "afl_banner        : %s\n"
             "afl_version       : " VERSION "\n"
             "target_mode       : %s%s%s%s%s%s%s\n"
             "command_line      : %s\n"
             "slowest_exec_ms   : %llu\n",
          start_time / 1000, get_cur_time() / 1000, getpid(),
          queue_cycle ? (queue_cycle - 1) : 0, total_execs, eps,
          queued_paths, queued_favored, queued_discovered, queued_imported,
          max_depth, current_entry, pending_favored, pending_not_fuzzed,
          queued_variable, stability, bitmap_cvg, unique_crashes,
          unique_hangs, last_path_time / 1000, last_crash_time / 1000,
          last_hang_time / 1000, total_execs - last_crash_execs,
          exec_tmout, use_banner,
          qemu_mode ? "qemu " : "", dumb_mode ? " dumb " : "",
          no_forkserver ? "no_forksrv " : "", crash_mode ? "crash " : "",
          persistent_mode ? "persistent " : "", deferred_mode ? "deferred " : "",
          (qemu_mode || dumb_mode || no_forkserver || crash_mode ||
           persistent_mode || deferred_mode)
              ? ""
              : "default",
          orig_cmdline, slowest_exec_ms);
  /* ignore errors */

  /* Get rss value from the children
     We must have killed the forkserver process and called waitpid
     before calling getrusage */
  if (getrusage(RUSAGE_CHILDREN, &usage))
  {
    WARNF("getrusage failed");
  }
  else if (usage.ru_maxrss == 0)
  {
    fprintf(f, "peak_rss_mb       : not available while afl is running\n");
  }
  else
  {
#ifdef __APPLE__
    fprintf(f, "peak_rss_mb       : %zu\n", usage.ru_maxrss >> 20);
#else
    fprintf(f, "peak_rss_mb       : %zu\n", usage.ru_maxrss >> 10);
#endif /* ^__APPLE__ */
  }

  fclose(f);
}

/* Update the plot file if there is a reason to. */

static void maybe_update_plot_file(double bitmap_cvg, double eps)
{

  static u32 prev_qp, prev_pf, prev_pnf, prev_ce, prev_md, prev_nodes, prev_edges, prev_chat_times;
  static u64 prev_qc, prev_uc, prev_uh;

  if (prev_qp == queued_paths && prev_pf == pending_favored &&
      prev_pnf == pending_not_fuzzed && prev_ce == current_entry &&
      prev_qc == queue_cycle && prev_uc == unique_crashes &&
      prev_uh == unique_hangs && prev_md == max_depth &&
      prev_nodes == agnnodes(ipsm) && prev_edges == agnedges(ipsm) &&
      prev_chat_times == chat_times)
    return;

  prev_qp = queued_paths;
  prev_pf = pending_favored;
  prev_pnf = pending_not_fuzzed;
  prev_ce = current_entry;
  prev_qc = queue_cycle;
  prev_uc = unique_crashes;
  prev_uh = unique_hangs;
  prev_md = max_depth;
  prev_nodes = agnnodes(ipsm);
  prev_edges = agnedges(ipsm);
  prev_chat_times = chat_times;

  /* Fields in the file:

     unix_time, cycles_done, cur_path, paths_total, paths_not_fuzzed,
     favored_not_fuzzed, unique_crashes, unique_hangs, max_depth,
     execs_per_sec, n_nodes, n_edges, chat_times */

  fprintf(plot_file,
          "%llu, %llu, %u, %u, %u, %u, %0.02f%%, %llu, %llu, %u, %0.02f, %d, %d, %d\n",
          get_cur_time() / 1000, queue_cycle - 1, current_entry, queued_paths,
          pending_not_fuzzed, pending_favored, bitmap_cvg, unique_crashes,
          unique_hangs, max_depth, eps, agnnodes(ipsm), agnedges(ipsm), chat_times); /* ignore errors */

  fflush(plot_file);
}

/* A helper function for maybe_delete_out_dir(), deleting all prefixed
   files in a directory. */

static u8 delete_files(u8 *path, u8 *prefix)
{

  DIR *d;
  struct dirent *d_ent;

  d = opendir(path);

  if (!d)
    return 0;

  while ((d_ent = readdir(d)))
  {

    if (d_ent->d_name[0] != '.' && (!prefix ||
                                    !strncmp(d_ent->d_name, prefix, strlen(prefix))))
    {

      u8 *fname = alloc_printf("%s/%s", path, d_ent->d_name);
      if (unlink(fname))
        PFATAL("Unable to delete '%s'", fname);
      ck_free(fname);
    }
  }

  closedir(d);

  return !!rmdir(path);
}

/* Get the number of runnable processes, with some simple smoothing. */

static double get_runnable_processes(void)
{

  static double res;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)

  /* I don't see any portable sysctl or so that would quickly give us the
     number of runnable processes; the 1-minute load average can be a
     semi-decent approximation, though. */

  if (getloadavg(&res, 1) != 1)
    return 0;

#else

  /* On Linux, /proc/stat is probably the best way; load averages are
     computed in funny ways and sometimes don't reflect extremely short-lived
     processes well. */

  FILE *f = fopen("/proc/stat", "r");
  u8 tmp[1024];
  u32 val = 0;

  if (!f)
    return 0;

  while (fgets(tmp, sizeof(tmp), f))
  {

    if (!strncmp(tmp, "procs_running ", 14) ||
        !strncmp(tmp, "procs_blocked ", 14))
      val += atoi(tmp + 14);
  }

  fclose(f);

  if (!res)
  {

    res = val;
  }
  else
  {

    res = res * (1.0 - 1.0 / AVG_SMOOTHING) +
          ((double)val) * (1.0 / AVG_SMOOTHING);
  }

#endif /* ^(__APPLE__ || __FreeBSD__ || __OpenBSD__) */

  return res;
}

/* Delete the temporary directory used for in-place session resume. */

static void nuke_resume_dir(void)
{

  u8 *fn;

  fn = alloc_printf("%s/_resume/.state/deterministic_done", out_dir);
  if (delete_files(fn, CASE_PREFIX))
    goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state/auto_extras", out_dir);
  if (delete_files(fn, "auto_"))
    goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state/redundant_edges", out_dir);
  if (delete_files(fn, CASE_PREFIX))
    goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state/variable_behavior", out_dir);
  if (delete_files(fn, CASE_PREFIX))
    goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state", out_dir);
  if (rmdir(fn) && errno != ENOENT)
    goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/_resume", out_dir);
  if (delete_files(fn, CASE_PREFIX))
    goto dir_cleanup_failed;
  ck_free(fn);

  return;

dir_cleanup_failed:

  FATAL("_resume directory cleanup failed");
}

/* Delete fuzzer output directory if we recognize it as ours, if the fuzzer
   is not currently running, and if the last run time isn't too great. */

static void maybe_delete_out_dir(void)
{

  FILE *f;
  u8 *fn = alloc_printf("%s/fuzzer_stats", out_dir);

  /* See if the output directory is locked. If yes, bail out. If not,
     create a lock that will persist for the lifetime of the process
     (this requires leaving the descriptor open).*/

  out_dir_fd = open(out_dir, O_RDONLY);
  if (out_dir_fd < 0)
    PFATAL("Unable to open '%s'", out_dir);

#ifndef __sun

  if (flock(out_dir_fd, LOCK_EX | LOCK_NB) && errno == EWOULDBLOCK)
  {

    SAYF("\n" cLRD "[-] " cRST
         "Looks like the job output directory is being actively used by another\n"
         "    instance of afl-fuzz. You will need to choose a different %s\n"
         "    or stop the other process first.\n",
         sync_id ? "fuzzer ID" : "output location");

    FATAL("Directory '%s' is in use", out_dir);
  }

#endif /* !__sun */

  f = fopen(fn, "r");

  if (f)
  {

    u64 start_time, last_update;

    if (fscanf(f, "start_time     : %llu\n"
                  "last_update    : %llu\n",
               &start_time, &last_update) != 2)
      FATAL("Malformed data in '%s'", fn);

    fclose(f);

    /* Let's see how much work is at stake. */

    if (!in_place_resume && last_update - start_time > OUTPUT_GRACE * 60)
    {

      SAYF("\n" cLRD "[-] " cRST
           "The job output directory already exists and contains the results of more\n"
           "    than %u minutes worth of fuzzing. To avoid data loss, afl-fuzz will *NOT*\n"
           "    automatically delete this data for you.\n\n"

           "    If you wish to start a new session, remove or rename the directory manually,\n"
           "    or specify a different output location for this job. To resume the old\n"
           "    session, put '-' as the input directory in the command line ('-i -') and\n"
           "    try again.\n",
           OUTPUT_GRACE);

      FATAL("At-risk data found in '%s'", out_dir);
    }
  }

  ck_free(fn);

  /* The idea for in-place resume is pretty simple: we temporarily move the old
     queue/ to a new location that gets deleted once import to the new queue/
     is finished. If _resume/ already exists, the current queue/ may be
     incomplete due to an earlier abort, so we want to use the old _resume/
     dir instead, and we let rename() fail silently. */

  if (in_place_resume)
  {

    u8 *orig_q = alloc_printf("%s/queue", out_dir);

    in_dir = alloc_printf("%s/_resume", out_dir);

    rename(orig_q, in_dir); /* Ignore errors */

    OKF("Output directory exists, will attempt session resume.");

    ck_free(orig_q);
  }
  else
  {

    OKF("Output directory exists but deemed OK to reuse.");
  }

  ACTF("Deleting old session data...");

  /* Okay, let's get the ball rolling! First, we need to get rid of the entries
     in <out_dir>/.synced/.../id:*, if any are present. */

  if (!in_place_resume)
  {

    fn = alloc_printf("%s/.synced", out_dir);
    if (delete_files(fn, NULL))
      goto dir_cleanup_failed;
    ck_free(fn);
  }

  /* Next, we need to clean up <out_dir>/queue/.state/ subdirectories: */

  fn = alloc_printf("%s/queue/.state/deterministic_done", out_dir);
  if (delete_files(fn, CASE_PREFIX))
    goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/queue/.state/auto_extras", out_dir);
  if (delete_files(fn, "auto_"))
    goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/queue/.state/redundant_edges", out_dir);
  if (delete_files(fn, CASE_PREFIX))
    goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/queue/.state/variable_behavior", out_dir);
  if (delete_files(fn, CASE_PREFIX))
    goto dir_cleanup_failed;
  ck_free(fn);

  /* Then, get rid of the .state subdirectory itself (should be empty by now)
     and everything matching <out_dir>/queue/id:*. */

  fn = alloc_printf("%s/queue/.state", out_dir);
  if (rmdir(fn) && errno != ENOENT)
    goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/queue", out_dir);
  if (delete_files(fn, CASE_PREFIX))
    goto dir_cleanup_failed;
  ck_free(fn);

  /* All right, let's do <out_dir>/replayable-crashes/id:* and <out_dir>/replayable-hangs/id:*. */

  if (!in_place_resume)
  {

    fn = alloc_printf("%s/replayable-crashes/README.txt", out_dir);
    unlink(fn); /* Ignore errors */
    ck_free(fn);
  }

  fn = alloc_printf("%s/replayable-crashes", out_dir);

  /* Make backup of the crashes directory if it's not empty and if we're
     doing in-place resume. */

  if (in_place_resume && rmdir(fn))
  {

    time_t cur_t = time(0);
    struct tm *t = localtime(&cur_t);

#ifndef SIMPLE_FILES

    u8 *nfn = alloc_printf("%s.%04u-%02u-%02u-%02u:%02u:%02u", fn,
                           t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                           t->tm_hour, t->tm_min, t->tm_sec);

#else

    u8 *nfn = alloc_printf("%s_%04u%02u%02u%02u%02u%02u", fn,
                           t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                           t->tm_hour, t->tm_min, t->tm_sec);

#endif /* ^!SIMPLE_FILES */

    rename(fn, nfn); /* Ignore errors. */
    ck_free(nfn);
  }

  if (delete_files(fn, CASE_PREFIX))
    goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/replayable-hangs", out_dir);

  /* Backup hangs, too. */

  if (in_place_resume && rmdir(fn))
  {

    time_t cur_t = time(0);
    struct tm *t = localtime(&cur_t);

#ifndef SIMPLE_FILES

    u8 *nfn = alloc_printf("%s.%04u-%02u-%02u-%02u:%02u:%02u", fn,
                           t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                           t->tm_hour, t->tm_min, t->tm_sec);

#else

    u8 *nfn = alloc_printf("%s_%04u%02u%02u%02u%02u%02u", fn,
                           t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                           t->tm_hour, t->tm_min, t->tm_sec);

#endif /* ^!SIMPLE_FILES */

    rename(fn, nfn); /* Ignore errors. */
    ck_free(nfn);
  }

  if (delete_files(fn, CASE_PREFIX))
    goto dir_cleanup_failed;
  ck_free(fn);

  /* Delete regions. */

  fn = alloc_printf("%s/regions", out_dir);
  if (delete_files(fn, ""))
    goto dir_cleanup_failed;
  ck_free(fn);

  /* Delete replayable-queue. */

  fn = alloc_printf("%s/replayable-queue", out_dir);
  if (delete_files(fn, ""))
    goto dir_cleanup_failed;
  ck_free(fn);

  /* Delete the old ipsm.dot */
  fn = alloc_printf("%s/ipsm.dot", out_dir);
  if (unlink(fn) && errno != ENOENT)
    goto dir_cleanup_failed;
  ck_free(fn);

  /* Delete the old replayable-new-ipsm-paths folder */
  fn = alloc_printf("%s/replayable-new-ipsm-paths", out_dir);
  if (delete_files(fn, ""))
    goto dir_cleanup_failed;
  ck_free(fn);

  /* Delete the old responses-ipsm folder */
  fn = alloc_printf("%s/responses-ipsm", out_dir);
  if (delete_files(fn, ""))
    goto dir_cleanup_failed;
  ck_free(fn);

  /* Delete the old protocol-grammars folder */
  fn = alloc_printf("%s/protocol-grammars", out_dir);
  if (delete_files(fn, ""))
    goto dir_cleanup_failed;
  ck_free(fn);

  /* Delete the old stall-interactions folder */
  fn = alloc_printf("%s/stall-interactions", out_dir);
  if (delete_files(fn, ""))
    goto dir_cleanup_failed;
  ck_free(fn);

  /* And now, for some finishing touches. */

  fn = alloc_printf("%s/.cur_input", out_dir);
  if (unlink(fn) && errno != ENOENT)
    goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/fuzz_bitmap", out_dir);
  if (unlink(fn) && errno != ENOENT)
    goto dir_cleanup_failed;
  ck_free(fn);

  if (!in_place_resume)
  {
    fn = alloc_printf("%s/fuzzer_stats", out_dir);
    if (unlink(fn) && errno != ENOENT)
      goto dir_cleanup_failed;
    ck_free(fn);
  }

  fn = alloc_printf("%s/plot_data", out_dir);
  if (unlink(fn) && errno != ENOENT)
    goto dir_cleanup_failed;
  ck_free(fn);

  OKF("Output dir cleanup successful.");

  /* Wow... is that all? If yes, celebrate! */

  return;

dir_cleanup_failed:

  SAYF("\n" cLRD "[-] " cRST
       "Whoops, the fuzzer tried to reuse your output directory, but bumped into\n"
       "    some files that shouldn't be there or that couldn't be removed - so it\n"
       "    decided to abort! This happened while processing this path:\n\n"

       "    %s\n\n"
       "    Please examine and manually delete the files, or specify a different\n"
       "    output location for the tool.\n",
       fn);

  FATAL("Output directory cleanup failed");
}

static void check_term_size(void);

/* A spiffy retro stats screen! This is called every stats_update_freq
   execve() calls, plus in several other circumstances. */

static void show_stats(void)
{

  static u64 last_stats_ms, last_plot_ms, last_ms, last_execs;
  static double avg_exec;
  double t_byte_ratio, stab_ratio;

  u64 cur_ms;
  u32 t_bytes, t_bits;

  u32 banner_len, banner_pad;
  u8 tmp[256];

  cur_ms = get_cur_time();

  /* If not enough time has passed since last UI update, bail out. */

  if (cur_ms - last_ms < 1000 / UI_TARGET_HZ)
    return;

  /* Check if we're past the 10 minute mark. */

  if (cur_ms - start_time > 10 * 60 * 1000)
    run_over10m = 1;

  /* Calculate smoothed exec speed stats. */

  if (!last_execs)
  {

    avg_exec = ((double)total_execs) * 1000 / (cur_ms - start_time);
  }
  else
  {

    double cur_avg = ((double)(total_execs - last_execs)) * 1000 /
                     (cur_ms - last_ms);

    /* If there is a dramatic (5x+) jump in speed, reset the indicator
       more quickly. */

    if (cur_avg * 5 < avg_exec || cur_avg / 5 > avg_exec)
      avg_exec = cur_avg;

    avg_exec = avg_exec * (1.0 - 1.0 / AVG_SMOOTHING) +
               cur_avg * (1.0 / AVG_SMOOTHING);
  }

  last_ms = cur_ms;
  last_execs = total_execs;

  /* Tell the callers when to contact us (as measured in execs). */

  stats_update_freq = avg_exec / (UI_TARGET_HZ * 10);
  if (!stats_update_freq)
    stats_update_freq = 1;

  /* Do some bitmap stats. */

  t_bytes = count_non_255_bytes(virgin_bits);
  t_byte_ratio = ((double)t_bytes * 100) / MAP_SIZE;

  if (t_bytes)
    stab_ratio = 100 - ((double)var_byte_count) * 100 / t_bytes;
  else
    stab_ratio = 100;

  /* Roughly every minute, update fuzzer stats and save auto tokens. */

  if (cur_ms - last_stats_ms > STATS_UPDATE_SEC * 1000)
  {

    last_stats_ms = cur_ms;
    write_stats_file(t_byte_ratio, stab_ratio, avg_exec);
    save_auto();
    write_bitmap();
  }

  /* Every now and then, write plot data. */

  if (cur_ms - last_plot_ms > PLOT_UPDATE_SEC * 1000)
  {

    last_plot_ms = cur_ms;
    maybe_update_plot_file(t_byte_ratio, avg_exec);
  }

  /* Honor AFL_EXIT_WHEN_DONE and AFL_BENCH_UNTIL_CRASH. */

  if (!dumb_mode && cycles_wo_finds > 100 && !pending_not_fuzzed &&
      getenv("AFL_EXIT_WHEN_DONE"))
    stop_soon = 2;

  if (total_crashes && getenv("AFL_BENCH_UNTIL_CRASH"))
    stop_soon = 2;

  /* If we're not on TTY, bail out. */

  if (not_on_tty)
    return;

  /* Compute some mildly useful bitmap stats. */

  t_bits = (MAP_SIZE << 3) - count_bits(virgin_bits);

  /* Now, for the visuals... */

  if (clear_screen)
  {

    SAYF(TERM_CLEAR CURSOR_HIDE);
    clear_screen = 0;

    check_term_size();
  }

  SAYF(TERM_HOME);

  if (term_too_small)
  {

    SAYF(cBRI "Your terminal is too small to display the UI.\n"
              "Please resize terminal window to at least 80x25.\n" cRST);

    return;
  }

  /* Let's start by drawing a centered banner. */

  banner_len = (crash_mode ? 24 : 22) + strlen(VERSION) + strlen(use_banner);
  banner_pad = (80 - banner_len) / 2;
  memset(tmp, ' ', banner_pad);

  sprintf(tmp + banner_pad, "%s " cLCY VERSION cLGN " (%s)", crash_mode ? cPIN "peruvian were-rabbit" : cYEL "american fuzzy lop", use_banner);

  SAYF("\n%s\n\n", tmp);

  /* "Handy" shortcuts for drawing boxes... */

#define bSTG bSTART cGRA
#define bH2 bH bH
#define bH5 bH2 bH2 bH
#define bH10 bH5 bH5
#define bH20 bH10 bH10
#define bH30 bH20 bH10
#define SP5 "     "
#define SP10 SP5 SP5
#define SP20 SP10 SP10

  /* Lord, forgive me this. */

  SAYF(SET_G1 bSTG bLT bH bSTOP cCYA " process timing " bSTG bH30 bH5 bH2 bHB
           bH bSTOP cCYA " overall results " bSTG bH5 bRT "\n");

  if (dumb_mode)
  {

    strcpy(tmp, cRST);
  }
  else
  {

    u64 min_wo_finds = (cur_ms - last_path_time) / 1000 / 60;

    /* First queue cycle: don't stop now! */
    if (queue_cycle == 1 || min_wo_finds < 15)
      strcpy(tmp, cMGN);
    else

      /* Subsequent cycles, but we're still making finds. */
      if (cycles_wo_finds < 25 || min_wo_finds < 30)
        strcpy(tmp, cYEL);
      else

        /* No finds for a long time and no test cases to try. */
        if (cycles_wo_finds > 100 && !pending_not_fuzzed && min_wo_finds > 120)
          strcpy(tmp, cLGN);

        /* Default: cautiously OK to stop? */
        else
          strcpy(tmp, cLBL);
  }

  SAYF(bV bSTOP "        run time : " cRST "%-34s " bSTG bV bSTOP
                "  cycles done : %s%-5s  " bSTG bV "\n",
       DTD(cur_ms, start_time), tmp, DI(queue_cycle - 1));

  /* We want to warn people about not seeing new paths after a full cycle,
     except when resuming fuzzing or running in non-instrumented mode. */

  if (!dumb_mode && (last_path_time || resuming_fuzz || queue_cycle == 1 ||
                     in_bitmap || crash_mode))
  {

    SAYF(bV bSTOP "   last new path : " cRST "%-34s ",
         DTD(cur_ms, last_path_time));
  }
  else
  {

    if (dumb_mode)

      SAYF(bV bSTOP "   last new path : " cPIN "n/a" cRST
                    " (non-instrumented mode)        ");

    else

      SAYF(bV bSTOP "   last new path : " cRST "none yet " cLRD
                    "(odd, check syntax!)      ");
  }

  SAYF(bSTG bV bSTOP "  total paths : " cRST "%-5s  " bSTG bV "\n",
       DI(queued_paths));

  /* Highlight crashes in red if found, denote going over the KEEP_UNIQUE_CRASH
     limit with a '+' appended to the count. */

  sprintf(tmp, "%s%s", DI(unique_crashes),
          (unique_crashes >= KEEP_UNIQUE_CRASH) ? "+" : "");

  SAYF(bV bSTOP " last uniq crash : " cRST "%-34s " bSTG bV bSTOP
                " uniq crashes : %s%-6s " bSTG bV "\n",
       DTD(cur_ms, last_crash_time), unique_crashes ? cLRD : cRST,
       tmp);

  sprintf(tmp, "%s%s", DI(unique_hangs),
          (unique_hangs >= KEEP_UNIQUE_HANG) ? "+" : "");

  SAYF(bV bSTOP "  last uniq hang : " cRST "%-34s " bSTG bV bSTOP
                "   uniq hangs : " cRST "%-6s " bSTG bV "\n",
       DTD(cur_ms, last_hang_time), tmp);

  SAYF(bVR bH bSTOP cCYA " cycle progress " bSTG bH20 bHB bH bSTOP cCYA
                         " map coverage " bSTG bH bHT bH20 bH2 bH bVL "\n");

  /* This gets funny because we want to print several variable-length variables
     together, but then cram them into a fixed-width field - so we need to
     put them in a temporary buffer first. */

  sprintf(tmp, "%s%s (%0.02f%%)", DI(current_entry),
          queue_cur->favored ? "" : "*",
          ((double)current_entry * 100) / queued_paths);

  SAYF(bV bSTOP "  now processing : " cRST "%-17s " bSTG bV bSTOP, tmp);

  sprintf(tmp, "%0.02f%% / %0.02f%%", ((double)queue_cur->bitmap_size) * 100 / MAP_SIZE, t_byte_ratio);

  SAYF("    map density : %s%-21s " bSTG bV "\n", t_byte_ratio > 70 ? cLRD : ((t_bytes < 200 && !dumb_mode) ? cPIN : cRST), tmp);

  sprintf(tmp, "%s (%0.02f%%)", DI(cur_skipped_paths),
          ((double)cur_skipped_paths * 100) / queued_paths);

  SAYF(bV bSTOP " paths timed out : " cRST "%-17s " bSTG bV, tmp);

  sprintf(tmp, "%0.02f bits/tuple",
          t_bytes ? (((double)t_bits) / t_bytes) : 0);

  SAYF(bSTOP " count coverage : " cRST "%-21s " bSTG bV "\n", tmp);

  SAYF(bVR bH bSTOP cCYA " stage progress " bSTG bH20 bX bH bSTOP cCYA
                         " findings in depth " bSTG bH20 bVL "\n");

  sprintf(tmp, "%s (%0.02f%%)", DI(queued_favored),
          ((double)queued_favored) * 100 / queued_paths);

  /* Yeah... it's still going on... halp? */

  SAYF(bV bSTOP "  now trying : " cRST "%-21s " bSTG bV bSTOP
                " favored paths : " cRST "%-22s " bSTG bV "\n",
       stage_name, tmp);

  if (!stage_max)
  {

    sprintf(tmp, "%s/-", DI(stage_cur));
  }
  else
  {

    sprintf(tmp, "%s/%s (%0.02f%%)", DI(stage_cur), DI(stage_max),
            ((double)stage_cur) * 100 / stage_max);
  }

  SAYF(bV bSTOP " stage execs : " cRST "%-21s " bSTG bV bSTOP, tmp);

  sprintf(tmp, "%s (%0.02f%%)", DI(queued_with_cov),
          ((double)queued_with_cov) * 100 / queued_paths);

  SAYF("  new edges on : " cRST "%-22s " bSTG bV "\n", tmp);

  sprintf(tmp, "%s (%s%s unique)", DI(total_crashes), DI(unique_crashes),
          (unique_crashes >= KEEP_UNIQUE_CRASH) ? "+" : "");

  if (crash_mode)
  {

    SAYF(bV bSTOP " total execs : " cRST "%-21s " bSTG bV bSTOP
                  "   new crashes : %s%-22s " bSTG bV "\n",
         DI(total_execs),
         unique_crashes ? cLRD : cRST, tmp);
  }
  else
  {

    SAYF(bV bSTOP " total execs : " cRST "%-21s " bSTG bV bSTOP
                  " total crashes : %s%-22s " bSTG bV "\n",
         DI(total_execs),
         unique_crashes ? cLRD : cRST, tmp);
  }

  /* Show a warning about slow execution. */

  if (avg_exec < 100)
  {

    sprintf(tmp, "%s/sec (%s)", DF(avg_exec), avg_exec < 20 ? "zzzz..." : "slow!");

    SAYF(bV bSTOP "  exec speed : " cLRD "%-21s ", tmp);
  }
  else
  {

    sprintf(tmp, "%s/sec", DF(avg_exec));
    SAYF(bV bSTOP "  exec speed : " cRST "%-21s ", tmp);
  }

  sprintf(tmp, "%s (%s%s unique)", DI(total_tmouts), DI(unique_tmouts),
          (unique_hangs >= KEEP_UNIQUE_HANG) ? "+" : "");

  SAYF(bSTG bV bSTOP "  total tmouts : " cRST "%-22s " bSTG bV "\n", tmp);

  /* Aaaalmost there... hold on! */

  SAYF(bVR bH cCYA bSTOP " fuzzing strategy yields " bSTG bH10 bH bHT bH10
           bH5 bHB bH bSTOP cCYA " path geometry " bSTG bH5 bH2 bH bVL "\n");

  if (skip_deterministic)
  {

    strcpy(tmp, "n/a, n/a, n/a");
  }
  else
  {

    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(stage_finds[STAGE_FLIP1]), DI(stage_cycles[STAGE_FLIP1]),
            DI(stage_finds[STAGE_FLIP2]), DI(stage_cycles[STAGE_FLIP2]),
            DI(stage_finds[STAGE_FLIP4]), DI(stage_cycles[STAGE_FLIP4]));
  }

  SAYF(bV bSTOP "   bit flips : " cRST "%-37s " bSTG bV bSTOP "    levels : " cRST "%-10s " bSTG bV "\n", tmp, DI(max_depth));

  if (!skip_deterministic)
    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(stage_finds[STAGE_FLIP8]), DI(stage_cycles[STAGE_FLIP8]),
            DI(stage_finds[STAGE_FLIP16]), DI(stage_cycles[STAGE_FLIP16]),
            DI(stage_finds[STAGE_FLIP32]), DI(stage_cycles[STAGE_FLIP32]));

  SAYF(bV bSTOP "  byte flips : " cRST "%-37s " bSTG bV bSTOP "   pending : " cRST "%-10s " bSTG bV "\n", tmp, DI(pending_not_fuzzed));

  if (!skip_deterministic)
    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(stage_finds[STAGE_ARITH8]), DI(stage_cycles[STAGE_ARITH8]),
            DI(stage_finds[STAGE_ARITH16]), DI(stage_cycles[STAGE_ARITH16]),
            DI(stage_finds[STAGE_ARITH32]), DI(stage_cycles[STAGE_ARITH32]));

  SAYF(bV bSTOP " arithmetics : " cRST "%-37s " bSTG bV bSTOP "  pend fav : " cRST "%-10s " bSTG bV "\n", tmp, DI(pending_favored));

  if (!skip_deterministic)
    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(stage_finds[STAGE_INTEREST8]), DI(stage_cycles[STAGE_INTEREST8]),
            DI(stage_finds[STAGE_INTEREST16]), DI(stage_cycles[STAGE_INTEREST16]),
            DI(stage_finds[STAGE_INTEREST32]), DI(stage_cycles[STAGE_INTEREST32]));

  SAYF(bV bSTOP "  known ints : " cRST "%-37s " bSTG bV bSTOP " own finds : " cRST "%-10s " bSTG bV "\n", tmp, DI(queued_discovered));

  if (!skip_deterministic)
    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(stage_finds[STAGE_EXTRAS_UO]), DI(stage_cycles[STAGE_EXTRAS_UO]),
            DI(stage_finds[STAGE_EXTRAS_UI]), DI(stage_cycles[STAGE_EXTRAS_UI]),
            DI(stage_finds[STAGE_EXTRAS_AO]), DI(stage_cycles[STAGE_EXTRAS_AO]));

  SAYF(bV bSTOP "  dictionary : " cRST "%-37s " bSTG bV bSTOP
                "  imported : " cRST "%-10s " bSTG bV "\n",
       tmp,
       sync_id ? DI(queued_imported) : (u8 *)"n/a");

  sprintf(tmp, "%s/%s, %s/%s",
          DI(stage_finds[STAGE_HAVOC]), DI(stage_cycles[STAGE_HAVOC]),
          DI(stage_finds[STAGE_SPLICE]), DI(stage_cycles[STAGE_SPLICE]));

  SAYF(bV bSTOP "       havoc : " cRST "%-37s " bSTG bV bSTOP, tmp);

  if (t_bytes)
    sprintf(tmp, "%0.02f%%", stab_ratio);
  else
    strcpy(tmp, "n/a");

  SAYF(" stability : %s%-10s " bSTG bV "\n", (stab_ratio < 85 && var_byte_count > 40) ? cLRD : ((queued_variable && (!persistent_mode || var_byte_count > 20)) ? cMGN : cRST), tmp);

  if (!bytes_trim_out)
  {

    sprintf(tmp, "n/a, ");
  }
  else
  {

    sprintf(tmp, "%0.02f%%/%s, ",
            ((double)(bytes_trim_in - bytes_trim_out)) * 100 / bytes_trim_in,
            DI(trim_execs));
  }

  if (!blocks_eff_total)
  {

    u8 tmp2[128];

    sprintf(tmp2, "n/a");
    strcat(tmp, tmp2);
  }
  else
  {

    u8 tmp2[128];

    sprintf(tmp2, "%0.02f%%",
            ((double)(blocks_eff_total - blocks_eff_select)) * 100 /
                blocks_eff_total);

    strcat(tmp, tmp2);
  }

  SAYF(bV bSTOP "        trim : " cRST "%-37s " bSTG bVR bH20 bH2 bH2 bRB "\n" bLB bH30 bH20 bH2 bH bRB bSTOP cRST RESET_G1, tmp);

  /* Provide some CPU utilization stats. */

  if (cpu_core_count)
  {

    double cur_runnable = get_runnable_processes();
    u32 cur_utilization = cur_runnable * 100 / cpu_core_count;

    u8 *cpu_color = cCYA;

    /* If we could still run one or more processes, use green. */

    if (cpu_core_count > 1 && cur_runnable + 1 <= cpu_core_count)
      cpu_color = cLGN;

    /* If we're clearly oversubscribed, use red. */

    if (!no_cpu_meter_red && cur_utilization >= 150)
      cpu_color = cLRD;

#ifdef HAVE_AFFINITY

    if (cpu_aff >= 0)
    {

      SAYF(SP10 cGRA "[cpu%03u:%s%3u%%" cGRA "]\r" cRST,
           MIN(cpu_aff, 999), cpu_color,
           MIN(cur_utilization, 999));
    }
    else
    {

      SAYF(SP10 cGRA "   [cpu:%s%3u%%" cGRA "]\r" cRST,
           cpu_color, MIN(cur_utilization, 999));
    }

#else

    SAYF(SP10 cGRA "   [cpu:%s%3u%%" cGRA "]\r" cRST,
         cpu_color, MIN(cur_utilization, 999));

#endif /* ^HAVE_AFFINITY */
  }
  else
    SAYF("\r");

  /* Show debugging stats for AFLNet only when AFLNET_DEBUG environment variable is set */
  if (getenv("AFLNET_DEBUG") && (atoi(getenv("AFLNET_DEBUG")) == 1) && state_aware_mode)
  {
    SAYF(cRST "\n\nMax_seed_region_count: %-4s, current_kl_messages_size: %-4s\n\n", DI(max_seed_region_count), DI(kl_messages->size));
    SAYF(cRST "State IDs and its #selected_times," cCYA "#fuzzs," cLRD "#discovered_paths," cGRA "#excersing_paths:\n");

    khint_t k;
    state_info_t *state;
    u32 i = 0;

    for (i = 0; i < state_ids_count; i++)
    {
      u32 state_id = state_ids[i];

      k = kh_get(hms, khms_states, state_id);
      if (k != kh_end(khms_states))
      {
        state = kh_val(khms_states, k);
        SAYF(cRST "S%-3s:%-4s," cCYA "%-5s," cLRD "%-5s," cGRA "%-5s", DI(state->id), DI(state->selected_times), DI(state->fuzzs), DI(state->paths_discovered), DI(state->paths));
        if ((i + 1) % 3 == 0)
          SAYF("\n");
      }
    }
  }

  /* Hallelujah! */

  fflush(0);
}

/* Display quick statistics at the end of processing the input directory,
   plus a bunch of warnings. Some calibration stuff also ended up here,
   along with several hardcoded constants. Maybe clean up eventually. */

static void show_init_stats(void)
{

  struct queue_entry *q = queue;
  u32 min_bits = 0, max_bits = 0;
  u64 min_us = 0, max_us = 0;
  u64 avg_us = 0;
  u32 max_len = 0;

  if (total_cal_cycles)
    avg_us = total_cal_us / total_cal_cycles;

  while (q)
  {

    if (!min_us || q->exec_us < min_us)
      min_us = q->exec_us;
    if (q->exec_us > max_us)
      max_us = q->exec_us;

    if (!min_bits || q->bitmap_size < min_bits)
      min_bits = q->bitmap_size;
    if (q->bitmap_size > max_bits)
      max_bits = q->bitmap_size;

    if (q->len > max_len)
      max_len = q->len;

    q = q->next;
  }

  SAYF("\n");

  if (avg_us > (qemu_mode ? 50000 : 10000))
    WARNF(cLRD "The target binary is pretty slow! See %s/perf_tips.txt.",
          doc_path);

  /* Let's keep things moving with slow binaries. */

  if (avg_us > 50000)
    havoc_div = 10; /* 0-19 execs/sec   */
  else if (avg_us > 20000)
    havoc_div = 5; /* 20-49 execs/sec  */
  else if (avg_us > 10000)
    havoc_div = 2; /* 50-100 execs/sec */

  if (!resuming_fuzz)
  {

    if (max_len > 50 * 1024)
      WARNF(cLRD "Some test cases are huge (%s) - see %s/perf_tips.txt!",
            DMS(max_len), doc_path);
    else if (max_len > 10 * 1024)
      WARNF("Some test cases are big (%s) - see %s/perf_tips.txt.",
            DMS(max_len), doc_path);

    if (useless_at_start && !in_bitmap)
      WARNF(cLRD "Some test cases look useless. Consider using a smaller set.");

    if (queued_paths > 100)
      WARNF(cLRD "You probably have far too many input files! Consider trimming down.");
    else if (queued_paths > 20)
      WARNF("You have lots of input files; try starting small.");
  }

  OKF("Here are some useful stats:\n\n"

      cGRA "    Test case count : " cRST "%u favored, %u variable, %u total\n" cGRA "       Bitmap range : " cRST "%u to %u bits (average: %0.02f bits)\n" cGRA "        Exec timing : " cRST "%s to %s us (average: %s us)\n",
      queued_favored, queued_variable, queued_paths, min_bits, max_bits,
      ((double)total_bitmap_size) / (total_bitmap_entries ? total_bitmap_entries : 1),
      DI(min_us), DI(max_us), DI(avg_us));

  if (!timeout_given)
  {

    /* Figure out the appropriate timeout. The basic idea is: 5x average or
       1x max, rounded up to EXEC_TM_ROUND ms and capped at 1 second.

       If the program is slow, the multiplier is lowered to 2x or 3x, because
       random scheduler jitter is less likely to have any impact, and because
       our patience is wearing thin =) */

    if (avg_us > 50000)
      exec_tmout = avg_us * 2 / 1000;
    else if (avg_us > 10000)
      exec_tmout = avg_us * 3 / 1000;
    else
      exec_tmout = avg_us * 5 / 1000;

    exec_tmout = MAX(exec_tmout, max_us / 1000);
    exec_tmout = (exec_tmout + EXEC_TM_ROUND) / EXEC_TM_ROUND * EXEC_TM_ROUND;

    if (exec_tmout > EXEC_TIMEOUT)
      exec_tmout = EXEC_TIMEOUT;

    ACTF("No -t option specified, so I'll use exec timeout of %u ms.",
         exec_tmout);

    timeout_given = 1;
  }
  else if (timeout_given == 3)
  {

    ACTF("Applying timeout settings from resumed session (%u ms).", exec_tmout);
  }

  /* In dumb mode, re-running every timing out test case with a generous time
     limit is very expensive, so let's select a more conservative default. */

  if (dumb_mode && !getenv("AFL_HANG_TMOUT"))
    hang_tmout = MIN(EXEC_TIMEOUT, exec_tmout * 2 + 100);

  OKF("All set and ready to roll!");
}

/* Write a modified test case, run program, process results. Handle
   error conditions, returning 1 if it's time to bail out. This is
   a helper function for fuzz_one(). */

EXP_ST u8 common_fuzz_stuff(char **argv, u8 *out_buf, u32 len)
{

  u8 fault;

  if (post_handler)
  {

    out_buf = post_handler(out_buf, &len);
    if (!out_buf || !len)
      return 0;
  }

  write_to_testcase(out_buf, len);

  /* AFLNet update kl_messages linked list */

  // parse the out_buf into messages
  u32 region_count = 0;
  region_t *regions = (*extract_requests)(out_buf, len, &region_count);
  if (!region_count)
    PFATAL("AFLNet Region count cannot be Zero");

  // update kl_messages linked list
  u32 i;
  kliter_t(lms) * prev_last_message, *cur_last_message;
  prev_last_message = get_last_message(kl_messages);

  // limit the #messages based on max_seed_region_count to reduce overhead
  for (i = 0; i < region_count; i++)
  {
    u32 len;
    // Identify region size
    if (i == max_seed_region_count)
    {
      len = regions[region_count - 1].end_byte - regions[i].start_byte + 1;
    }
    else
    {
      len = regions[i].end_byte - regions[i].start_byte + 1;
    }

    // Create a new message
    message_t *m = (message_t *)ck_alloc(sizeof(message_t));
    m->mdata = (char *)ck_alloc(len);
    m->msize = len;
    if (m->mdata == NULL)
      PFATAL("Unable to allocate memory region to store new message");
    memcpy(m->mdata, &out_buf[regions[i].start_byte], len);

    // Insert the message to the linked list
    *kl_pushp(lms, kl_messages) = m;

    // Update M2_next in case it points to the tail (M3 is empty)
    // because the tail in klist is updated once a new entry is pushed into it
    // in fact, the old tail storage is used to store the newly added entry and a new tail is created
    if (M2_next->next == kl_end(kl_messages))
    {
      M2_next = kl_end(kl_messages);
    }

    if (i == max_seed_region_count)
      break;
  }
  ck_free(regions);

  cur_last_message = get_last_message(kl_messages);

  // update the linked list with the new M2 & free the previous M2

  // detach the head of previous M2 from the list
  kliter_t(lms) * old_M2_start;
  if (M2_prev == NULL)
  {
    old_M2_start = kl_begin(kl_messages);
    kl_begin(kl_messages) = kl_next(prev_last_message);
    kl_next(cur_last_message) = M2_next;
    kl_next(prev_last_message) = kl_end(kl_messages);
  }
  else
  {
    old_M2_start = kl_next(M2_prev);
    kl_next(M2_prev) = kl_next(prev_last_message);
    kl_next(cur_last_message) = M2_next;
    kl_next(prev_last_message) = kl_end(kl_messages);
  }

  // free the previous M2
  kliter_t(lms) * cur_it, *next_it;
  cur_it = old_M2_start;
  next_it = kl_next(cur_it);
  do
  {
    ck_free(kl_val(cur_it)->mdata);
    ck_free(kl_val(cur_it));
    kmp_free(lms, kl_messages->mp, cur_it);
    --kl_messages->size;

    cur_it = next_it;
    next_it = kl_next(next_it);
  } while (cur_it != M2_next);

  /* End of AFLNet code */

  fault = run_target(argv, exec_tmout);

  // Update fuzz count, no matter whether the generated test is interesting or not
  if (state_aware_mode)
    update_fuzzs();

  if (stop_soon)
    return 1;

  if (fault == FAULT_TMOUT)
  {

    if (subseq_tmouts++ > TMOUT_LIMIT)
    {
      cur_skipped_paths++;
      return 1;
    }
  }
  else
    subseq_tmouts = 0;

  /* Users can hit us with SIGUSR1 to request the current input
     to be abandoned. */

  if (skip_requested)
  {

    skip_requested = 0;
    cur_skipped_paths++;
    return 1;
  }

  /* This handles FAULT_ERROR for us: */

  u8 is_interesting = save_if_interesting(argv, out_buf, len, fault);

  if (is_interesting)
  {
    uninteresting_times = 0;
  }
  else
  {
    uninteresting_times++;
  }

  queued_discovered += is_interesting;

  if (!(stage_cur % stats_update_freq) || stage_cur + 1 == stage_max)
    show_stats();

  return 0;
}

/* Helper to choose random block len for block operations in fuzz_one().
   Doesn't return zero, provided that max_len is > 0. */

static u32 choose_block_len(u32 limit)
{

  u32 min_value, max_value;
  u32 rlim = MIN(queue_cycle, 3);

  if (!run_over10m)
    rlim = 1;

  switch (UR(rlim))
  {

  case 0:
    min_value = 1;
    max_value = HAVOC_BLK_SMALL;
    break;

  case 1:
    min_value = HAVOC_BLK_SMALL;
    max_value = HAVOC_BLK_MEDIUM;
    break;

  default:

    if (UR(10))
    {

      min_value = HAVOC_BLK_MEDIUM;
      max_value = HAVOC_BLK_LARGE;
    }
    else
    {

      min_value = HAVOC_BLK_LARGE;
      max_value = HAVOC_BLK_XL;
    }
  }

  if (min_value >= limit)
    min_value = 1;

  return min_value + UR(MIN(max_value, limit) - min_value + 1);
}

/* Calculate case desirability score to adjust the length of havoc fuzzing.
   A helper function for fuzz_one(). Maybe some of these constants should
   go into config.h. */

static u32 calculate_score(struct queue_entry *q)
{

  u32 avg_exec_us = total_cal_us / total_cal_cycles;
  u32 avg_bitmap_size = total_bitmap_size / total_bitmap_entries;
  u32 perf_score = 100;

  /* Adjust score based on execution speed of this path, compared to the
     global average. Multiplier ranges from 0.1x to 3x. Fast inputs are
     less expensive to fuzz, so we're giving them more air time. */

  if (q->exec_us * 0.1 > avg_exec_us)
    perf_score = 10;
  else if (q->exec_us * 0.25 > avg_exec_us)
    perf_score = 25;
  else if (q->exec_us * 0.5 > avg_exec_us)
    perf_score = 50;
  else if (q->exec_us * 0.75 > avg_exec_us)
    perf_score = 75;
  else if (q->exec_us * 4 < avg_exec_us)
    perf_score = 300;
  else if (q->exec_us * 3 < avg_exec_us)
    perf_score = 200;
  else if (q->exec_us * 2 < avg_exec_us)
    perf_score = 150;

  /* Adjust score based on bitmap size. The working theory is that better
     coverage translates to better targets. Multiplier from 0.25x to 3x. */

  if (q->bitmap_size * 0.3 > avg_bitmap_size)
    perf_score *= 3;
  else if (q->bitmap_size * 0.5 > avg_bitmap_size)
    perf_score *= 2;
  else if (q->bitmap_size * 0.75 > avg_bitmap_size)
    perf_score *= 1.5;
  else if (q->bitmap_size * 3 < avg_bitmap_size)
    perf_score *= 0.25;
  else if (q->bitmap_size * 2 < avg_bitmap_size)
    perf_score *= 0.5;
  else if (q->bitmap_size * 1.5 < avg_bitmap_size)
    perf_score *= 0.75;

  /* Adjust score based on handicap. Handicap is proportional to how late
     in the game we learned about this path. Latecomers are allowed to run
     for a bit longer until they catch up with the rest. */

  if (q->handicap >= 4)
  {

    perf_score *= 4;
    q->handicap -= 4;
  }
  else if (q->handicap)
  {

    perf_score *= 2;
    q->handicap--;
  }

  /* Final adjustment based on input depth, under the assumption that fuzzing
     deeper test cases is more likely to reveal stuff that can't be
     discovered with traditional fuzzers. */

  switch (q->depth)
  {

  case 0 ... 3:
    break;
  case 4 ... 7:
    perf_score *= 2;
    break;
  case 8 ... 13:
    perf_score *= 3;
    break;
  case 14 ... 25:
    perf_score *= 4;
    break;
  default:
    perf_score *= 5;
  }

  /* Make sure that we don't go over limit. */

  if (perf_score > HAVOC_MAX_MULT * 100)
    perf_score = HAVOC_MAX_MULT * 100;

  return perf_score;
}

/* Helper function to see if a particular change (xor_val = old ^ new) could
   be a product of deterministic bit flips with the lengths and stepovers
   attempted by afl-fuzz. This is used to avoid dupes in some of the
   deterministic fuzzing operations that follow bit flips. We also
   return 1 if xor_val is zero, which implies that the old and attempted new
   values are identical and the exec would be a waste of time. */

static u8 could_be_bitflip(u32 xor_val)
{

  u32 sh = 0;

  if (!xor_val)
    return 1;

  /* Shift left until first bit set. */

  while (!(xor_val & 1))
  {
    sh++;
    xor_val >>= 1;
  }

  /* 1-, 2-, and 4-bit patterns are OK anywhere. */

  if (xor_val == 1 || xor_val == 3 || xor_val == 15)
    return 1;

  /* 8-, 16-, and 32-bit patterns are OK only if shift factor is
     divisible by 8, since that's the stepover for these ops. */

  if (sh & 7)
    return 0;

  if (xor_val == 0xff || xor_val == 0xffff || xor_val == 0xffffffff)
    return 1;

  return 0;
}

/* Helper function to see if a particular value is reachable through
   arithmetic operations. Used for similar purposes. */

static u8 could_be_arith(u32 old_val, u32 new_val, u8 blen)
{

  u32 i, ov = 0, nv = 0, diffs = 0;

  if (old_val == new_val)
    return 1;

  /* See if one-byte adjustments to any byte could produce this result. */

  for (i = 0; i < blen; i++)
  {

    u8 a = old_val >> (8 * i),
       b = new_val >> (8 * i);

    if (a != b)
    {
      diffs++;
      ov = a;
      nv = b;
    }
  }

  /* If only one byte differs and the values are within range, return 1. */

  if (diffs == 1)
  {

    if ((u8)(ov - nv) <= ARITH_MAX ||
        (u8)(nv - ov) <= ARITH_MAX)
      return 1;
  }

  if (blen == 1)
    return 0;

  /* See if two-byte adjustments to any byte would produce this result. */

  diffs = 0;

  for (i = 0; i < blen / 2; i++)
  {

    u16 a = old_val >> (16 * i),
        b = new_val >> (16 * i);

    if (a != b)
    {
      diffs++;
      ov = a;
      nv = b;
    }
  }

  /* If only one word differs and the values are within range, return 1. */

  if (diffs == 1)
  {

    if ((u16)(ov - nv) <= ARITH_MAX ||
        (u16)(nv - ov) <= ARITH_MAX)
      return 1;

    ov = SWAP16(ov);
    nv = SWAP16(nv);

    if ((u16)(ov - nv) <= ARITH_MAX ||
        (u16)(nv - ov) <= ARITH_MAX)
      return 1;
  }

  /* Finally, let's do the same thing for dwords. */

  if (blen == 4)
  {

    if ((u32)(old_val - new_val) <= ARITH_MAX ||
        (u32)(new_val - old_val) <= ARITH_MAX)
      return 1;

    new_val = SWAP32(new_val);
    old_val = SWAP32(old_val);

    if ((u32)(old_val - new_val) <= ARITH_MAX ||
        (u32)(new_val - old_val) <= ARITH_MAX)
      return 1;
  }

  return 0;
}

/* Last but not least, a similar helper to see if insertion of an
   interesting integer is redundant given the insertions done for
   shorter blen. The last param (check_le) is set if the caller
   already executed LE insertion for current blen and wants to see
   if BE variant passed in new_val is unique. */

static u8 could_be_interest(u32 old_val, u32 new_val, u8 blen, u8 check_le)
{

  u32 i, j;

  if (old_val == new_val)
    return 1;

  /* See if one-byte insertions from interesting_8 over old_val could
     produce new_val. */

  for (i = 0; i < blen; i++)
  {

    for (j = 0; j < sizeof(interesting_8); j++)
    {

      u32 tval = (old_val & ~(0xff << (i * 8))) |
                 (((u8)interesting_8[j]) << (i * 8));

      if (new_val == tval)
        return 1;
    }
  }

  /* Bail out unless we're also asked to examine two-byte LE insertions
     as a preparation for BE attempts. */

  if (blen == 2 && !check_le)
    return 0;

  /* See if two-byte insertions over old_val could give us new_val. */

  for (i = 0; i < blen - 1; i++)
  {

    for (j = 0; j < sizeof(interesting_16) / 2; j++)
    {

      u32 tval = (old_val & ~(0xffff << (i * 8))) |
                 (((u16)interesting_16[j]) << (i * 8));

      if (new_val == tval)
        return 1;

      /* Continue here only if blen > 2. */

      if (blen > 2)
      {

        tval = (old_val & ~(0xffff << (i * 8))) |
               (SWAP16(interesting_16[j]) << (i * 8));

        if (new_val == tval)
          return 1;
      }
    }
  }

  if (blen == 4 && check_le)
  {

    /* See if four-byte insertions could produce the same result
       (LE only). */

    for (j = 0; j < sizeof(interesting_32) / 4; j++)
      if (new_val == (u32)interesting_32[j])
        return 1;
  }

  return 0;
}

/* Take the current entry from the queue, fuzz it for a while. This
   function is a tad too long... returns 0 if fuzzed successfully, 1 if
   skipped or bailed out. */
// fuzz_one 函数接受一个命令行参数数组 argv，并返回一个字节值。
// 如果成功地进行了模糊测试，则返回 0；如果跳过或中止，则返回 1。
static u8 fuzz_one(char **argv)
{
  s32 len, fd, temp_len, i, j; // 定义一些整数变量用于长度、文件描述符等。
  u8 *in_buf = NULL, *out_buf, *orig_in, *ex_tmp, *eff_map = 0; // 定义指针变量用于输入缓冲区、输出缓冲区等。
  u64 havoc_queued, orig_hit_cnt, new_hit_cnt; // 定义一些无符号长整型变量用于计数。
  u32 splice_cycle = 0, perf_score = 100, orig_perf, prev_cksum, eff_cnt = 1, M2_len; // 定义一些无符号整型变量用于性能评分、哈希值等。
  u8 ret_val = 1, doing_det = 0; // 定义返回值和是否正在执行确定性阶段的标志。
  u8 a_collect[MAX_AUTO_EXTRA]; // 定义一个数组用于收集自动额外数据。
  u32 a_len = 0; // 定义一个变量用于记录收集到的数据长度。

#ifdef IGNORE_FINDS
    // 在 IGNORE_FINDS 模式下，跳过任何不在初始数据集中的条目。
  if (queue_cur->depth > 1)
      return 1;
#else
  // 跳过某些步骤，如果在 state_aware_mode 下，因为在这种模式下种子的选择基于状态感知算法。
  if (state_aware_mode)
      goto AFLNET_REGIONS_SELECTION;

  // 如果有优先级高且未被模糊过的新的队列项，可能跳过当前已经模糊过的或优先级低的案例。
  if (pending_favored)
  {
      if ((queue_cur->was_fuzzed || !queue_cur->favored) && UR(100) < SKIP_TO_NEW_PROB)
          return 1;
  }
  else if (!dumb_mode && !queue_cur->favored && queued_paths > 10)
  {
      // 如果不在 dumb_mode 模式下，并且当前队列项不是优先级高的，且队列中的路径数量大于 10：
      // dumb_mode 是一种简化模式，不使用覆盖率信息。
      // queue_cur->favored 表示当前队列项是否是优先级高的。
      // queued_paths 是当前已知路径的数量。

      // 对于已经模糊过的输入，跳过的概率较高。
      if (queue_cycle > 1 && !queue_cur->was_fuzzed)
      {
          // 如果当前已经是第二个或更多个循环周期，并且当前队列项尚未被模糊过：
          if (UR(100) < SKIP_NFAV_NEW_PROB)
              return 1;
          // 使用随机数生成器 UR(100) 生成一个 0 到 99 之间的随机数。
          // 如果这个随机数小于 SKIP_NFAV_NEW_PROB（通常是一个较小的概率），则跳过当前队列项。
      }
      else
      {
          // 对于已经模糊过的输入，跳过的概率较低。
          if (UR(100) < SKIP_NFAV_OLD_PROB)
              return 1;
          // 同样使用随机数生成器 UR(100) 生成一个 0 到 99 之间的随机数。
          // 如果这个随机数小于 SKIP_NFAV_OLD_PROB（通常是一个较高的概率），则跳过当前队列项。
      }
  }
  #endif /* ^IGNORE_FINDS */

  // 如果不是在控制台上运行，显示当前处理的测试用例的信息。
  if (not_on_tty)
  {
      ACTF("Fuzzing test case #%u (%u total, %llu uniq crashes found)...",
          current_entry, queued_paths, unique_crashes);
      fflush(stdout);
  }

  AFLNET_REGIONS_SELECTION:;

  // 初始化超时计数器和其他变量。
  subseq_tmouts = 0;
  cur_depth = queue_cur->depth;

  // 定义 M2 区域的起始 ID 和区域数量。
  u32 M2_start_region_ID = 0, M2_region_count = 0;

  // 识别前缀 M1、候选子序列 M2 和后缀 M3。参见 AFLNet 论文。
  // 在此实现中，我们只需要识别 M2_start_region_ID 和 M2_region_count。
  // 如何识别这些信息取决于状态感知模式。
  if (state_aware_mode)
  {
      // 在状态感知模式下，根据目标状态 ID 选择 M2。
      u32 total_region = queue_cur->region_count;
      if (total_region == 0)
          PFATAL("0 region found for %s", queue_cur->fname);
      // 如果当前队列项没有区域信息，则报错并终止。

      if (target_state_id == 0)
      { 
          // 如果没有目标状态 ID，则跳过当前队列项。
          // No prefix subsequence (M1 is empty)
          M2_start_region_ID = 0; // M2 的起始区域 ID 为 0。
          M2_region_count = 0;   // M2 的区域数量为 0。

          // To compute M2_region_count, we identify the first region which has a different annotation
          // Now we quickly compare the state count, we could make it more fine grained by comparing the exact response codes
          for (i = 0; i < queue_cur->region_count; i++)  
          {
              if (queue_cur->regions[i].state_count != queue_cur->regions[0].state_count)
                  break;
              M2_region_count++;
          }
          // 遍历所有区域，直到找到第一个状态计数不同的区域，计算 M2 区域的数量。
      }
      else
      {
          // M1 is unlikely to be empty
          M2_start_region_ID = 0;

          // Identify M2_start_region_ID first based on the target_state_id
          for (i = 0; i < queue_cur->region_count; i++)
          {
              u32 regionalStateCount = queue_cur->regions[i].state_count;
              if (regionalStateCount > 0)
              {
                  // reachableStateID is the last ID in the state_sequence
                  u32 reachableStateID = queue_cur->regions[i].state_sequence[regionalStateCount - 1];
                  M2_start_region_ID++;
                  if (reachableStateID == target_state_id)
                      break;
              }
              else
              {
                  // No annotation for this region
                  return 1;
              }
          }
          // 遍历所有区域，找到包含目标状态 ID 的区域，设置 M2 的起始区域 ID。

          // Then identify M2_region_count
          for (i = M2_start_region_ID; i < queue_cur->region_count; i++)
          {
              if (queue_cur->regions[i].state_count != queue_cur->regions[M2_start_region_ID].state_count)
                  break;
              M2_region_count++;
          }
          // 从 M2 的起始区域开始，遍历所有区域，直到找到第一个状态计数不同的区域，计算 M2 区域的数量。

          // Handle corner case(s) and skip the current queue entry
          if (M2_start_region_ID >= queue_cur->region_count)
              return 1;
          // 如果 M2 的起始区域 ID 超过了总区域数，跳过当前队列项。
      }
  }
  else
  {
      /* Select M2 randomly */
      u32 total_region = queue_cur->region_count;
      if (total_region == 0)
          PFATAL("0 region found for %s", queue_cur->fname);
      // 如果当前队列项没有区域信息，则报错并终止。

      M2_start_region_ID = UR(total_region);
      M2_region_count = UR(total_region - M2_start_region_ID);
      if (M2_region_count == 0)
          M2_region_count++; // Mutate one region at least
      // 随机选择 M2 的起始区域 ID 和区域数量，确保至少变异一个区域。
  }
  /* Construct the kl_messages linked list and identify boundary pointers (M2_prev and M2_next) */
  kl_messages = construct_kl_messages(queue_cur->fname, queue_cur->regions, queue_cur->region_count);
  // 构建包含当前队列项所有消息的链表 kl_messages
  // queue_cur->fname: 当前队列项的文件名
  // queue_cur->regions: 当前队列项的区域信息
  // queue_cur->region_count: 当前队列项的区域数量

  kliter_t(lms) * it;  // 定义一个迭代器 it 用于遍历 kl_messages 链表

  M2_prev = NULL;  // 初始化 M2 区域的前一个消息指针为 NULL
  M2_next = kl_end(kl_messages);  // 初始化 M2 区域的后一个消息指针为链表的末尾

  u32 count = 0;  // 计数器，记录当前遍历到的消息索引
  for (it = kl_begin(kl_messages); it != kl_end(kl_messages); it = kl_next(it))
  {
      if (count == M2_start_region_ID - 1)
      {
          M2_prev = it;  // 当遍历到 M2 区域的前一个消息时，将 M2_prev 设置为当前迭代器
      }

      if (count == M2_start_region_ID + M2_region_count)
      {
          M2_next = it;  // 当遍历到 M2 区域的后一个消息时，将 M2_next 设置为当前迭代器
      }
      count++;  // 增加计数器
  }

  if (uninteresting_times >= UNINTERESTING_THRESHOLD && chat_times < CHATTING_THRESHOLD)
  {
      uninteresting_times = 0;  // 重置不感兴趣次数
      // Fuzzing is stalled - ask LLM for help by taking the current sequence and if it is has a prefix,
      // ask the LLM to generate a possibly correct next message

      u32 *response_bytes_temp = NULL;  // 存储响应字节的临时数组
      u32 buffer_len = 0;  // 缓冲区长度

      u32 response_count = 0;  // 响应数量
      char *response_fname = alloc_printf("%s/responses-ipsm/id:%s", out_dir, basename(queue_cur->fname));
      // 构建响应文件的路径
      // out_dir: 输出目录
      // queue_cur->fname: 当前队列项的文件名

      char **responses_temp = get_responses_from_file(response_fname, &response_bytes_temp, &response_count, &buffer_len);
      // 从文件中读取响应数据，存储在 responses_temp 中，并获取响应的字节数和数量

      if (responses_temp != NULL)
      {
          chat_times++;  // 增加与 LLM 交互的次数
          ck_free(response_fname);  // 释放响应文件路径

          char *history = NULL;  // 历史对话内容
          u32 history_len = 0;  // 历史对话内容的长度
          char *examples = NULL;  // 示例对话内容
          int examples_len = 0;  // 示例对话内容的长度
          kliter_t(lms) *it_pref = kl_begin(kl_messages);  // 初始化迭代器 it_pref 为链表的起始位置
          int i = 0;  // 计数器，记录当前处理的响应索引
          int empty = 1;  // 标记是否为空
          int prev_len = 0;  // 上一次响应的长度

          for (; i < response_count && it_pref != M2_prev; i++, it_pref = kl_next(it_pref))
          {
              empty = 0;  // 标记为非空

              json_object *request_v = json_object_new_string_len(kl_val(it_pref)->mdata, kl_val(it_pref)->msize);
              // 创建 JSON 对象，包含当前消息的数据和大小
              char *request = strdup(json_object_to_json_string(request_v));
              // 将 JSON 对象转换为字符串并复制
              json_object_put(request_v);  // 释放 JSON 对象
              int request_len = strlen(request) - 2;
              request++;  // 跳过开头的双引号
              for (int j = 0; j < request_len; j++)
              {
                  if (!isprint(request[j]) || request[j] < 0 || request[j] >= 127)  // 确保字符是可打印的
                      request[j] = ' ';
              }

              json_object *response_v = json_object_new_string_len(responses_temp[i], response_bytes_temp[i] - prev_len);
              // 创建 JSON 对象，包含当前响应的数据和大小
              char *response = strdup(json_object_to_json_string(response_v));
              // 将 JSON 对象转换为字符串并复制
              json_object_put(response_v);  // 释放 JSON 对象
              prev_len = response_bytes_temp[i];  // 更新上一次响应的长度
              int response_len = strlen(response) - 2;
              response++;  // 跳过开头的双引号
              for (int j = 0; j < response_len; j++)
              {
                  if (!isprint(response[j]) || response[j] < 0 || response[j] >= 127)
                      response[j] = ' ';
              }

              if (i == 0)
              {
                  examples_len = asprintf(&examples, "Request-1:\\n%.*s\\nRequest-2:\\n%.*s\\n", request_len, request, request_len, request);
                  // 构建示例对话内容
              }

              history = ck_realloc(history, history_len + request_len);
              memcpy(history + history_len, request, request_len);
              history_len += request_len;  // 将请求添加到历史对话内容中

              history = ck_realloc(history, history_len + response_len);
              memcpy(history + history_len, response, response_len);
              history_len += response_len;  // 将响应添加到历史对话内容中

              free(request - 1);  // 释放请求字符串
              free(response - 1);  // 释放响应字符串
          }

          if (!empty)
          {
              history = ck_realloc(history, history_len + 1);
              history[history_len] = '\0';  // 结束历史对话内容字符串

              // Trim the strings to ensure the prompt is not too big
              if (history_len > HISTORY_PROMPT_LENGTH)
              {
                  int offset = history_len - HISTORY_PROMPT_LENGTH;
                  if (history[offset - 1] == '\\')
                  {
                      offset++;
                  }
                  char *history_temp = ck_strdup(history + offset);
                  ck_free(history);
                  history = history_temp;
                  history_len = history_len - offset;  // 截断历史对话内容以确保不超过最大长度
              }

              if (examples_len > EXAMPLES_PROMPT_LENGTH)
              {
                  int offset = examples_len - EXAMPLES_PROMPT_LENGTH;
                  if (examples[offset - 1] == '\\')
                  {
                      offset++;
                  }
                  char *examples_temp = strdup(examples + offset);
                  free(examples);
                  examples = examples_temp;
                  examples_len = examples_len - offset;  // 截断示例对话内容以确保不超过最大长度
              }

              char *stall_prompt = construct_prompt_stall(protocol_name, examples, history);
              // 构建停滞提示
              // protocol_name: 协议名称
              // examples: 示例对话内容
              // history: 历史对话内容

              // printf("Got prompt:\n\n%s\n", stall_prompt);  // 打印提示（调试用）

              char *stall_response = chat_with_llm(stall_prompt, "turbo", STALL_RETRIES, 1.5);
              // 使用 LLM 生成响应
              // stall_prompt: 停滞提示
              // "turbo": LLM 模型名称
              // STALL_RETRIES: 重试次数
              // 1.5: 温度参数

              // printf("Got response:\n\n%s\n", stall_response);  // 打印响应（调试用）

              {
                  char *stall_prompt_path = alloc_printf("%s/stall-interactions/prompt-%d", out_dir, chat_times);
                  // 构建停滞提示文件路径
                  int stall_prompt_fd = open(stall_prompt_path, O_WRONLY | O_CREAT, 0600);
                  // 打开或创建停滞提示文件

                  ck_write(stall_prompt_fd, stall_prompt, strlen(stall_prompt), stall_prompt_path);
                  // 写入停滞提示内容

                  close(stall_prompt_fd);  // 关闭文件
                  ck_free(stall_prompt_path);  // 释放文件路径
              }

              if (stall_response == NULL)
                  goto free_stall;  // 如果没有生成响应，跳转到清理部分

              {
                  char *stall_response_path = alloc_printf("%s/stall-interactions/response-%d", out_dir, chat_times);
                  // 构建停滞响应文件路径
                  int stall_response_fd = open(stall_response_path, O_WRONLY | O_CREAT, 0600);
                  // 打开或创建停滞响应文件

                  ck_write(stall_response_fd, stall_response, strlen(stall_response), stall_response_path);
                  // 写入停滞响应内容

                  close(stall_response_fd);  // 关闭文件
                  ck_free(stall_response_path);  // 释放文件路径
              }

              char *stall_message = extract_stalled_message(stall_response, strlen(stall_response));
              // 从响应中提取停滞消息

              if (stall_message == NULL)
                  goto free_stall;  // 如果没有提取到消息，跳转到清理部分

              stall_message = format_request_message(stall_message);
              // 格式化请求消息

              if (stall_message != NULL)
              {
                  // printf("Filtered message:\n%s\n", stall_message);  // 打印格式化后的消息（调试用）

                  if (common_fuzz_stuff(argv, stall_message, strlen(stall_message)))
                  {
                      // code diverges from abandon entry due to less allocations
                      splicing_with = -1;  // 重置拼接标志

                      /* Update pending_not_fuzzed count if we made it through the calibration
                        cycle and have not seen this entry before. */

                      if (!stop_soon && !queue_cur->cal_failed && !queue_cur->was_fuzzed)
                      {
                          queue_cur->was_fuzzed = 1;  // 标记当前队列项已被模糊测试
                          was_fuzzed_map[get_state_index(target_state_id)][queue_cur->index] = 1;  // 更新已模糊测试映射
                          pending_not_fuzzed--;  // 减少待模糊测试的数量
                          if (queue_cur->favored)
                              pending_favored--;  // 减少待模糊测试的优先级数量
                      }

                      ck_free(stall_message);  // 释放停滞消息
                      delete_kl_messages(kl_messages);  // 删除消息链表

                      return ret_val;  // 返回结果
                  }

                  ck_free(stall_message);  // 释放停滞消息
              }

              free(stall_response);  // 释放响应
          free_stall:
              free(stall_prompt);  // 释放提示
              ck_free(history);  // 释放历史对话内容
              free(examples);  // 释放示例对话内容
          }
          else
          {
              // printf("Had empty prompt\n");  // 打印空提示（调试用）
          }
      }
  }
  /* Construct the buffer to be mutated and update out_buf */
  if (M2_prev == NULL)
  {
      it = kl_begin(kl_messages);
  }
  else
  {
      it = kl_next(M2_prev);
  }
  // 如果 M2_prev 为 NULL，则从 kl_messages 的起始位置开始；
  // 否则，从 M2_prev 的下一个位置开始。

  u32 in_buf_size = 0;
  while (it != M2_next)
  {
      in_buf = (u8 *)ck_realloc(in_buf, in_buf_size + kl_val(it)->msize);
      if (!in_buf)
          PFATAL("AFLNet cannot allocate memory for in_buf");
      // 动态分配内存以容纳 in_buf 和当前消息的数据
      // 如果内存分配失败，输出错误信息并退出

      // Retrieve data from kl_messages to populate the in_buf
      memcpy(&in_buf[in_buf_size], kl_val(it)->mdata, kl_val(it)->msize);
      // 将当前消息的数据复制到 in_buf 的适当位置

      in_buf_size += kl_val(it)->msize;
      it = kl_next(it);
      // 更新 in_buf 的总大小，并移动迭代器到下一个消息
  }

  orig_in = in_buf;
  // 保存原始输入缓冲区

  out_buf = ck_alloc_nozero(in_buf_size);
  memcpy(out_buf, in_buf, in_buf_size);
  // 分配新的输出缓冲区并初始化为 in_buf 的内容

  // Update len to keep the correct size of the buffer being mutated
  len = in_buf_size;
  // 更新 len 为 in_buf 的大小，以便后续操作知道缓冲区的大小

  // Save the len for later use
  M2_len = len;
  // 保存 len 到 M2_len，供后续使用

  /*********************
   * PERFORMANCE SCORE *
   *********************/

  orig_perf = perf_score = calculate_score(queue_cur);
  // 计算当前队列项的性能得分，并分别保存到 orig_perf 和 perf_score

  /* Skip right away if -d is given, if we have done deterministic fuzzing on
    this entry ourselves (was_fuzzed), or if it has gone through deterministic
    testing in earlier, resumed runs (passed_det). */

  if (skip_deterministic || queue_cur->was_fuzzed || queue_cur->passed_det)
      goto havoc_stage;
  // 如果跳过确定性模糊测试标志设置、当前队列项已被确定性模糊测试或已通过早期确定性测试，则跳转到 havoc 阶段

  /* Skip deterministic fuzzing if exec path checksum puts this out of scope
    for this master instance. */

  if (master_max && (queue_cur->exec_cksum % master_max) != master_id - 1)
      goto havoc_stage;
  // 如果当前执行路径校验和不在主实例范围内，则跳转到 havoc 阶段

  doing_det = 1;
  // 标记正在执行确定性模糊测试

  /*********************************************
   * SIMPLE BITFLIP (+dictionary construction) *
   *********************************************/

  #define FLIP_BIT(_ar, _b)                   \
  do                                          \
  {                                           \
      u8 *_arf = (u8 *)(_ar);                 \
      u32 _bf = (_b);                         \
      _arf[(_bf) >> 3] ^= (128 >> ((_bf)&7)); \
  } while (0)
  // 定义宏 FLIP_BIT 用于翻转指定位

  /* Single walking bit. */

  stage_short = "flip1";
  stage_max = len << 3;
  stage_name = "bitflip 1/1";
  // 初始化阶段名称和最大步数（位数）

  stage_val_type = STAGE_VAL_NONE;
  // 设置阶段值类型为无

  orig_hit_cnt = queued_paths + unique_crashes;
  // 保存当前的路径数和唯一崩溃数

  prev_cksum = queue_cur->exec_cksum;
  // 保存当前队列项的执行路径校验和

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++)
  {
    stage_cur_byte = stage_cur >> 3;
    // 计算当前位所在的字节索引

    FLIP_BIT(out_buf, stage_cur);
    // 翻转当前位

    if (common_fuzz_stuff(argv, out_buf, len))
        goto abandon_entry;
    // 执行通用模糊测试操作，如果成功则跳转到放弃当前条目

    FLIP_BIT(out_buf, stage_cur);
    // 恢复翻转的位

    /* While flipping the least significant bit in every byte, pull of an extra
       trick to detect possible syntax tokens. In essence, the idea is that if
       you have a binary blob like this:

       xxxxxxxxIHDRxxxxxxxx

       ...and changing the leading and trailing bytes causes variable or no
       changes in program flow, but touching any character in the "IHDR" string
       always produces the same, distinctive path, it's highly likely that
       "IHDR" is an atomically-checked magic value of special significance to
       the fuzzed format.

       We do this here, rather than as a separate stage, because it's a nice
       way to keep the operation approximately "free" (i.e., no extra execs).

       Empirically, performing the check when flipping the least significant bit
       is advantageous, compared to doing it at the time of more disruptive
       changes, where the program flow may be affected in more violent ways.

       The caveat is that we won't generate dictionaries in the -d mode or -S
       mode - but that's probably a fair trade-off.

       This won't work particularly well with paths that exhibit variable
       behavior, but fails gracefully, so we'll carry out the checks anyway.

      */

    if (!dumb_mode && (stage_cur & 7) == 7)
    {
      u32 cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);
      // 计算当前 trace_bits 的哈希值

      if (stage_cur == stage_max - 1 && cksum == prev_cksum)
      {
        // 如果到达文件末尾且哈希值未改变
        if (a_len < MAX_AUTO_EXTRA)
          a_collect[a_len] = out_buf[stage_cur >> 3];
        a_len++;
        // 收集最后一个字符并增加 a_len

        if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
          maybe_add_auto(a_collect, a_len);
        // 如果收集的字符串长度合适，尝试添加到自动字典
      }
      else if (cksum != prev_cksum)
      {
        // 如果哈希值发生变化
        if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
          maybe_add_auto(a_collect, a_len);
        // 如果收集的字符串长度合适，尝试添加到自动字典

        a_len = 0;
        prev_cksum = cksum;
        // 重置 a_len 并更新 prev_cksum
      }

      // 继续收集字符串，但前提是位翻转确实产生了影响
      if (cksum != queue_cur->exec_cksum)
      {
        if (a_len < MAX_AUTO_EXTRA)
          a_collect[a_len] = out_buf[stage_cur >> 3];
        a_len++;
      }
    }
  }
  new_hit_cnt = queued_paths + unique_crashes;
  // 更新新的命中计数

  stage_finds[STAGE_FLIP1] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP1] += stage_max;
  // 更新单个位翻转阶段的命中数和循环次数

  /* Two walking bits. */
  stage_name = "bitflip 2/1";
  stage_short = "flip2";
  stage_max = (len << 3) - 1;
  // 设置双位翻转阶段的名称、简短名称和最大步数

  orig_hit_cnt = new_hit_cnt;
  // 更新原始命中计数

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++)
  {
    stage_cur_byte = stage_cur >> 3;
    // 计算当前位所在的字节索引

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);
    // 翻转当前位及其后一位

    if (common_fuzz_stuff(argv, out_buf, len))
      goto abandon_entry;
    // 执行通用模糊测试操作，如果成功则跳转到放弃当前条目

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);
    // 恢复翻转的位
  }

  new_hit_cnt = queued_paths + unique_crashes;
  // 更新新的命中计数

  stage_finds[STAGE_FLIP2] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP2] += stage_max;
  // 更新双位翻转阶段的命中数和循环次数

  /* Four walking bits. */
  stage_name = "bitflip 4/1";
  stage_short = "flip4";
  stage_max = (len << 3) - 3;
  // 设置四位翻转阶段的名称、简短名称和最大步数

  orig_hit_cnt = new_hit_cnt;
  // 更新原始命中计数

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++)
  {
    stage_cur_byte = stage_cur >> 3;
    // 计算当前位所在的字节索引

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);
    FLIP_BIT(out_buf, stage_cur + 2);
    FLIP_BIT(out_buf, stage_cur + 3);
    // 翻转当前位及其后三位

    if (common_fuzz_stuff(argv, out_buf, len))
      goto abandon_entry;
    // 执行通用模糊测试操作，如果成功则跳转到放弃当前条目

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);
    FLIP_BIT(out_buf, stage_cur + 2);
    FLIP_BIT(out_buf, stage_cur + 3);
    // 恢复翻转的位
  }

  new_hit_cnt = queued_paths + unique_crashes;
  // 更新新的命中计数

  stage_finds[STAGE_FLIP4] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP4] += stage_max;
  // 更新四位翻转阶段的命中数和循环次数

  /* Effector map setup. These macros calculate:

     EFF_APOS      - position of a particular file offset in the map.
     EFF_ALEN      - length of a map with a particular number of bytes.
     EFF_SPAN_ALEN - map span for a sequence of bytes.

   */

#define EFF_APOS(_p) ((_p) >> EFF_MAP_SCALE2)
#define EFF_REM(_x) ((_x) & ((1 << EFF_MAP_SCALE2) - 1))
#define EFF_ALEN(_l) (EFF_APOS(_l) + !!EFF_REM(_l))
#define EFF_SPAN_ALEN(_p, _l) (EFF_APOS((_p) + (_l)-1) - EFF_APOS(_p) + 1)
  /* Initialize effector map for the next step (see comments below). Always
    flag first and last byte as doing something. */

  eff_map = ck_alloc(EFF_ALEN(len));
  // 分配 eff_map 数组，用于标记哪些字节对执行路径有影响
  eff_map[0] = 1;
  // 标记第一个字节总是有效

  if (EFF_APOS(len - 1) != 0)
  {
    eff_map[EFF_APOS(len - 1)] = 1;
    eff_cnt++;
  }
  // 如果最后一个字节不在 eff_map 的第一个位置，标记它并增加 eff_cnt

  /* Walking byte. */

  stage_name = "bitflip 8/8";
  stage_short = "flip8";
  stage_max = len;
  // 设置阶段名称、简短名称和最大步数

  orig_hit_cnt = new_hit_cnt;
  // 更新原始命中计数

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++)
  {
    stage_cur_byte = stage_cur;
    // 当前字节索引

    out_buf[stage_cur] ^= 0xFF;
    // 翻转当前字节

    if (common_fuzz_stuff(argv, out_buf, len))
      goto abandon_entry;
    // 执行通用模糊测试操作，如果成功则跳转到放弃当前条目

    /* We also use this stage to pull off a simple trick: we identify
      bytes that seem to have no effect on the current execution path
      even when fully flipped - and we skip them during more expensive
      deterministic stages, such as arithmetics or known ints. */

    if (!eff_map[EFF_APOS(stage_cur)])
    {
      u32 cksum;

      /* If in dumb mode or if the file is very short, just flag everything
        without wasting time on checksums. */

      if (!dumb_mode && len >= EFF_MIN_LEN)
        cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);
      else
        cksum = ~queue_cur->exec_cksum;
      // 计算当前 trace_bits 的哈希值，如果在智能模式且文件长度足够长

      if (cksum != queue_cur->exec_cksum)
      {
        eff_map[EFF_APOS(stage_cur)] = 1;
        eff_cnt++;
      }
      // 如果哈希值变化，标记当前字节为有效并增加 eff_cnt
    }

    out_buf[stage_cur] ^= 0xFF;
    // 恢复翻转的字节
  }

  /* If the effector map is more than EFF_MAX_PERC dense, just flag the
    whole thing as worth fuzzing, since we wouldn't be saving much time
    anyway. */

  if (eff_cnt != EFF_ALEN(len) &&
      eff_cnt * 100 / EFF_ALEN(len) > EFF_MAX_PERC)
  {
    memset(eff_map, 1, EFF_ALEN(len));
    // 如果 eff_cnt 超过 EFF_MAX_PERC 的密度，标记整个 eff_map 为有效
    blocks_eff_select += EFF_ALEN(len);
  }
  else
  {
    blocks_eff_select += eff_cnt;
  }
  // 否则，只增加 eff_cnt

  blocks_eff_total += EFF_ALEN(len);
  // 增加总的 eff_map 长度

  new_hit_cnt = queued_paths + unique_crashes;
  // 更新新的命中计数

  stage_finds[STAGE_FLIP8] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP8] += stage_max;
  // 更新八位翻转阶段的命中数和循环次数

  /* Two walking bytes. */

  if (len < 2)
    goto skip_bitflip;
  // 如果长度小于 2，跳过此阶段

  stage_name = "bitflip 16/8";
  stage_short = "flip16";
  stage_cur = 0;
  stage_max = len - 1;
  // 设置阶段名称、简短名称、当前步数和最大步数

  orig_hit_cnt = new_hit_cnt;
  // 更新原始命中计数

  for (i = 0; i < len - 1; i++)
  {
    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)])
    {
      stage_max--;
      continue;
    }
    // 如果当前字节和下一个字节都不在 eff_map 中，减少 stage_max 并继续

    stage_cur_byte = i;
    // 当前字节索引

    *(u16 *)(out_buf + i) ^= 0xFFFF;
    // 翻转当前字节和下一个字节

    if (common_fuzz_stuff(argv, out_buf, len))
      goto abandon_entry;
    // 执行通用模糊测试操作，如果成功则跳转到放弃当前条目
    stage_cur++;

    *(u16 *)(out_buf + i) ^= 0xFFFF;
    // 恢复翻转的字节
  }

  new_hit_cnt = queued_paths + unique_crashes;
  // 更新新的命中计数

  stage_finds[STAGE_FLIP16] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP16] += stage_max;
  // 更新十六位翻转阶段的命中数和循环次数

  if (len < 4)
    goto skip_bitflip;
  // 如果长度小于 4，跳过后续阶段

  /* Four walking bytes. */

  stage_name = "bitflip 32/8";
  stage_short = "flip32";
  stage_cur = 0;
  stage_max = len - 3;
  // 设置阶段名称、简短名称、当前步数和最大步数

  orig_hit_cnt = new_hit_cnt;
  // 更新原始命中计数

  for (i = 0; i < len - 3; i++)
  {
    /* Let's consult the effector map... */
    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)])
    {
      stage_max--;
      continue;
    }
    // 如果当前字节及其后三个字节都不在 eff_map 中，减少 stage_max 并继续

    stage_cur_byte = i;
    // 当前字节索引

    *(u32 *)(out_buf + i) ^= 0xFFFFFFFF;
    // 翻转当前字节及其后三个字节

    if (common_fuzz_stuff(argv, out_buf, len))
      goto abandon_entry;
    // 执行通用模糊测试操作，如果成功则跳转到放弃当前条目
    stage_cur++;

    *(u32 *)(out_buf + i) ^= 0xFFFFFFFF;
    // 恢复翻转的字节
  }

  new_hit_cnt = queued_paths + unique_crashes;
  // 更新新的命中计数

  stage_finds[STAGE_FLIP32] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP32] += stage_max;
  // 更新三十二位翻转阶段的命中数和循环次数
skip_bitflip:

  if (no_arith)
    goto skip_arith;

  /**********************
   * ARITHMETIC INC/DEC *
   **********************/

  /* 8-bit arithmetics. */
  stage_name = "arith 8/8";
  stage_short = "arith8";
  stage_cur = 0;
  stage_max = 2 * len * ARITH_MAX;
  // 设置阶段名称、简短名称、当前步数和最大步数

  stage_val_type = STAGE_VAL_LE;
  // 设置值类型为小端序

  orig_hit_cnt = new_hit_cnt;
  // 更新原始命中计数

  for (i = 0; i < len; i++)
  {
    u8 orig = out_buf[i];
    // 获取当前字节的原始值

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)])
    {
      stage_max -= 2 * ARITH_MAX;
      continue;
    }
    // 如果当前字节不在效标图中，减少 stage_max 并继续下一次循环

    stage_cur_byte = i;
    // 设置当前字节索引

    for (j = 1; j <= ARITH_MAX; j++)
    {
      u8 r = orig ^ (orig + j);
      // 计算加法后的异或结果

      /* Do arithmetic operations only if the result couldn't be a product
        of a bitflip. */

      if (!could_be_bitflip(r))
      {
        stage_cur_val = j;
        out_buf[i] = orig + j;
        // 进行加法操作

        if (common_fuzz_stuff(argv, out_buf, len))
          goto abandon_entry;
        // 执行通用模糊测试操作，如果成功则跳转到放弃当前条目
        stage_cur++;
      }
      else
        stage_max--;
      // 如果结果可能是位翻转的结果，减少 stage_max

      r = orig ^ (orig - j);
      // 计算减法后的异或结果

      if (!could_be_bitflip(r))
      {
        stage_cur_val = -j;
        out_buf[i] = orig - j;
        // 进行减法操作

        if (common_fuzz_stuff(argv, out_buf, len))
          goto abandon_entry;
        // 执行通用模糊测试操作，如果成功则跳转到放弃当前条目
        stage_cur++;
      }
      else
        stage_max--;
      // 如果结果可能是位翻转的结果，减少 stage_max

      out_buf[i] = orig;
      // 恢复原始值
    }
  }

  new_hit_cnt = queued_paths + unique_crashes;
  // 更新新的命中计数

  stage_finds[STAGE_ARITH8] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_ARITH8] += stage_max;
  // 更新八位算术操作阶段的命中数和循环次数

  /* 16-bit arithmetic operations, both endians. */

  if (len < 2)
    goto skip_arith;
  // 如果长度小于 2，跳过此阶段

  stage_name = "arith 16/8";
  stage_short = "arith16";
  stage_cur = 0;
  stage_max = 4 * (len - 1) * ARITH_MAX;
  // 设置阶段名称、简短名称、当前步数和最大步数

  orig_hit_cnt = new_hit_cnt;
  // 更新原始命中计数

  for (i = 0; i < len - 1; i++)
  {
    u16 orig = *(u16 *)(out_buf + i);
    // 获取当前两个字节的原始值

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)])
    {
      stage_max -= 4 * ARITH_MAX;
      continue;
    }
    // 如果当前字节及其后一个字节都不在效标图中，减少 stage_max 并继续下一次循环

    stage_cur_byte = i;
    // 设置当前字节索引

    for (j = 1; j <= ARITH_MAX; j++)
    {
      u16 r1 = orig ^ (orig + j),
          r2 = orig ^ (orig - j),
          r3 = orig ^ SWAP16(SWAP16(orig) + j),
          r4 = orig ^ SWAP16(SWAP16(orig) - j);
      // 计算各种算术操作后的异或结果

      /* Try little endian addition and subtraction first. Do it only
        if the operation would affect more than one byte (hence the
        & 0xff overflow checks) and if it couldn't be a product of
        a bitflip. */

      stage_val_type = STAGE_VAL_LE;
      // 设置值类型为小端序

      if ((orig & 0xff) + j > 0xff && !could_be_bitflip(r1))
      {
        stage_cur_val = j;
        *(u16 *)(out_buf + i) = orig + j;
        // 进行小端序加法操作

        if (common_fuzz_stuff(argv, out_buf, len))
          goto abandon_entry;
        // 执行通用模糊测试操作，如果成功则跳转到放弃当前条目
        stage_cur++;
      }
      else
        stage_max--;
      // 如果结果可能是位翻转的结果，减少 stage_max

      if ((orig & 0xff) < j && !could_be_bitflip(r2))
      {
        stage_cur_val = -j;
        *(u16 *)(out_buf + i) = orig - j;
        // 进行小端序减法操作

        if (common_fuzz_stuff(argv, out_buf, len))
          goto abandon_entry;
        // 执行通用模糊测试操作，如果成功则跳转到放弃当前条目
        stage_cur++;
      }
      else
        stage_max--;
      // 如果结果可能是位翻转的结果，减少 stage_max

      /* Big endian comes next. Same deal. */

      stage_val_type = STAGE_VAL_BE;
      // 设置值类型为大端序

      if ((orig >> 8) + j > 0xff && !could_be_bitflip(r3))
      {
        stage_cur_val = j;
        *(u16 *)(out_buf + i) = SWAP16(SWAP16(orig) + j);
        // 进行大端序加法操作

        if (common_fuzz_stuff(argv, out_buf, len))
          goto abandon_entry;
        // 执行通用模糊测试操作，如果成功则跳转到放弃当前条目
        stage_cur++;
      }
      else
        stage_max--;
      // 如果结果可能是位翻转的结果，减少 stage_max

      if ((orig >> 8) < j && !could_be_bitflip(r4))
      {
        stage_cur_val = -j;
        *(u16 *)(out_buf + i) = SWAP16(SWAP16(orig) - j);
        // 进行大端序减法操作

        if (common_fuzz_stuff(argv, out_buf, len))
          goto abandon_entry;
        // 执行通用模糊测试操作，如果成功则跳转到放弃当前条目
        stage_cur++;
      }
      else
        stage_max--;
      // 如果结果可能是位翻转的结果，减少 stage_max

      *(u16 *)(out_buf + i) = orig;
      // 恢复原始值
    }
  }

  new_hit_cnt = queued_paths + unique_crashes;
  // 更新新的命中计数

  stage_finds[STAGE_ARITH16] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_ARITH16] += stage_max;
  // 更新十六位算术操作阶段的命中数和循环次数
  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_ARITH16] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_ARITH16] += stage_max;

  /* 32-bit arithmetics, both endians. */

  if (len < 4)
    goto skip_arith;

  stage_name = "arith 32/8";
  stage_short = "arith32";
  stage_cur = 0;
  stage_max = 4 * (len - 3) * ARITH_MAX;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; i++)
  {
    u32 orig = *(u32 *)(out_buf + i);
    // 获取当前四个字节的原始值

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)])
    {
      stage_max -= 4 * ARITH_MAX;
      continue;
    }
    // 如果当前字节及其后三个字节都不在效标图中，减少 stage_max 并继续下一次循环

    stage_cur_byte = i;
    // 设置当前字节索引

    for (j = 1; j <= ARITH_MAX; j++)
    {
      u32 r1 = orig ^ (orig + j),
          r2 = orig ^ (orig - j),
          r3 = orig ^ SWAP32(SWAP32(orig) + j),
          r4 = orig ^ SWAP32(SWAP32(orig) - j);
      // 计算各种算术操作后的异或结果

      /* Little endian first. Same deal as with 16-bit: we only want to
        try if the operation would have effect on more than two bytes. */

      stage_val_type = STAGE_VAL_LE;
      // 设置值类型为小端序

      if ((orig & 0xffff) + j > 0xffff && !could_be_bitflip(r1))
      {
        stage_cur_val = j;
        *(u32 *)(out_buf + i) = orig + j;
        // 进行小端序加法操作

        if (common_fuzz_stuff(argv, out_buf, len))
          goto abandon_entry;
        // 执行通用模糊测试操作，如果成功则跳转到放弃当前条目
        stage_cur++;
      }
      else
        stage_max--;
      // 如果结果可能是位翻转的结果，减少 stage_max

      if ((orig & 0xffff) < j && !could_be_bitflip(r2))
      {
        stage_cur_val = -j;
        *(u32 *)(out_buf + i) = orig - j;
        // 进行小端序减法操作

        if (common_fuzz_stuff(argv, out_buf, len))
          goto abandon_entry;
        // 执行通用模糊测试操作，如果成功则跳转到放弃当前条目
        stage_cur++;
      }
      else
        stage_max--;
      // 如果结果可能是位翻转的结果，减少 stage_max

      /* Big endian next. */

      stage_val_type = STAGE_VAL_BE;
      // 设置值类型为大端序

      if ((SWAP32(orig) & 0xffff) + j > 0xffff && !could_be_bitflip(r3))
      {
        stage_cur_val = j;
        *(u32 *)(out_buf + i) = SWAP32(SWAP32(orig) + j);
        // 进行大端序加法操作

        if (common_fuzz_stuff(argv, out_buf, len))
          goto abandon_entry;
        // 执行通用模糊测试操作，如果成功则跳转到放弃当前条目
        stage_cur++;
      }
      else
        stage_max--;
      // 如果结果可能是位翻转的结果，减少 stage_max

      if ((SWAP32(orig) & 0xffff) < j && !could_be_bitflip(r4))
      {
        stage_cur_val = -j;
        *(u32 *)(out_buf + i) = SWAP32(SWAP32(orig) - j);
        // 进行大端序减法操作

        if (common_fuzz_stuff(argv, out_buf, len))
          goto abandon_entry;
        // 执行通用模糊测试操作，如果成功则跳转到放弃当前条目
        stage_cur++;
      }
      else
        stage_max--;
      // 如果结果可能是位翻转的结果，减少 stage_max

      *(u32 *)(out_buf + i) = orig;
      // 恢复原始值
    }
  }

  new_hit_cnt = queued_paths + unique_crashes;
  // 更新新的命中计数

  stage_finds[STAGE_ARITH32] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_ARITH32] += stage_max;
  // 更新三十二位算术操作阶段的命中数和循环次数
skip_arith:

  /**********************
   * INTERESTING VALUES *
   **********************/
  /* Setting 8-bit integers. */

  stage_name = "interest 8/8";
  stage_short = "int8";
  stage_cur = 0;
  stage_max = len * sizeof(interesting_8);
  // 设置阶段名称、简短名称、当前步数和最大步数

  stage_val_type = STAGE_VAL_LE;
  // 设置值类型为小端序

  orig_hit_cnt = new_hit_cnt;
  // 更新原始命中计数

  for (i = 0; i < len; i++)
  {
    u8 orig = out_buf[i];
    // 获取当前字节的原始值

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)])
    {
      stage_max -= sizeof(interesting_8);
      continue;
    }
    // 如果当前字节不在效标图中，减少 stage_max 并继续下一次循环

    stage_cur_byte = i;
    // 设置当前字节索引

    for (j = 0; j < sizeof(interesting_8); j++)
    {
      /* Skip if the value could be a product of bitflips or arithmetics. */

      if (could_be_bitflip(orig ^ (u8)interesting_8[j]) ||
          could_be_arith(orig, (u8)interesting_8[j], 1))
      {
        stage_max--;
        continue;
      }
      // 如果结果可能是位翻转或算术操作的结果，减少 stage_max 并继续下一次循环

      stage_cur_val = interesting_8[j];
      out_buf[i] = interesting_8[j];
      // 设置当前字节为感兴趣的 8 位整数

      if (common_fuzz_stuff(argv, out_buf, len))
        goto abandon_entry;
      // 执行通用模糊测试操作，如果成功则跳转到放弃当前条目

      out_buf[i] = orig;
      // 恢复原始值
      stage_cur++;
    }
  }

  new_hit_cnt = queued_paths + unique_crashes;
  // 更新新的命中计数

  stage_finds[STAGE_INTEREST8] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_INTEREST8] += stage_max;
  // 更新八位整数插入阶段的命中数和循环次数

  /* Setting 16-bit integers, both endians. */

  if (no_arith || len < 2)
    goto skip_interest;
  // 如果禁用算术操作或长度小于 2，跳过此阶段

  stage_name = "interest 16/8";
  stage_short = "int16";
  stage_cur = 0;
  stage_max = 2 * (len - 1) * (sizeof(interesting_16) >> 1);
  // 设置阶段名称、简短名称、当前步数和最大步数

  orig_hit_cnt = new_hit_cnt;
  // 更新原始命中计数

  for (i = 0; i < len - 1; i++)
  {
    u16 orig = *(u16 *)(out_buf + i);
    // 获取当前两个字节的原始值

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)])
    {
      stage_max -= sizeof(interesting_16);
      continue;
    }
    // 如果当前字节及其后一个字节都不在效标图中，减少 stage_max 并继续下一次循环

    stage_cur_byte = i;
    // 设置当前字节索引

    for (j = 0; j < sizeof(interesting_16) / 2; j++)
    {
      stage_cur_val = interesting_16[j];

      /* Skip if this could be a product of a bitflip, arithmetics,
        or single-byte interesting value insertion. */

      if (!could_be_bitflip(orig ^ (u16)interesting_16[j]) &&
          !could_be_arith(orig, (u16)interesting_16[j], 2) &&
          !could_be_interest(orig, (u16)interesting_16[j], 2, 0))
      {
        stage_val_type = STAGE_VAL_LE;
        // 设置值类型为小端序

        *(u16 *)(out_buf + i) = interesting_16[j];
        // 设置当前两个字节为感兴趣的小端序 16 位整数

        if (common_fuzz_stuff(argv, out_buf, len))
          goto abandon_entry;
        // 执行通用模糊测试操作，如果成功则跳转到放弃当前条目
        stage_cur++;
      }
      else
        stage_max--;
      // 如果结果可能是位翻转、算术操作或单字节感兴趣值插入的结果，减少 stage_max

      if ((u16)interesting_16[j] != SWAP16(interesting_16[j]) &&
          !could_be_bitflip(orig ^ SWAP16(interesting_16[j])) &&
          !could_be_arith(orig, SWAP16(interesting_16[j]), 2) &&
          !could_be_interest(orig, SWAP16(interesting_16[j]), 2, 1))
      {
        stage_val_type = STAGE_VAL_BE;
        // 设置值类型为大端序

        *(u16 *)(out_buf + i) = SWAP16(interesting_16[j]);
        // 设置当前两个字节为感兴趣的大端序 16 位整数

        if (common_fuzz_stuff(argv, out_buf, len))
          goto abandon_entry;
        // 执行通用模糊测试操作，如果成功则跳转到放弃当前条目
        stage_cur++;
      }
      else
        stage_max--;
      // 如果结果可能是位翻转、算术操作或单字节感兴趣值插入的结果，减少 stage_max
    }

    *(u16 *)(out_buf + i) = orig;
    // 恢复原始值
  }

  new_hit_cnt = queued_paths + unique_crashes;
  // 更新新的命中计数

  stage_finds[STAGE_INTEREST16] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_INTEREST16] += stage_max;
  // 更新十六位整数插入阶段的命中数和循环次数

  if (len < 4)
    goto skip_interest;
  // 如果长度小于 4，跳过后续阶段
  /* Setting 32-bit integers, both endians. */

  stage_name = "interest 32/8";
  stage_short = "int32";
  stage_cur = 0;
  stage_max = 2 * (len - 3) * (sizeof(interesting_32) >> 2);
  // 设置阶段名称、简短名称、当前步数和最大步数

  orig_hit_cnt = new_hit_cnt;
  // 更新原始命中计数

  for (i = 0; i < len - 3; i++)
  {
    u32 orig = *(u32 *)(out_buf + i);
    // 获取当前四个字节的原始值

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)])
    {
      stage_max -= sizeof(interesting_32) >> 1;
      continue;
    }
    // 如果当前字节及其后三个字节都不在效标图中，减少 stage_max 并继续下一次循环

    stage_cur_byte = i;
    // 设置当前字节索引

    for (j = 0; j < sizeof(interesting_32) / 4; j++)
    {
      stage_cur_val = interesting_32[j];

      /* Skip if this could be a product of a bitflip, arithmetics,
        or word interesting value insertion. */

      if (!could_be_bitflip(orig ^ (u32)interesting_32[j]) &&
          !could_be_arith(orig, interesting_32[j], 4) &&
          !could_be_interest(orig, interesting_32[j], 4, 0))
      {
        stage_val_type = STAGE_VAL_LE;
        // 设置值类型为小端序

        *(u32 *)(out_buf + i) = interesting_32[j];
        // 设置当前四个字节为感兴趣的小端序 32 位整数

        if (common_fuzz_stuff(argv, out_buf, len))
          goto abandon_entry;
        // 执行通用模糊测试操作，如果成功则跳转到放弃当前条目
        stage_cur++;
      }
      else
        stage_max--;
      // 如果结果可能是位翻转、算术操作或单字节感兴趣值插入的结果，减少 stage_max

      if ((u32)interesting_32[j] != SWAP32(interesting_32[j]) &&
          !could_be_bitflip(orig ^ SWAP32(interesting_32[j])) &&
          !could_be_arith(orig, SWAP32(interesting_32[j]), 4) &&
          !could_be_interest(orig, SWAP32(interesting_32[j]), 4, 1))
      {
        stage_val_type = STAGE_VAL_BE;
        // 设置值类型为大端序

        *(u32 *)(out_buf + i) = SWAP32(interesting_32[j]);
        // 设置当前四个字节为感兴趣的大端序 32 位整数

        if (common_fuzz_stuff(argv, out_buf, len))
          goto abandon_entry;
        // 执行通用模糊测试操作，如果成功则跳转到放弃当前条目
        stage_cur++;
      }
      else
        stage_max--;
      // 如果结果可能是位翻转、算术操作或单字节感兴趣值插入的结果，减少 stage_max
    }

    *(u32 *)(out_buf + i) = orig;
    // 恢复原始值
  }

  new_hit_cnt = queued_paths + unique_crashes;
  // 更新新的命中计数

  stage_finds[STAGE_INTEREST32] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_INTEREST32] += stage_max;
  // 更新三十二位整数插入阶段的命中数和循环次数
skip_interest:

  /********************
   * DICTIONARY STUFF *
   ********************/
  /* Overwrite with user-supplied extras. */

  if (!extras_cnt)
      goto skip_user_extras;
  // 如果没有用户提供的额外数据，跳过此阶段

  stage_name = "user extras (over)";
  stage_short = "ext_UO";
  stage_cur = 0;
  stage_max = extras_cnt * len;
  // 设置阶段名称、简短名称、当前步数和最大步数

  stage_val_type = STAGE_VAL_NONE;
  // 设置值类型为无

  orig_hit_cnt = new_hit_cnt;
  // 更新原始命中计数

  for (i = 0; i < len; i++)
  {
    u32 last_len = 0;
    // 记录最后一个插入的额外数据的长度

    stage_cur_byte = i;
    // 设置当前字节索引

    /* Extras are sorted by size, from smallest to largest. This means
      that we don't have to worry about restoring the buffer in
      between writes at a particular offset determined by the outer
      loop. */

    for (j = 0; j < extras_cnt; j++)
    {
      /* Skip extras probabilistically if extras_cnt > MAX_DET_EXTRAS. Also
        skip them if there's no room to insert the payload, if the token
        is redundant, or if its entire span has no bytes set in the effector
        map. */

      if ((extras_cnt > MAX_DET_EXTRAS && UR(extras_cnt) >= MAX_DET_EXTRAS) ||
          extras[j].len > len - i ||
          !memcmp(extras[j].data, out_buf + i, extras[j].len) ||
          !memchr(eff_map + EFF_APOS(i), 1, EFF_SPAN_ALEN(i, extras[j].len)))
      {
        stage_max--;
        continue;
      }
      // 跳过概率性选择的额外数据，或者没有空间插入，或者数据冗余，或者效标图中没有有效字节

      last_len = extras[j].len;
      memcpy(out_buf + i, extras[j].data, last_len);
      // 将当前额外数据复制到输出缓冲区

      if (common_fuzz_stuff(argv, out_buf, len))
        goto abandon_entry;
      // 执行通用模糊测试操作，如果成功则跳转到放弃当前条目
      stage_cur++;
    }

    /* Restore all the clobbered memory. */
    memcpy(out_buf + i, in_buf + i, last_len);
    // 恢复被覆盖的内存
  }

  new_hit_cnt = queued_paths + unique_crashes;
  // 更新新的命中计数

  stage_finds[STAGE_EXTRAS_UO] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_EXTRAS_UO] += stage_max;
  // 更新用户额外数据覆盖阶段的命中数和循环次数

  /* Insertion of user-supplied extras. */

  stage_name = "user extras (insert)";
  stage_short = "ext_UI";
  stage_cur = 0;
  stage_max = extras_cnt * len;
  // 设置阶段名称、简短名称、当前步数和最大步数

  orig_hit_cnt = new_hit_cnt;
  // 更新原始命中计数

  ex_tmp = ck_alloc(len + MAX_DICT_FILE);
  // 分配临时缓冲区

  for (i = 0; i <= len; i++)
  {
    stage_cur_byte = i;
    // 设置当前字节索引

    for (j = 0; j < extras_cnt; j++)
    {
      if (len + extras[j].len > MAX_FILE)
      {
        stage_max--;
        continue;
      }
      // 如果插入后超出文件大小限制，跳过

      /* Insert token */
      memcpy(ex_tmp + i, extras[j].data, extras[j].len);
      // 将当前额外数据插入临时缓冲区

      /* Copy tail */
      memcpy(ex_tmp + i + extras[j].len, out_buf + i, len - i);
      // 复制剩余部分到临时缓冲区

      if (common_fuzz_stuff(argv, ex_tmp, len + extras[j].len))
      {
        ck_free(ex_tmp);
        goto abandon_entry;
      }
      // 执行通用模糊测试操作，如果成功则跳转到放弃当前条目
      stage_cur++;
    }

    /* Copy head */
    ex_tmp[i] = out_buf[i];
    // 复制头部数据到临时缓冲区
  }

  ck_free(ex_tmp);
  // 释放临时缓冲区

  new_hit_cnt = queued_paths + unique_crashes;
  // 更新新的命中计数

  stage_finds[STAGE_EXTRAS_UI] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_EXTRAS_UI] += stage_max;
  // 更新用户额外数据插入阶段的命中数和循环次数
skip_user_extras:
  /* Overwrite with auto-generated extras. */

  if (!a_extras_cnt)
      goto skip_extras;
  // 如果没有自动生成的额外数据，跳过此阶段

  stage_name = "auto extras (over)";
  stage_short = "ext_AO";
  stage_cur = 0;
  stage_max = MIN(a_extras_cnt, USE_AUTO_EXTRAS) * len;
  // 设置阶段名称、简短名称、当前步数和最大步数

  stage_val_type = STAGE_VAL_NONE;
  // 设置值类型为无

  orig_hit_cnt = new_hit_cnt;
  // 更新原始命中计数

  for (i = 0; i < len; i++)
  {
    u32 last_len = 0;
    // 记录最后一个插入的额外数据的长度

    stage_cur_byte = i;
    // 设置当前字节索引

    for (j = 0; j < MIN(a_extras_cnt, USE_AUTO_EXTRAS); j++)
    {
      /* See the comment in the earlier code; extras are sorted by size. */

      if (a_extras[j].len > len - i ||
          !memcmp(a_extras[j].data, out_buf + i, a_extras[j].len) ||
          !memchr(eff_map + EFF_APOS(i), 1, EFF_SPAN_ALEN(i, a_extras[j].len)))
      {
        stage_max--;
        continue;
      }
      // 跳过如果没有空间插入，或者数据冗余，或者效标图中没有有效字节

      last_len = a_extras[j].len;
      memcpy(out_buf + i, a_extras[j].data, last_len);
      // 将当前额外数据复制到输出缓冲区

      if (common_fuzz_stuff(argv, out_buf, len))
        goto abandon_entry;
      // 执行通用模糊测试操作，如果成功则跳转到放弃当前条目
      stage_cur++;
    }

    /* Restore all the clobbered memory. */
    memcpy(out_buf + i, in_buf + i, last_len);
    // 恢复被覆盖的内存
  }

  new_hit_cnt = queued_paths + unique_crashes;
  // 更新新的命中计数

  stage_finds[STAGE_EXTRAS_AO] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_EXTRAS_AO] += stage_max;
  // 更新自动生成额外数据覆盖阶段的命中数和循环次数

skip_extras:

  /* If we made it this far without jumping to havoc_stage or abandon_entry,
      we're properly done with deterministic steps and can mark it as such
      in the .state/ directory. */

  if (!queue_cur->passed_det)
      mark_as_det_done(queue_cur);
  // 如果我们已经到达这里而没有跳转到 havoc_stage 或 abandon_entry，
  // 表示确定性步骤已经完成，可以在 .state/ 目录中标记为已完成
  /****************
   * RANDOM HAVOC *
   ****************/

havoc_stage:

  stage_cur_byte = -1;
  // 初始化当前字节索引为 -1，表示没有特定的字节被选中

  /* The havoc stage mutation code is also invoked when splicing files; if the
    splice_cycle variable is set, generate different descriptions and such. */

  if (!splice_cycle)
  {
    // 如果不是拼接模式
    stage_name = "havoc";
    stage_short = "havoc";
    stage_max = (doing_det ? HAVOC_CYCLES_INIT : HAVOC_CYCLES) *
                perf_score / havoc_div / 100;
    // 设置阶段名称、简短名称和最大步数
    // 如果正在进行确定性步骤，则使用初始循环次数，否则使用默认循环次数
    // 最大步数根据性能评分和 Havoc 除数计算
  }
  else
  {
    static u8 tmp[32];
    // 定义一个静态数组用于存储拼接阶段的名称

    perf_score = orig_perf;
    // 使用原始性能评分

    sprintf(tmp, "splice %u", splice_cycle);
    stage_name = tmp;
    stage_short = "splice";
    stage_max = SPLICE_HAVOC * perf_score / havoc_div / 100;
    // 设置阶段名称为拼接阶段，并计算最大步数
  }

  if (stage_max < HAVOC_MIN)
    stage_max = HAVOC_MIN;
  // 确保最大步数不低于最小值 HAVOC_MIN

  temp_len = len;
  // 设置临时长度为输入缓冲区的长度

  orig_hit_cnt = queued_paths + unique_crashes;
  // 更新原始命中计数

  havoc_queued = queued_paths;
  // 记录当前排队的路径数

  /* We essentially just do several thousand runs (depending on perf_score)
    where we take the input file and make random stacked tweaks. */

  // u32 mutable_len = 0;
  // for(int i = 0; i < rc;i++){
  //   mutable_len += ranges[i].len;
  // }
  // 计算可变区域的总长度（注释掉的部分）

  range_list original_ranges;
  kv_init(original_ranges);
  // 初始化范围列表

  double epsilon = UR(100) / 100.0;
  // 生成一个随机数 [0, 1)

  int is_exploration = epsilon < EPSILON_CHOICE;
  // 判断是否进行探索（完全随机搜索）

  if (is_exploration)
  {
    stage_name = "havoc explore";
    stage_short = "havoc_explore";
    // 探索模式 - 完全随机搜索
    range v = {.len = temp_len, .start = 0, .mutable = 1};
    kv_push(range, original_ranges, v);
    // 将整个输入缓冲区标记为可变区域
  }
  else
  {
    stage_name = "havoc exploit";
    stage_short = "havoc_exploit";
    // 利用模式 - 利用已有的语法结构

    original_ranges = parse_buffer(out_buf, temp_len);
    // 解析输入缓冲区，生成可变区域列表
  }

  int rc = kv_size(original_ranges);
  // 获取可变区域列表的大小

  range *ranges = ck_alloc(rc * sizeof(range));
  // 分配内存用于存储可变区域

  memcpy(ranges, original_ranges.a, rc * sizeof(range));
  // 复制可变区域列表到新分配的内存中
  for (stage_cur = 0; stage_cur < stage_max; stage_cur++)
  {
    // 遍历从 0 到 stage_max 的每一个阶段

    u32 use_stacking = 1 << (1 + UR(HAVOC_STACK_POW2));
    // 生成一个随机的堆叠层数，范围为 2 到 2^(1 + UR(HAVOC_STACK_POW2))

    stage_cur_val = use_stacking;
    // 设置当前阶段的堆叠层数

    for (i = 0; i < use_stacking; i++)
    {
      // 对于每一层堆叠

      u32 range_choice = UR(rc);
      // 选择一个随机的可变区域索引

      // while(!ranges[range_choice].mutable){
      //   range_choice = UR(rc);
      // }
      // 确保选择的区域是可变的（注释掉的部分）

      switch (UR(15 + 2 + (region_level_mutation ? 8 : 0)))
      {
        // 生成一个随机数，范围为 0 到 15 + 2 + (region_level_mutation ? 8 : 0)
        // 这个随机数决定了要应用的变异操作类型
      case 0:
        /* Flip a single bit somewhere. Spooky! */
        if (ranges[range_choice].len < 1)
          break;
        // 如果选定的可变区域长度小于 1，跳过此操作

        FLIP_BIT((out_buf + ranges[range_choice].start), UR(ranges[range_choice].len << 3));
        // 在选定的可变区域内随机选择一个位并翻转它
        // FLIP_BIT(out_buf, UR(temp_len << 3));
        // （注释掉的部分）在整个输入缓冲区内随机选择一个位并翻转它
        break;

      case 1:
        /* Set byte to interesting value. */
        if (ranges[range_choice].len < 1)
          break;
        // 如果选定的可变区域长度小于 1，跳过此操作

        out_buf[ranges[range_choice].start + UR(ranges[range_choice].len)] = interesting_8[UR(sizeof(interesting_8))];
        // 在选定的可变区域内随机选择一个字节，并将其设置为一个有趣的 8 位值
        break;

      case 2:
        /* Set word to interesting value, randomly choosing endian. */
        if (ranges[range_choice].len < 2)
          break;
        // 如果选定的可变区域长度小于 2，跳过此操作

        if (UR(2))
        {
          s32 offset = ranges[range_choice].start + UR(ranges[range_choice].len - 1);
          *(u16 *)(out_buf + offset) = interesting_16[UR(sizeof(interesting_16) >> 1)];
          // 在选定的可变区域内随机选择一个位置，并将其设置为一个有趣的 16 位值（小端序）
        }
        else
        {
          s32 offset = ranges[range_choice].start + UR(ranges[range_choice].len - 1);
          *(u16 *)(out_buf + offset) = SWAP16(interesting_16[UR(sizeof(interesting_16) >> 1)]);
          // 在选定的可变区域内随机选择一个位置，并将其设置为一个有趣的 16 位值（大端序）
        }
        break;

      case 3:
        /* Set dword to interesting value, randomly choosing endian. */
        if (ranges[range_choice].len < 4)
          break;
        // 如果选定的可变区域长度小于 4，跳过此操作

        if (UR(2))
        {
          s32 offset = ranges[range_choice].start + UR(ranges[range_choice].len - 3);
          *(u32 *)(out_buf + offset) = interesting_32[UR(sizeof(interesting_32) >> 2)];
          // 在选定的可变区域内随机选择一个位置，并将其设置为一个有趣的 32 位值（小端序）
        }
        else
        {
          s32 offset = ranges[range_choice].start + UR(ranges[range_choice].len - 3);
          *(u32 *)(out_buf + offset) = SWAP32(interesting_32[UR(sizeof(interesting_32) >> 2)]);
          // 在选定的可变区域内随机选择一个位置，并将其设置为一个有趣的 32 位值（大端序）
        }
        break;

      case 4:
        if (ranges[range_choice].len < 1)
          break;
        /* Randomly subtract from byte. */
        out_buf[ranges[range_choice].start + UR(ranges[range_choice].len)] -= 1 + UR(ARITH_MAX);
        // 在选定的可变区域内随机选择一个字节，并从中随机减去一个 1 到 ARITH_MAX 之间的值
        break;

      case 5:
        if (ranges[range_choice].len < 1)
          break;
        /* Randomly add to byte. */
        out_buf[ranges[range_choice].start + UR(ranges[range_choice].len)] += 1 + UR(ARITH_MAX);
        // 在选定的可变区域内随机选择一个字节，并向其中随机加上一个 1 到 ARITH_MAX 之间的值
        break;

      case 6:
        /* Randomly subtract from word, random endian. */
        if (ranges[range_choice].len < 2)
          break;
        // 如果选定的可变区域长度小于 2，跳过此操作

        if (UR(2))
        {
          u32 pos = ranges[range_choice].start + UR(ranges[range_choice].len - 1);
          *(u16 *)(out_buf + pos) -= 1 + UR(ARITH_MAX);
          // 在选定的可变区域内随机选择一个位置，并从中随机减去一个 1 到 ARITH_MAX 之间的值（小端序）
        }
        else
        {
          u32 pos = ranges[range_choice].start + UR(ranges[range_choice].len - 1);
          u16 num = 1 + UR(ARITH_MAX);
          *(u16 *)(out_buf + pos) = SWAP16(SWAP16(*(u16 *)(out_buf + pos)) - num);
          // 在选定的可变区域内随机选择一个位置，并从中随机减去一个 1 到 ARITH_MAX 之间的值（大端序）
        }
        break;

      case 7:
        /* Randomly add to word, random endian. */
        if (ranges[range_choice].len < 2)
          break;
        // 如果选定的可变区域长度小于 2，跳过此操作

        if (UR(2))
        {
          u32 pos = ranges[range_choice].start + UR(ranges[range_choice].len - 1);
          *(u16 *)(out_buf + pos) += 1 + UR(ARITH_MAX);
          // 在选定的可变区域内随机选择一个位置，并向其中随机加上一个 1 到 ARITH_MAX 之间的值（小端序）
        }
        else
        {
          u32 pos = ranges[range_choice].start + UR(ranges[range_choice].len - 1);
          u16 num = 1 + UR(ARITH_MAX);
          *(u16 *)(out_buf + pos) = SWAP16(SWAP16(*(u16 *)(out_buf + pos)) + num);
          // 在选定的可变区域内随机选择一个位置，并向其中随机加上一个 1 到 ARITH_MAX 之间的值（大端序）
        }
        break;

      case 8:
        /* Randomly subtract from dword, random endian. */
        if (ranges[range_choice].len < 4)
          break;
        // 如果选定的可变区域长度小于 4，跳过此操作

        if (UR(2))
        {
          u32 pos = ranges[range_choice].start + UR(ranges[range_choice].len - 3);
          *(u32 *)(out_buf + pos) -= 1 + UR(ARITH_MAX);
          // 在选定的可变区域内随机选择一个位置，并从中随机减去一个 1 到 ARITH_MAX 之间的值（小端序）
        }
        else
        {
          u32 pos = ranges[range_choice].start + UR(ranges[range_choice].len - 3);
          u32 num = 1 + UR(ARITH_MAX);
          *(u32 *)(out_buf + pos) = SWAP32(SWAP32(*(u32 *)(out_buf + pos)) - num);
          // 在选定的可变区域内随机选择一个位置，并从中随机减去一个 1 到 ARITH_MAX 之间的值（大端序）
        }
        break;

      case 9:
        /* Randomly add to dword, random endian. */
        if (ranges[range_choice].len < 4)
          break;
        // 如果选定的可变区域长度小于 4，跳过此操作

        if (UR(2))
        {
          u32 pos = ranges[range_choice].start + UR(ranges[range_choice].len - 3);
          *(u32 *)(out_buf + pos) += 1 + UR(ARITH_MAX);
          // 在选定的可变区域内随机选择一个位置，并向其中随机加上一个 1 到 ARITH_MAX 之间的值（小端序）
        }
        else
        {
          u32 pos = ranges[range_choice].start + UR(ranges[range_choice].len - 3);
          u32 num = 1 + UR(ARITH_MAX);
          *(u32 *)(out_buf + pos) = SWAP32(SWAP32(*(u32 *)(out_buf + pos)) + num);
          // 在选定的可变区域内随机选择一个位置，并向其中随机加上一个 1 到 ARITH_MAX 之间的值（大端序）
        }
        break;

      case 10:
        if (ranges[range_choice].len < 1)
          break;
        /* Just set a random byte to a random value. Because, why not. We use XOR with 1-255 to eliminate the possibility of a no-op. */
        out_buf[ranges[range_choice].start + UR(ranges[range_choice].len)] ^= 1 + UR(255);
        // 在选定的可变区域内随机选择一个字节，并将其与 1 到 255 之间的随机值进行异或操作
        break;
      case 11 ... 12:
      {
        /* Delete bytes. We're making this a bit more likely
          than insertion (the next option) in hopes of keeping
          files reasonably small. */

        u32 del_from, del_len;

        if (ranges[range_choice].len < 2)
          break;
        // 如果选定的可变区域长度小于 2，跳过此操作

        /* Don't delete too much. */
        del_len = choose_block_len(ranges[range_choice].len - 1);
        // 选择要删除的字节数，不超过选定区域长度减 1

        del_from = ranges[range_choice].start + UR(ranges[range_choice].len - del_len + 1);
        // 在选定的可变区域内随机选择一个起始位置

        memmove(out_buf + del_from, out_buf + del_from + del_len,
                temp_len - del_from - del_len);
        // 将删除后的部分向前移动

        temp_len -= del_len;
        // 更新总长度

        for (int i = range_choice + 1; i < rc; i++)
        {
          ranges[i].start -= del_len;
        }
        // 更新后续区域的起始位置

        ranges[range_choice].len -= del_len;
        // 更新选定区域的长度
        break;
      }

      case 13:
      {
        if (temp_len + HAVOC_BLK_XL < MAX_FILE)
        {
          /* Clone bytes (75%) or insert a block of constant bytes (25%). */

          u8 actually_clone = UR(4);
          // 生成一个随机数，决定是否克隆字节（75%）还是插入常量字节（25%）

          u32 clone_from, clone_to, clone_len;
          u8 *new_buf;

          if (actually_clone)
          {
            clone_len = choose_block_len(temp_len);
            // 选择要克隆的字节数

            clone_from = UR(temp_len - clone_len + 1);
            // 在整个缓冲区内随机选择一个起始位置
          }
          else
          {
            clone_len = choose_block_len(HAVOC_BLK_XL);
            // 选择要插入的常量字节数

            clone_from = 0;
          }

          clone_to = ranges[range_choice].start + (ranges[range_choice].len == 0 ? 0 : UR(ranges[range_choice].len));
          // 在选定的可变区域内随机选择一个插入位置

          new_buf = ck_alloc_nozero(temp_len + clone_len);
          // 分配新的缓冲区

          /* Head */
          memcpy(new_buf, out_buf, clone_to);
          // 拷贝头部

          /* Inserted part */
          if (actually_clone)
            memcpy(new_buf + clone_to, out_buf + clone_from, clone_len);
          // 克隆字节
          else
            memset(new_buf + clone_to,
                  UR(2) ? UR(256) : out_buf[UR(temp_len)], clone_len);
          // 插入常量字节

          /* Tail */
          memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
                temp_len - clone_to);
          // 拷贝尾部

          ck_free(out_buf);
          out_buf = new_buf;
          temp_len += clone_len;
          // 更新总长度

          for (int i = range_choice + 1; i < rc; i++)
          {
            ranges[i].start += clone_len;
          }
          // 更新后续区域的起始位置

          ranges[range_choice].len += clone_len;
          // 更新选定区域的长度
        }
        break;
      }

      case 14:
      {
        /* Overwrite bytes with a randomly selected chunk (75%) or fixed
          bytes (25%). */

        u32 copy_from, copy_to, copy_len;

        if (ranges[range_choice].len < 2)
          break;
        // 如果选定的可变区域长度小于 2，跳过此操作

        copy_len = choose_block_len(ranges[range_choice].len - 1);
        // 选择要覆盖的字节数

        copy_from = UR(temp_len - copy_len + 1);
        // 在整个缓冲区内随机选择一个起始位置

        copy_to = ranges[range_choice].start + UR(ranges[range_choice].len - copy_len + 1);
        // 在选定的可变区域内随机选择一个目标位置

        if (UR(4))
        {
          if (copy_from != copy_to)
            memmove(out_buf + copy_to, out_buf + copy_from, copy_len);
          // 覆盖字节（75%）
        }
        else
          memset(out_buf + copy_to,
                UR(2) ? UR(256) : out_buf[UR(temp_len)], copy_len);
        // 填充固定字节（25%）
        break;
      }

      /* Values 15 and 16 can be selected only if there are any extras
        present in the dictionaries. */

      case 15:
      {
        if (extras_cnt + a_extras_cnt == 0)
          break;
        // 如果没有额外的字典项，跳过此操作

        /* Overwrite bytes with an extra. */

        if (!extras_cnt || (a_extras_cnt && UR(2)))
        {
          /* No user-specified extras or odds in our favor. Let's use an
            auto-detected one. */

          u32 use_extra = UR(a_extras_cnt);
          // 选择一个自动检测的额外项

          u32 extra_len = a_extras[use_extra].len;
          // 获取额外项的长度

          u32 insert_at;

          if (extra_len > ranges[range_choice].len)
            break;
          // 如果额外项长度超过选定区域长度，跳过此操作

          insert_at = ranges[range_choice].start + UR(ranges[range_choice].len - extra_len + 1);
          // 在选定的可变区域内随机选择一个插入位置

          memcpy(out_buf + insert_at, a_extras[use_extra].data, extra_len);
          // 拷贝额外项数据
        }
        else
        {
          /* No auto extras or odds in our favor. Use the dictionary. */

          u32 use_extra = UR(extras_cnt);
          // 选择一个用户指定的额外项

          u32 extra_len = extras[use_extra].len;
          // 获取额外项的长度

          u32 insert_at;

          if (extra_len > ranges[range_choice].len)
            break;
          // 如果额外项长度超过选定区域长度，跳过此操作

          insert_at = ranges[range_choice].start + UR(ranges[range_choice].len - extra_len + 1);
          // 在选定的可变区域内随机选择一个插入位置

          memcpy(out_buf + insert_at, extras[use_extra].data, extra_len);
          // 拷贝额外项数据
        }
        break;
      }

      case 16:
      {
        if (extras_cnt + a_extras_cnt == 0)
          break;
        // 如果没有额外的字典项，跳过此操作

        u32 use_extra, extra_len, insert_at = ranges[range_choice].start + UR(ranges[range_choice].len + 1);
        u8 *new_buf;

        /* Insert an extra. Do the same dice-rolling stuff as for the
          previous case. */

        if (!extras_cnt || (a_extras_cnt && UR(2)))
        {
          use_extra = UR(a_extras_cnt);
          // 选择一个自动检测的额外项

          extra_len = a_extras[use_extra].len;
          // 获取额外项的长度

          if (temp_len + extra_len >= MAX_FILE)
            break;
          // 如果插入后总长度超过最大文件大小，跳过此操作

          new_buf = ck_alloc_nozero(temp_len + extra_len);
          // 分配新的缓冲区

          /* Head */
          memcpy(new_buf, out_buf, insert_at);
          // 拷贝头部

          /* Inserted part */
          memcpy(new_buf + insert_at, a_extras[use_extra].data, extra_len);
          // 插入额外项数据
        }
        else
        {
          use_extra = UR(extras_cnt);
          // 选择一个用户指定的额外项

          extra_len = extras[use_extra].len;
          // 获取额外项的长度

          if (temp_len + extra_len >= MAX_FILE)
            break;
          // 如果插入后总长度超过最大文件大小，跳过此操作

          new_buf = ck_alloc_nozero(temp_len + extra_len);
          // 分配新的缓冲区

          /* Head */
          memcpy(new_buf, out_buf, insert_at);
          // 拷贝头部

          /* Inserted part */
          memcpy(new_buf + insert_at, extras[use_extra].data, extra_len);
          // 插入额外项数据
        }

        /* Tail */
        memcpy(new_buf + insert_at + extra_len, out_buf + insert_at,
              temp_len - insert_at);
        // 拷贝尾部

        ck_free(out_buf);
        out_buf = new_buf;
        temp_len += extra_len;
        // 更新总长度

        for (int i = range_choice + 1; i < rc; i++)
        {
          ranges[i].start += extra_len;
        }
        // 更新后续区域的起始位置

        ranges[range_choice].len += extra_len;
        // 更新选定区域的长度

        break;
      }

      /* Values 17 to 20 can be selected only if region-level mutations are enabled */

      /* Replace the current region with a random region from a random seed */
      case 17 ... 18:
      {
        u32 src_region_len = 0;
        u8 *new_buf = choose_source_region(&src_region_len);
        if (new_buf == NULL)
          break;
        // 选择一个随机源区域

        // replace the current region
        ck_free(out_buf);
        ck_free(ranges);
        // 释放旧的缓冲区和区域列表

        out_buf = new_buf;
        temp_len = src_region_len;
        // 更新缓冲区和总长度

        range_list temp_ranges = parse_buffer(out_buf, temp_len);
        rc = kv_size(temp_ranges);
        ranges = temp_ranges.a;
        // 解析新的缓冲区，更新区域列表
        break;
      }

      /* Insert a random region from a random seed to the beginning of the current region */
      case 19 ... 20:
      {
        u32 src_region_len = 0;
        u8 *src_region = choose_source_region(&src_region_len);
        if (src_region == NULL)
          break;
        // 选择一个随机源区域

        if (temp_len + src_region_len >= MAX_FILE)
        {
          ck_free(src_region);
          break;
        }
        // 如果插入后总长度超过最大文件大小，跳过此操作

        u8 *new_buf = ck_alloc_nozero(temp_len + src_region_len);
        // 分配新的缓冲区

        memcpy(new_buf, src_region, src_region_len);
        // 拷贝源区域

        memcpy(&new_buf[src_region_len], out_buf, temp_len);
        // 拷贝原缓冲区

        ck_free(out_buf);
        ck_free(src_region);
        out_buf = new_buf;
        temp_len += src_region_len;
        // 更新缓冲区和总长度

        for (int i = 0; i < rc; i++)
        {
          ranges[i].start += src_region_len;
        }
        // 更新所有区域的起始位置
        break;
      }

      /* Insert a random region from a random seed to the end of the current region */
      case 21 ... 22:
      {
        u32 src_region_len = 0;
        u8 *src_region = choose_source_region(&src_region_len);
        if (src_region == NULL)
          break;
        // 选择一个随机源区域

        if (temp_len + src_region_len >= MAX_FILE)
        {
          ck_free(src_region);
          break;
        }
        // 如果插入后总长度超过最大文件大小，跳过此操作

        u8 *new_buf = ck_alloc_nozero(temp_len + src_region_len);
        // 分配新的缓冲区

        memcpy(new_buf, out_buf, temp_len);
        // 拷贝原缓冲区

        memcpy(new_buf + temp_len, src_region, src_region_len);
        // 拷贝源区域

        ck_free(out_buf);
        ck_free(src_region);
        out_buf = new_buf;
        temp_len += src_region_len;
        // 更新缓冲区和总长度
        break;
      }

      /* Duplicate the currently selected region */
      case 23 ... 24:
      {
        if (temp_len + ranges[range_choice].len >= MAX_FILE)
          break;
        // 如果复制后总长度超过最大文件大小，跳过此操作

        u8 *new_buf = ck_alloc_nozero(temp_len + ranges[range_choice].len);
        // 分配新的缓冲区

        u8 *start_dest = new_buf;
        u8 *start_src = out_buf;

        memcpy(start_dest, start_src, ranges[range_choice].start);
        // 拷贝头部

        start_dest += ranges[range_choice].start;
        start_src += ranges[range_choice].start;

        memcpy(start_dest, start_src, ranges[range_choice].len);
        // 拷贝选定区域

        start_dest += ranges[range_choice].len;

        memcpy(start_dest, start_src, ranges[range_choice].len);
        // 再次拷贝选定区域

        start_dest += ranges[range_choice].len;
        start_src += ranges[range_choice].len;

        memcpy(start_dest, start_src,
              temp_len - (ranges[range_choice].start + ranges[range_choice].len));
        // 拷贝尾部

        ck_free(out_buf);
        out_buf = new_buf;
        temp_len += ranges[range_choice].len;
        // 更新缓冲区和总长度

        for (int i = range_choice + 1; i < rc; i++)
        {
          ranges[i].start += ranges[range_choice].len;
        }
        // 更新后续区域的起始位置

        ranges[range_choice].len *= 2;
        // 更新选定区域的长度
        break;
      }
      }
    }

    if (common_fuzz_stuff(argv, out_buf, temp_len))
      goto abandon_entry;
    // 执行通用模糊测试操作，如果成功则跳转到放弃当前条目

    /* out_buf might have been mangled a bit, so let's restore it to its
      original size and shape. */

    if (temp_len < len)
      out_buf = ck_realloc(out_buf, len);
    // 如果临时长度小于原始长度，重新分配 out_buf 的内存以恢复其原始大小

    temp_len = len;
    // 将临时长度恢复为原始长度

    if (rc != kv_size(original_ranges))
      ranges = ck_realloc(ranges, kv_size(original_ranges) * sizeof(range));
    // 如果可变区域列表的大小发生变化，重新分配 ranges 的内存

    rc = kv_size(original_ranges);
    // 更新可变区域列表的大小

    memcpy(out_buf, in_buf, len);
    // 恢复 out_buf 到其原始内容

    memcpy(ranges, original_ranges.a, rc * sizeof(range));
    // 恢复 ranges 到其原始内容

    /* If we're finding new stuff, let's run for a bit longer, limits
      permitting. */

    if (queued_paths != havoc_queued)
    {
      // 如果发现了新的路径
      if (perf_score <= HAVOC_MAX_MULT * 100)
      {
        stage_max *= 2;
        perf_score *= 2;
      }
      // 如果性能评分不超过上限，增加最大步数和性能评分

      havoc_queued = queued_paths;
      // 更新当前排队的路径数
    }
    // 结束内层循环
  }
  kv_destroy(original_ranges);
  // 销毁可变区域列表

  ck_free(ranges);
  // 释放 ranges 的内存

  new_hit_cnt = queued_paths + unique_crashes;
  // 更新新的命中计数

  if (!splice_cycle)
  {
    stage_finds[STAGE_HAVOC] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_HAVOC] += stage_max;
    // 更新 Havoc 阶段的命中数和循环次数
  }
  else
  {
    stage_finds[STAGE_SPLICE] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_SPLICE] += stage_max;
    // 更新拼接阶段的命中数和循环次数
  }

#ifndef IGNORE_FINDS

  /************
   * SPLICING *
   ************/

  /* This is a last-resort strategy triggered by a full round with no findings.
     It takes the current input file, randomly selects another input, and
     splices them together at some offset, then relies on the havoc
     code to mutate that blob. */

retry_splicing:
  if (use_splicing && splice_cycle++ < SPLICE_CYCLES &&
      queued_paths > 1 && M2_len > 1)
  {
    struct queue_entry *target;
    u32 tid, split_at;
    u8 *new_buf;
    s32 f_diff, l_diff;

    /* First of all, if we've modified in_buf for havoc, let's clean that
      up... */

    if (in_buf != orig_in)
    {
      ck_free(in_buf);
      in_buf = orig_in;
      len = M2_len;
    }
    // 如果 in_buf 已经被修改过，恢复其原始状态

    /* Pick a random queue entry and seek to it. Don't splice with yourself. */

    do
    {
      tid = UR(queued_paths);
    } while (tid == current_entry);
    // 随机选择一个队列条目，确保不选择当前条目

    splicing_with = tid;
    target = queue;

    while (tid >= 100)
    {
      target = target->next_100;
      tid -= 100;
    }
    while (tid--)
      target = target->next;
    // 寻找目标队列条目

    /* Make sure that the target has a reasonable length. */

    while (target && (target->len < 2 || target == queue_cur))
    {
      target = target->next;
      splicing_with++;
    }
    // 确保目标条目的长度合理且不等于当前条目

    if (!target)
      goto retry_splicing;
    // 如果没有找到合适的条目，重试拼接

    /* Read the testcase into a new buffer. */

    fd = open(target->fname, O_RDONLY);

    if (fd < 0)
      PFATAL("Unable to open '%s'", target->fname);
    // 打开目标条目的文件

    new_buf = ck_alloc_nozero(target->len);

    ck_read(fd, new_buf, target->len, target->fname);

    close(fd);
    // 读取目标条目的内容到新缓冲区

    /* Find a suitable splicing location, somewhere between the first and
      the last differing byte. Bail out if the difference is just a single
      byte or so. */

    locate_diffs(in_buf, new_buf, MIN(len, target->len), &f_diff, &l_diff);
    // 查找两个缓冲区之间的第一个和最后一个不同字节的位置

    if (f_diff < 0 || l_diff < 2 || f_diff == l_diff)
    {
      ck_free(new_buf);
      goto retry_splicing;
    }
    // 如果差异只有一个字节或没有差异，重试拼接

    /* Split somewhere between the first and last differing byte. */

    split_at = f_diff + UR(l_diff - f_diff);
    // 在第一个和最后一个不同字节之间随机选择一个分割点

    /* Do the thing. */

    len = target->len;
    memcpy(new_buf, in_buf, split_at);
    in_buf = new_buf;
    // 将 in_buf 的前半部分复制到 new_buf

    ck_free(out_buf);
    out_buf = ck_alloc_nozero(len);
    memcpy(out_buf, in_buf, len);
    // 将 new_buf 的内容复制到 out_buf

    goto havoc_stage;
    // 跳转到 Havoc 阶段
  }

#endif /* !IGNORE_FINDS */

  ret_val = 0;

abandon_entry:
  splicing_with = -1;
  // 将 splicing_with 设置为 -1，表示没有正在进行的拼接操作

  /* Update pending_not_fuzzed count if we made it through the calibration
    cycle and have not seen this entry before. */

  if (!stop_soon && !queue_cur->cal_failed && !queue_cur->was_fuzzed)
  {
    // 如果没有停止标志，校准未失败，且当前条目尚未被模糊测试
    queue_cur->was_fuzzed = 1;
    // 标记当前条目已进行模糊测试
    was_fuzzed_map[get_state_index(target_state_id)][queue_cur->index] = 1;
    // 更新 was_fuzzed_map，标记该条目在特定状态下的模糊测试状态
    pending_not_fuzzed--;
    // 减少待模糊测试的条目计数
    if (queue_cur->favored)
      pending_favored--;
    // 如果当前条目是优先条目，减少待模糊测试的优先条目计数
  }

  // munmap(orig_in, queue_cur->len);
  // （注释掉的部分）解除 orig_in 的内存映射
  ck_free(orig_in);
  // 释放 orig_in 的内存

  if (in_buf != orig_in)
    ck_free(in_buf);
  // 如果 in_buf 不是 orig_in，释放 in_buf 的内存
  ck_free(out_buf);
  // 释放 out_buf 的内存
  ck_free(eff_map);
  // 释放 eff_map 的内存

  delete_kl_messages(kl_messages);
  // 删除内核消息

  return ret_val;
  // 返回函数结果
#undef FLIP_BIT
}

/* Grab interesting test cases from other fuzzers. */

static void sync_fuzzers(char **argv)
{

  DIR *sd;
  struct dirent *sd_ent;
  u32 sync_cnt = 0;

  sd = opendir(sync_dir);
  if (!sd)
    PFATAL("Unable to open '%s'", sync_dir);

  stage_max = stage_cur = 0;
  cur_depth = 0;

  /* Look at the entries created for every other fuzzer in the sync directory. */

  while ((sd_ent = readdir(sd)))
  {

    static u8 stage_tmp[128];

    DIR *qd;
    struct dirent *qd_ent;
    u8 *qd_path, *qd_synced_path;
    u32 min_accept = 0, next_min_accept;

    s32 id_fd;

    /* Skip dot files and our own output directory. */

    if (sd_ent->d_name[0] == '.' || !strcmp(sync_id, sd_ent->d_name))
      continue;

    /* Skip anything that doesn't have a queue/ subdirectory. */

    qd_path = alloc_printf("%s/%s/queue", sync_dir, sd_ent->d_name);

    if (!(qd = opendir(qd_path)))
    {
      ck_free(qd_path);
      continue;
    }

    /* Retrieve the ID of the last seen test case. */

    qd_synced_path = alloc_printf("%s/.synced/%s", out_dir, sd_ent->d_name);

    id_fd = open(qd_synced_path, O_RDWR | O_CREAT, 0600);

    if (id_fd < 0)
      PFATAL("Unable to create '%s'", qd_synced_path);

    if (read(id_fd, &min_accept, sizeof(u32)) > 0)
      lseek(id_fd, 0, SEEK_SET);

    next_min_accept = min_accept;

    /* Show stats */

    sprintf(stage_tmp, "sync %u", ++sync_cnt);
    stage_name = stage_tmp;
    stage_cur = 0;
    stage_max = 0;

    /* For every file queued by this fuzzer, parse ID and see if we have looked at
       it before; exec a test case if not. */

    while ((qd_ent = readdir(qd)))
    {

      u8 *path;
      s32 fd;
      struct stat st;

      if (qd_ent->d_name[0] == '.' ||
          sscanf(qd_ent->d_name, CASE_PREFIX "%06u", &syncing_case) != 1 ||
          syncing_case < min_accept)
        continue;

      /* OK, sounds like a new one. Let's give it a try. */

      if (syncing_case >= next_min_accept)
        next_min_accept = syncing_case + 1;

      path = alloc_printf("%s/%s", qd_path, qd_ent->d_name);

      /* Allow this to fail in case the other fuzzer is resuming or so... */

      fd = open(path, O_RDONLY);

      if (fd < 0)
      {
        ck_free(path);
        continue;
      }

      if (fstat(fd, &st))
        PFATAL("fstat() failed");

      /* Ignore zero-sized or oversized files. */

      if (st.st_size && st.st_size <= MAX_FILE)
      {

        u8 fault;
        u8 *mem = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

        if (mem == MAP_FAILED)
          PFATAL("Unable to mmap '%s'", path);

        /* See what happens. We rely on save_if_interesting() to catch major
           errors and save the test case. */

        write_to_testcase(mem, st.st_size);

        region_t *regions;
        u32 region_count;
        regions = (*extract_requests)(mem, st.st_size, &region_count);
        kl_messages = construct_kl_messages(path, regions, region_count);

        fault = run_target(argv, exec_tmout);

        if (stop_soon)
          return;

        /* AFLNet: set this flag to enable request extractions while adding new seed to the queue */
        corpus_read_or_sync = 2;

        syncing_party = sd_ent->d_name;
        queued_imported += save_if_interesting(argv, mem, st.st_size, fault);
        syncing_party = 0;

        /* AFLNet delete the kl_messages */
        ck_free(regions);
        delete_kl_messages(kl_messages);

        /* AFLNet: unset this flag to disable request extractions while adding new seed to the queue */
        corpus_read_or_sync = 0;

        munmap(mem, st.st_size);

        if (!(stage_cur++ % stats_update_freq))
          show_stats();
      }

      ck_free(path);
      close(fd);
    }

    ck_write(id_fd, &next_min_accept, sizeof(u32), qd_synced_path);

    close(id_fd);
    closedir(qd);
    ck_free(qd_path);
    ck_free(qd_synced_path);
  }

  closedir(sd);
}

/* Handle stop signal (Ctrl-C, etc). */

static void handle_stop_sig(int sig)
{

  stop_soon = 1;

  if (child_pid > 0)
    kill(child_pid, SIGKILL);
  if (forksrv_pid > 0)
    kill(forksrv_pid, SIGKILL);
}

/* Handle skip request (SIGUSR1). */

static void handle_skipreq(int sig)
{

  skip_requested = 1;
}

/* Handle timeout (SIGALRM). */

static void handle_timeout(int sig)
{

  if (child_pid > 0)
  {

    child_timed_out = 1;
    kill(child_pid, SIGKILL);
  }
  else if (child_pid == -1 && forksrv_pid > 0)
  {

    child_timed_out = 1;
    kill(forksrv_pid, SIGKILL);
  }
}

/* Do a PATH search and find target binary to see that it exists and
   isn't a shell script - a common and painful mistake. We also check for
   a valid ELF header and for evidence of AFL instrumentation. */

EXP_ST void check_binary(u8 *fname)
{

  u8 *env_path = 0;
  struct stat st;

  s32 fd;
  u8 *f_data;
  u32 f_len = 0;

  ACTF("Validating target binary...");

  if (strchr(fname, '/') || !(env_path = getenv("PATH")))
  {

    target_path = ck_strdup(fname);
    if (stat(target_path, &st) || !S_ISREG(st.st_mode) ||
        !(st.st_mode & 0111) || (f_len = st.st_size) < 4)
      FATAL("Program '%s' not found or not executable", fname);
  }
  else
  {

    while (env_path)
    {

      u8 *cur_elem, *delim = strchr(env_path, ':');

      if (delim)
      {

        cur_elem = ck_alloc(delim - env_path + 1);
        memcpy(cur_elem, env_path, delim - env_path);
        delim++;
      }
      else
        cur_elem = ck_strdup(env_path);

      env_path = delim;

      if (cur_elem[0])
        target_path = alloc_printf("%s/%s", cur_elem, fname);
      else
        target_path = ck_strdup(fname);

      ck_free(cur_elem);

      if (!stat(target_path, &st) && S_ISREG(st.st_mode) &&
          (st.st_mode & 0111) && (f_len = st.st_size) >= 4)
        break;

      ck_free(target_path);
      target_path = 0;
    }

    if (!target_path)
      FATAL("Program '%s' not found or not executable", fname);
  }

  if (getenv("AFL_SKIP_BIN_CHECK"))
    return;

  /* Check for blatant user errors. */

  if ((!strncmp(target_path, "/tmp/", 5) && !strchr(target_path + 5, '/')) ||
      (!strncmp(target_path, "/var/tmp/", 9) && !strchr(target_path + 9, '/')))
    FATAL("Please don't keep binaries in /tmp or /var/tmp");

  fd = open(target_path, O_RDONLY);

  if (fd < 0)
    PFATAL("Unable to open '%s'", target_path);

  f_data = mmap(0, f_len, PROT_READ, MAP_PRIVATE, fd, 0);

  if (f_data == MAP_FAILED)
    PFATAL("Unable to mmap file '%s'", target_path);

  close(fd);

  if (f_data[0] == '#' && f_data[1] == '!')
  {

    SAYF("\n" cLRD "[-] " cRST
         "Oops, the target binary looks like a shell script. Some build systems will\n"
         "    sometimes generate shell stubs for dynamically linked programs; try static\n"
         "    library mode (./configure --disable-shared) if that's the case.\n\n"

         "    Another possible cause is that you are actually trying to use a shell\n"
         "    wrapper around the fuzzed component. Invoking shell can slow down the\n"
         "    fuzzing process by a factor of 20x or more; it's best to write the wrapper\n"
         "    in a compiled language instead.\n");

    FATAL("Program '%s' is a shell script", target_path);
  }

#ifndef __APPLE__

  if (f_data[0] != 0x7f || memcmp(f_data + 1, "ELF", 3))
    FATAL("Program '%s' is not an ELF binary", target_path);

#else

  if (f_data[0] != 0xCF || f_data[1] != 0xFA || f_data[2] != 0xED)
    FATAL("Program '%s' is not a 64-bit Mach-O binary", target_path);

#endif /* ^!__APPLE__ */

  if (!qemu_mode && !dumb_mode &&
      !memmem(f_data, f_len, SHM_ENV_VAR, strlen(SHM_ENV_VAR) + 1))
  {

    SAYF("\n" cLRD "[-] " cRST
         "Looks like the target binary is not instrumented! The fuzzer depends on\n"
         "    compile-time instrumentation to isolate interesting test cases while\n"
         "    mutating the input data. For more information, and for tips on how to\n"
         "    instrument binaries, please see %s/README.\n\n"

         "    When source code is not available, you may be able to leverage QEMU\n"
         "    mode support. Consult the README for tips on how to enable this.\n"

         "    (It is also possible to use afl-fuzz as a traditional, \"dumb\" fuzzer.\n"
         "    For that, you can use the -n option - but expect much worse results.)\n",
         doc_path);

    FATAL("No instrumentation detected");
  }

  if (qemu_mode &&
      memmem(f_data, f_len, SHM_ENV_VAR, strlen(SHM_ENV_VAR) + 1))
  {

    SAYF("\n" cLRD "[-] " cRST
         "This program appears to be instrumented with afl-gcc, but is being run in\n"
         "    QEMU mode (-Q). This is probably not what you want - this setup will be\n"
         "    slow and offer no practical benefits.\n");

    FATAL("Instrumentation found in -Q mode");
  }

  if (memmem(f_data, f_len, "libasan.so", 10) ||
      memmem(f_data, f_len, "__msan_init", 11))
    uses_asan = 1;

  /* Detect persistent & deferred init signatures in the binary. */

  if (memmem(f_data, f_len, PERSIST_SIG, strlen(PERSIST_SIG) + 1))
  {

    OKF(cPIN "Persistent mode binary detected.");
    setenv(PERSIST_ENV_VAR, "1", 1);
    persistent_mode = 1;
  }
  else if (getenv("AFL_PERSISTENT"))
  {

    WARNF("AFL_PERSISTENT is no longer supported and may misbehave!");
  }

  if (memmem(f_data, f_len, DEFER_SIG, strlen(DEFER_SIG) + 1))
  {

    OKF(cPIN "Deferred forkserver binary detected.");
    setenv(DEFER_ENV_VAR, "1", 1);
    deferred_mode = 1;
  }
  else if (getenv("AFL_DEFER_FORKSRV"))
  {

    WARNF("AFL_DEFER_FORKSRV is no longer supported and may misbehave!");
  }

  if (munmap(f_data, f_len))
    PFATAL("unmap() failed");
}

/* Trim and possibly create a banner for the run. */

static void fix_up_banner(u8 *name)
{

  if (!use_banner)
  {

    if (sync_id)
    {

      use_banner = sync_id;
    }
    else
    {

      u8 *trim = strrchr(name, '/');
      if (!trim)
        use_banner = name;
      else
        use_banner = trim + 1;
    }
  }

  if (strlen(use_banner) > 40)
  {

    u8 *tmp = ck_alloc(44);
    sprintf(tmp, "%.40s...", use_banner);
    use_banner = tmp;
  }
}

/* Check if we're on TTY. */

static void check_if_tty(void)
{

  struct winsize ws;

  if (getenv("AFL_NO_UI"))
  {
    OKF("Disabling the UI because AFL_NO_UI is set.");
    not_on_tty = 1;
    return;
  }

  if (ioctl(1, TIOCGWINSZ, &ws))
  {

    if (errno == ENOTTY)
    {
      OKF("Looks like we're not running on a tty, so I'll be a bit less verbose.");
      not_on_tty = 1;
    }

    return;
  }
}

/* Check terminal dimensions after resize. */

static void check_term_size(void)
{

  struct winsize ws;

  term_too_small = 0;

  if (ioctl(1, TIOCGWINSZ, &ws))
    return;

  if (ws.ws_row == 0 && ws.ws_col == 0)
    return;
  if (ws.ws_row < 25 || ws.ws_col < 80)
    term_too_small = 1;
}

/* Display usage hints. */

static void usage(u8 *argv0)
{

  SAYF("\n%s [ options ] -- /path/to/fuzzed_app [ ... ]\n\n"

       "Required parameters:\n\n"

       "  -i dir        - input directory with test cases\n"
       "  -o dir        - output directory for fuzzer findings\n\n"

       "Execution control settings:\n\n"

       "  -f file       - location read by the fuzzed program (stdin)\n"
       "  -t msec       - timeout for each run (auto-scaled, 50-%u ms)\n"
       "  -m megs       - memory limit for child process (%u MB)\n"
       "  -Q            - use binary-only instrumentation (QEMU mode)\n\n"

       "Fuzzing behavior settings:\n\n"

       "  -d            - quick & dirty mode (skips deterministic steps)\n"
       "  -n            - fuzz without instrumentation (dumb mode)\n"
       "  -x dir        - optional fuzzer dictionary (see README)\n\n"

       "Settings for network protocol fuzzing (AFLNet):\n\n"

       "  -N netinfo    - server information (e.g., tcp://127.0.0.1/8554)\n"
       "  -P protocol   - application protocol to be tested (e.g., RTSP, FTP, DTLS12, DNS, SMTP, SSH, TLS)\n"
       "  -D usec       - waiting time (in micro seconds) for the server to initialize\n"
       "  -W msec       - waiting time (in miliseconds) for receiving the first response to each input sent\n"
       "  -w usec       - waiting time (in micro seconds) for receiving follow-up responses\n"
       "  -e netnsname  - run server in a different network namespace\n"
       "  -K            - send SIGTERM to gracefully terminate the server (see README.md)\n"
       "  -E            - enable state aware mode (see README.md)\n"
       "  -R            - enable region-level mutation operators (see README.md)\n"
       "  -F            - enable false negative reduction mode (see README.md)\n"
       "  -c cleanup    - name or full path to the server cleanup script (see README.md)\n"
       "  -q algo       - state selection algorithm (See aflnet.h for all available options)\n"
       "  -s algo       - seed selection algorithm (See aflnet.h for all available options)\n\n"

       "Other stuff:\n\n"

       "  -T text       - text banner to show on the screen\n"
       "  -M / -S id    - distributed mode (see parallel_fuzzing.txt)\n"
       "  -C            - crash exploration mode (the peruvian rabbit thing)\n\n"

       "For additional tips, please consult %s/README.\n\n",

       argv0, EXEC_TIMEOUT, MEM_LIMIT, doc_path);

  exit(1);
}

/* Prepare output directories and fds. */

EXP_ST void setup_dirs_fds(void)
{

  u8 *tmp;
  s32 fd;

  ACTF("Setting up output directories...");

  if (sync_id && mkdir(sync_dir, 0700) && errno != EEXIST)
    PFATAL("Unable to create '%s'", sync_dir);

  if (mkdir(out_dir, 0700))
  {

    if (errno != EEXIST)
      PFATAL("Unable to create '%s'", out_dir);

    maybe_delete_out_dir();
  }
  else
  {

    if (in_place_resume)
      FATAL("Resume attempted but old output directory not found");

    out_dir_fd = open(out_dir, O_RDONLY);

#ifndef __sun

    if (out_dir_fd < 0 || flock(out_dir_fd, LOCK_EX | LOCK_NB))
      PFATAL("Unable to flock() output directory.");

#endif /* !__sun */
  }

  /* Queue directory for any starting & discovered paths. */

  tmp = alloc_printf("%s/queue", out_dir);
  if (mkdir(tmp, 0700))
    PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Top-level directory for queue metadata used for session
     resume and related tasks. */

  tmp = alloc_printf("%s/queue/.state/", out_dir);
  if (mkdir(tmp, 0700))
    PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Directory for flagging queue entries that went through
     deterministic fuzzing in the past. */

  tmp = alloc_printf("%s/queue/.state/deterministic_done/", out_dir);
  if (mkdir(tmp, 0700))
    PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Directory with the auto-selected dictionary entries. */

  tmp = alloc_printf("%s/queue/.state/auto_extras/", out_dir);
  if (mkdir(tmp, 0700))
    PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* The set of paths currently deemed redundant. */

  tmp = alloc_printf("%s/queue/.state/redundant_edges/", out_dir);
  if (mkdir(tmp, 0700))
    PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* The set of paths showing variable behavior. */

  tmp = alloc_printf("%s/queue/.state/variable_behavior/", out_dir);
  if (mkdir(tmp, 0700))
    PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Sync directory for keeping track of cooperating fuzzers. */

  if (sync_id)
  {

    tmp = alloc_printf("%s/.synced/", out_dir);

    if (mkdir(tmp, 0700) && (!in_place_resume || errno != EEXIST))
      PFATAL("Unable to create '%s'", tmp);

    ck_free(tmp);
  }

  /* All recorded crashes. */

  tmp = alloc_printf("%s/replayable-crashes", out_dir);
  if (mkdir(tmp, 0700))
    PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* All recorded hangs. */

  tmp = alloc_printf("%s/replayable-hangs", out_dir);
  if (mkdir(tmp, 0700))
    PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* All files keeping extracted regions -- for debugging purpose. */

  tmp = alloc_printf("%s/regions", out_dir);
  if (mkdir(tmp, 0700))
    PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* All output from the LLM and resulting grammars -- for debugging purposes. */

  tmp = alloc_printf("%s/protocol-grammars", out_dir);
  if (mkdir(tmp, 0700))
    PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* All output from the LLM's help for unblocking the state stall -- for debugging purposes.  */
  tmp = alloc_printf("%s/stall-interactions", out_dir);
  if (mkdir(tmp, 0700))
    PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);


  /* All recorded new paths exercising the implemented state machine. */

  tmp = alloc_printf("%s/replayable-new-ipsm-paths", out_dir);
  if (mkdir(tmp, 0700))
    PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* All recorded responses over the implemented state machine. */
  tmp = alloc_printf("%s/responses-ipsm", out_dir);
  if (mkdir(tmp, 0700))
    PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* All recorded paths in structure files. */

  tmp = alloc_printf("%s/replayable-queue", out_dir);
  if (mkdir(tmp, 0700))
    PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Generally useful file descriptors. */

  dev_null_fd = open("/dev/null", O_RDWR);
  if (dev_null_fd < 0)
    PFATAL("Unable to open /dev/null");

  dev_urandom_fd = open("/dev/urandom", O_RDONLY);
  if (dev_urandom_fd < 0)
    PFATAL("Unable to open /dev/urandom");

  /* Gnuplot output file. */

  tmp = alloc_printf("%s/plot_data", out_dir);
  fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0)
    PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  plot_file = fdopen(fd, "w");
  if (!plot_file)
    PFATAL("fdopen() failed");

  fprintf(plot_file, "# unix_time, cycles_done, cur_path, paths_total, "
                     "pending_total, pending_favs, map_size, unique_crashes, "
                     "unique_hangs, max_depth, execs_per_sec, n_nodes, n_edges, chat_times\n");
  /* ignore errors */
}

/* Setup the output file for fuzzed data, if not using -f. */

EXP_ST void setup_stdio_file(void)
{

  u8 *fn = alloc_printf("%s/.cur_input", out_dir);

  unlink(fn); /* Ignore errors */

  out_fd = open(fn, O_RDWR | O_CREAT | O_EXCL, 0600);

  if (out_fd < 0)
    PFATAL("Unable to create '%s'", fn);

  ck_free(fn);
}

/* Make sure that core dumps don't go to a program. */

static void check_crash_handling(void)
{

#ifdef __APPLE__

  /* Yuck! There appears to be no simple C API to query for the state of
     loaded daemons on MacOS X, and I'm a bit hesitant to do something
     more sophisticated, such as disabling crash reporting via Mach ports,
     until I get a box to test the code. So, for now, we check for crash
     reporting the awful way. */

  if (system("launchctl list 2>/dev/null | grep -q '\\.ReportCrash$'"))
    return;

  SAYF("\n" cLRD "[-] " cRST
       "Whoops, your system is configured to forward crash notifications to an\n"
       "    external crash reporting utility. This will cause issues due to the\n"
       "    extended delay between the fuzzed binary malfunctioning and this fact\n"
       "    being relayed to the fuzzer via the standard waitpid() API.\n\n"
       "    To avoid having crashes misinterpreted as timeouts, please run the\n"
       "    following commands:\n\n"

       "    SL=/System/Library; PL=com.apple.ReportCrash\n"
       "    launchctl unload -w ${SL}/LaunchAgents/${PL}.plist\n"
       "    sudo launchctl unload -w ${SL}/LaunchDaemons/${PL}.Root.plist\n");

  if (!getenv("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"))
    FATAL("Crash reporter detected");

#else

  /* This is Linux specific, but I don't think there's anything equivalent on
   *BSD, so we can just let it slide for now. */

  s32 fd = open("/proc/sys/kernel/core_pattern", O_RDONLY);
  u8 fchar;

  if (fd < 0)
    return;

  ACTF("Checking core_pattern...");

  if (read(fd, &fchar, 1) == 1 && fchar == '|')
  {

    SAYF("\n" cLRD "[-] " cRST
         "Hmm, your system is configured to send core dump notifications to an\n"
         "    external utility. This will cause issues: there will be an extended delay\n"
         "    between stumbling upon a crash and having this information relayed to the\n"
         "    fuzzer via the standard waitpid() API.\n\n"

         "    To avoid having crashes misinterpreted as timeouts, please log in as root\n"
         "    and temporarily modify /proc/sys/kernel/core_pattern, like so:\n\n"

         "    echo core >/proc/sys/kernel/core_pattern\n");

    if (!getenv("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"))
      FATAL("Pipe at the beginning of 'core_pattern'");
  }

  close(fd);

#endif /* ^__APPLE__ */
}

/* Check CPU governor. */

static void check_cpu_governor(void)
{

  FILE *f;
  u8 tmp[128];
  u64 min = 0, max = 0;

  if (getenv("AFL_SKIP_CPUFREQ"))
    return;

  f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor", "r");
  if (!f)
    return;

  ACTF("Checking CPU scaling governor...");

  if (!fgets(tmp, 128, f))
    PFATAL("fgets() failed");

  fclose(f);

  if (!strncmp(tmp, "perf", 4))
    return;

  f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_min_freq", "r");

  if (f)
  {
    if (fscanf(f, "%llu", &min) != 1)
      min = 0;
    fclose(f);
  }

  f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq", "r");

  if (f)
  {
    if (fscanf(f, "%llu", &max) != 1)
      max = 0;
    fclose(f);
  }

  if (min == max)
    return;

  SAYF("\n" cLRD "[-] " cRST
       "Whoops, your system uses on-demand CPU frequency scaling, adjusted\n"
       "    between %llu and %llu MHz. Unfortunately, the scaling algorithm in the\n"
       "    kernel is imperfect and can miss the short-lived processes spawned by\n"
       "    afl-fuzz. To keep things moving, run these commands as root:\n\n"

       "    cd /sys/devices/system/cpu\n"
       "    echo performance | tee cpu*/cpufreq/scaling_governor\n\n"

       "    You can later go back to the original state by replacing 'performance' with\n"
       "    'ondemand'. If you don't want to change the settings, set AFL_SKIP_CPUFREQ\n"
       "    to make afl-fuzz skip this check - but expect some performance drop.\n",
       min / 1024, max / 1024);

  FATAL("Suboptimal CPU scaling governor");
}

/* Count the number of logical CPU cores. */

static void get_core_count(void)
{

  u32 cur_runnable = 0;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)

  size_t s = sizeof(cpu_core_count);

  /* On *BSD systems, we can just use a sysctl to get the number of CPUs. */

#ifdef __APPLE__

  if (sysctlbyname("hw.logicalcpu", &cpu_core_count, &s, NULL, 0) < 0)
    return;

#else

  int s_name[2] = {CTL_HW, HW_NCPU};

  if (sysctl(s_name, 2, &cpu_core_count, &s, NULL, 0) < 0)
    return;

#endif /* ^__APPLE__ */

#else

#ifdef HAVE_AFFINITY

  cpu_core_count = sysconf(_SC_NPROCESSORS_ONLN);

#else

  FILE *f = fopen("/proc/stat", "r");
  u8 tmp[1024];

  if (!f)
    return;

  while (fgets(tmp, sizeof(tmp), f))
    if (!strncmp(tmp, "cpu", 3) && isdigit(tmp[3]))
      cpu_core_count++;

  fclose(f);

#endif /* ^HAVE_AFFINITY */

#endif /* ^(__APPLE__ || __FreeBSD__ || __OpenBSD__) */

  if (cpu_core_count > 0)
  {

    cur_runnable = (u32)get_runnable_processes();

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)

    /* Add ourselves, since the 1-minute average doesn't include that yet. */

    cur_runnable++;

#endif /* __APPLE__ || __FreeBSD__ || __OpenBSD__ */

    OKF("You have %u CPU core%s and %u runnable tasks (utilization: %0.0f%%).",
        cpu_core_count, cpu_core_count > 1 ? "s" : "",
        cur_runnable, cur_runnable * 100.0 / cpu_core_count);

    if (cpu_core_count > 1)
    {

      if (cur_runnable > cpu_core_count * 1.5)
      {

        WARNF("System under apparent load, performance may be spotty.");
      }
      else if (cur_runnable + 1 <= cpu_core_count)
      {

        OKF("Try parallel jobs - see %s/parallel_fuzzing.txt.", doc_path);
      }
    }
  }
  else
  {

    cpu_core_count = 0;
    WARNF("Unable to figure out the number of CPU cores.");
  }
}

/* Validate and fix up out_dir and sync_dir when using -S. */

static void fix_up_sync(void)
{

  u8 *x = sync_id;

  if (dumb_mode)
    FATAL("-S / -M and -n are mutually exclusive");

  if (skip_deterministic)
  {

    if (force_deterministic)
      FATAL("use -S instead of -M -d");
    else
      FATAL("-S already implies -d");
  }

  while (*x)
  {

    if (!isalnum(*x) && *x != '_' && *x != '-')
      FATAL("Non-alphanumeric fuzzer ID specified via -S or -M");

    x++;
  }

  if (strlen(sync_id) > 32)
    FATAL("Fuzzer ID too long");

  x = alloc_printf("%s/%s", out_dir, sync_id);

  sync_dir = out_dir;
  out_dir = x;

  if (!force_deterministic)
  {
    skip_deterministic = 1;
    use_splicing = 1;
  }
}

/* Handle screen resize (SIGWINCH). */

static void handle_resize(int sig)
{
  clear_screen = 1;
}

/* Check ASAN options. */

static void check_asan_opts(void)
{
  u8 *x = getenv("ASAN_OPTIONS");

  if (x)
  {

    if (!strstr(x, "abort_on_error=1"))
      FATAL("Custom ASAN_OPTIONS set without abort_on_error=1 - please fix!");

    if (!strstr(x, "symbolize=0"))
      FATAL("Custom ASAN_OPTIONS set without symbolize=0 - please fix!");
  }

  x = getenv("MSAN_OPTIONS");

  if (x)
  {

    if (!strstr(x, "exit_code=" STRINGIFY(MSAN_ERROR)))
      FATAL("Custom MSAN_OPTIONS set without exit_code=" STRINGIFY(MSAN_ERROR) " - please fix!");

    if (!strstr(x, "symbolize=0"))
      FATAL("Custom MSAN_OPTIONS set without symbolize=0 - please fix!");
  }
}

/* Detect @@ in args. */

EXP_ST void detect_file_args(char **argv)
{

  u32 i = 0;
  u8 *cwd = getcwd(NULL, 0);

  if (!cwd)
    PFATAL("getcwd() failed");

  while (argv[i])
  {

    u8 *aa_loc = strstr(argv[i], "@@");

    if (aa_loc)
    {

      u8 *aa_subst, *n_arg;

      /* If we don't have a file name chosen yet, use a safe default. */

      if (!out_file)
        out_file = alloc_printf("%s/.cur_input", out_dir);

      /* Be sure that we're always using fully-qualified paths. */

      if (out_file[0] == '/')
        aa_subst = out_file;
      else
        aa_subst = alloc_printf("%s/%s", cwd, out_file);

      /* Construct a replacement argv value. */

      *aa_loc = 0;
      n_arg = alloc_printf("%s%s%s", argv[i], aa_subst, aa_loc + 2);
      argv[i] = n_arg;
      *aa_loc = '@';

      if (out_file[0] != '/')
        ck_free(aa_subst);
    }

    i++;
  }

  free(cwd); /* not tracked */
}

/* Set up signal handlers. More complicated that needs to be, because libc on
   Solaris doesn't resume interrupted reads(), sets SA_RESETHAND when you call
   siginterrupt(), and does other unnecessary things. */

EXP_ST void setup_signal_handlers(void)
{

  struct sigaction sa;

  sa.sa_handler = NULL;
  sa.sa_flags = SA_RESTART;
  sa.sa_sigaction = NULL;

  sigemptyset(&sa.sa_mask);

  /* Various ways of saying "stop". */

  sa.sa_handler = handle_stop_sig;
  sigaction(SIGHUP, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  /* Exec timeout notifications. */

  sa.sa_handler = handle_timeout;
  sigaction(SIGALRM, &sa, NULL);

  /* Window resize */

  sa.sa_handler = handle_resize;
  sigaction(SIGWINCH, &sa, NULL);

  /* SIGUSR1: skip entry */

  sa.sa_handler = handle_skipreq;
  sigaction(SIGUSR1, &sa, NULL);

  /* Things we don't care about. */

  sa.sa_handler = SIG_IGN;
  sigaction(SIGTSTP, &sa, NULL);
  sigaction(SIGPIPE, &sa, NULL);
}

/* Rewrite argv for QEMU. */

static char **get_qemu_argv(u8 *own_loc, char **argv, int argc)
{

  char **new_argv = ck_alloc(sizeof(char *) * (argc + 4));
  u8 *tmp, *cp, *rsl, *own_copy;

  /* Workaround for a QEMU stability glitch. */

  setenv("QEMU_LOG", "nochain", 1);

  memcpy(new_argv + 3, argv + 1, sizeof(char *) * argc);

  new_argv[2] = target_path;
  new_argv[1] = "--";

  /* Now we need to actually find the QEMU binary to put in argv[0]. */

  tmp = getenv("AFL_PATH");

  if (tmp)
  {

    cp = alloc_printf("%s/afl-qemu-trace", tmp);

    if (access(cp, X_OK))
      FATAL("Unable to find '%s'", tmp);

    target_path = new_argv[0] = cp;
    return new_argv;
  }

  own_copy = ck_strdup(own_loc);
  rsl = strrchr(own_copy, '/');

  if (rsl)
  {

    *rsl = 0;

    cp = alloc_printf("%s/afl-qemu-trace", own_copy);
    ck_free(own_copy);

    if (!access(cp, X_OK))
    {

      target_path = new_argv[0] = cp;
      return new_argv;
    }
  }
  else
    ck_free(own_copy);

  if (!access(BIN_PATH "/afl-qemu-trace", X_OK))
  {

    target_path = new_argv[0] = ck_strdup(BIN_PATH "/afl-qemu-trace");
    return new_argv;
  }

  SAYF("\n" cLRD "[-] " cRST
       "Oops, unable to find the 'afl-qemu-trace' binary. The binary must be built\n"
       "    separately by following the instructions in qemu_mode/README.qemu. If you\n"
       "    already have the binary installed, you may need to specify AFL_PATH in the\n"
       "    environment.\n\n"

       "    Of course, even without QEMU, afl-fuzz can still work with binaries that are\n"
       "    instrumented at compile time with afl-gcc. It is also possible to use it as a\n"
       "    traditional \"dumb\" fuzzer by specifying '-n' in the command line.\n");

  FATAL("Failed to locate 'afl-qemu-trace'.");
}

/* Make a copy of the current command line. */

static void save_cmdline(u32 argc, char **argv)
{

  u32 len = 1, i;
  u8 *buf;

  for (i = 0; i < argc; i++)
    len += strlen(argv[i]) + 1;

  buf = orig_cmdline = ck_alloc(len);

  for (i = 0; i < argc; i++)
  {

    u32 l = strlen(argv[i]);

    memcpy(buf, argv[i], l);
    buf += l;

    if (i != argc - 1)
      *(buf++) = ' ';
  }

  *buf = 0;
}

/* Check that afl-fuzz (file/process) has some effective and permitted capability */

static int check_ep_capability(cap_value_t cap, const char *filename)
{
  cap_t file_cap, proc_cap;
  cap_flag_value_t cap_flag_value;
  int no_capability = 1;
  int pid = getpid();

  file_cap = cap_get_file(filename);
  proc_cap = cap_get_proc();

  if (!file_cap && !proc_cap)
    return no_capability;

  if (file_cap)
  {
    if (cap_get_flag(file_cap, cap, CAP_EFFECTIVE, &cap_flag_value))
      PFATAL("Could not get CAP_EFFECTIVE flag value from file \"%s\"", filename);

    if (cap_flag_value != CAP_SET)
      return no_capability;

    if (cap_get_flag(file_cap, cap, CAP_PERMITTED, &cap_flag_value))
      PFATAL("Could not get CAP_PERMITTED flag value from file \"%s\"", filename);

    if (cap_flag_value != CAP_SET)
      return no_capability;
  }

  if (proc_cap)
  {
    if (cap_get_flag(proc_cap, cap, CAP_EFFECTIVE, &cap_flag_value))
      PFATAL("Could not get CAP_EFFECTIVE flag value from process id %d", pid);

    if (cap_flag_value != CAP_SET)
      return no_capability;

    if (cap_get_flag(proc_cap, cap, CAP_PERMITTED, &cap_flag_value))
      PFATAL("Could not get CAP_PERMITTED flag value from process id %d", pid);

    if (cap_flag_value != CAP_SET)
      return no_capability;
  }

  return 0;
}

#ifndef AFL_LIB

/* Main entry point */

int main(int argc, char **argv)
{

  s32 opt;
  u64 prev_queued = 0;
  u32 sync_interval_cnt = 0, seek_to;
  u8 *extras_dir = 0;
  u8 mem_limit_given = 0;
  u8 exit_1 = !!getenv("AFL_BENCH_JUST_ONE");
  // char** use_argv;

  struct timeval tv;
  struct timezone tz;

  SAYF(cCYA "afl-fuzz " cBRI VERSION cRST " by <lcamtuf@google.com>\n");

  doc_path = access(DOC_PATH, F_OK) ? "docs" : DOC_PATH;

  gettimeofday(&tv, &tz);
  srandom(tv.tv_sec ^ tv.tv_usec ^ getpid());

  while ((opt = getopt(argc, argv, "+i:o:f:m:t:T:dnCB:S:M:x:QN:D:W:w:e:P:KEq:s:RFc:l:")) > 0)

    switch (opt)
    {

    case 'i': /* input dir */

      if (in_dir)
        FATAL("Multiple -i options not supported");
      in_dir = optarg;

      if (!strcmp(in_dir, "-"))
        in_place_resume = 1;

      break;

    case 'o': /* output dir */

      if (out_dir)
        FATAL("Multiple -o options not supported");
      out_dir = optarg;
      break;

    case 'M':
    { /* master sync ID */

      u8 *c;

      if (sync_id)
        FATAL("Multiple -S or -M options not supported");
      sync_id = ck_strdup(optarg);

      if ((c = strchr(sync_id, ':')))
      {

        *c = 0;

        if (sscanf(c + 1, "%u/%u", &master_id, &master_max) != 2 ||
            !master_id || !master_max || master_id > master_max ||
            master_max > 1000000)
          FATAL("Bogus master ID passed to -M");
      }

      force_deterministic = 1;
    }

    break;

    case 'S':

      if (sync_id)
        FATAL("Multiple -S or -M options not supported");
      sync_id = ck_strdup(optarg);
      break;

    case 'f': /* target file */

      if (out_file)
        FATAL("Multiple -f options not supported");
      out_file = optarg;
      break;

    case 'x': /* dictionary */

      if (extras_dir)
        FATAL("Multiple -x options not supported");
      extras_dir = optarg;
      break;

    case 't':
    { /* timeout */

      u8 suffix = 0;

      if (timeout_given)
        FATAL("Multiple -t options not supported");

      if (sscanf(optarg, "%u%c", &exec_tmout, &suffix) < 1 ||
          optarg[0] == '-')
        FATAL("Bad syntax used for -t");

      if (exec_tmout < 5)
        FATAL("Dangerously low value of -t");

      if (suffix == '+')
        timeout_given = 2;
      else
        timeout_given = 1;

      break;
    }

    case 'm':
    { /* mem limit */

      u8 suffix = 'M';

      if (mem_limit_given)
        FATAL("Multiple -m options not supported");
      mem_limit_given = 1;

      if (!strcmp(optarg, "none"))
      {

        mem_limit = 0;
        break;
      }

      if (sscanf(optarg, "%llu%c", &mem_limit, &suffix) < 1 ||
          optarg[0] == '-')
        FATAL("Bad syntax used for -m");

      switch (suffix)
      {

      case 'T':
        mem_limit *= 1024 * 1024;
        break;
      case 'G':
        mem_limit *= 1024;
        break;
      case 'k':
        mem_limit /= 1024;
        break;
      case 'M':
        break;

      default:
        FATAL("Unsupported suffix or bad syntax for -m");
      }

      if (mem_limit < 5)
        FATAL("Dangerously low value of -m");

      if (sizeof(rlim_t) == 4 && mem_limit > 2000)
        FATAL("Value of -m out of range on 32-bit systems");
    }

    break;

    case 'd': /* skip deterministic */

      if (skip_deterministic)
        FATAL("Multiple -d options not supported");
      skip_deterministic = 1;
      use_splicing = 1;
      break;

    case 'B': /* load bitmap */

    /*这是一个秘密的未记录的选项！这是有用的，如果你找到
    在一个正常的模糊测试过程中，一个有趣的测试用例
    在不重新发现任何已经存在的测试用例的情况下改变它
    在早期运行期间发现的。

    要使用此模式，您需要将-B指向生成的fuzz_bitmap
    通过之前运行的完全相同的二进制文件…就是这样。

    我只用过一两次来得到一个特定的变量
    档案，所以我不会把它定为正式设置。* /

      if (in_bitmap)
        FATAL("Multiple -B options not supported");

      in_bitmap = optarg;
      read_bitmap(in_bitmap);
      break;

    case 'C': /* crash mode */

      if (crash_mode)
        FATAL("Multiple -C options not supported");
      crash_mode = FAULT_CRASH;
      break;

    case 'n': /* dumb mode */

      if (dumb_mode)
        FATAL("Multiple -n options not supported");
      if (getenv("AFL_DUMB_FORKSRV"))
        dumb_mode = 2;
      else
        dumb_mode = 1;

      break;

    case 'T': /* banner */

      if (use_banner)
        FATAL("Multiple -T options not supported");
      use_banner = optarg;
      break;

    case 'Q': /* QEMU mode */

      if (qemu_mode)
        FATAL("Multiple -Q options not supported");
      qemu_mode = 1;

      if (!mem_limit_given)
        mem_limit = MEM_LIMIT_QEMU;

      break;

    case 'N': /* Network configuration */
      if (use_net)
        FATAL("Multiple -N options not supported");
      if (parse_net_config(optarg, &net_protocol, &net_ip, &net_port))
        FATAL("Bad syntax used for -N. Check the network setting. [tcp/udp]://127.0.0.1/port");

      use_net = 1;
      break;

    case 'D': /* waiting time for the server initialization */
      if (server_wait)
        FATAL("Multiple -D options not supported");

      if (sscanf(optarg, "%u", &server_wait_usecs) < 1 || optarg[0] == '-')
        FATAL("Bad syntax used for -D");
      server_wait = 1;
      break;

    case 'W': /* polling timeout determining maximum amount of time waited before concluding that no responses are forthcoming*/
      if (socket_timeout)
        FATAL("Multiple -W options not supported");

      if (sscanf(optarg, "%u", &poll_wait_msecs) < 1 || optarg[0] == '-')
        FATAL("Bad syntax used for -W");
      poll_wait = 1;
      break;

    case 'w': /* receive/send socket timeout determining time waited for each response */
      if (socket_timeout)
        FATAL("Multiple -w options not supported");

      if (sscanf(optarg, "%u", &socket_timeout_usecs) < 1 || optarg[0] == '-')
        FATAL("Bad syntax used for -w");
      socket_timeout = 1;
      break;

    case 'e': /* network namespace name */
      if (netns_name)
        FATAL("Multiple -e options not supported");

      netns_name = optarg;
      break;

    case 'P': /* protocol to be tested */
      if (protocol_selected)
        FATAL("Multiple -P options not supported");

      if (!strcmp(optarg, "RTSP"))
      {
        extract_requests = &extract_requests_rtsp;
        extract_response_codes = &extract_response_codes_rtsp;
      }
      else if (!strcmp(optarg, "FTP"))
      {
        extract_requests = &extract_requests_ftp;
        extract_response_codes = &extract_response_codes_ftp;
      }
      else if (!strcmp(optarg, "DTLS12"))
      {
        extract_requests = &extract_requests_dtls12;
        extract_response_codes = &extract_response_codes_dtls12;
      }
      else if (!strcmp(optarg, "DNS"))
      {
        extract_requests = &extract_requests_dns;
        extract_response_codes = &extract_response_codes_dns;
      }
      else if (!strcmp(optarg, "DICOM"))
      {
        extract_requests = &extract_requests_dicom;
        extract_response_codes = &extract_response_codes_dicom;
      }
      else if (!strcmp(optarg, "SMTP"))
      {
        extract_requests = &extract_requests_smtp;
        extract_response_codes = &extract_response_codes_smtp;
      }
      else if (!strcmp(optarg, "SSH"))
      {
        extract_requests = &extract_requests_ssh;
        extract_response_codes = &extract_response_codes_ssh;
      }
      else if (!strcmp(optarg, "TLS"))
      {
        extract_requests = &extract_requests_tls;
        extract_response_codes = &extract_response_codes_tls;
      }
      else if (!strcmp(optarg, "SIP"))
      {
        extract_requests = &extract_requests_sip;
        extract_response_codes = &extract_response_codes_sip;
      }
      else if (!strcmp(optarg, "HTTP"))
      {
        extract_requests = &extract_requests_http;
        extract_response_codes = &extract_response_codes_http;
      }
      else if (!strcmp(optarg, "IPP"))
      {
        extract_requests = &extract_requests_ipp;
        extract_response_codes = &extract_response_codes_ipp;
      }
      else
      {
        FATAL("%s protocol is not supported yet!", optarg);
      }
      protocol_name = ck_strdup(optarg);
      protocol_selected = 1;

      break;

    case 'K':
      if (terminate_child)
        FATAL("Multiple -K options not supported");
      terminate_child = 1;
      break;

    case 'E':
      if (state_aware_mode)
        FATAL("Multiple -E options not supported");
      state_aware_mode = 1;
      break;

    case 'q': /* state selection option */
      if (sscanf(optarg, "%hhu", &state_selection_algo) < 1 || optarg[0] == '-')
        FATAL("Bad syntax used for -q");
      break;

    case 's': /* seed selection option */
      if (sscanf(optarg, "%hhu", &seed_selection_algo) < 1 || optarg[0] == '-')
        FATAL("Bad syntax used for -s");
      break;

    case 'R':
      if (region_level_mutation)
        FATAL("Multiple -R options not supported");
      region_level_mutation = 1;
      break;

    case 'F':
      if (false_negative_reduction)
        FATAL("Multiple -F options not supported");
      false_negative_reduction = 1;
      break;

    case 'c': /* cleanup script */

      if (cleanup_script)
        FATAL("Multiple -c options not supported");
      cleanup_script = optarg;
      break;

    case 'l': /* local port to connect from */
      // This option is only used for targets that send responses to a specific port number
      // The Kamailio SIP server is an example

      if (local_port)
        FATAL("Multiple -l options not supported");
      local_port = atoi(optarg);
      if (local_port < 1024 || local_port > 65535)
        FATAL("Invalid source port number");
      break;

    default:

      usage(argv[0]);
    }

  if (optind == argc || !in_dir || !out_dir)
    usage(argv[0]);

  // AFLNet - Check for required arguments
  if (!use_net)
    FATAL("Please specify network information of the server under test (e.g., tcp://127.0.0.1/8554)");

  if (!protocol_selected)
    FATAL("Please specify the protocol to be tested using the -P option");

  if (netns_name)
  {
    if (check_ep_capability(CAP_SYS_ADMIN, argv[0]) != 0)
      FATAL("Could not run the server under test in a \"%s\" network namespace "
            "without CAP_SYS_ADMIN capability.\n You can set it by invoking "
            "afl-fuzz with sudo or by \"$ setcap cap_sys_admin+ep /path/to/afl-fuzz\".",
            netns_name);
  }

  setup_signal_handlers();
  check_asan_opts();

  if (sync_id)
    fix_up_sync();

  if (!strcmp(in_dir, out_dir))
    FATAL("Input and output directories can't be the same");

  if (dumb_mode)
  {

    if (crash_mode)
      FATAL("-C and -n are mutually exclusive");
    if (qemu_mode)
      FATAL("-Q and -n are mutually exclusive");
  }

  if (getenv("AFL_NO_FORKSRV"))
    no_forkserver = 1;
  if (getenv("AFL_NO_CPU_RED"))
    no_cpu_meter_red = 1;
  if (getenv("AFL_NO_ARITH"))
    no_arith = 1;
  if (getenv("AFL_SHUFFLE_QUEUE"))
    shuffle_queue = 1;
  if (getenv("AFL_FAST_CAL"))
    fast_cal = 1;

  if (getenv("AFL_HANG_TMOUT"))
  {
    hang_tmout = atoi(getenv("AFL_HANG_TMOUT"));
    if (!hang_tmout)
      FATAL("Invalid value of AFL_HANG_TMOUT");
  }

  if (dumb_mode == 2 && no_forkserver)
    FATAL("AFL_DUMB_FORKSRV and AFL_NO_FORKSRV are mutually exclusive");

  if (getenv("AFL_PRELOAD"))
  {
    setenv("LD_PRELOAD", getenv("AFL_PRELOAD"), 1);
    setenv("DYLD_INSERT_LIBRARIES", getenv("AFL_PRELOAD"), 1);
  }

  if (getenv("AFL_LD_PRELOAD"))
    FATAL("Use AFL_PRELOAD instead of AFL_LD_PRELOAD");

  save_cmdline(argc, argv);

  fix_up_banner(argv[optind]);

  check_if_tty();

  get_core_count();

#ifdef HAVE_AFFINITY
  bind_to_free_cpu();
#endif /* HAVE_AFFINITY */

  check_crash_handling();
  check_cpu_governor();

  setup_post();
  setup_shm();
  init_count_class16();

  setup_ipsm();

  setup_dirs_fds();

  if (protocol_selected)
  {
    protocol_patterns = kl_init(rang);
    message_types_set = kh_init(strSet);

    setup_llm_grammars_semantics();
    enrich_testcases();
  }
  read_testcases();
  load_auto();

  pivot_inputs();

  if (extras_dir)
    load_extras(extras_dir);

  if (!timeout_given)
    find_timeout();

  detect_file_args(argv + optind + 1);

  if (!out_file)
    setup_stdio_file();

  check_binary(argv[optind]);

  start_time = get_cur_time();

  if (qemu_mode)
    use_argv = get_qemu_argv(argv[0], argv + optind, argc - optind);
  else
    use_argv = argv + optind;

  perform_dry_run(use_argv);

  cull_queue();

  show_init_stats();

  seek_to = find_start_position();

  write_stats_file(0, 0, 0);
  save_auto();

  if (stop_soon)
    goto stop_fuzzing;

  /* Woop woop woop */

  if (!not_on_tty)
  {
    sleep(4);
    start_time += 4000;
    if (stop_soon)
      goto stop_fuzzing;
  }

  if (state_aware_mode)
  {

    if (state_ids_count == 0)
    {
      PFATAL("No server states have been detected. Server responses are likely empty!");
    }

    while (1)
    {
      u8 skipped_fuzz;

      struct queue_entry *selected_seed = NULL;
      while (!selected_seed || selected_seed->region_count == 0)
      {
        target_state_id = choose_target_state(state_selection_algo);

        /* Update favorites based on the selected state */
        cull_queue();

        /* Update number of times a state has been selected for targeted fuzzing */
        khint_t k = kh_get(hms, khms_states, target_state_id);
        if (k != kh_end(khms_states))
        {
          kh_val(khms_states, k)->selected_times++;
        }

        selected_seed = choose_seed(target_state_id, seed_selection_algo);
      }

      /* Seek to the selected seed */
      if (selected_seed)
      {
        if (!queue_cur)
        {
          current_entry = 0;
          cur_skipped_paths = 0;
          queue_cur = queue;
          queue_cycle++;
        }
        while (queue_cur != selected_seed)
        {
          queue_cur = queue_cur->next;
          current_entry++;
          if (!queue_cur)
          {
            current_entry = 0;
            cur_skipped_paths = 0;
            queue_cur = queue;
            queue_cycle++;
          }
        }
      }

      skipped_fuzz = fuzz_one(use_argv);

      if (!stop_soon && sync_id && !skipped_fuzz)
      {

        if (!(sync_interval_cnt++ % SYNC_INTERVAL))
          sync_fuzzers(use_argv);
      }

      if (!stop_soon && exit_1)
        stop_soon = 2;

      if (stop_soon)
        break;
    }
  }
  else
  {
    while (1)
    {

      u8 skipped_fuzz;

      cull_queue();

      if (!queue_cur)
      {

        queue_cycle++;
        current_entry = 0;
        cur_skipped_paths = 0;
        queue_cur = queue;

        while (seek_to)
        {
          current_entry++;
          seek_to--;
          queue_cur = queue_cur->next;
        }

        show_stats();

        if (not_on_tty)
        {
          ACTF("Entering queue cycle %llu.", queue_cycle);
          fflush(stdout);
        }

        /* If we had a full queue cycle with no new finds, try
           recombination strategies next. */

        if (queued_paths == prev_queued)
        {

          if (use_splicing)
            cycles_wo_finds++;
          else
            use_splicing = 1;
        }
        else
          cycles_wo_finds = 0;

        prev_queued = queued_paths;

        if (sync_id && queue_cycle == 1 && getenv("AFL_IMPORT_FIRST"))
          sync_fuzzers(use_argv);
      }

      skipped_fuzz = fuzz_one(use_argv);

      if (!stop_soon && sync_id && !skipped_fuzz)
      {

        if (!(sync_interval_cnt++ % SYNC_INTERVAL))
          sync_fuzzers(use_argv);
      }

      if (!stop_soon && exit_1)
        stop_soon = 2;

      if (stop_soon)
        break;

      queue_cur = queue_cur->next;
      current_entry++;
    }
  }

  if (queue_cur)
    show_stats();

  /* If we stopped programmatically, we kill the forkserver and the current runner.
     If we stopped manually, this is done by the signal handler. */
  if (stop_soon == 2)
  {
    if (child_pid > 0)
      kill(child_pid, SIGKILL);
    if (forksrv_pid > 0)
      kill(forksrv_pid, SIGKILL);
  }
  /* Now that we've killed the forkserver, we wait for it to be able to get rusage stats. */
  if (waitpid(forksrv_pid, NULL, 0) <= 0)
  {
    WARNF("error waitpid\n");
  }

  write_bitmap();
  write_stats_file(0, 0, 0);
  save_auto();

stop_fuzzing:

  SAYF(CURSOR_SHOW cLRD "\n\n+++ Testing aborted %s +++\n" cRST,
       stop_soon == 2 ? "programmatically" : "by user");

  /* Running for more than 30 minutes but still doing first cycle? */

  if (queue_cycle == 1 && get_cur_time() - start_time > 30 * 60 * 1000)
  {

    SAYF("\n" cYEL "[!] " cRST
         "Stopped during the first cycle, results may be incomplete.\n"
         "    (For info on resuming, see %s/README.)\n",
         doc_path);
  }

  fclose(plot_file);
  destroy_queue();
  destroy_extras();
  ck_free(target_path);
  ck_free(sync_id);

  destroy_ipsm();

  alloc_report();

  OKF("We're done here. Have a nice day!\n");

  exit(0);
}

#endif /* !AFL_LIB */
