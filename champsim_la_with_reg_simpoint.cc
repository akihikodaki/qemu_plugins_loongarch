#include <algorithm>
#include <iostream>
#include <sstream>
#include <fstream>
#include <set>
#include <map>
#include <mutex>
#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <zlib.h>
#include <vector>

#include <fcntl.h>
#include <sys/mman.h>

extern "C" {
#include "qemu-plugin.h"
}

#include "util.h"
#include "loongarch_decode_insns.c.inc"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

using namespace std;

#define NUM_INSTR_DESTINATIONS 1
#define NUM_INSTR_SOURCES 3


typedef struct trace_instr_format {
    unsigned long long int ip;  // instruction pointer (program counter) value
    unsigned long long int destination_memory[NUM_INSTR_DESTINATIONS]; // output memory
    unsigned long long int source_memory[NUM_INSTR_SOURCES];           // input memory
    unsigned long long ret_val;
    unsigned int inst;
    //unsigned short op;
    unsigned char is_branch;    // is this branch
    unsigned char branch_taken; // if so, is this taken

    unsigned char destination_registers[NUM_INSTR_DESTINATIONS]; // output registers
    unsigned char source_registers[NUM_INSTR_SOURCES];           // input registers
} trace_instr_format_t;

// branch types
enum branch_type {
  NOT_BRANCH = 0,
  BRANCH_DIRECT_JUMP = 1,
  BRANCH_INDIRECT = 2,
  BRANCH_CONDITIONAL = 3,
  BRANCH_DIRECT_CALL = 4,
  BRANCH_INDIRECT_CALL = 5,
  BRANCH_RETURN = 6,
  BRANCH_OTHER = 7
};

const char* branch_type(int is_branch) {
    switch (is_branch) {
        case NOT_BRANCH:            return "";
        case BRANCH_DIRECT_JUMP:    return "direct_jump";
        case BRANCH_INDIRECT:       return "indirect_jump";
        case BRANCH_CONDITIONAL:    return "conditional";
        case BRANCH_DIRECT_CALL:    return "direct_call";
        case BRANCH_INDIRECT_CALL:  return "indirect_call";
        case BRANCH_RETURN:         return "return";
        case BRANCH_OTHER:          return "other";
    }
    return "NULL";
};

void dump_trace(trace_instr_format_t& t) {
    const char* taken = "";
    if (t.is_branch) {
        if (t.branch_taken) {
            taken = "taken";
        } else {
            taken = "not taken";
        }
    }
    fprintf(stderr, "ip:%-1llx %-10s %-15s", t.ip, taken, branch_type(t.is_branch));
    string reg_str("register: ");
    for (int i = 0; i < NUM_INSTR_DESTINATIONS; i++) {
        if (t.destination_registers[i]) {
            reg_str += to_string(t.destination_registers[i]);
            reg_str += " ";
        }
    }

    if (t.destination_registers[0]) {
        stringstream stream;
        stream << std::hex << t.ret_val;
        reg_str += "(0x" + stream.str() + ")";
    }

    reg_str += " <= ";
    for (int i = 0; i < NUM_INSTR_SOURCES; i++) {
        if (t.source_registers[i]) {
            reg_str += to_string(t.source_registers[i]);
            reg_str += " ";
        }
    }

    fprintf(stderr, "%-27s ", reg_str.c_str());

    if (t.destination_memory[0]) {
        fprintf(stderr, "write memory:");
        for (int i = 0; i < NUM_INSTR_DESTINATIONS; i++) {
            if (t.destination_memory[i]) {
                fprintf(stderr, "%llx ", t.destination_memory[i]);
            } else {
                fprintf(stderr, " ");
            }
        }
    }

    if (t.source_memory[0]) {
        fprintf(stderr, "read memory:");
        for (int i = 0; i < NUM_INSTR_SOURCES; i++) {
            if (t.source_memory[i]) {
                fprintf(stderr, "%llx ", t.source_memory[i]);
            } else {
                fprintf(stderr, " ");
            }
        }
    }
    fprintf(stderr, "\n");
}

// typedef __int128 insn_code;
typedef uint64_t insn_code;

insn_code insn_code_init(uint64_t pc, const uint8_t* data, int size) {
    // insn_code r = 0;
    // for (size_t i = 0; i < size; i++)
    // {
    //     r <<= 8;
    //     r |= data[i];
    // }
    // return r;
    return pc;
}

map<insn_code, void*> insn_code_data;

// trace_instr_format_t curr_instr;
// instructions has finished
int64_t REAL_INSN_COUNT = -1;
int64_t BB_INTERVAL = 10000;
int64_t BB_SAVE_NUM;
const char* trace_filename;
int trace_fd;
uint64_t filesize;
trace_instr_format_t* trace_buffer;
// int64_t trace_buffer_index = -1;
char current_trace_filename[1024];


bool verbose;
bool early_exit;


#define MAX_SIMPOINTS_NUM 1024
int64_t simpoints[MAX_SIMPOINTS_NUM];
size_t simpoints_num;

long long SM_INTERVAL = 1000000;

static int cmpfunc (const void * a, const void * b) {
    // reverse
   return ( *(uint64_t*)b - *(uint64_t*)a );
}

static void plugin_init(const qemu_info_t* info) {
    fprintf(stderr, "sizeof(trace_instr_format):%zu\n",
            sizeof(trace_instr_format));
    if (getenv("VERBOSE")) {
        verbose = true;
    }
    if (getenv("EARLY_EXIT")) {
        early_exit = true;
    }

    const char* SIMPOINT_FILE_ENV = getenv("SIMPOINT_FILE");
    if (SIMPOINT_FILE_ENV) {
        FILE* f = fopen_nofail(SIMPOINT_FILE_ENV, "r");
        while (fscanf(f, "%ld%*f", simpoints + simpoints_num) == 1) {
            ++ simpoints_num;
            if (simpoints_num >= MAX_SIMPOINTS_NUM) {
                fprintf(stderr, "simpoints too large\n");
                exit(1);
            }
        }
        fclose(f);
        qsort(simpoints, simpoints_num, sizeof(simpoints[0]), cmpfunc);

        // 1:1 warm up
        // if (simpoints[simpoints_num - 1] == 0) {
        //     simpoints[simpoints_num - 1] = 1;
        //     if (simpoints_num >=2 && simpoints[simpoints_num - 1] == 1 && simpoints[simpoints_num - 2] == 1) {
        //         simpoints_num --;
        //     }
        // }
        // for (size_t i = 0; i < simpoints_num; i++) {
        //     simpoints[i] --;
        // }
        // for (size_t i = 0; i < simpoints_num - 1; i++) {
        //     if (simpoints[i] + 1 == simpoints[i + 1]) {
        //         fprintf(stderr, "simpoints overlap, not supportted currently\n");
        //         exit(EXIT_FAILURE);
        //     }
        // }

        for (size_t i = 0; i < simpoints_num; i++) {
            fprintf(stderr, "%ld ", simpoints[i]);
        }
        fprintf(stderr, "\n");
    }

    const char* BB_INTERVAL_ENV = getenv("BB_INTERVAL");
    if (BB_INTERVAL_ENV) {
        BB_INTERVAL = atoll(BB_INTERVAL_ENV);
        // 1:1 warmup
        // BB_SAVE_NUM = BB_INTERVAL * 2;
        // none warm up
        BB_SAVE_NUM = BB_INTERVAL;
    }

    trace_filename = getenv("TRACE_FILENAME");
    if (!trace_filename) {
        trace_filename = "champsim.trace";
    }
    filesize = BB_SAVE_NUM * sizeof(trace_instr_format_t);

    printf("%s\n", info->target_name);
}

int la_inst_branch_type(LA_DECODE& la_decode) {
    switch (la_decode.id) {
        case LA_INST_B:
            return BRANCH_DIRECT_JUMP;
        case LA_INST_BCEQZ:
        case LA_INST_BCNEZ:
        case LA_INST_BEQZ:
        case LA_INST_BNEZ:
        case LA_INST_BEQ:
        case LA_INST_BNE:
        case LA_INST_BLT:
        case LA_INST_BGE:
        case LA_INST_BLTU:
        case LA_INST_BGEU:
            return BRANCH_CONDITIONAL;
        case LA_INST_BL:
            return BRANCH_DIRECT_CALL;
        case LA_INST_JIRL:
            if (la_decode.op[0].val == 1) {
                return BRANCH_INDIRECT_CALL;
            } else if (la_decode.op[1].val == 1) {
                return BRANCH_RETURN;
            } else {
                return BRANCH_INDIRECT;
            }
        default:
            return NOT_BRANCH;
    }
    return NOT_BRANCH;
}

int encode_reg(LA_OP op) {
    if (op.type == LA_OP_GPR) {
        return op.val;
    } else if (op.type == LA_OP_FR || op.type == LA_OP_VR || op.type == LA_OP_XR) {
        return op.val + 32;
    } else if (op.type == LA_OP_FCC) {
        return op.val + 64;
    }
    return 0;
}

void fill_insn_template(trace_instr_format* insn, uint64_t pc,
                        const uint8_t* data, int size) {
    insn->ip = pc;
    insn->branch_taken = size;
    insn->inst = *(uint32_t*)data;
    LA_DECODE la_decode;
    decode(&la_decode, *(uint32_t*)data);
    // char buf[1024];
    // la_inst_str(&la_decode, buf);
    // fprintf(stderr, "%s\n", buf);
    insn->is_branch = la_inst_branch_type(la_decode);
    insn->ret_val = 0;
    if (la_decode.id == LA_INST_BL) {
#ifdef QEMU_PLUGIN_HAS_ENV_PTR
        insn->ret_val = 1;
#endif
        insn->destination_registers[0] = 1;
    } else if (la_inst_is_branch_not_link(la_decode.id) || la_inst_is_st(la_decode.id)) {
        for (int i = 0; i < min(la_decode.opcnt, NUM_INSTR_SOURCES); i++) {
            insn->source_registers[i] = encode_reg(la_decode.op[i]);
        }
    } else {
#ifdef QEMU_PLUGIN_HAS_ENV_PTR
        if (la_decode.opcnt >= 1 && la_decode.op[0].type == LA_OP_GPR) {
            insn->ret_val = la_decode.op[0].val;
        }
#endif
        if (la_decode.opcnt >= 1) {
            insn->destination_registers[0] = encode_reg(la_decode.op[0]);
        }

        for (int i = 0; i < min(la_decode.opcnt - 1, NUM_INSTR_SOURCES); i++) {
            insn->source_registers[i] = encode_reg(la_decode.op[i + 1]);
        }
    }
}
int save;
int saved_inst_num;
bool has_ibar_begin;
bool has_ibar_end;

void plugin_exit(qemu_plugin_id_t id, void* p) {
    if (save && saved_inst_num < BB_SAVE_NUM) {
        msync(trace_buffer, filesize, MS_SYNC);
        munmap(trace_buffer, filesize);
        int r = truncate(current_trace_filename, min((uint64_t)saved_inst_num, (uint64_t)BB_SAVE_NUM) *
                                    sizeof(trace_instr_format_t));
        if (r < 0) {
            fprintf(stderr, "errno=%d, err_msg=\"%s\", line:%d\n", errno,
                strerror(errno), __LINE__);
        } else {
            fprintf(stderr, "truncate %s to %ld * %zu\n", current_trace_filename, min((uint64_t)saved_inst_num, (uint64_t)BB_SAVE_NUM) ,
                                    sizeof(trace_instr_format_t));
        }

    }
    fprintf(stderr, "plugin fini, trace fini\n");
}

static void qemu_dump_guest_reg(const char* filename) {
#ifdef QEMU_PLUGIN_HAS_ENV_PTR
    uint64_t* env = (uint64_t*)qemu_plugin_env_ptr();
    FILE* f = fopen(filename, "w");
    if (f == NULL) {
        fprintf(stderr, "unable to open %s, %s\n", filename, strerror(errno));
        return;
    }
    for (int i = 0; i < 32; i++) {
        fprintf(f, "gpr, %d, %016lx\n", i, env[i]);
    }

    fclose(f);
#endif
}

static void vcpu_insn_exec(unsigned int vcpu_index, void* userdata) {
    if (!has_ibar_begin) {
        return;
    }
    ++ REAL_INSN_COUNT;
    // fprintf(stderr, "simpoints_num :%ld REAL_INSN_COUNT:%ld BB_INTERVAL:%ld simpoints[simpoints_num - 1]:%ld\n", simpoints_num, REAL_INSN_COUNT, BB_INTERVAL, simpoints[simpoints_num - 1]);
    // 1:1 warmup
    if (save == 0 && simpoints_num > 0 && REAL_INSN_COUNT == (BB_INTERVAL * simpoints[simpoints_num - 1])) {
        fprintf(stderr, "save begin %ld\n", simpoints[simpoints_num - 1]);
        simpoints_num --;
        save = 1;
        saved_inst_num = 0;
    }

    if (save == 0) {
        return;
    }
    trace_instr_format* p = (trace_instr_format*)userdata;
    if (saved_inst_num) {
        trace_instr_format* p = (trace_instr_format*)userdata;
        trace_instr_format* t = trace_buffer + saved_inst_num - 1;
        if (t->ip + t->branch_taken != p->ip) {
            t->branch_taken = 1;
        } else {
            t->branch_taken = 0;
        }
#ifdef QEMU_PLUGIN_HAS_ENV_PTR
        uint64_t* env = (uint64_t*)qemu_plugin_env_ptr();
        t->ret_val = env[t->ret_val];
#endif
    } else {
        char filename_buffer[1024];
        sprintf(filename_buffer, "%s_%ld.champsim.trace", trace_filename, REAL_INSN_COUNT);
        trace_fd = open(filename_buffer, O_RDWR | O_CREAT, (mode_t)0600);
        if (trace_fd < 0) {
            fprintf(stderr, "errno=%d, err_msg=\"%s\", line:%d\n", errno, strerror(errno), __LINE__);
            exit(EXIT_FAILURE);
        }
        int r = ftruncate(trace_fd, BB_SAVE_NUM * sizeof(trace_instr_format_t));
        if (r < 0) {
            fprintf(stderr, "errno=%d, err_msg=\"%s\", line:%d\n", errno, strerror(errno), __LINE__);
            exit(EXIT_FAILURE);
        }

        trace_buffer = (trace_instr_format_t*)mmap(
            0, filesize, PROT_READ | PROT_WRITE, MAP_SHARED, trace_fd, 0);

        if (trace_buffer == MAP_FAILED) {
            fprintf(stderr, "errno=%d, err_msg=\"%s\", line:%d\n", errno,
                    strerror(errno), __LINE__);
            exit(EXIT_FAILURE);
        }
        close(trace_fd);
        strcpy(current_trace_filename, filename_buffer);
        sprintf(filename_buffer, "%s_%ld.memory.bin", trace_filename, REAL_INSN_COUNT);
#ifdef QEMU_PLUGIN_HAS_DUMP_MEMORY
        qemu_plugin_dump_memory(filename_buffer);
#endif
        sprintf(filename_buffer, "%s_%ld.regfile.txt", trace_filename, REAL_INSN_COUNT);
        qemu_dump_guest_reg(filename_buffer);
    }
    trace_buffer[saved_inst_num] = *p;
    if (verbose) {
        printf("cpu:%d, pc:%llx, is_branch:%d\n", vcpu_index, p->ip, p->is_branch);
    }

    if (saved_inst_num == 500) {
        char filename_buffer[1024];
        sprintf(filename_buffer, "%s_%ld.regfile500.txt", trace_filename, REAL_INSN_COUNT - 500);
        qemu_dump_guest_reg(filename_buffer);
    }
    saved_inst_num ++;
    if (saved_inst_num == BB_SAVE_NUM) {
        msync(trace_buffer, filesize, MS_SYNC);
        munmap(trace_buffer, filesize);
        fprintf(stderr, "trace fini\n");
        save = 0;
    }
}

static void vcpu_mem_access(unsigned int vcpu_index, qemu_plugin_meminfo_t info,
                            uint64_t vaddr, void* userdata) {
    if (!has_ibar_begin) {
        return;
    }
    if (!save) {
        return;
    }
    trace_instr_format_t* p = trace_buffer + saved_inst_num - 1;
    bool is_st = qemu_plugin_mem_is_store(info);
        if (is_st) {
            for (size_t i = 0; i < NUM_INSTR_DESTINATIONS; i++) {
                if (p->destination_memory[i] == 0) {
                    p->destination_memory[i] = vaddr;
                    break;
                }
            }
        } else {
            for (size_t i = 0; i < NUM_INSTR_SOURCES; i++) {
                if (p->source_memory[i] == 0) {
                    p->source_memory[i] = vaddr;
                    break;
                }
            }
        }
        if (verbose) {
            printf("cpu:%d, pc:%p, mem_addr:%lx, size:%d, is_st:%d\n", vcpu_index,
                    userdata, vaddr, 1 << qemu_plugin_mem_size_shift(info), is_st);
        }
}

static void tb_record(qemu_plugin_id_t id, struct qemu_plugin_tb* tb) {
    size_t insns = qemu_plugin_tb_n_insns(tb);

    for (size_t i = 0; i < insns; i++) {
        struct qemu_plugin_insn* insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t addr = qemu_plugin_insn_vaddr(insn);
        const uint8_t* data = (uint8_t*)qemu_plugin_insn_data(insn);
        int size = qemu_plugin_insn_size(insn);
        insn_code ic = insn_code_init(addr, data, size);
        if (insn_code_data.count(ic) == 0) {
            trace_instr_format* insn_template =
                (trace_instr_format*)aligned_alloc(64,
                                                   sizeof(trace_instr_format));
            memset(insn_template, 0, sizeof(trace_instr_format));
            fill_insn_template(insn_template, addr, data, size);
            insn_code_data[ic] = insn_template;
        }

        if (*(uint32_t*)data == 0x38728040) {
            fprintf(stderr, "ibar begin\n");
            has_ibar_begin = 1;
        }
        if (*(uint32_t*)data == 0x38728041) {
            fprintf(stderr, "ibar end\n");
            has_ibar_end = 1;
            exit(0);
        }

        qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec,
                                                QEMU_PLUGIN_CB_NO_REGS,
                                                (void*)insn_code_data[ic]);
        qemu_plugin_register_vcpu_mem_cb(insn, vcpu_mem_access,
                                            QEMU_PLUGIN_CB_NO_REGS,
                                            QEMU_PLUGIN_MEM_RW, (void*)addr);
    }
}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    plugin_init(info);

    has_ibar_begin = !plugin_args_get_bool_or_else(argc, argv, "check_ibar", false);
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_record);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
