#include <algorithm>
#include <iostream>
#include <sstream>
#include <fstream>
#include <set>
#include <map>
#include <mutex>
#include <unordered_set>
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
#include "riscv.h"

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
        case BRANCH_YIELD:          return "yield";
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

insn_code insn_code_init(uint64_t pc, uint32_t data, int size) {
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

namespace riscv {
    static const char * const cpu[] = {
        "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "fp", "s1",
        "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
        "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
        "t3", "t4", "t5", "t6"
    };

    static const char * const fpu[] = {
        "ft0", "ft1", "ft2", "ft3", "ft4", "ft5", "ft6", "ft7", "fs0", "fs1",
        "fa0", "fa1", "fa2", "fa3", "fa4", "fa5", "fa6", "fa7",
        "fs2", "fs3", "fs4", "fs5", "fs6", "fs7", "fs8", "fs9", "fs10", "fs11",
        "ft8", "ft9", "ft10", "ft11"
    };

    static const size_t size = (sizeof(cpu) + sizeof(fpu)) / sizeof(const char *);
    static bool target;
};

class vcpu {
public:
    vcpu(unsigned int vcpu_index) : buf(g_byte_array_new()), vcpu_index(vcpu_index) {
        mem_stream.exceptions(ofstream::badbit | ofstream::failbit | ofstream::eofbit);

        if (riscv::target) {
            g_autoptr(GArray) descriptors = qemu_plugin_get_registers();

            for (guint i = 0; i < descriptors->len; i++) {
                auto& descriptor = g_array_index(descriptors, qemu_plugin_reg_descriptor, i);
                const char * const * names;
                size_t names_size;
                size_t offset;

                if (!strcmp(descriptor.feature, "org.gnu.gdb.riscv.cpu")) {
                    offset = 0;
                    names = riscv::cpu;
                    names_size = sizeof(riscv::cpu);
                } else if (!strcmp(descriptor.feature, "org.gnu.gdb.riscv.fpu")) {
                    offset = sizeof(riscv::cpu);
                    names = riscv::fpu;
                    names_size = sizeof(riscv::fpu);
                } else {
                    continue;
                }

                for (size_t i = 0; i < names_size / sizeof(*names); i++) {
                    if (!strcmp(names[i], descriptor.name)) {
                        riscv_handles[offset + i] = descriptor.handle;
                        break;
                    }
                }
            }
        }
    }

    ~vcpu() {
        g_byte_array_unref(buf);
    }

    void mem_open(const char* filename) {
        if (mem_stream.is_open()) {
            abort();
        }
        mem_stream.open(filename);
    }

    void mem_close() {
        //mem_stream.close();
        mem_vaddrs.clear();
    }

    void mem_write(uint64_t vaddr) {
        uint64_t page_size = riscv::target ? 4096 : 16384;
        auto page_vaddr = vaddr - vaddr % page_size;

        if (!mem_vaddrs.insert(page_vaddr).second) {
            return;
        }

        qemu_plugin_read_memory_vaddr(page_vaddr, buf, page_size);
        uint64_t header[8] = {page_vaddr, buf->len};
        mem_stream.write(reinterpret_cast<char*>(header), sizeof(header));
        mem_stream.write(reinterpret_cast<char*>(buf->data), buf->len);
    }

    uint64_t riscv_read(size_t index) {
        auto handle = riscv_handles[index];
        g_byte_array_set_size(buf, 0);
        qemu_plugin_read_register(handle, buf);
        return *(uint64_t *)buf->data;
    }

    static vcpu* find(unsigned int vcpu_index) {
        return instance && instance->vcpu_index == vcpu_index ?
               &(*instance) : nullptr;
    }

    static void init(unsigned int vcpu_index) {
        if (instance) {
            return;
        }

        instance.emplace(vcpu_index);
    }

    static void exit() {
        instance.reset();
    }

private:
    GByteArray * const buf;
    const unsigned int vcpu_index;
    ofstream mem_stream;
    unordered_set<uint64_t> mem_vaddrs;
    qemu_plugin_register* riscv_handles[riscv::size];
    static optional<vcpu> instance;
};

optional<vcpu> vcpu::instance;

static int cmpfunc (const void * a, const void * b) {
    // reverse
   return ( *(uint64_t*)b - *(uint64_t*)a );
}

static void plugin_init(const qemu_info_t* info) {
    try {
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
    } catch (exception& e) {
        cerr << __func__ << ": " << e.what() << '\n';
    }
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
                        uint32_t data, int size) {
    insn->ip = pc;
    insn->branch_taken = size;
    insn->inst = data;
    if (riscv::target) {
        champsim::riscv::decoded_inst decoded_inst(data);
        insn->is_branch = decoded_inst.branch_type;

        for (uint8_t i = 0;
             i < NUM_INSTR_SOURCES && decoded_inst.source_registers[i] != UINT8_MAX;
             i++) {
            insn->source_registers[i] = decoded_inst.source_registers[i];
        }

        for (uint8_t i = 0;
             i < NUM_INSTR_DESTINATIONS && decoded_inst.destination_registers[i] != UINT8_MAX;
             i++) {
            insn->destination_registers[i] = decoded_inst.destination_registers[i];
        }

        return;
    }
    LA_DECODE la_decode;
    decode(&la_decode, data);
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
    try {
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
        vcpu::exit();
        fprintf(stderr, "plugin fini, trace fini\n");
    } catch (exception& e) {
        cerr << __func__ << ": " << e.what() << '\n';
    }
}

static void qemu_dump_guest_reg(vcpu& vcpu, const char* filename) {
    if (riscv::target) {
        ofstream stream(filename);
        for (size_t i = 0; i < riscv::size; i++) {
            auto buf = vcpu.riscv_read(i);
            stream << "gpr, " << i << ", " <<
                      hex << setfill('0') << setw(16) << buf << '\n';
        }
        return;
    }
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
    try {
        auto vcpu = vcpu::find(vcpu_index);
        if (!has_ibar_begin || !vcpu) {
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
            if (riscv::target) {
                t->ret_val = vcpu->riscv_read(t->destination_registers[0]);
            } else {
    #ifdef QEMU_PLUGIN_HAS_ENV_PTR
                uint64_t* env = (uint64_t*)qemu_plugin_env_ptr();
                t->ret_val = env[t->ret_val];
    #endif
            }
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
            vcpu->mem_open(filename_buffer);
            sprintf(filename_buffer, "%s_%ld.regfile.txt", trace_filename, REAL_INSN_COUNT);
            qemu_dump_guest_reg(*vcpu, filename_buffer);
        }
        trace_buffer[saved_inst_num] = *p;
        if (verbose) {
            printf("cpu:%d, pc:%llx, is_branch:%d\n", vcpu_index, p->ip, p->is_branch);
        }

        if (saved_inst_num == 500) {
            char filename_buffer[1024];
            sprintf(filename_buffer, "%s_%ld.regfile500.txt", trace_filename, REAL_INSN_COUNT - 500);
            qemu_dump_guest_reg(*vcpu, filename_buffer);
        }
        saved_inst_num ++;
        if (saved_inst_num == BB_SAVE_NUM) {
            msync(trace_buffer, filesize, MS_SYNC);
            munmap(trace_buffer, filesize);
            vcpu->mem_close();
            fprintf(stderr, "trace fini\n");
            save = 0;
        }
    } catch (exception& e) {
        cerr << __func__ << ": " << e.what() << '\n';
    }
}

static void vcpu_mem_access(unsigned int vcpu_index, qemu_plugin_meminfo_t info,
                            uint64_t vaddr, void* userdata) {
    try {
        auto vcpu = vcpu::find(vcpu_index);
        if (!has_ibar_begin || !vcpu) {
            return;
        }
        if (!save) {
            return;
        }
        vcpu->mem_write(vaddr);
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
    } catch (exception& e) {
        cerr << __func__ << ": " << e.what() << '\n';
    }
}

static void init(qemu_plugin_id_t id, unsigned int vcpu_index) {
    try {
        vcpu::init(vcpu_index);
    } catch (exception& e) {
        cerr << __func__ << ": " << e.what() << '\n';
    }
}

static void exit(qemu_plugin_id_t id, unsigned int vcpu_index) {
    try {
        if (vcpu::find(vcpu_index)) {
            vcpu::exit();
        }
    } catch (exception& e) {
        cerr << __func__ << ": " << e.what() << '\n';
    }
}

static void tb_record(qemu_plugin_id_t id, struct qemu_plugin_tb* tb) {
    try {
        size_t insns = qemu_plugin_tb_n_insns(tb);

        for (size_t i = 0; i < insns; i++) {
            struct qemu_plugin_insn* insn = qemu_plugin_tb_get_insn(tb, i);
            uint64_t addr = qemu_plugin_insn_vaddr(insn);
            uint32_t data;
            int size = qemu_plugin_insn_data(insn, &data, sizeof(data));
            insn_code ic = insn_code_init(addr, data, size);
            if (insn_code_data.count(ic) == 0) {
                trace_instr_format* insn_template =
                    (trace_instr_format*)aligned_alloc(64,
                                                    sizeof(trace_instr_format));
                memset(insn_template, 0, sizeof(trace_instr_format));
                fill_insn_template(insn_template, addr, data, size);
                insn_code_data[ic] = insn_template;
            }

            if (data == 0x38728040) {
                fprintf(stderr, "ibar begin\n");
                has_ibar_begin = 1;
            }
            if (data == 0x38728041) {
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
    } catch (exception& e) {
        cerr << __func__ << ": " << e.what() << '\n';
    }
}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    try {
        plugin_init(info);

        if (!strcmp(info->target_name, "riscv64")) {
            riscv::target = true;
        } else if (strcmp(info->target_name, "loongarch64")) {
            throw runtime_error("unknown target");
        }

        has_ibar_begin = !plugin_args_get_bool_or_else(argc, argv, "check_ibar", false);
        qemu_plugin_register_vcpu_init_cb(id, init);
        qemu_plugin_register_vcpu_exit_cb(id, exit);
        qemu_plugin_register_vcpu_tb_trans_cb(id, tb_record);
        qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
        return 0;
    } catch (exception& e) {
        cerr << __func__ << ": " << e.what() << '\n';
        return 1;
    }
}
