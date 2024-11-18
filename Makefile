QEMU_DIR ?=${HOME}/qemu
GLIB_INC ?=$(shell pkg-config --cflags glib-2.0)
CFLAGS ?= -march=native -g -Wall -march=native -I $(QEMU_DIR)/include/qemu/ $(GLIB_INC) -O2 -MMD -MP
CXXFLAGS ?= -march=native -g -Wall -std=c++14 -march=native -iquote $(QEMU_DIR)/include/qemu/ -I$(CHAMPSIM_DIR)/inc -I$(CHAMPSIM_DIR)/loongarch -I$(CHAMPSIM_DIR)/riscv-unified-db/gen/champsim $(GLIB_INC) -O2 -std=c++17 -MMD -MP
#-I/home/lxy/github/capstone/include/
ifeq ($(wildcard $(QEMU_DIR)),)
    $(error $$QEMU_DIR [$(QEMU_DIR)] not exsited)
endif

BUILD_DIR := ./build
SRC_DIRS := ./

SOURCES := $(wildcard *.cc */*.cc)
OBJS := $(addprefix $(BUILD_DIR)/, $(addprefix lib, $(patsubst %.cc,%.so,$(SOURCES))) libbbv.so)
DEPS := $(OBJS:.so=.d)

$(info $$SOURCES is [${SOURCES}])
$(info $$OBJS is [${OBJS}])
$(info $$DEPS is [${DEPS}])

SUBDIRS := util


NO_CAPSTONE_SOURCES := \
	bt_indirect.cc \
	champsim_la_with_reg.cc \
	icount.cc \
	icount_insn_cb2.cc \
	icount_insn_cb.cc \
	icount_insn_inline.cc \
	insn_perf.cc \
	insn_trace2.cc \
	insn_trace.cc \
	test.cc \
	trace.cc

NO_CAPSTONE_OBJS := $(addprefix $(BUILD_DIR)/, $(addprefix lib, $(patsubst %.cc,%.so,$(NO_CAPSTONE_SOURCES))))

all: $(OBJS) $(SUBDIRS)

no_capstone: $(NO_CAPSTONE_OBJS)

util: $(SUBDIRS)


$(SUBDIRS):
	$(MAKE) -C $@

$(QEMU_DIR):
	@echo "Folder $(QEMU_DIR) does not exist"
	false

$(BUILD_DIR)/lib%.so : %.cc | $(CHAMPSIM_DIR)/riscv-unified-db/gen/champsim/riscv.h
	mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -shared -fPIC -o $@ $< -ldl -lrt -lz

$(BUILD_DIR)/libbbv.so: $(QEMU_DIR)/contrib/plugins/bbv.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $<

$(CHAMPSIM_DIR)/riscv-unified-db/gen/champsim/riscv.h:
	$(MAKE) -C $(CHAMPSIM_DIR) riscv-unified-db/gen/champsim/riscv.h

-include $(DEPS)

clean:
	rm -rf *.o *.so *.d $(BUILD_DIR)
	for dir in $(SUBDIRS); do \
	$(MAKE) -C $$dir -f Makefile $@; \
	done

.PHONY: all $(SUBDIRS) $(CHAMPSIM_DIR)/obj/riscv.h
