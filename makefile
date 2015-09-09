#File start

#Project directory
PROJECT_DIR := .
SRC_DIR := $(PROJECT_DIR)/src
LIB_DIR := $(PROJECT_DIR)/lib
OBJ_DIR := $(PROJECT_DIR)/obj
UTIL_DIR := $(PROJECT_DIR)/util

#Compiler paraments
CPPFLAGS := -g -I$(PROJECT_DIR)
LDFLAG := -L$(LIB_DIR)

#Sources and objs
SOURCES := $(wildcard $(SRC_DIR)/*.cc)
SOURCES += $(wildcard $(UTIL_DIR)/*.cc)
OBJS := $(call filter,%_test.cc,$(call patsubst,%.cc,%.o,$(call addprefix,$(OBJ_DIR)/,$(call notdir,$(SOURCES)))))

BIN = ./bin/ccv-add ./bin/ccv-commit ./bin/ccv-checkout ./bin/ccv-init

#Define the final target which will be generate
all: $(BIN) $(OBJS)

#Shell command will be excuted every time
$(shell mkdir -p $(OBJ_DIR))
$(shell mkdir -p ./test)

#Auto generate dependency
$(SRC_DIR)/%.d: $(SRC_DIR)/%.cc 
	@set -e; rm -f $@; \
	$(CXX) -MM $(CPPFLAGS)  $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,$(OBJ_DIR)/\1.o $@ : ,g' < $@.$$$$ > $@; \
	sed '$$a\	$(CXX) -c $< $(CPPFLAGS)/ -o $(OBJ_DIR)/$(call patsubst,%.cc,%.o,$(call notdir,$<))' -i $@; \
	rm -f $@.$$$$

$(UTIL_DIR)/%.d: $(UTIL_DIR)/%.cc 
	@set -e; rm -f $@; \
	$(CXX) -MM $(CPPFLAGS)  $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,$(OBJ_DIR)/\1.o $@ : ,g' < $@.$$$$ > $@; \
	sed '$$a\	$(CXX) -c $< $(CPPFLAGS)/ -o $(OBJ_DIR)/$(call patsubst,%.cc,%.o,$(call notdir,$<))' -i $@; \
	rm -f $@.$$$$


#Include the dependency and command
#Command will not be excuted unless we need them
sinclude $(SOURCES:.cc=.d)

#./src/test:./obj/mempool.o ./obj/md5.o ./obj/test.o
#	$(CXX) -o $@ $(CPPFLAGS) $^
#	rm -f $(SOURCES:.cc=.d)

#./test/file_test: ./obj/file.o ./obj/log.o ./obj/file_test.o
#	$(CXX) -o $@ $(CPPFLAGS) $^
#	rm -f $(SOURCES:.cc=.d)

./bin/ccv-init: ./obj/logcat.o ./obj/file.o ./obj/mempool.o ./obj/md5.o ./obj/transAction.o ./obj/object.o ./obj/repertory.o ./obj/ccv-init.o
	$(CXX) -o $@ $(CPPFLAGS) $^
	rm -f $(SOURCES:.cc=.d)
	
./bin/ccv-commit: ./obj/logcat.o ./obj/file.o ./obj/mempool.o ./obj/md5.o ./obj/transAction.o ./obj/object.o ./obj/repertory.o ./obj/ccv-commit.o
	$(CXX) -o $@ $(CPPFLAGS) $^

./bin/ccv-checkout: ./obj/logcat.o ./obj/file.o ./obj/mempool.o ./obj/md5.o ./obj/transAction.o ./obj/object.o ./obj/repertory.o ./obj/ccv-checkout.o
	$(CXX) -o $@ $(CPPFLAGS) $^

./bin/ccv-add: ./obj/logcat.o ./obj/file.o ./obj/mempool.o ./obj/md5.o ./obj/transAction.o ./obj/object.o ./obj/repertory.o ./obj/ccv-add.o
	$(CXX) -o $@ $(CPPFLAGS) $^


#main:$(OBJS)
#	$(CXX) -o main $(CPPFLAGS) $(OBJS)


.PHONY:clean 
clean:
	rm -r ./test
	rm -r $(OBJ_DIR)

#File end