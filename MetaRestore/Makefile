include ../Make.rules
TARGET= mfs_meta_restore
INCLUDE+=-DAPPNAME=mfsmetarestore -DMETARESTORE -I../Master
LIB=-L$(LIBDIR) -lCommUtil -lz

SRCDIRS := .
SRCEXTS := .cpp
SOURCES := $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/*,$(SRCEXTS))))

SOURCES += ../Master/FileIDMgr.cpp ../Master/FileSysMgr.cpp 
SOURCES += ../Master/ChunkJob.cpp ../Master/ChunkObj.cpp ../Master/ChunkGoal.cpp
SOURCES += ../Master/ChunkMgr.cpp ../Master/FileSysOpr.cpp ../Master/mfsFactory.cpp
SOURCES += ../Master/FsEdge.cpp ../Master/FsNode.cpp ../Master/FsQuota.cpp ../Master/FsXAttr.cpp 

OBJS    := $(foreach x,$(SRCEXTS),$(patsubst %$(x),%.o,$(filter %$(x),$(SOURCES))))
OBJECTS := $(addprefix $(TMPDIR), $(notdir $(OBJS)))

all:$(TARGET)
	cp -f $(TARGET) $(BINDIR) 
	
$(TARGET):$(OBJECTS)
	$(CC) $^ $(LIB) -o $@

%.o : ../Master/%.cpp
	$(CC) $(FLAGS) $(INCLUDE) -o $@ -c $<
	
.cpp.o:
	$(CC) $(FLAGS) $(INCLUDE) -o $@ -c $<

clean:
	rm -rf $(TARGET)
	rm -f $(OBJECTS)
	rm -rf $(BINDIR)$(TARGET)
