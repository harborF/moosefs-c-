include ../Make.rules
TARGET= mfs_meta_logger
INCLUDE+=-DAPPNAME=mfsmetalogger -I../SvrCore
LIB=-L$(LIBDIR) -lCommUtil -lz

SRCDIRS := . ../SvrCore

SRCEXTS := .cpp
SOURCES := $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/*,$(SRCEXTS))))
OBJS    := $(foreach x,$(SRCEXTS),$(patsubst %$(x),%.o,$(filter %$(x),$(SOURCES))))
OBJECTS := $(addprefix $(TMPDIR), $(notdir $(OBJS)))

all:$(TARGET)
	cp -f $(TARGET) $(BINDIR) 
	
$(TARGET):$(OBJECTS)
	$(CC) $^ $(LIB) -o $@

%.o : ../SvrCore/%.cpp
	$(CC) $(FLAGS) $(INCLUDE) -o $@ -c $<
	
.cpp.o:
	$(CC) $(FLAGS) $(INCLUDE) -o $@ -c $<

clean:
	rm -rf $(TARGET)
	rm -f $(OBJECTS)
	rm -rf $(BINDIR)$(TARGET)
