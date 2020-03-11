include ../Make.rules
TARGET= libCommUtil.a

SRCDIRS := .

SRCEXTS := .cpp
SOURCES := $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/*,$(SRCEXTS))))
OBJS    := $(foreach x,$(SRCEXTS),$(patsubst %$(x),%.o,$(filter %$(x),$(SOURCES))))
OBJECTS := $(addprefix $(TMPDIR), $(notdir $(OBJS)))

all:$(TARGET)
	cp -f $(TARGET) $(LIBDIR) 

$(TARGET):$(OBJECTS)
	$(AR) r $(TARGET) $(OBJECTS)
	$(RANLIB) $(TARGET)
		
%.o : %.cpp
	$(CC) $(FLAGS) $(INCLUDE) -o $@ -c $<

clean:
	rm -rf $(TARGET)
	rm -f $(OBJECTS)
	rm -rf $(LIBDIR)$(TARGET)

