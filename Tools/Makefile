include ../Make.rules
TARGET= mfs_tools
LIB=-L$(LIBDIR) -lCommUtil -lz
OBJS=$(patsubst %.cpp,%.o,$(wildcard  *.cpp))

all:$(TARGET)
	cp -f $(TARGET) $(BINDIR) 
	
$(TARGET):$(OBJS)
	$(CC) $^ $(LIB) -o $@

.cpp.o:
	$(CC) $(FLAGS) $(INCLUDE) -o $@ -c $<

clean:
	rm -rf $(TARGET)
	rm -f $(OBJS)
	rm -rf $(BINDIR)$(TARGET)
