include ../Make.rules
TARGET= mfs_mount
INCLUDE+=-DAPPNAME=mfsmount -DFUSE_USE_VERSION=26 -D_FILE_OFFSET_BITS=64 -D_USE_PTHREADS $(FUSE_INCLUDE)
LIB=-L$(LIBDIR) -lCommUtil -lz $(FUSE_LIB)
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
