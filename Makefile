SUBDIRS := CommUtil Master Chunk Mount MetaLogger Restore Tools

all:
	-@mkdir libs
	-@mkdir bin
	
	for dir in $(SUBDIRS); do $(MAKE) -C $${dir}; done

clean:
	for dir in $(SUBDIRS); do $(MAKE) -C $${dir} clean; done

install:
	mkdir -p /usr/local/iuni_mfs/svr
	cp -rf ./bin/* /usr/local/iuni_mfs/svr

