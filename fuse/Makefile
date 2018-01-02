cdfs_fuse: cdfs_fuse.o
	g++ -o cdfs_fuse cdfs_fuse.o -lfuse -ljson-c -L../lib/ -lns -lshift
cdfs_fuse.o: cdfs_fuse.c
	g++ -D_FILE_OFFSET_BITS=64 -g -c cdfs_fuse.c -I../h/
clean:
	rm *.o cdfs_fuse 
