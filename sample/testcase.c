 #include "eventpack.h"

#include <string.h>
#include <stdlib.h>
#include <assert.h>

void test_alloctor()
{
	//ep_allocator_pool();
}

void test_compress()
{
	char * uncompress = "helloworld";
	unsigned int uncompress_size = 10;
	char * compress;
	unsigned int compress_alloced_size;
	unsigned int compress_size;

	compress = ep_compress(uncompress, uncompress_size, &compress_alloced_size, &compress_size);
	uncompress = ep_decompress(compress, compress_size, uncompress_size);
	ep_free(compress);
}

void test_crypt()
{
	const unsigned char key[16] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x014, 0x015
	};

#define vec_declare \
	unsigned char vec[16] = { \
		0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x014, 0x015, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 \
	}

	const char * buffer = "helloworld";
	int buffer_size = 10;
	int crypt_size;
	unsigned char * crypt;

	{
		vec_declare;
		crypt = ep_crypt_aes((const unsigned char *)buffer, buffer_size, &crypt_size, key, vec, 1);
	}

	{
		unsigned char * dec;
		vec_declare;

		dec = ep_crypt_aes(crypt, crypt_size, &buffer_size, key, vec, 0);
		ep_free(crypt);
		ep_free(dec);
	}
}

void test_rsa()
{
static const char RSA_PRI_KEY[] = {
	0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x42, 0x45, 0x47, 0x49, 0x4E, 0x20, 0x52, 0x53, 0x41, 0x20, 0x50, 
	0x52, 0x49, 0x56, 0x41, 0x54, 0x45, 0x20, 0x4B, 0x45, 0x59, 0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x0A, 
	0x4D, 0x49, 0x49, 0x43, 0x58, 0x51, 0x49, 0x42, 0x41, 0x41, 0x4B, 0x42, 0x67, 0x51, 0x44, 0x55, 
	0x54, 0x77, 0x49, 0x78, 0x69, 0x57, 0x4F, 0x38, 0x6F, 0x43, 0x53, 0x67, 0x2B, 0x64, 0x76, 0x51, 
	0x51, 0x72, 0x5A, 0x44, 0x61, 0x58, 0x39, 0x39, 0x58, 0x35, 0x72, 0x30, 0x6F, 0x43, 0x33, 0x68, 
	0x6A, 0x4E, 0x76, 0x6D, 0x76, 0x62, 0x4B, 0x4C, 0x79, 0x53, 0x52, 0x32, 0x44, 0x30, 0x58, 0x37, 
	0x0A, 0x64, 0x51, 0x54, 0x4E, 0x72, 0x53, 0x68, 0x64, 0x74, 0x62, 0x33, 0x77, 0x79, 0x6C, 0x33, 
	0x4B, 0x4A, 0x50, 0x55, 0x71, 0x62, 0x46, 0x6D, 0x71, 0x75, 0x6D, 0x2B, 0x32, 0x56, 0x54, 0x6B, 
	0x74, 0x4A, 0x6A, 0x34, 0x48, 0x44, 0x50, 0x48, 0x32, 0x74, 0x54, 0x32, 0x68, 0x63, 0x74, 0x71, 
	0x4B, 0x44, 0x6C, 0x68, 0x2B, 0x57, 0x43, 0x48, 0x6B, 0x36, 0x34, 0x76, 0x79, 0x48, 0x74, 0x70, 
	0x77, 0x0A, 0x75, 0x67, 0x41, 0x36, 0x6E, 0x46, 0x78, 0x77, 0x52, 0x59, 0x67, 0x71, 0x78, 0x65, 
	0x72, 0x71, 0x45, 0x67, 0x41, 0x68, 0x4B, 0x66, 0x42, 0x65, 0x58, 0x55, 0x38, 0x58, 0x66, 0x34, 
	0x75, 0x37, 0x32, 0x30, 0x70, 0x4B, 0x5A, 0x42, 0x44, 0x63, 0x61, 0x73, 0x37, 0x2B, 0x36, 0x49, 
	0x5A, 0x45, 0x51, 0x6B, 0x59, 0x43, 0x73, 0x7A, 0x71, 0x79, 0x34, 0x77, 0x49, 0x44, 0x41, 0x51, 
	0x41, 0x42, 0x0A, 0x41, 0x6F, 0x47, 0x42, 0x41, 0x4C, 0x33, 0x35, 0x73, 0x4E, 0x6E, 0x49, 0x75, 
	0x61, 0x46, 0x6F, 0x6E, 0x7A, 0x34, 0x59, 0x4E, 0x68, 0x52, 0x6D, 0x44, 0x5A, 0x66, 0x47, 0x79, 
	0x42, 0x6A, 0x55, 0x75, 0x75, 0x43, 0x59, 0x6B, 0x46, 0x57, 0x61, 0x61, 0x49, 0x39, 0x52, 0x51, 
	0x58, 0x6F, 0x4A, 0x30, 0x34, 0x46, 0x38, 0x36, 0x7A, 0x38, 0x32, 0x46, 0x38, 0x55, 0x2F, 0x59, 
	0x37, 0x5A, 0x75, 0x0A, 0x30, 0x50, 0x61, 0x73, 0x37, 0x6A, 0x33, 0x61, 0x30, 0x6A, 0x4A, 0x53, 
	0x33, 0x2B, 0x32, 0x41, 0x68, 0x45, 0x50, 0x67, 0x67, 0x4A, 0x67, 0x67, 0x39, 0x7A, 0x42, 0x4F, 
	0x33, 0x57, 0x34, 0x5A, 0x2B, 0x4D, 0x58, 0x4E, 0x56, 0x64, 0x33, 0x63, 0x38, 0x2B, 0x78, 0x35, 
	0x63, 0x7A, 0x70, 0x6D, 0x45, 0x51, 0x42, 0x47, 0x73, 0x75, 0x48, 0x36, 0x5A, 0x68, 0x49, 0x5A, 
	0x62, 0x44, 0x48, 0x61, 0x0A, 0x52, 0x6F, 0x71, 0x53, 0x61, 0x61, 0x6B, 0x58, 0x47, 0x38, 0x57, 
	0x71, 0x65, 0x7A, 0x6E, 0x49, 0x51, 0x67, 0x6E, 0x36, 0x65, 0x33, 0x54, 0x49, 0x4E, 0x76, 0x44, 
	0x6F, 0x65, 0x37, 0x34, 0x68, 0x50, 0x4B, 0x52, 0x74, 0x55, 0x63, 0x6A, 0x48, 0x64, 0x65, 0x30, 
	0x6E, 0x75, 0x74, 0x73, 0x70, 0x41, 0x6B, 0x45, 0x41, 0x2F, 0x2F, 0x72, 0x37, 0x4B, 0x48, 0x63, 
	0x44, 0x64, 0x75, 0x70, 0x33, 0x0A, 0x35, 0x30, 0x2B, 0x43, 0x55, 0x48, 0x66, 0x6A, 0x72, 0x70, 
	0x2F, 0x42, 0x39, 0x4D, 0x76, 0x4F, 0x6B, 0x36, 0x51, 0x6C, 0x2F, 0x48, 0x4F, 0x68, 0x4B, 0x75, 
	0x4E, 0x6A, 0x67, 0x4B, 0x36, 0x4C, 0x56, 0x33, 0x46, 0x63, 0x52, 0x30, 0x78, 0x38, 0x36, 0x2F, 
	0x56, 0x59, 0x6D, 0x70, 0x76, 0x70, 0x70, 0x37, 0x2B, 0x54, 0x4F, 0x46, 0x43, 0x48, 0x52, 0x4F, 
	0x6B, 0x48, 0x73, 0x77, 0x79, 0x70, 0x0A, 0x4C, 0x37, 0x6C, 0x65, 0x36, 0x4E, 0x50, 0x4B, 0x31, 
	0x77, 0x4A, 0x42, 0x41, 0x4E, 0x52, 0x54, 0x4B, 0x39, 0x56, 0x30, 0x74, 0x63, 0x30, 0x66, 0x37, 
	0x47, 0x78, 0x53, 0x32, 0x46, 0x76, 0x51, 0x45, 0x6C, 0x37, 0x78, 0x33, 0x4A, 0x58, 0x77, 0x51, 
	0x38, 0x58, 0x70, 0x44, 0x78, 0x51, 0x55, 0x67, 0x45, 0x57, 0x4D, 0x70, 0x2B, 0x65, 0x2F, 0x39, 
	0x44, 0x6F, 0x6D, 0x62, 0x73, 0x57, 0x36, 0x0A, 0x68, 0x64, 0x5A, 0x51, 0x63, 0x32, 0x49, 0x38, 
	0x49, 0x73, 0x56, 0x43, 0x6B, 0x57, 0x76, 0x6B, 0x77, 0x33, 0x64, 0x52, 0x66, 0x63, 0x46, 0x46, 
	0x68, 0x72, 0x42, 0x35, 0x4B, 0x4B, 0x47, 0x55, 0x77, 0x74, 0x55, 0x43, 0x51, 0x48, 0x61, 0x63, 
	0x4E, 0x67, 0x70, 0x75, 0x38, 0x78, 0x55, 0x44, 0x32, 0x65, 0x45, 0x39, 0x62, 0x7A, 0x57, 0x59, 
	0x42, 0x39, 0x44, 0x66, 0x52, 0x38, 0x45, 0x46, 0x0A, 0x4F, 0x73, 0x67, 0x67, 0x6C, 0x46, 0x56, 
	0x67, 0x77, 0x72, 0x6F, 0x62, 0x75, 0x50, 0x78, 0x6B, 0x5A, 0x44, 0x35, 0x31, 0x55, 0x58, 0x76, 
	0x63, 0x44, 0x6A, 0x70, 0x4C, 0x61, 0x65, 0x33, 0x68, 0x39, 0x71, 0x64, 0x36, 0x31, 0x6C, 0x32, 
	0x4F, 0x75, 0x73, 0x38, 0x4D, 0x5A, 0x7A, 0x76, 0x6F, 0x7A, 0x76, 0x42, 0x46, 0x4A, 0x5A, 0x77, 
	0x65, 0x6E, 0x75, 0x73, 0x43, 0x51, 0x45, 0x4F, 0x67, 0x0A, 0x67, 0x68, 0x4F, 0x6F, 0x36, 0x73, 
	0x62, 0x38, 0x35, 0x67, 0x62, 0x53, 0x6C, 0x45, 0x73, 0x61, 0x43, 0x4E, 0x2F, 0x6F, 0x31, 0x55, 
	0x4F, 0x45, 0x6C, 0x58, 0x47, 0x52, 0x2B, 0x39, 0x56, 0x2F, 0x65, 0x69, 0x4F, 0x73, 0x32, 0x30, 
	0x58, 0x37, 0x59, 0x38, 0x53, 0x70, 0x76, 0x52, 0x71, 0x4A, 0x67, 0x46, 0x74, 0x30, 0x6F, 0x47, 
	0x75, 0x6E, 0x6A, 0x38, 0x4F, 0x59, 0x6F, 0x6B, 0x7A, 0x6C, 0x0A, 0x50, 0x6B, 0x54, 0x67, 0x31, 
	0x64, 0x63, 0x62, 0x56, 0x2F, 0x30, 0x5A, 0x65, 0x68, 0x47, 0x4E, 0x47, 0x6B, 0x6B, 0x43, 0x51, 
	0x51, 0x44, 0x64, 0x33, 0x65, 0x43, 0x58, 0x6D, 0x59, 0x65, 0x58, 0x51, 0x59, 0x42, 0x35, 0x53, 
	0x52, 0x31, 0x39, 0x54, 0x50, 0x65, 0x37, 0x36, 0x6E, 0x67, 0x4F, 0x76, 0x62, 0x77, 0x42, 0x78, 
	0x76, 0x6C, 0x62, 0x49, 0x6A, 0x77, 0x49, 0x32, 0x63, 0x66, 0x64, 0x0A, 0x65, 0x47, 0x6A, 0x65, 
	0x57, 0x6A, 0x32, 0x67, 0x67, 0x55, 0x42, 0x75, 0x66, 0x4B, 0x79, 0x6C, 0x32, 0x70, 0x67, 0x4D, 
	0x39, 0x7A, 0x57, 0x43, 0x4E, 0x79, 0x46, 0x36, 0x4F, 0x50, 0x30, 0x6B, 0x38, 0x31, 0x37, 0x66, 
	0x79, 0x78, 0x77, 0x37, 0x50, 0x73, 0x2F, 0x44, 0x0A, 0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x45, 0x4E, 
	0x44, 0x20, 0x52, 0x53, 0x41, 0x20, 0x50, 0x52, 0x49, 0x56, 0x41, 0x54, 0x45, 0x20, 0x4B, 0x45, 
	0x59, 0x2D, 0x2D, 0x2D, 0x2D, 0x2D
};

static const char RSA_PUB_KEY[] = {
	0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x42, 0x45, 0x47, 0x49, 0x4E, 0x20, 0x52, 0x53, 0x41, 0x20, 0x50, 
	0x55, 0x42, 0x4C, 0x49, 0x43, 0x20, 0x4B, 0x45, 0x59, 0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x0D, 0x0A, 
	0x4D, 0x49, 0x47, 0x4A, 0x41, 0x6F, 0x47, 0x42, 0x41, 0x4E, 0x52, 0x50, 0x41, 0x6A, 0x47, 0x4A, 
	0x59, 0x37, 0x79, 0x67, 0x4A, 0x4B, 0x44, 0x35, 0x32, 0x39, 0x42, 0x43, 0x74, 0x6B, 0x4E, 0x70, 
	0x66, 0x33, 0x31, 0x66, 0x6D, 0x76, 0x53, 0x67, 0x4C, 0x65, 0x47, 0x4D, 0x32, 0x2B, 0x61, 0x39, 
	0x73, 0x6F, 0x76, 0x4A, 0x4A, 0x48, 0x59, 0x50, 0x52, 0x66, 0x74, 0x31, 0x42, 0x4D, 0x32, 0x74, 
	0x0D, 0x0A, 0x4B, 0x46, 0x32, 0x31, 0x76, 0x66, 0x44, 0x4B, 0x58, 0x63, 0x6F, 0x6B, 0x39, 0x53, 
	0x70, 0x73, 0x57, 0x61, 0x71, 0x36, 0x62, 0x37, 0x5A, 0x56, 0x4F, 0x53, 0x30, 0x6D, 0x50, 0x67, 
	0x63, 0x4D, 0x38, 0x66, 0x61, 0x31, 0x50, 0x61, 0x46, 0x79, 0x32, 0x6F, 0x6F, 0x4F, 0x57, 0x48, 
	0x35, 0x59, 0x49, 0x65, 0x54, 0x72, 0x69, 0x2F, 0x49, 0x65, 0x32, 0x6E, 0x43, 0x36, 0x41, 0x44, 
	0x71, 0x63, 0x0D, 0x0A, 0x58, 0x48, 0x42, 0x46, 0x69, 0x43, 0x72, 0x46, 0x36, 0x75, 0x6F, 0x53, 
	0x41, 0x43, 0x45, 0x70, 0x38, 0x46, 0x35, 0x64, 0x54, 0x78, 0x64, 0x2F, 0x69, 0x37, 0x76, 0x62, 
	0x53, 0x6B, 0x70, 0x6B, 0x45, 0x4E, 0x78, 0x71, 0x7A, 0x76, 0x37, 0x6F, 0x68, 0x6B, 0x52, 0x43, 
	0x52, 0x67, 0x4B, 0x7A, 0x4F, 0x72, 0x4C, 0x6A, 0x41, 0x67, 0x4D, 0x42, 0x41, 0x41, 0x45, 0x3D, 
	0x0D, 0x0A, 0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x45, 0x4E, 0x44, 0x20, 0x52, 0x53, 0x41, 0x20, 0x50, 
	0x55, 0x42, 0x4C, 0x49, 0x43, 0x20, 0x4B, 0x45, 0x59, 0x2D, 0x2D, 0x2D, 0x2D, 0x2D
};

    
    char * ptr;
	int ptr_size;
    char * ptr2;
    int ptr_size2;
	int r;
    
    char buffer[] = "hello world";
    int size = 11;
    
	assert(buffer != NULL);
	r = ep_crypt_rsa(RSA_PUB_KEY, sizeof(RSA_PUB_KEY), buffer, size, &ptr, &ptr_size, 1);
	assert(r == 1);
	r = ep_crypt_rsa(RSA_PRI_KEY, sizeof(RSA_PRI_KEY), ptr, ptr_size, &ptr2, &ptr_size2, 0);
	assert(r == 1);
    ep_free(ptr);
    ep_free(ptr2);
}

void test_packet()
{
	ep_pack_t * pack;

	pack = ep_pack_new();
	ep_pack_append_string(pack, "hello", "world");
	ep_pack_append_start_array(pack, "student");
	ep_pack_append_string(pack, "name", "zhang3");
	ep_pack_append_int(pack, "age", 19);
	ep_pack_append_start_array(pack, "phone");
	ep_pack_append_string(pack, "type", "mobile");
	ep_pack_append_int(pack, "number", 1000);
	ep_pack_append_finish_array(pack);
	ep_pack_append_start_array(pack, "school");
	ep_pack_append_string(pack, "type", "local");
	ep_pack_append_int(pack, "number", 1001);
	ep_pack_append_finish_array(pack);
	ep_pack_append_string(pack, "comment", "he is at home");
	ep_pack_append_finish_array(pack);
	ep_pack_finish(pack);
	
	ep_pack_print(pack);
	ep_pack_destroy(&pack);
}

void test_queue()
{
	ep_queue_t * queue;
	char * buffer;

	queue = ep_queue_new();
	ep_queue_push(queue, (void *)strdup("helloworld"));
	ep_queue_get(queue, (void **)&buffer, 0);
	free(buffer);

	ep_queue_push(queue, (void *)strdup("helloworld2"));
	ep_queue_stop(queue);
	ep_queue_get(queue, (void **)&buffer, 0);
	free(buffer);

	ep_queue_destroy(&queue);
}

void test_ringbuffer()
{
	ep_rb_t * rb;

	char * data;
	int capacity;
	int can_read;
	int can_write;
	int read;
	int write;

	rb = ep_rb_new(5, 15);
	write = ep_rb_write(rb, "hello", 5);
	assert(write == 5);
	capacity = ep_rb_capacity(rb);
	assert(capacity = 5);
	can_read = ep_rb_can_read(rb);
	assert(can_read = 5);
	can_write = ep_rb_can_write(rb);
	assert(can_write == 10);

	write = ep_rb_write(rb, "world", 5);
	assert(write == 5);
	capacity = ep_rb_capacity(rb);
	assert(capacity = 15);
	can_read = ep_rb_can_read(rb);
	assert(can_read = 10);
	can_write = ep_rb_can_write(rb);
	assert(can_write == 5);

	read = ep_rb_read(rb, &data, 5);
	data = NULL;
	read = ep_rb_read(rb, &data, 5);
	data = NULL;
	read = ep_rb_read(rb, &data, 5);
	assert(read == 0);

	ep_rb_free(&rb);
}

void test_threadpool()
{
#ifdef TEST_EP_THREADPOOL_H
#include <windows.h>
#include <stdio.h>
#include <vld.h>

#include "ep_threadpool.h"

	void * process_cb(void * opaque)
	{
		int taskid;
		taskid = (int)opaque;
		printf("taskid = %d.\n", taskid);
		Sleep(2000);

		return NULL;
	}

	void complete_cb(ep_tp_worker_t * worker, void * result, void * opaque)
	{
	}

	int main()
	{
		ep_tp_t * pool;

		pool = ep_tp_create(5);

		{
			ep_tp_process_cb pcb;
			ep_tp_complete_cb ccb;
			void * opaque;
			int tasks;

			pcb = process_cb;
			ccb = complete_cb;

			for (tasks = 0; tasks < 19; tasks++)
			{
				ep_tp_worker_t * worker;
				ep_tp_state state;
				void * result;

				opaque = (void *)tasks;
				worker = ep_tp_worker_register(pool, pcb, ccb, opaque);
				state = ep_tp_worker_touch(worker);

				result = NULL;
				//result = ep_tp_worker_wait(worker);
			}

			ep_tp_destroy(&pool, tp_kill_wait);
			printf("destroy ok.\n");
		}
	}
#endif

}

void do_testcase()
{
	test_alloctor();
	test_compress();
    test_rsa();
	test_crypt();
	test_packet();
	test_queue();
	test_ringbuffer();
}
