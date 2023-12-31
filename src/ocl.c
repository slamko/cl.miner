#include "ocl.h"
#include <CL/cl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <endian.h>
#include <arpa/inet.h>
#include <math.h>
#include "miner.h"

cl_device_id device;
cl_program prog;
cl_command_queue queue;
cl_context context;
cl_program program;

const char *getErrorString(cl_int error)
{
    switch(error){
    // run-time and JIT compiler errors
    case 0: return "CL_SUCCESS";
    case -1: return "CL_DEVICE_NOT_FOUND";
    case -2: return "CL_DEVICE_NOT_AVAILABLE";
    case -3: return "CL_COMPILER_NOT_AVAILABLE";
    case -4: return "CL_MEM_OBJECT_ALLOCATION_FAILURE";
    case -5: return "CL_OUT_OF_RESOURCES";
    case -6: return "CL_OUT_OF_HOST_MEMORY";
    case -7: return "CL_PROFILING_INFO_NOT_AVAILABLE";
    case -8: return "CL_MEM_COPY_OVERLAP";
    case -9: return "CL_IMAGE_FORMAT_MISMATCH";
    case -10: return "CL_IMAGE_FORMAT_NOT_SUPPORTED";
    case -11: return "CL_BUILD_PROGRAM_FAILURE";
    case -12: return "CL_MAP_FAILURE";
    case -13: return "CL_MISALIGNED_SUB_BUFFER_OFFSET";
    case -14: return "CL_EXEC_STATUS_ERROR_FOR_EVENTS_IN_WAIT_LIST";
    case -15: return "CL_COMPILE_PROGRAM_FAILURE";
    case -16: return "CL_LINKER_NOT_AVAILABLE";
    case -17: return "CL_LINK_PROGRAM_FAILURE";
    case -18: return "CL_DEVICE_PARTITION_FAILED";
    case -19: return "CL_KERNEL_ARG_INFO_NOT_AVAILABLE";

    // compile-time errors
    case -30: return "CL_INVALID_VALUE";
    case -31: return "CL_INVALID_DEVICE_TYPE";
    case -32: return "CL_INVALID_PLATFORM";
    case -33: return "CL_INVALID_DEVICE";
    case -34: return "CL_INVALID_CONTEXT";
    case -35: return "CL_INVALID_QUEUE_PROPERTIES";
    case -36: return "CL_INVALID_COMMAND_QUEUE";
    case -37: return "CL_INVALID_HOST_PTR";
    case -38: return "CL_INVALID_MEM_OBJECT";
    case -39: return "CL_INVALID_IMAGE_FORMAT_DESCRIPTOR";
    case -40: return "CL_INVALID_IMAGE_SIZE";
    case -41: return "CL_INVALID_SAMPLER";
    case -42: return "CL_INVALID_BINARY";
    case -43: return "CL_INVALID_BUILD_OPTIONS";
    case -44: return "CL_INVALID_PROGRAM";
    case -45: return "CL_INVALID_PROGRAM_EXECUTABLE";
    case -46: return "CL_INVALID_KERNEL_NAME";
    case -47: return "CL_INVALID_KERNEL_DEFINITION";
    case -48: return "CL_INVALID_KERNEL";
    case -49: return "CL_INVALID_ARG_INDEX";
    case -50: return "CL_INVALID_ARG_VALUE";
    case -51: return "CL_INVALID_ARG_SIZE";
    case -52: return "CL_INVALID_KERNEL_ARGS";
    case -53: return "CL_INVALID_WORK_DIMENSION";
    case -54: return "CL_INVALID_WORK_GROUP_SIZE";
    case -55: return "CL_INVALID_WORK_ITEM_SIZE";
    case -56: return "CL_INVALID_GLOBAL_OFFSET";
    case -57: return "CL_INVALID_EVENT_WAIT_LIST";
    case -58: return "CL_INVALID_EVENT";
    case -59: return "CL_INVALID_OPERATION";
    case -60: return "CL_INVALID_GL_OBJECT";
    case -61: return "CL_INVALID_BUFFER_SIZE";
    case -62: return "CL_INVALID_MIP_LEVEL";
    case -63: return "CL_INVALID_GLOBAL_WORK_SIZE";
    case -64: return "CL_INVALID_PROPERTY";
    case -65: return "CL_INVALID_IMAGE_DESCRIPTOR";
    case -66: return "CL_INVALID_COMPILER_OPTIONS";
    case -67: return "CL_INVALID_LINKER_OPTIONS";
    case -68: return "CL_INVALID_DEVICE_PARTITION_COUNT";

    // extension errors
    case -1000: return "CL_INVALID_GL_SHAREGROUP_REFERENCE_KHR";
    case -1001: return "CL_PLATFORM_NOT_FOUND_KHR";
    case -1002: return "CL_INVALID_D3D10_DEVICE_KHR";
    case -1003: return "CL_INVALID_D3D10_RESOURCE_KHR";
    case -1004: return "CL_D3D10_RESOURCE_ALREADY_ACQUIRED_KHR";
    case -1005: return "CL_D3D10_RESOURCE_NOT_ACQUIRED_KHR";
    default: return "Unknown OpenCL error";
    }
}

int ocl_init(void) {
    cl_int ret = {0};

    cl_platform_id platform;
    cl_uint ret_num;

    clGetPlatformIDs(1, &platform, &ret_num);

    if (ret_num == 0) {
        err("No supported platfroms\n");
        return 1;
    }

    clGetDeviceIDs(platform, CL_DEVICE_TYPE_ALL, 1, &device, &ret_num);

    if (!ret_num) {
        err("No supported devices\n");
        return 1;
    }

    context = clCreateContext(NULL, 1, &device, NULL, NULL, &ret);
    if (ret) {
        error("Context creation failed: %s\n", getErrorString(ret));
        return 1;
    }

    cl_queue_properties props[] = { CL_QUEUE_PROFILING_ENABLE };
    queue = clCreateCommandQueueWithProperties(context, device, props, &ret);
    if (ret) {
        error("Command queue creation failed: %s\n", getErrorString(ret));
        ret_code(1);
    }

    FILE *srcf = fopen("src/miner.cl", "r");
    if (!srcf) {
        err("No source file\n");
        ret_code(2);
    }

    fseek(srcf, 0, SEEK_END);
    size_t len = ftell(srcf);
    fseek(srcf, 0, SEEK_SET);

    if (!len) {
        err("CL source is empty\n");
        ret_code(2);
    }

    char *src_str = malloc(len + 1);
    if (!src_str) {
        err("Out of memory\n");
        ret_code(2);
    }
    src_str[len] = '\0';

    fread(src_str, sizeof(*src_str), len, srcf);

    program = clCreateProgramWithSource(context, 1, (const char **)&src_str, &len, &ret);
    if (ret) {
        err("Program creation failed\n");
        ret_code(1);
    }

    if (clBuildProgram(program, 1, &device, NULL, NULL, NULL)) {
        char build_log[0x2000];
        clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, sizeof(build_log), build_log, NULL);
        puts(build_log);
    }

    return 0;

  cleanup:
    if (context)
        clReleaseContext(context);

    if (srcf)
        fclose(srcf);

    if (program)
        clReleaseProgram(program);

    if (queue)
        clReleaseCommandQueue(queue);
   
    return ret;
}

int ocl_merkle_root_hash(transaction_list_t *tx_list, hash_t *merkle_root) {
    if (!tx_list || !merkle_root) {
        return 1;
    }

    cl_kernel kernel = {0};
    cl_int ret = {0};
    hash_t *merkle_tree = NULL;
    size_t merkle_tree_size = tx_list->len * sizeof (*merkle_tree);

    merkle_tree = cmalloc(merkle_tree_size);
    memcpy(merkle_tree, tx_list->txid_list, merkle_tree_size);

    cl_mem tx_list_mem = clCreateBuffer(context, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, merkle_tree_size, merkle_tree, &ret);
    if (ret) {
        error("Failed to allocate OCL buffer: %s\n", getErrorString(ret));
        ret_label(clean_merkle_tree, ret);
    }

    kernel = clCreateKernel(program, "merkle_root_hash", &ret);
    if (ret) {
        error("merkle root: OCL kernel creation failed: %s\n", getErrorString(ret));
        ret_label(clean_tx_mem, 1);
    }

    ret |= clSetKernelArg(kernel, 0, sizeof(cl_mem), &tx_list_mem);
    ret |= clSetKernelArg(kernel, 1, sizeof(cl_mem), &tx_list->len);

    if (ret) {
        error("merkle root: Invalid kernel args: %s\n", getErrorString(ret));
        ret_code(1);
    }

    const size_t glob_wg[] = { align_down(tx_list->len / 2, 64) };
    const size_t loc_wg[] = { 64 };

    ret = clEnqueueNDRangeKernel(queue, kernel, 1, NULL, glob_wg, loc_wg, 0, NULL, NULL);
    if (ret) {
        error("merkle root: Kernel execution failed: %s\n", getErrorString(ret));
        ret_code(1);
    }

    ret = clEnqueueReadBuffer(queue, tx_list_mem, CL_TRUE, 0u, sizeof (merkle_root->byte_hash), merkle_root->byte_hash, 0, NULL, NULL);
    if (ret) {
        error("Failed to merkle root buffer: %s\n", getErrorString(ret));
        ret_code(1);
    }
  cleanup:
    if (kernel) clReleaseKernel(kernel);
 clean_tx_mem:
    clReleaseMemObject(tx_list_mem);
  clean_merkle_tree:
    free(merkle_tree);

    return ret;
}

int mine(struct block_header *block, hash_t *target, hash_t *hash) {
    if (!block || !target || !hash) {
        return 1;
    }

    cl_kernel kernel = {0};
    uint8_t block_input[128] = {0};

    print_buf("Merkle:", block->merkle_root_hash, 32);

    block_pack(block, block_input);
    block_input[BLOCK_RAW_LEN] = 0x80;
   
    uint32_t big_len = htonl((uint32_t)BLOCK_RAW_LEN << 3);
    memcpy(block_input + sizeof(block_input) - sizeof(big_len), &big_len, sizeof(big_len));

    /* print_buf("\n Mine Input", block_input, sizeof block_input); */

    cl_int ret = {0};

    cl_mem inp_mem = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof block_input, block_input, &ret);
    if (ret) {
        error("Failed to allocate OCL buffer: %s\n", getErrorString(ret));
        return (1);
    }

    cl_mem target_mem = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof target->uint_hash, target->uint_hash, &ret);
    if (ret) {
        error("Failed to allocate OCL buffer: %s\n", getErrorString(ret));
        ret_label(clean_inp_mem, 1);
    }

    uint32_t nonce = 0;
    cl_mem nonce_mem = clCreateBuffer(context, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, sizeof (cl_ulong), &nonce, &ret);
    if (ret) {
        error("Failed to allocate OCL buffer: %s\n", getErrorString(ret));
        ret_label(clean_target_mem, 1);
    }

    kernel = clCreateKernel(program, "mine256", &ret);
    if (ret) {
        error("OCL kernel creation failed: %s\n", getErrorString(ret));
        ret_label(clean_nonce_mem, 1);
    }

    ret |= clSetKernelArg(kernel, 0, sizeof(cl_mem), &inp_mem);
    ret |= clSetKernelArg(kernel, 1, sizeof(cl_mem), &target_mem);
    ret |= clSetKernelArg(kernel, 2, sizeof(cl_mem), &nonce_mem);

    if (ret) {
        error("Invalid kernel args: %s\n", getErrorString(ret));
        ret_code(1);
    }

    const size_t glob_wg[] = { align_down(UINT32_MAX, 1024) };
    const size_t loc_wg[] = { 1024 };

    ret = clEnqueueNDRangeKernel(queue, kernel, 1, NULL, glob_wg, loc_wg, 0, NULL, NULL);
    if (ret) {
        error("Kernel execution failed: %s\n", getErrorString(ret));
        ret_code(1);
    }

    ret = clEnqueueReadBuffer(queue, nonce_mem, CL_TRUE, 0u, sizeof (cl_ulong), &nonce, 0, NULL, NULL);
    if (ret) {
        error("Failed to read nonce buffer: %s\n", getErrorString(ret));
        ret_code(1);
    }

    block->nonce = nonce;
        printf("Nonce: %d\n", block->nonce);

  cleanup:
    if (kernel) clReleaseKernel(kernel);
  clean_nonce_mem:
    clReleaseMemObject(nonce_mem);
  clean_target_mem:
    clReleaseMemObject(target_mem);
  clean_inp_mem:
    clReleaseMemObject(inp_mem);

    return ret;
}

int sha256(const uint8_t *data, uint8_t *out, size_t len) {
    if (!len) {
        return 1;
    }

    size_t al_inp_size = align((len + 8), 64);
    uint8_t *input = calloc(al_inp_size, sizeof *input);
    memcpy(input, data, len);
    input[len] = 0x80;
   
    uint32_t big_len = htonl((uint32_t)len << 3);
    memcpy((char *)(input + al_inp_size - sizeof(big_len)), &big_len, sizeof(big_len));

    /* print_buf("\nSha256 Input", input, al_inp_size); */

    cl_int ret = {0};

    cl_mem inp_mem = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, al_inp_size, input, &ret);
    if (ret) ret_code(ret);

    cl_mem out_mem = clCreateBuffer(context, CL_MEM_WRITE_ONLY, STR_HASH_LEN, NULL, &ret);
    if (ret) ret_code(ret);

    cl_kernel kernel = clCreateKernel(program, "kern_sha256", &ret);
    if (ret) ret_code(ret);

    ret |= clSetKernelArg(kernel, 0, sizeof(cl_mem), &inp_mem);
    ret |= clSetKernelArg(kernel, 1, sizeof(cl_ulong), &al_inp_size);
    ret |= clSetKernelArg(kernel, 2, sizeof(cl_mem), &out_mem);
    if (ret) ret_code(ret);

    /* const size_t glob_wg[] = { (UINT32_MAX / 1024) * 1024 }; */
    /* const size_t loc_wg[] = { 1024 }; */
    const size_t glob_wg[] = { 1 };
    const size_t loc_wg[] = { 1 };
    ret = clEnqueueNDRangeKernel(queue, kernel, 1, NULL, glob_wg, loc_wg, 0, NULL, NULL);
    if (ret) ret_code(ret);

    ret = clEnqueueReadBuffer(queue, out_mem, CL_TRUE, 0u, STR_HASH_LEN, out, 0, NULL, NULL);
    if (ret) ret_code(ret);

    print_buf("Sha256", out, STR_HASH_LEN);

  cleanup:
    free(input);
    clReleaseKernel(kernel);

    return ret;
}

int double_sha256(uint8_t *input, uint8_t *out, size_t len) {
    int ret = 0;
    uint8_t first_out[32];

    ret = sha256(input, first_out, len);
    if (ret) {
        return ret;
    }

    ret = sha256(first_out, out, sizeof first_out);

    return ret;
}

void ocl_version(void) {
    char driver_version[64];

    if (clGetDeviceInfo(device, CL_DEVICE_OPENCL_C_VERSION, sizeof driver_version, &driver_version, NULL)) {
        err("Error getting version information\n");
        return;
    }
    
    printf("Version: %s\n", driver_version);
}

int ocl_free(void) {
    cl_int ret = {0};

    ret = clReleaseContext(context);
    /* if (ret) return ret; */
    ret = clReleaseProgram(program);
    /* if (ret) return ret; */
    ret = clReleaseCommandQueue(queue);

    return ret;
}
