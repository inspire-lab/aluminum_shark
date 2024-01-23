#include <iostream>

#include "tensorflow/c/experimental/next_pluggable_device/c_api.h"
#include "tensorflow/c/experimental/stream_executor/stream_executor.h"

constexpr const char* DEVICE_NAME =
    "SHARK";  // It is device's type, such as GPU, APU, which
              // is visible in the python front-end.
constexpr const char* DEVICE_TYPE =
    "HE";  // it is SE platform's name, such as CUDA,
           // ROCM. Sets struct_size to a valid value,
           // and zero initializes other attributes.

//----------------- boilerplate code -----------------

// platform functions used in SE_PlatformRegistrationParams->platform_fns

// Callbacks for getting device count
void plugin_get_device_count(const SP_Platform* platform, int* device_count,
                             TF_Status* status) {
  *device_count = 1;
}
// Callbacks for creating/destroying SP_Device.
void plugin_create_device(const SP_Platform* platform,
                          SE_CreateDeviceParams* params, TF_Status* status) {
  // todo: parse params
}

// Clean up fields inside SP_Device that were allocated
// by the plugin. `device` itself should not be deleted here.
void plugin_destroy_device(const SP_Platform* platform, SP_Device* device) {
  // nothing todo atm
}

// Callbacks for creating/destroying SP_DeviceFns.
void plugin_create_device_fns(const SP_Platform* platform,
                              SE_CreateDeviceFnsParams* params,
                              TF_Status* status) {
  // todo: don't know what to do here yet
}

// Clean up fields inside SP_DeviceFns that were allocated
// by the plugin. `device_fns` itself should not be deleted here.
void plugin_destroy_device_fns(const SP_Platform* platform,
                               SP_DeviceFns* device_fns) {
  // todo: don't know what to do here yet
}

// Callbacks for creating/destroying SP_StreamExecutor.
void plugin_create_stream_executor(const SP_Platform* platform,
                                   SE_CreateStreamExecutorParams* params,
                                   TF_Status* status) {
  std::cout << "creating stream executor" << std::endl;
  SP_StreamExecutor* se = params->stream_executor;
  se->struct_size = SP_STREAMEXECUTOR_STRUCT_SIZE;

  // these are all lambas for now and do mostly nothing

  se->allocate = [](const SP_Device* device, uint64_t size,
                    int64_t memory_space, SP_DeviceMemoryBase* mem) {};

  se->deallocate = [](const SP_Device* device, SP_DeviceMemoryBase* mem) {};

  se->host_memory_allocate = [](const SP_Device* device,
                                uint64_t size) -> void* { return nullptr; };

  se->host_memory_deallocate = [](const SP_Device* device, void* mem) {};

  se->unified_memory_allocate = [](const SP_Device* device,
                                   uint64_t size) -> void* { return nullptr; };

  se->unified_memory_deallocate = [](const SP_Device* device, void* mem) {};

  se->get_allocator_stats = [](const SP_Device* device,
                               SP_AllocatorStats* stats) -> TF_Bool {
    return 0;
  };

  se->device_memory_usage = [](const SP_Device* device, int64_t* free,
                               int64_t* total) -> TF_Bool {
    // totally made up numbers
    *free = 2 >> 15;
    *total = 2 >> 16;
    return true;
  };

  se->create_stream = [](const SP_Device* device, SP_Stream* stream,
                         TF_Status* status) {
    // todo: Creates SP_Stream. This call should also allocate stream
    // resources on the underlying platform and initializes its
    // internals.
  };

  se->destroy_stream = [](const SP_Device* device, SP_Stream stream) {};

  se->create_stream_dependency = [](const SP_Device* device,
                                    SP_Stream dependent, SP_Stream other,
                                    TF_Status* status) {};

  se->get_stream_status = [](const SP_Device* device, SP_Stream stream,
                             TF_Status* status) {};

  se->create_event = [](const SP_Device* device, SP_Event* event,
                        TF_Status* status) {};

  se->destroy_event = [](const SP_Device* device, SP_Event event) {};

  se->get_event_status = [](const SP_Device* device, SP_Event event) {
    return SE_EVENT_UNKNOWN;
  };

  se->record_event = [](const SP_Device* device, SP_Stream stream,
                        SP_Event event, TF_Status* const status) {};

  se->wait_for_event = [](const SP_Device* const device, SP_Stream stream,
                          SP_Event event, TF_Status* const status) {};

  se->create_timer = [](const SP_Device* device, SP_Timer* timer,
                        TF_Status* status) {};

  se->destroy_timer = [](const SP_Device* device, SP_Timer timer) {};

  se->start_timer = [](const SP_Device* device, SP_Stream stream,
                       SP_Timer timer, TF_Status* status) {};

  se->stop_timer = [](const SP_Device* device, SP_Stream stream, SP_Timer timer,
                      TF_Status* status) {};

  se->memcpy_dtoh = [](const SP_Device* device, SP_Stream stream,
                       void* host_dst, const SP_DeviceMemoryBase* device_src,
                       uint64_t size, TF_Status* status) {};

  se->memcpy_htod = [](const SP_Device* device, SP_Stream stream,
                       SP_DeviceMemoryBase* device_dst, const void* host_src,
                       uint64_t size, TF_Status* status) {};

  se->memcpy_dtod = [](const SP_Device* device, SP_Stream stream,
                       SP_DeviceMemoryBase* device_dst,
                       const SP_DeviceMemoryBase* device_src, uint64_t size,
                       TF_Status* status) {};

  se->sync_memcpy_dtoh = [](const SP_Device* device, void* host_dst,
                            const SP_DeviceMemoryBase* device_src,
                            uint64_t size, TF_Status* status) {};

  se->sync_memcpy_htod =
      [](const SP_Device* device, SP_DeviceMemoryBase* device_dst,
         const void* host_src, uint64_t size, TF_Status* status) {};

  se->sync_memcpy_dtod = [](const SP_Device* device,
                            SP_DeviceMemoryBase* device_dst,
                            const SP_DeviceMemoryBase* device_src,
                            uint64_t size, TF_Status* status) {};

  se->block_host_for_event = [](const SP_Device* device, SP_Event event,
                                TF_Status* status) {};

  se->block_host_until_done = [](const SP_Device* device, SP_Stream stream,
                                 TF_Status* status) {};

  se->synchronize_all_activity = [](const SP_Device* device,
                                    TF_Status* status) {};

  se->mem_zero = [](const SP_Device* device, SP_Stream stream,
                    SP_DeviceMemoryBase* location, uint64_t size,
                    TF_Status* status) {};

  se->memset = [](const SP_Device* device, SP_Stream stream,
                  SP_DeviceMemoryBase* location, uint8_t pattern, uint64_t size,
                  TF_Status* status) {};

  se->memset32 = [](const SP_Device* device, SP_Stream stream,
                    SP_DeviceMemoryBase* location, uint32_t pattern,
                    uint64_t size, TF_Status* status) {};

  se->host_callback = [](const SP_Device* device, SP_Stream stream,
                         SE_StatusCallbackFn callback_fn,
                         void* callback_arg) -> unsigned char { return 0; };
}

// Clean up fields inside SP_StreamExecutor that were allocated
// by the plugin. `stream_executor` itself should not be deleted here.
void plugin_destroy_stream_executor(const SP_Platform* platform,
                                    SP_StreamExecutor* stream_executor) {
  // todo: delte stream executor
}

// Callbacks for creating/destroying SP_TimerFns.
void plugin_create_timer_fns(const SP_Platform* platform, SP_TimerFns* timer,
                             TF_Status* status) {
  // todo: create timer
}

void plugin_destroy_timer_fns(const SP_Platform* platform,
                              SP_TimerFns* timer_fns) {
  // todo: delete timer
}

// Clean up fields inside SP_Platform that were allocated
// by the plugin. `platform` itself should not be deleted here.
void plugin_destroy_platform(SP_Platform* platform) {
  // todo: delete platform
}

void plugin_destroy_platform_fns(SP_PlatformFns* platform_fns) {
  // todo: delete platform fns
}

//----------------- TF entry point for the stream executor -----------------

void SE_InitPlugin(SE_PlatformRegistrationParams* params, TF_Status* status) {
  std::cout << "initialzing plugin\n  type: " << DEVICE_TYPE
            << "\n  name: " << DEVICE_NAME
            << "\n  TF pluggable API version: " << params->major_version << "."
            << params->minor_version << "." << params->patch_version
            << std::endl;

  params->platform->struct_size = SP_PLATFORM_STRUCT_SIZE;
  params->platform->type = DEVICE_TYPE;
  params->platform->name = DEVICE_NAME;

  params->platform_fns->struct_size = SP_PLATFORM_FNS_STRUCT_SIZE;
  params->platform_fns->get_device_count = plugin_get_device_count;
  params->platform_fns->create_device = plugin_create_device;
  params->platform_fns->destroy_device = plugin_destroy_device;
  params->platform_fns->create_device_fns = plugin_create_device_fns;
  params->platform_fns->destroy_device_fns = plugin_destroy_device_fns;
  params->platform_fns->create_stream_executor = plugin_create_stream_executor;
  params->platform_fns->destroy_stream_executor =
      plugin_destroy_stream_executor;
  params->platform_fns->create_timer_fns = plugin_create_timer_fns;
  params->platform_fns->destroy_timer_fns = plugin_destroy_timer_fns;
  params->destroy_platform = plugin_destroy_platform;
  params->destroy_platform_fns = plugin_destroy_platform_fns;
}

// static initalizer code. only used for logging at this point
const bool init = []() {
  std::cout << "loading plugin\n  type: " << DEVICE_TYPE
            << "\n  name: " << DEVICE_NAME << std::endl;
  return true;
}();