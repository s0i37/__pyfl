#include <pin.H>
#include <string>
#include <cstdlib>
#include <iostream>

#define VERSION "0.12"

#ifdef _WIN64
    #define __win__ 1
#elif _WIN32
    #define __win__ 1
#endif

#ifdef __linux__
    #include <sys/shm.h>
    #include <sys/wait.h>
#elif __win__
    namespace windows {
        #include <Windows.h>
    }
#endif

#include "colors.hpp"

// 65536
#define MAP_SIZE    (1 << 16)
#define FORKSRV_FD  198

//  CLI options -----------------------------------------------------------

KNOB<BOOL> Knob_debug(KNOB_MODE_WRITEONCE,  "pintool",
    "debug", "0", "Enable debug mode");

//  Global Vars -----------------------------------------------------------

ADDRINT min_addr = 0;
ADDRINT max_addr = 0;

uint8_t *bitmap_shm = 0;
uint8_t *bitmap_shm_full = 0;
uint8_t *bitmap_shm_signal = 0;

ADDRINT last_id = 0;

//  inlined functions -----------------------------------------------------

inline ADDRINT valid_addr(ADDRINT addr)
{
    if ( addr >= min_addr && addr <= max_addr )
        return true;

    return false;
}

//  Inserted functions ----------------------------------------------------


// Unused currently but could become a fast call in the future once I have tested it more.
VOID TrackBranch(ADDRINT cur_addr)
{
    ADDRINT cur_id = cur_addr - min_addr;

     if (Knob_debug) {
         std::cout << "CURADDR:  " << cur_addr << std::endl;
         //std::cout << "rel_addr: " << (cur_addr - min_addr) << std::endl;
         //std::cout << "cur_id:  " << cur_id << std::endl;
         //std::cout << "index:  " << ((cur_id ^ last_id) % MAP_SIZE) << std::endl;
     }

    //bitmap_shm[((cur_id ^ last_id) % MAP_SIZE)]++;
    bitmap_shm[(cur_id % MAP_SIZE)]++;
    last_id = cur_id;
}

VOID TrackBranchAll(ADDRINT cur_addr)
{
    ADDRINT cur_id = cur_addr;
    bitmap_shm_full[(cur_id % MAP_SIZE)]++;
    last_id = cur_id;
}

//  Analysis functions ----------------------------------------------------

VOID Trace(TRACE trace, VOID *v)
{
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
        {
            // make sure it is in a segment we want to instrument!
            if (valid_addr(INS_Address(ins)))
            {
                if (INS_IsBranch(ins)) {
                    // As per afl-as.c we only care about conditional branches (so no JMP instructions)
                    if (INS_HasFallThrough(ins) || INS_IsCall(ins))
                    {
                        if (Knob_debug) {
                            
                       //     std::cout << "BRACH: 0x" << std::hex << INS_Address(ins) << ":\t" << INS_Disassemble(ins) << std::endl;
                        }

                        // Instrument the code.
                        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)TrackBranch,
                            IARG_INST_PTR,
                            IARG_END);
                    }
                }
            }
            else
            {
                if( INS_IsBranch(ins) )
                {
                    if( INS_HasFallThrough(ins) || INS_IsCall(ins) )
                        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)TrackBranchAll,
                            IARG_INST_PTR,
                            IARG_END);
                }
            }
        }
    }
}

/* not use now */
VOID entry_point(VOID *ptr)
{
    /*  Much like the original instrumentation from AFL we only want to instrument the segments of code
     *  from the actual application and not the link and PIN setup itself.
     *
     *  Inspired by: http://joxeankoret.com/blog/2012/11/04/a-simple-pin-tool-unpacker-for-the-linux-version-of-skype/
     */

    IMG img = APP_ImgHead();
    for(SEC sec= IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {
        // lets sanity check the exec flag 
        // TODO: the check for .text name might be too much, there could be other executable segments we
        //       need to instrument but maybe not things like the .plt or .fini/init
        // IF this changes, we need to change the code in the instrumentation code, save all the base addresses.

        if (SEC_IsExecutable(sec) && SEC_Name(sec) == ".text")
        {
            ADDRINT sec_addr = SEC_Address(sec);
            UINT64  sec_size = SEC_Size(sec);
            
            if (Knob_debug)
            {
                std::cout << "Name: " << SEC_Name(sec) << std::endl;
                std::cout << "Addr: 0x" << std::hex << sec_addr << std::endl;
                std::cout << "Size: " << sec_size << std::endl << std::endl;
            }

            if (sec_addr != 0)
            {
                ADDRINT high_addr = sec_addr + sec_size;

                if (sec_addr > min_addr || min_addr == 0)
                    min_addr = sec_addr;

                // Now check and set the max_addr.
                if (sec_addr > max_addr || max_addr == 0)
                    max_addr = sec_addr;

                if (high_addr > max_addr)
                    max_addr = high_addr;
            }
        }
    }
    if (Knob_debug)
    {
        std::cout << "min_addr:\t0x" << std::hex << min_addr << std::endl;
        std::cout << "max_addr:\t0x" << std::hex << max_addr << std::endl << std::endl;
    }
}

// Main functions ------------------------------------------------

INT32 Usage()
{
    std::cerr << "AFLPIN -- A pin tool to enable blackbox binaries to be fuzzed with AFL on Linux" << std::endl;
    std::cerr << "   -debug --  prints extra debug information." << std::endl;
    return -1;
}

#ifdef __win__
namespace windows {
    bool setup_shm()
    {
        HANDLE map_file;
        map_file = CreateFileMapping(
                    INVALID_HANDLE_VALUE,    // use paging file
                    NULL,                    // default security
                    PAGE_READWRITE,          // read/write access
                    0,                       // maximum object size (high-order DWORD)
                    MAP_SIZE,                // maximum object size (low-order DWORD)
                    (char *)"afl_shm_default");

        bitmap_shm = (unsigned char *) MapViewOfFile(map_file, // handle to map object
                FILE_MAP_ALL_ACCESS,  // read/write permission
                0,
                0,
                MAP_SIZE);
        memset(bitmap_shm, '\x00', MAP_SIZE);

        map_file = CreateFileMapping(
                    INVALID_HANDLE_VALUE,    // use paging file
                    NULL,                    // default security
                    PAGE_READWRITE,          // read/write access
                    0,                       // maximum object size (high-order DWORD)
                    MAP_SIZE,                // maximum object size (low-order DWORD)
                    (char *)"afl_shm_full_default");

        bitmap_shm_full = (unsigned char *) MapViewOfFile(map_file, // handle to map object
                FILE_MAP_ALL_ACCESS,  // read/write permission
                0,
                0,
                MAP_SIZE);
        memset(bitmap_shm_full, '\x00', MAP_SIZE);

        map_file = CreateFileMapping(
                    INVALID_HANDLE_VALUE,    // use paging file
                    NULL,                    // default security
                    PAGE_READWRITE,          // read/write access
                    0,                       // maximum object size (high-order DWORD)
                    10,                // maximum object size (low-order DWORD)
                    (char *)"afl_shm_signal_default");

        bitmap_shm_signal = (unsigned char *) MapViewOfFile(map_file, // handle to map object
                FILE_MAP_ALL_ACCESS,  // read/write permission
                0,
                0,
                10);
        memset(bitmap_shm_signal, '\x00', 10);

        return true;
    }
}
#elif __linux__
bool setup_shm()
{
    if (char * shm_key = getenv("AFL_SHM_ID")) {
        int shm_id;
        std::cout << "shm_key: " << shm_key << std::endl;        
    
        if( ( shm_id = shmget( (key_t) atoi(shm_key), MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600 ) ) < 0 )  // try create by key
        {
            std::cout << red << "failed to create shm" << cend << std::endl;
            return false;
        }
        bitmap_shm = reinterpret_cast<uint8_t*>(shmat(shm_id, 0, 0));
        
        if (bitmap_shm == reinterpret_cast<void *>(-1)) {
            std::cout << red << "failed to get shm addr from shmmat()" << cend << std::endl;
            return false;
        }
    }
    else {
        std::cout << red << "failed to get shm_id envvar" << cend << std::endl;
        return false;
    }

    if (char *shm_key = getenv("AFL_SHM_FULL_ID")) {
        int shm_id;
        std::cout << "shm_key: " << shm_key << std::endl;        
    
        if( ( shm_id = shmget( (key_t) atoi(shm_key), MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600 ) ) < 0 )  // try create by key
        {
            std::cout << red << "failed to create shm" << cend << std::endl;
            return false;
        }
        bitmap_shm_full = reinterpret_cast<uint8_t*>(shmat(shm_id, 0, 0));
        
        if (bitmap_shm_full == reinterpret_cast<void *>(-1)) {
            std::cout << red << "failed to get shm addr from shmmat()" << cend << std::endl;
            return false;
        }
    }
    else {
        std::cout << red << "failed to get shm_id envvar" << cend << std::endl;
        return false;
    }

    if (char *shm_key = getenv("AFL_SHM_SIGNAL_ID")) {
        int shm_id;
        std::cout << "shm_key: " << shm_key << std::endl;        
    
        if( ( shm_id = shmget( (key_t) atoi(shm_key), MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600 ) ) < 0 )  // try create by key
        {
            std::cout << red << "failed to create shm" << cend << std::endl;
            return false;
        }
        bitmap_shm_signal = reinterpret_cast<uint8_t*>(shmat(shm_id, 0, 0));
        
        if (bitmap_shm_signal == reinterpret_cast<void *>(-1)) {
            std::cout << red << "failed to get shm addr from shmmat()" << cend << std::endl;
            return false;
        }
    }
    else {
        std::cout << red << "failed to get shm_id envvar" << cend << std::endl;
        return false;
    }

    return true;
}
#endif

VOID img_instrument(IMG img, VOID * v)
{
    if( IMG_IsMainExecutable(img) )
    {
        for(SEC sec= IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
        {
            if (SEC_IsExecutable(sec) && SEC_Name(sec) == ".text")
            {
                ADDRINT sec_addr = SEC_Address(sec);
                UINT64  sec_size = SEC_Size(sec);
                if(sec_addr)
                {
                    min_addr = sec_addr;
                    max_addr = sec_addr + sec_size;
                }
            }
        }
        printf("0x%lx <= cover <= 0x%lx", min_addr, max_addr);
        fflush(stdout);
    }
}

unsigned int exceptionCount;
static CONTEXT savedFromContext;
static CONTEXT savedToContext;
static INT32   savedReason;
void context_change(THREADID threadIndex, 
                        CONTEXT_CHANGE_REASON reason, 
                        const CONTEXT *ctxtFrom,
                        CONTEXT *ctxtTo,
                        INT32 info, 
                        VOID *v)
{
    if(reason == CONTEXT_CHANGE_REASON_EXCEPTION)
    {
        if(exceptionCount++ == 0)
        {
            PIN_SaveContext (ctxtFrom, &savedFromContext);
            PIN_SaveContext (ctxtTo,   &savedToContext);
            savedReason = info;
        }
        printf("Exception 0x%08x (number %d) in 0x%08x\n"
                "EAX: 0x%08x ECX: 0x%08x EDX: 0x%08x EBX: 0x%08x\n"
                "EBP: 0x%08x ESP: 0x%08x ESI: 0x%08x EDI: 0x%08x\n",
                info, exceptionCount,
                PIN_GetContextReg(ctxtFrom, REG_INST_PTR),
                PIN_GetContextReg(ctxtFrom, REG_GAX),
                PIN_GetContextReg(ctxtFrom, REG_GCX),
                PIN_GetContextReg(ctxtFrom, REG_GDX),
                PIN_GetContextReg(ctxtFrom, REG_GBX),
                PIN_GetContextReg(ctxtFrom, REG_GBP),
                PIN_GetContextReg(ctxtFrom, REG_STACK_PTR),
                PIN_GetContextReg(ctxtFrom, REG_GSI),
                PIN_GetContextReg(ctxtFrom, REG_GDI)
            );
        
        if(exceptionCount == 2)
        {
            // Check that the second exception is the same as the first, at least to a first approximation.
            if (info == savedReason && 
                PIN_GetContextReg(ctxtFrom, REG_INST_PTR) == PIN_GetContextReg(&savedFromContext, REG_INST_PTR))
            {
                printf("Second exception looks like a replay, good!\n");
            }
            else
            {
                printf("Second exception does not look like a replay, BAD!\n");
                bitmap_shm_signal[0] = 1;
            }
            exceptionCount = 0;
        }
    }
    else
        printf("context switch\n");
}


int main(int argc, char *argv[])
{
    if(PIN_Init(argc, argv)){
        return Usage();
    }

    #ifdef __win__
    windows::setup_shm();
    #elif __linux__
    setup_shm();
    #endif
    PIN_SetSyntaxIntel();
    IMG_AddInstrumentFunction(img_instrument, 0);
    TRACE_AddInstrumentFunction(Trace, 0);
    //PIN_AddApplicationStartFunction(entry_point, 0);

    PIN_AddContextChangeFunction(context_change, 0);
    PIN_StartProgram();

    // AFL_NO_FORKSRV=1
    // We could use this main function to talk to the fork server's fd and then enable the fork server with this tool...
}

