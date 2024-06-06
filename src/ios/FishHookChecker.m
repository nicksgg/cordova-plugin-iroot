//  Translated from IOSSecuritySuite
// https://github.com/securing/IOSSecuritySuite/blob/master/IOSSecuritySuite/FishHookChecker.swift
//  FishHookChecker.swift
//  IOSSecuritySuite
//
//  Created by jintao on 2020/4/24.
//  Copyright © 2020 wregula. All rights reserved.
//  https://github.com/TannerJin/anti-fishhook

// swiftlint:disable all


#import "FishHookChecker.h"
#import "mach-o/loader.h"
#import "mach-o/dyld.h"
#import "dlfcn.h"
#import "string.h"

/*
 Lazy_Symbol_Ptr:
 
 call symbol2
 |
 |
 |   stubs(TEXT)
 |   *--------------*            stub_symbol:
 |   | stub_symbol1 |                         ldr x16 ptr   (ptr = pointer of lazy_symbol_ptr)
 |   |              |                         br x16
 *---> stub_symbol2 |
 |   ...        |
 *--------------*
 
 
 lazy_symbol_ptr(DATA)                   stub_helper(TEXT)
 *--------------*                        *---------------------------*
 |     ptr1     |                        |    br dyld_stub_binder    |    <-------------------*
 |     ptr2  ---------*                  |    symbol_binder_code_1   |                        |
 |     ptr3     |     *------------------->   symbol_binder_code_2   |                        |
 |     ...      |                        |          ...              |                        |
 *--------------*                        *---------------------------*                        |
 |
 symbol_binder_code:                           |
 ldr w16, #8(.byte)        |
 b br_dyld_stub_binder  ---*
 .byte
 
 
 .byte of the symbol is offset from beginning of lazy_binding_info to beginning of symbol_info
 
 lazy_binding_info(LINKEDIT -> DYLD_INFO -> LazyBindingInfo)
 *-----------------*
 |  symbol_info_1  |          symbol_info:
 |  symbol_info_2  |                         bind_opcode_done
 |  symbol_info_3  |                         bind_opcode_set_segment_and_offset_uleb
 |  ...            |                         uleb128
 *-----------------*                         BIND_OPCODE_SET_DYLIB_ORDINAL_IMM
 BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM
 **SymbolName**
 bind_opcode_do_bind
 
 
 
 The `denyFishHook` will look for code of `symbol_binder_code` of the symbol, and then make `lazy_symbol_ptr` of the symbol pointee to it
 
 Non_Lazy_Symbol_Ptr:
 wait to do based on export_info and binding_info
 */





// Macro Definitions
#define BIND_OPCODE_DONE                       0x00
#define BIND_OPCODE_SET_DYLIB_ORDINAL_IMM      0x10
#define BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB     0x20
#define BIND_OPCODE_SET_DYLIB_SPECIAL_IMM      0x30
#define BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM 0x40
#define BIND_OPCODE_SET_TYPE_IMM               0x50
#define BIND_OPCODE_SET_ADDEND_SLEB            0x60
#define BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB 0x70
#define BIND_OPCODE_ADD_ADDR_ULEB              0x80
#define BIND_OPCODE_DO_BIND                    0x90
#define BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED 0xA0
#define BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB      0xB0
#define BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB 0xC0
#define BIND_OPCODE_THREADED                   0xD0

#define BIND_IMMEDIATE_MASK                    0x0F
#define BIND_OPCODE_MASK                       0xF0

#define EXPORT_SYMBOL_FLAGS_KIND_MASK          0x03
#define EXPORT_SYMBOL_FLAGS_KIND_REGULAR       0x00
#define EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL  0x01
#define EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE      0x02
#define EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER  0x10

#define LC_SEGMENT_64                          0x19
#define LC_DYLD_INFO_ONLY                      0x80000022
#define LC_DYLD_INFO                           0x22
#define LC_DYLD_EXPORTS_TRIE                   0x80000033
#define LC_REEXPORT_DYLIB                      0x8000001F
#define LC_LOAD_DYLIB                          0xC
#define LC_LOAD_WEAK_DYLIB                     0x18
#define LC_LOAD_UPWARD_DYLIB                   0x1F

#define SEG_LINKEDIT                           "__LINKEDIT"

static uint64_t readUleb128(uint8_t **ptr, uint8_t *end);
static int64_t readSleb128(uint8_t **ptr, uint8_t *end);

@implementation FishHookChecker

+ (void)denyFishHook:(NSString *)symbol {
    void *symbolAddress = NULL;
    for (uint32_t imgIndex = 0; imgIndex < _dyld_image_count(); imgIndex++) {
        const struct mach_header *image = _dyld_get_image_header(imgIndex);
        if (image) {
            if (!symbolAddress) {
                [SymbolFound lookSymbol:symbol atImage:image imageSlide:_dyld_get_image_vmaddr_slide(imgIndex) symbolAddress:&symbolAddress];
            }
            if (symbolAddress) {
                void *oldMethod = NULL;
                [FishHook replaceSymbol:symbol atImage:image imageSlide:_dyld_get_image_vmaddr_slide(imgIndex) newMethod:symbolAddress oldMethod:&oldMethod];
            }
        }
    }
}

+ (void)denyFishHook:(NSString *)symbol atImage:(const struct mach_header *)image imageSlide:(intptr_t)slide {
    void *symbolAddress = NULL;
    if ([SymbolFound lookSymbol:symbol atImage:image imageSlide:slide symbolAddress:&symbolAddress] && symbolAddress) {
        void *oldMethod = NULL;
        [FishHook replaceSymbol:symbol atImage:image imageSlide:slide newMethod:symbolAddress oldMethod:&oldMethod];
    }
}

@end

@implementation SymbolFound

static const int BindTypeThreadedRebase = 102;

+ (BOOL)lookSymbol:(NSString *)symbol atImage:(const struct mach_header *)image imageSlide:(intptr_t)slide symbolAddress:(void **)symbolAddress {
    // Target commands
    struct segment_command_64 *linkeditCmd = NULL;
    struct dyld_info_command *dyldInfoCmd = NULL;
    NSMutableArray<NSString *> *allLoadDylds = [NSMutableArray array];
    
    void *curCmdPointer = (void *)((uintptr_t)image + sizeof(struct mach_header_64));
    if (!curCmdPointer) {
        return NO;
    }
    
    // All commands
    for (uint32_t i = 0; i < image->ncmds; i++) {
        struct segment_command_64 *curCmd = (struct segment_command_64 *)curCmdPointer;
        
        switch (curCmd->cmd) {
            case LC_SEGMENT_64: {
                size_t offset = sizeof(curCmd->cmd) + sizeof(curCmd->cmdsize);
                const char *curCmdName = (char *)(curCmdPointer + offset);
                if (strcmp(curCmdName, SEG_LINKEDIT) == 0) {
                    linkeditCmd = curCmd;
                }
                break;
            }
            case LC_DYLD_INFO_ONLY:
            case LC_DYLD_INFO:
                dyldInfoCmd = (struct dyld_info_command *)curCmdPointer;
                break;
            case LC_LOAD_DYLIB:
            case LC_LOAD_WEAK_DYLIB:
            case LC_LOAD_UPWARD_DYLIB:
            case LC_REEXPORT_DYLIB: {
                struct dylib_command *loadDyldCmd = (struct dylib_command *)curCmdPointer;
                const char *loadDyldName = (char *)(curCmdPointer + loadDyldCmd->dylib.name.offset);
                [allLoadDylds addObject:[NSString stringWithUTF8String:loadDyldName]];
                break;
            }
            default:
                break;
        }
        
        curCmdPointer += curCmd->cmdsize;
    }
    
    if (!linkeditCmd || !dyldInfoCmd) {
        return NO;
    }
    uint64_t linkeditBase = slide + linkeditCmd->vmaddr - linkeditCmd->fileoff;
    
    // Look by LazyBindInfo
    if (dyldInfoCmd->lazy_bind_size > 0) {
        uint8_t *lazyBindInfoCmd = (uint8_t *)(uintptr_t)(linkeditBase + dyldInfoCmd->lazy_bind_off);
        if (lazyBindInfoCmd && [self lookLazyBindSymbol:symbol symbolAddr:symbolAddress lazyBindInfoCmd:lazyBindInfoCmd lazyBindInfoSize:dyldInfoCmd->lazy_bind_size allLoadDylds:allLoadDylds]) {
            return YES;
        }
    }
    
    // Look by NonLazyBindInfo
    if (dyldInfoCmd->bind_size > 0) {
        uint8_t *bindCmd = (uint8_t *)(uintptr_t)(linkeditBase + dyldInfoCmd->bind_off);
        if (bindCmd && [self lookBindSymbol:symbol symbolAddr:symbolAddress bindInfoCmd:bindCmd bindInfoSize:dyldInfoCmd->bind_size allLoadDylds:allLoadDylds]) {
            return YES;
        }
    }
    
    return NO;
}

// LazySymbolBindInfo
+ (BOOL)lookLazyBindSymbol:(NSString *)symbol symbolAddr:(void **)symbolAddress lazyBindInfoCmd:(uint8_t *)lazyBindInfoCmd lazyBindInfoSize:(int)lazyBindInfoSize allLoadDylds:(NSArray<NSString *> *)allLoadDylds {
    uint8_t *ptr = lazyBindInfoCmd;
    uint8_t *lazyBindingInfoEnd = lazyBindInfoCmd + lazyBindInfoSize;
    int ordinal = -1;
    BOOL foundSymbol = NO;
    int addend = 0;
    int32_t type = 0;
    
    while (ptr < lazyBindingInfoEnd) {
        int32_t immediate = *ptr & BIND_IMMEDIATE_MASK;
        int32_t opcode = *ptr & BIND_OPCODE_MASK;
        ptr++;
        
        switch (opcode) {
            case BIND_OPCODE_DONE:
                continue;
            case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
                ordinal = immediate;
                break;
            case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
                ordinal = (int)readUleb128(&ptr, lazyBindingInfoEnd);
                break;
            case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
                ordinal = (immediate == 0) ? 0 : (BIND_OPCODE_MASK | immediate);
                break;
            case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: {
                const char *symbolName = (char *)ptr + 1;
                if (strcmp(symbolName, symbol.UTF8String) == 0) {
                    foundSymbol = YES;
                }
                while (*ptr != 0) {
                    ptr++;
                }
                ptr++;
                break;
            }
            case BIND_OPCODE_SET_TYPE_IMM:
                type = immediate;
                continue;
            case BIND_OPCODE_SET_ADDEND_SLEB:
                addend = (int)readSleb128(&ptr, lazyBindingInfoEnd);
                break;
            case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                readUleb128(&ptr, lazyBindingInfoEnd);
                break;
            case BIND_OPCODE_ADD_ADDR_ULEB:
                readUleb128(&ptr, lazyBindingInfoEnd);
                break;
            case BIND_OPCODE_DO_BIND:
                if (foundSymbol && ordinal >= 0) {
                    const char *loadDyldName = allLoadDylds[ordinal].UTF8String;
                    void *dladdr = dlopen(loadDyldName, RTLD_LAZY);
                    if (dladdr) {
                        *symbolAddress = dlsym(dladdr, symbol.UTF8String);
                        dlclose(dladdr);
                        return YES;
                    }
                }
                ptr += sizeof(void *);
                break;
            case BIND_OPCODE_THREADED:
                if (immediate == BindTypeThreadedRebase) {
                    ptr += sizeof(void *);
                    break;
                }
            default:
                break;
        }
    }
    
    return NO;
}

// NonLazyBindInfo
+ (BOOL)lookBindSymbol:(NSString *)symbol symbolAddr:(void **)symbolAddress bindInfoCmd:(uint8_t *)bindCmd bindInfoSize:(int)bindInfoSize allLoadDylds:(NSArray<NSString *> *)allLoadDylds {
    uint8_t *ptr = bindCmd;
    uint8_t *bindingInfoEnd = bindCmd + bindInfoSize;
    int ordinal = -1;
    BOOL foundSymbol = NO;
    int addend = 0;
    int32_t type = 0;
    
    while (ptr < bindingInfoEnd) {
        int32_t immediate = *ptr & BIND_IMMEDIATE_MASK;
        int32_t opcode = *ptr & BIND_OPCODE_MASK;
        ptr++;
        
        switch (opcode) {
            case BIND_OPCODE_DONE:
                continue;
            case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
                ordinal = immediate;
                break;
            case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
                ordinal = (int)readUleb128(&ptr, bindingInfoEnd);
                break;
            case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
                ordinal = (immediate == 0) ? 0 : (BIND_OPCODE_MASK | immediate);
                break;
            case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: {
                const char *symbolName = (char *)ptr + 1;
                if (strcmp(symbolName, symbol.UTF8String) == 0) {
                    foundSymbol = YES;
                }
                while (*ptr != 0) {
                    ptr++;
                }
                ptr++;
                break;
            }
            case BIND_OPCODE_SET_TYPE_IMM:
                type = immediate;
                continue;
            case BIND_OPCODE_SET_ADDEND_SLEB:
                addend = (int)readSleb128(&ptr, bindingInfoEnd);
                break;
            case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                readUleb128(&ptr, bindingInfoEnd);
                break;
            case BIND_OPCODE_ADD_ADDR_ULEB:
                readUleb128(&ptr, bindingInfoEnd);
                break;
            case BIND_OPCODE_DO_BIND:
                if (foundSymbol && ordinal >= 0) {
                    const char *loadDyldName = allLoadDylds[ordinal].UTF8String;
                    void *dladdr = dlopen(loadDyldName, RTLD_LAZY);
                    if (dladdr) {
                        *symbolAddress = dlsym(dladdr, symbol.UTF8String);
                        dlclose(dladdr);
                        return YES;
                    }
                }
                ptr += sizeof(void *);
                break;
            case BIND_OPCODE_THREADED:
                if (immediate == BindTypeThreadedRebase) {
                    ptr += sizeof(void *);
                    break;
                }
            default:
                break;
        }
    }
    
    return NO;
}

@end


// MARK: - FishHook
// MARK: - FishHook

@implementation FishHook

+ (void)replaceSymbol:(NSString *)symbol atImage:(const struct mach_header *)image imageSlide:(intptr_t)slide newMethod:(void *)newMethod oldMethod:(void **)oldMethod {
    uint8_t *ptr = NULL;
    uint8_t *end = NULL;
    uint64_t count = 0;
    int segmentIndex = 0;

    // Iterate through all the segments of the image
    while (segmentIndex < image->ncmds) {
        struct load_command *loadCmd = (struct load_command *)((uint8_t *)image + count);

        if (loadCmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *segCmd = (struct segment_command_64 *)loadCmd;
            if (strcmp(segCmd->segname, "__LINKEDIT") == 0) {
                // Found the __LINKEDIT segment
                ptr = (uint8_t *)(segCmd->vmaddr + slide);
                end = ptr + segCmd->vmsize;
                break;
            }
        }

        count += loadCmd->cmdsize;
        segmentIndex++;
    }

    if (!ptr || !end) {
        // Couldn't find the __LINKEDIT segment
        return;
    }

    // Iterate through the bind commands to find the symbol
    while (ptr < end) {
        uint8_t opcode = *ptr & BIND_OPCODE_MASK;
        uint8_t immediate = *ptr & BIND_IMMEDIATE_MASK;
        ptr++;

        switch (opcode) {
            case BIND_OPCODE_DONE:
                // End of the bind commands
                return;
            case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: {
                // Get the symbol name
                const char *bindSymbol = (char *)ptr;
                ptr += strlen(bindSymbol) + 1;

                // Check if this is the symbol we're looking for
                if (strcmp(bindSymbol, [symbol UTF8String]) == 0) {
                    // Replace the old method with the new method
                    *oldMethod = *(void **)ptr;
                    *(void **)ptr = newMethod;
                    return;
                }
                break;
            }
            default: {
                // Get the immediate value
                int32_t value = 0;
                if (opcode == BIND_OPCODE_SET_DYLIB_ORDINAL_IMM || opcode == BIND_OPCODE_SET_TYPE_IMM || opcode == BIND_OPCODE_SET_ADDEND_SLEB) {
                    value = immediate;
                } else {
                    value = readUleb128(&ptr, end);
                }
                // Move the pointer based on the opcode
                switch (opcode) {
                    case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
                    case BIND_OPCODE_SET_TYPE_IMM:
                    case BIND_OPCODE_SET_ADDEND_SLEB:
                        break;
                    case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                    case BIND_OPCODE_ADD_ADDR_ULEB:
                    case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
                    case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
                        break;
                    case BIND_OPCODE_DO_BIND:
                    case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
                        break;
                    default:
                        break;
                }
                break;
            }
        }
    }
}

@end


static uint64_t readUleb128(uint8_t **ptr, uint8_t *end) {
    uint8_t *p = *ptr;
    uint64_t result = 0;
    int bit = 0;
    do {
        if (p == end) {
            break;
        }
        uint64_t slice = *p & 0x7f;
        if (bit >= 64 || slice << bit >> bit != slice) {
            break;
        } else {
            result |= (slice << bit);
            bit += 7;
        }
    } while (*p++ & 0x80);
    *ptr = p;
    return result;
}

static int64_t readSleb128(uint8_t **ptr, uint8_t *end) {
    uint8_t *p = *ptr;
    int64_t result = 0;
    int bit = 0;
    uint8_t byte;
    do {
        if (p == end) {
            break;
        }
        byte = *p++;
        result |= ((byte & 0x7f) << bit);
        bit += 7;
    } while (byte & 0x80);
    
    if ((byte & 0x40) != 0) {
        result |= (-1LL) << bit;
    }
    *ptr = p;
    return result;
}
