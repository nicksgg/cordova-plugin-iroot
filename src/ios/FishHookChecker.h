#import <Foundation/Foundation.h>
#import <mach-o/loader.h>

@interface FishHookChecker : NSObject

+ (void)denyFishHook:(NSString *)symbol;
+ (void)denyFishHook:(NSString *)symbol atImage:(const struct mach_header *)image imageSlide:(intptr_t)slide;

@end

@interface SymbolFound : NSObject

+ (BOOL)lookSymbol:(NSString *)symbol atImage:(const struct mach_header *)image imageSlide:(intptr_t)slide symbolAddress:(void **)symbolAddress;

@end
