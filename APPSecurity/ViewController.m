//
//  ViewController.m
//  APPSecurity
//
//  Created by 李彬 on 16/1/15.
//  Copyright © 2016年 李彬. All rights reserved.
//

#import "ViewController.h"
#import <sys/sysctl.h>
#import <mach-o/getsect.h>
#import <dlfcn.h>
#import <sys/types.h>

/**
 *  判断当前应用是否在debug模式
 *
 *  @returns 是：YES 否：NO
 */
NS_INLINE BOOL _isDebugging()
{
    size_t size = sizeof(struct kinfo_proc);
    struct kinfo_proc   info;                               //(kernal information of process)的结构体指针,对进程的内核信息
    int                 result, name[4];
    memset(&info, 0, size);                                 //清空初始化内容
    name[0] = CTL_KERN;                                     //指定本请求定向到内核的哪个子系统
    name[1] = KERN_PROC;                                    //第二个及其后元素依次细化指定该系统的某个部分
    name[2] = KERN_PROC_PID;
    name[3] = getpid();                                     //获得当前进程的进程ID
    if ((result = (sysctl(name,                             //描述信息
                       sizeof(name)/sizeof(*name),
                       &info,                               //输出缓冲器
                       &size,                               //输出缓冲器的大小,这个缓冲不够大，函数就返回ENOMEM错误
                       NULL, 0)))) {
        
        //ret 为0表示成功，-1表示失败。如果获取失败，异常情况，返回YES
        if (result) return YES;
    }
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}

/**
 *  判断文件是否存在
 *
 *  @param filePath 文件路径
 *
 *  @returns 存在：YES 不存在：NO
 */
NS_INLINE BOOL fileExist(NSString *filePath) {
    if (!filePath) {
        return NO;
    }
    return [[NSFileManager defaultManager] fileExistsAtPath:filePath];
}

/**
 *  是否越狱
 *
 *  @returns 越狱：YES 非越狱：NO
 */
NS_INLINE BOOL _isJailbroken()
{
#if TARGET_IPHONE_SIMULATOR
    return NO;
#endif /* TARGET_IPHONE_SIMULATOR */
    
    if (system(0)) {                                            /*调用系统命令 /bin/sh,未越狱的情况下不应该有执行权限。
                                                                    越狱的情况下返回1或者执行失败(-1)，未越狱情况下返回0*/
        return YES;
    } else if (fopen("/bin/ssh", "r")) {                        //是否有系统文件的读取权限，因为是沙盒的情况下，不应该能访问外部文件
        return YES;
    } else {
        NSString *cydiaPath = @"/Applications/Cydia.app";       //判断是否有安装Cydia
        if (fileExist(cydiaPath)) {
            return YES;
        }
        NSString *aptPath = @"/private/var/lib/apt/";           //判断是否有apt
        if (fileExist(aptPath)) {
            return YES;
        }
        extern char **environ;                                  //环境变量
        char **env = environ;
        while (*env) {
            if(strstr(*env,"MobileSubstrate")) {                //查找安装源，MobileSubstrate是其中一个而已
                return YES;
            }
            env++;
        }
    }
    return NO;
}


/**
 *  检查二进制PIE
 *      如果地址被固定的情况，文件编译后的变量地址等都会被固定下来，被窜改的风向很大
 *
 *  @param args 参数
 *
 *  @returns 有：YES 无：NO
 */
NS_INLINE BOOL _hasPIE()
{
    NSString *binaryPath = [[NSBundle mainBundle] executablePath];
    struct mach_header *currentHeader;                          //存放mach-o文件相关头部信息
    FILE *fp;
    currentHeader = alloca(sizeof(struct mach_header));         //sizeof方法依赖 #import <mach-o/getsect.h>
    if((fp = fopen([binaryPath UTF8String], "r")) == NULL) {
        return NO;
    }
    
    if((fread(currentHeader, sizeof(struct mach_header), 1, fp)) == (int)NULL)
    {
        return NO;
    }
    fclose(fp);
    fp = NULL;
    return !!(currentHeader->flags & MH_PIE);                   //如果设置PIE的情况下，deployment target>=4.3且
                                                                //Don't Create Position-Independent Executable=no（默认）
}

typedef int (*ptrace_ptr_t)(int _request, pid_t _pid, caddr_t _addr, int _data);
#if !defined(PT_DENY_ATTACH)
#define PT_DENY_ATTACH 31
#endif  // !defined(PT_DENY_ATTACH)

/**
 *  阻止debugger的应用依附
 */
void disable_debugger() {
    //RTLD_GLOBAL:动态库中定义的符号可被其后打开的其它库解析
    //RTLD_NOW:需要在dlopen返回前，解析出所有未定义符号，如果解析不出来，在dlopen会返回NULL，错误为：: undefined symbol: xxxx.......
    
    void* handle = dlopen(0, RTLD_GLOBAL | RTLD_NOW);   //打开一个动态链接库
    ptrace_ptr_t ptrace_ptr = dlsym(handle, "ptrace");
    ptrace_ptr(PT_DENY_ATTACH, 0, 0, 0);
    dlclose(handle);                                    //使用dlclose（）来卸载打开的库
}


@interface ViewController ()

@end

@implementation ViewController



- (void)viewDidLoad {
    [super viewDidLoad];
    
    BOOL isDebug = _isDebugging();
    BOOL isJailbroken = _isJailbroken();
    BOOL hasPIE = _hasPIE();
    UIAlertView *alertView = [[UIAlertView alloc] initWithTitle:@"提示" message:[NSString stringWithFormat:@"isDebug:%zi,isJailbroken:%zi,hasPIE:%zi",isDebug,isJailbroken,hasPIE] delegate:self cancelButtonTitle:nil otherButtonTitles:nil, nil];
    [alertView show];
    
//    if (isDebug) {
//        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
//            disable_debugger();
//        });
//    }
}

@end
