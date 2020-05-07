# Writing Python scripts for lldb

## 0x00 参考资料

官方手册：https://lldb.llvm.org/use/python-reference.html 

ZDI博客：https://www.thezdi.com/blog/2020/4/20/mindshare-using-lldbinit-to-enhance-the-lldb-debugger

lldbinit：https://github.com/gdbinit/lldbinit

## 0x01  安装lldbinit

首先安装一个比较优秀的扩展lldbinit，对于exp调试来说，还有lisa、xia0lldb等工具，这里为了二次开发先以lldbinit为例。

```bash
$ git clone https://github.com/gdbinit/lldbinit.git
$ cp lldbinit.py ~/
$ echo "command script import  ~/lldbinit.py" >>$HOME/.lldbinit
```

界面如下：

```
(lldbinit) r
Process 33032 launched: '/Users/1wc/Desktop/tester' (x86_64)
-----------------------------------------------------------------------------------------------------------------------[regs]
  RAX: 0x00000001000015F0  RBX: 0x0000000000000000  RBP: 0x00007FFEEFBFFA68  RSP: 0x00007FFEEFBFFA58  o d I t s Z a P c 
  RDI: 0x0000000000000001  RSI: 0x00007FFEEFBFFA78  RDX: 0x00007FFEEFBFFA88  RCX: 0x00007FFEEFBFFB70  RIP: 0x00000001000015F0
  R8:  0x0000000000000000  R9:  0x0000000000000000  R10: 0x0000000000000000  R11: 0x0000000000000000  R12: 0x0000000000000000
  R13: 0x0000000000000000  R14: 0x0000000000000000  R15: 0x0000000000000000
  CS:  002B  FS: 0000  GS: 0000                                              
-----------------------------------------------------------------------------------------------------------------------[code]
main @ /Users/1wc/Desktop/tester:
->  0x1000015f0 (0x1000015f0): 55                    push   rbp
    0x1000015f1 (0x1000015f1): 48 89 e5              mov    rbp, rsp
    0x1000015f4 (0x1000015f4): 53                    push   rbx
    0x1000015f5 (0x1000015f5): 48 83 e4 e0           and    rsp, -0x20
    0x1000015f9 (0x1000015f9): 48 81 ec 40 01 00 00  sub    rsp, 0x140
    0x100001600 (0x100001600): 48 89 e3              mov    rbx, rsp
    0x100001603 (0x100001603): 31 c0                 xor    eax, eax
    0x100001605 (0x100001605): 89 c1                 mov    ecx, eax
-----------------------------------------------------------------------------------------------------------------------------

Process 33032 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
    frame #0: 0x00000001000015f0 tester`main
Target 0: (tester) stopped.

```

lldbinit的所有命令如下所示：

```
(lldbinit) lldbinitcmds 
lldbinit available commands:
 lldbinitcmds         - this command                  
 enable               - configure lldb and lldbinit options
 disable              - configure lldb and lldbinit options
 contextcodesize      - set number of instruction lines in code window
 b                    - breakpoint address            
 bpt                  - set a temporary software breakpoint
 bhb                  - set an hardware breakpoint    
 bpc                  - clear breakpoint              
 bpca                 - clear all breakpoints         
 bpd                  - disable breakpoint            
 bpda                 - disable all breakpoints       
 bpe                  - enable a breakpoint           
 bpea                 - enable all breakpoints        
 bcmd                 - alias to breakpoint command add
 bpl                  - list all breakpoints          
 bpn                  - temporarly breakpoint next instruction
 break_entrypoint     - launch target and stop at entrypoint
 skip                 - skip current instruction      
 int3                 - patch memory address with INT3
 rint3                - restore original byte at address patched with INT3
 listint3             - list all INT3 patched addresses
 nop                  - patch memory address with NOP 
 null                 - patch memory address with NULL
 stepo                - step over calls and loop instructions
 lb                   - load breakpoints from file and apply them (currently only func names are applied)
 lbrva                - load breakpoints from file and apply to main executable, only RVA in this case
 db/dw/dd/dq          - memory hex dump in different formats
 findmem              - search memory                 
 cfa/cfc/cfd/cfi/cfo/cfp/cfs/cft/cfz - change CPU flags              
 u                    - dump instructions             
 iphone               - connect to debugserver running on iPhone
 ctx/context          - show current instruction pointer CPU context
 show_loadcmds        - show otool output of Mach-O load commands
 show_header          - show otool output of Mach-O header
 enablesolib/disablesolib - enable/disable the stop on library load events
 enableaslr/disableaslr - enable/disable process ASLR   
 crack                - return from current function  
 crackcmd             - set a breakpoint and return from that function
 crackcmd_noret       - set a breakpoint and set a register value. doesn't return from function
 datawin              - set start address to display on data window
 rip/rax/rbx/etc      - shortcuts to modify x64 registers
 eip/eax/ebx/etc      - shortcuts to modify x86 register
 asm32/asm64          - x86/x64 assembler using keystone
 arm32/arm64/armthumb - ARM assembler using keystone  

Use 'cmdname help' for extended command help.
```

可以看到除了一些参数设置之外，大多数是和断点设置、指令patch、寄存器修改相关的命令，还有连接iphone debugserver的命令，Mark。

## 0x02 基于lldbinit源码学习lldb的Python插件编写

`__lldb_init_module`函数在脚本初始化时执行，可以用来进行一些设置的初始化设置。

```python
ci.HandleCommand("command script add -f lldbinit.cmd_bpt bpt", res)
```

这里将`lldbinit`中定义的`cmd_bhb`命令的缩写设置为`bhb`。

查询官方文档可知，能够当作LLDB交互式命令的Python函数，至少要有四个参数如下：

>```
>def command_function(debugger, command, result, internal_dict):
>		"""This command takes a lot of options and does many fancy things"""
>    # Your code goes here
>```

可选的，也可以提供一个Python docstring作为help信息。自lldb 3.5.2起，也可以将一个`SBExecutionContext`类型的变量当作参数，所以就变成五个参数：

>```
>def command_function(debugger, command, exe_ctx, result, internal_dict):
>    # Your code goes here
>```

`debugger`是`lldb.SBDebugger`类型的变量，是当前的debugger对象；`command`是输入的命令；`exe_ctx`是执行上下文对象；`result`封装命令的返回成功/失败；`internal_dict`当前script session全程hold的一个dictionary。

`lldbinit`中命令均命名为`cmd_xxx`。

以`cmd_bpt`为例，即bpt命令，功能是设置临时的软断点：

```python
# temporary software breakpoint
def cmd_bpt(debugger, command, result, dict):
    '''Set a temporary software breakpoint. Use \'bpt help\' for more information.'''
    help = """
Set a temporary software breakpoint.

Syntax: bpt <address>

Note: expressions supported, do not use spaces between operators.
"""

    cmd = command.split() # 处理命令字符串
    if len(cmd) != 1:
        print("[-] error: please insert a breakpoint address.")
        print("")
        print(help)
        return
    if cmd[0] == "help":
        print(help)
        return
    
    value = evaluate(cmd[0]) # 求解表达式的值
    if value == None:
        print("[-] error: invalid input value.")
        print("")
        print(help)
        return
    
    target = get_target() # 获取目标程序
    breakpoint = target.BreakpointCreateByAddress(value) # 根据目的地址下断点
    breakpoint.SetOneShot(True)	# 令断点只触发一次（即临时）
    breakpoint.SetThreadID(get_frame().GetThread().GetThreadID()) # 断点位于当前栈帧的当前线程

    print("[+] Set temporary breakpoint at 0x{:x}".format(value))
    
```

这里的`evalute`是lldbinit封装的用来求解表达式的值的函数，代码如下

```python
# evaluate an expression and return the value it represents
def evaluate(command):
    frame = get_frame()
    if frame != None:
        value = frame.EvaluateExpression(command)
        if value.IsValid() == False:
            return None
        try:
            value = int(value.GetValue(), base=10)
            return value
        except Exception as e:
            print("Exception on evaluate: " + str(e))
            return None
    # use the target version - if no target exists we can't do anything about it
    else:
        target = get_target()    
        if target == None:
            return None
        value = target.EvaluateExpression(command)
        if value.IsValid() == False:
            return None
        try:
            value = int(value.GetValue(), base=10)
            return value
        except:
            return None
```

lldb模块的代码位置位于：`/Library/Developer/CommandLineTools/Library/PrivateFrameworks/LLDB.framework/Resources/Python/lldb/__init__.py`。但如果我们想在交互式环境中查询某个模块的用法，例如刚刚用到的`lldb.SBBreakpoint`类的成员和函数，如下：

```
(lldbinit) script help(lldb.SBBreakpoint)
Help on class SBBreakpoint in module lldb:

......

 |  Methods defined here:
 |  
 |  AddLocation(self, address)
 |      AddLocation(SBBreakpoint self, SBAddress address) -> SBError
 |  
 |  AddName(self, new_name)
 |      AddName(SBBreakpoint self, str const * new_name) -> bool
 |  
......
```

至此，我们已经了解lldb Python脚本编写的基本方法，而`lldbinit`中进行了一些很方便的封装，我们可以在其基础上进行二次开发。

## 0x03  实现模块+偏移断点

在lldb默认无法直接通过模块+偏移设置断点，例如`bp addresslib+1EE6`，而只能通过`image list`  & `breakpoint set -a 0x0x00007fff4bf65000+0x1234`这种方法设置，过于复杂。

有了前面的知识，我们可以如前述ZDI博客中所做的，自己实现这个功能。

### 枚举模块名和加载基址

为了枚举当前的模块，最好是有上下文信息，需要传入`exe_ctx`参数。首先看一下这个类。

```
(lldbinit) script help(lldb.SBExecutionContext)
Help on class SBExecutionContext in module lldb:

class SBExecutionContext(__builtin__.object)
 |  Proxy of C++ lldb::SBExecutionContext class.
 |  
 |  Methods defined here:
 |  
 |  GetFrame(self)
 |      GetFrame(SBExecutionContext self) -> SBFrame
 |  
 |  GetProcess(self)
 |      GetProcess(SBExecutionContext self) -> SBProcess
 |  
 |  GetTarget(self)
 |      GetTarget(SBExecutionContext self) -> SBTarget
 |  
 |  GetThread(self)
 |      GetThread(SBExecutionContext self) -> SBThread
```

可以通过`GetTarget()`获取目标程序，然后列举模块即可。

```python
def get_mods(exe_ctx):
    global loaded_mods
    loaded_mods = {}
    target = exe_ctx.GetTarget()
    for mod in target.get_modules_array():
        loaded_mods[mod.file.basename.lower()] = mod.GetObjectFileHeaderAddress().GetLoadAddress(target)
    return loaded_mods
```

###处理模块名和偏移 

用Python自带的`shlex`模块进行简单的unix命令行文法分析，遍历token将模块名替换为加载基址，构成地址相加的表达式。

```python
def eval_mod_name(expr, exe_ctx):
    import shlex
    mods = get_mods(exe_ctx)
    lexer = shlex.shlex(expr)
    lexer.wordchars = lexer.wordchars + (".")
    final_expr = ""
    for token in lexer:
        if token.lower() in mods:
            final_expr += str(mods[token]) # mod => addr
        else:
            final_expr += str(token) # addr
    return final_expr
```

这里实际上原博文中代码有点问题，因为很多macOS/iOS下的模块中有`.`，所以这里要对`.`特殊处理。

### 修改cmd_bpt

```python
# temporary software breakpoint
def cmd_bpt(debugger, command, exe_ctx, result, dict):
    '''Set a temporary software breakpoint. Use \'bpt help\' for more information.'''
    help = """
Set a temporary software breakpoint.

Syntax: bpt <address or mods>

Note: expressions supported, do not use spaces between operators.
"""

    cmd = command.split()
    if len(cmd) != 1:
        print("[-] error: please insert a breakpoint address.")
        print("")
        print(help)
        return
    if cmd[0] == "help":
        print(help)
        return
    print (cmd[0])
    value = evaluate(eval_mod_name(cmd[0], exe_ctx))
    if value == None:
        print("[-] error: invalid input value.")
        print("")
        print(help)
        return
    
    target = get_target()
    breakpoint = target.BreakpointCreateByAddress(value)
    breakpoint.SetOneShot(True)
    breakpoint.SetThreadID(get_frame().GetThread().GetThreadID())

    print("[+] Set temporary breakpoint at 0x{:x}".format(value))
```

### 效果

成功实现！

```
(lldbinit) bpt libbsm.0.dylib+0x2
[+] Set temporary breakpoint at 0x7fff69794002
```

## 0x04 实现gdb中的start

这是我自身的一个需求，lldb没有`start`命令总感觉很难受。实现起来不算复杂。

先在main函数处下断点，然后launch一个新进程即可！！！

```python
def cmd_start(debugger, command, exe_ctx, result, dict):
    '''Start command like gdb'''
    help = """
Start the target like gdb!!!

Syntax: start [args]
"""
    cmd = command.split()
    if len(cmd) > 0 and cmd[0] == "help":
        print(help)
        return
    target = get_target()
    breakpoint = target.BreakpointCreateByName("main")
    breakpoint.SetOneShot(True)

    debugger.SetAsync(True)
    res = lldb.SBCommandReturnObject()
    process = lldb.debugger.GetSelectedTarget().LaunchSimple(command.split(), None, os.getcwd())
    result.SetStatus(lldb.eReturnStatusSuccessFinishNoResult)
```

## 0x05 TODO

在利用开发过程中有用的功能，能否实现。







