## Gluttony Feedback stuffs 
`<(^_^)>`

### Summary/Features/Limitations
Uh... I guess it's a pluggable blackbox feedback engine for fuzzers that utilizes Dynamorio. 
The goal is to just run whatever program with Gluttony and then get feedback all ezpz like. 
No source needed, no nothin', just a binary and some fuzz cases to get started 
(#shameless plug for mutiny-fuzzer and decept proxy to get network fuzzing real quick). 

*Seriously, this has just been a freetime project, so please don't judge too much \[\^\_\^\]* 

Currently it's only been integrated with mutiny-fuzzer, but future plans include trying to 
make it as generic as possible, to streamline the process of turning dumb fuzzers (like mutiny)
into less dumb fuzzers. Other future plans (there's alot) include multi-threading and 
support for Windows, since Dynamorio is capable of all those things and such.  

With regards to the actual feedback mechanism, right now Gluttony just copies AFL (standing on
the shoulders of giants), and does the basic block pairs xor'ed with a bit shift, then notifies
whatever fuzzer you're using, which should then actually proceed to dump/queue the fuzz case.     

~Cheers.

### Requirement: Dynamorio
For full instructions try here: [https://github.com/DynamoRIO/dynamorio/wiki/How-To-Build](https://github.com/DynamoRIO/dynamorio/wiki/How-To-Build)

### Building a Dynamorio Client
* `mkdir build && cd build &&& cmake .. && cp libgluttony.so ..` 
* Look at CMakeLists.txt for a basic overview of the minimal requirements.
* You have to do that bullshit if you want any extensions (like drcontainers `>_>`)
* If cmake is being weird, run this from inside the `build` dir:

 `cmake -DDynamoRIO_DIR=$(pwd)/../dynamorio/exports/cmake ..`

### Running a Dynamorio Client
Inside my .bashrc:

`alias gluttony="drrun -root <dynamorio_cloneLoc>/dynamorio/exports"`
 
So then you can run with `gluttony -c <client.so> <client_opts> -- <target_bin>`

### Commandline Options:
```
  --help          - Print out this info.
  --debug         - Get lots and lots of output (recommend outputting to file when enabled). 
  --savedir <dir> - Choose where to save persitance data. Two files, `seen_backup.bin` and 
                  | `unseen_backup.bin` will be created. These files are just qword aligned 
                  | arrays of the basic block transitions that occur. Relocation is manually 
                  | done, so the data can be accurate between runs. Currently only basic 
                  \ block transitions from the main binary (first module loaded) are saved. 
---------------------
Stuff to be added vvv
---------------------
  --trace <lib.so>        - Specify multiple libraries/modules to trace/persist. 
  --startAddr <0x..>      - Select a lowerbound for BB addresses to track in main binary.
  --endAddr <0x..>        - Select an upper bound for BB addresses to track in main binary.
                          \ (this option should speed up fuzzing quite a bit.) 
  --signal <SIGX,SIGY>... - Dump fuzz cases for other signals besides SIGSEGV/SIGABRT 


```

### Running with Mutiny's Feedback Mode: 
Example - apache2 (for no reason inparticular):

* `service apache2 stop` (if apache2 can't bind, it gets sad)
* `drun -c gluttony.so <Gluttony options> -- /usr/sbin/apache2 -X`  (drun => alias from above, -X for debugmode/single threaded) 
* (in a new console/window) `cd mutiny-fuzzer && python feedback_mode.py sample_fuzzers/apache_tests 127.0.0.1` (ip => wherever gluttony/target are running) 
* #SetItAndForgetIt

### Internals:
The obligatory ascii diagram given below demonstrates using mutiny-fuzzer with gluttony,
but Gluttony was designed with portability in mind, so hopefully it's not too bad to 
write code and interact with it using whatever fuzzer.

```
            (port:???)-| 
 -------------------   v   
|Gluttony   |Target|| <-> |mutiny.py|<--[T:61600]--| feedback_mode.py | 
|(unixsocket)       |                              |                  |--->(dumps/queues new fuzzers)
|    NetworkHandler | --------[T:61601]----------->|                  |   
 -------------------      

```
### Network Stuff
```
#    1        4   <len>
# [opcode][length][data]
```
Note: 'fin\x00' is sent in reply to any message.

Note2: There's more messages defined in the code, but haven't really been tested/implimented.

Since I'm not a huge fan of abstraction, as of right now the only messages that get sent are as follows:

#### Handshake
* Gluttony -> Feedback : "boop" (handshake part 1)
* Feedback => Gluttony : "doop" (handshake done)

#### Gluttony => Feedback Control Messages
* "\x80\x00\x00\x00\x00" : "Hey, that was a cool fuzz case, queue it."
* "\x8F\x00\x00\x00\x04" : "Crash Detected!" (not sure why it ends with \x04...)

#### Feedback => Gluttony Control Messages
* "\x03\x00\x00\x00\x00" : "New fuzz case being sent over"
* "\x06\x00\x00\x00\x00" : "Yo Gluttony, please start tracking new basic blocks." 
