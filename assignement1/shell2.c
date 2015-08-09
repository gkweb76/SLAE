main()
{
        printf("Shellcode Length:  %d\n", strlen(shellcode));
        int (*ret)() = (int(*)())shellcode;
        ret();
}

