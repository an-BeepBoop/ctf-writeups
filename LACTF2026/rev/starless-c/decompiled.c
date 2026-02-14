typedef struct sigaction {
} sigaction;

void _start(void)
{
    sigaction handler;  
    char v1;  
    const char* message = 
            "There is a flag in the binary.\n"
            "(The flag is a metaphor but also still a flag.)\n"
            "  (The binary could rightly be considered a gimmick.)\n";
    // write(STDOUT, message, 135)
    write(STDOUT, message, 135);
    *((void* *)&handler) = segfault_handler;
    v1 = 4;
    // rt_sigaction(SIGSEGV, segfault_handler)
    rt_sigaction(11, &handler, NULL, 8);
    sub_6767900c();
    return;
}

void segfault_handler(void)
{
    const char *message = "And so the son of the fortune-teller does not find his way to"
                          "the Starless C. Not yet.\n";
    write(STDOUT, message, 87);
    // Stops the program
    exit(1); 
}

void sub_42069000(void)
{
    char v0[8];
    const char *path = "flag.txt";
    const char *message =
      "A person this far into a challenge has their path to follow. There were many"
      "paths, once, in a time that is past, lost many bytes and pages ago. Now there"
      "is only one path for you to choose. The path that leads to the flag.\n"
    write(STDOUT, message, 224);
    strncpy(v1, "flag.txt", 8);
    // send the contents (0x100 bytes) of  flag.txt to STDOUT
    sendfile(STDOUT, open(&v0, O_RDONLY, 224), NULL, 0x100);
    exit(0); /* do not return */
}

void sub_6767900C()
{
  signed __int64 v0; // rax
  int v1; // eax
  int v2; // eax
  int v3; // eax
  int v4; // eax
  signed __int64 v5; // rax
  int v6; // eax
  int v7; // eax
  int v8; // eax
  int v9; // eax
  signed __int64 v10; // rax
  int v11; // eax
  int v12; // eax
  int v13; // eax
  int v14; // eax
  signed __int64 v15; // rax
  int v16; // eax
  int v17; // eax
  int v18; // eax
  int v19; // eax
  signed __int64 v20; // rax
  int v21; // eax
  int v22; // eax
  int v23; // eax
  int v24; // eax
  signed __int64 v25; // rax
  int v26; // eax
  int v27; // eax
  int v28; // eax
  int v29; // eax
  signed __int64 v30; // rax
  int v31; // eax
  int v32; // eax
  int v33; // eax
  int v34; // eax
  signed __int64 v35; // rax
  int v36; // eax
  int v37; // eax
  int v38; // eax
  int v39; // eax
  signed __int64 v40; // rax
  int v41; // eax
  int v42; // eax
  int v43; // eax
  int v44; // eax
  signed __int64 v45; // rax
  int v46; // eax
  int v47; // eax
  int v48; // eax
  int v49; // eax
  signed __int64 v50; // rax
  int v51; // eax
  int v52; // eax
  int v53; // eax
  int v54; // eax
  signed __int64 v55; // rax
  int v56; // eax
  int v57; // eax
  int v58; // eax
  int v59; // eax
  signed __int64 v60; // rax
  int v61; // eax
  int v62; // eax
  int v63; // eax
  int v64; // eax
  signed __int64 v65; // rax
  int v66; // eax
  int v67; // eax
  int v68; // eax
  int v69; // eax
  signed __int64 v70; // rax
  int v71; // eax
  int v72; // eax
  int v73; // eax
  int v74; // eax
  signed __int64 v75; // rax
  int v76; // eax
  int v77; // eax
  int v78; // eax
  int v79; // eax
  signed __int64 v80; // rax
  int v81; // eax
  int v82; // eax
  int v83; // eax
  int v84; // eax
  signed __int64 v85; // rax
  int v86; // eax
  int v87; // eax
  int v88; // eax
  int v89; // eax
  signed __int64 v90; // rax
  int v91; // eax
  int v92; // eax
  int v93; // eax
  int v94; // eax
  signed __int64 v95; // rax
  int v96; // eax
  int v97; // eax
  int v98; // eax
  int v99; // eax
  signed __int64 v100; // rax
  int v101; // eax
  int v102; // eax
  int v103; // eax
  int v104; // eax
  signed __int64 v105; // rax
  int v106; // eax
  int v107; // eax
  int v108; // eax
  int v109; // eax
  signed __int64 v110; // rax
  int v111; // eax
  int v112; // eax
  int v113; // eax
  int v114; // eax
  _UNKNOWN *retaddr; // [rsp+0h] [rbp+0h] BYREF

  while ( 1 )
  {
    while ( 1 )
    {
      do
        v0 = sys_read(0, (char *)&retaddr, 1u);
      while ( (_BYTE)retaddr == 10 );
      if ( (_BYTE)retaddr == 119 )
        goto LABEL_8;
      if ( (_BYTE)retaddr != 115 )
        break;
      v2 = dword_67681000;
      if ( (_BYTE)dword_67681000 == 0x90 )
      {
        dword_67681000 = 8962097;
        dword_67689000 = v2;
      }
      while ( 1 )
      {
        do
LABEL_41:
          v10 = sys_read(0, (char *)&retaddr, 1u);
        while ( (_BYTE)retaddr == 10 );
        if ( (_BYTE)retaddr == 119 )
          goto LABEL_48;
        if ( (_BYTE)retaddr != 115 )
          break;
        v12 = dword_67689000;
        if ( (_BYTE)dword_67689000 == 0x90 )
        {
          dword_67689000 = 8962097;
          dword_67691000 = v12;
        }
        do
LABEL_141:
          v35 = sys_read(0, (char *)&retaddr, 1u);
        while ( (_BYTE)retaddr == 10 );
        if ( (_BYTE)retaddr != 119 )
        {
          switch ( (_BYTE)retaddr )
          {
            case 's':
              v37 = dword_67691000;
              if ( (_BYTE)dword_67691000 == 0x90 )
              {
                dword_67691000 = 8962097;
                dword_67699000 = v37;
              }
              goto LABEL_241;
            case 'a':
              v38 = MEMORY[0x67688000];
              if ( MEMORY[0x67688000] == 0x90 )
              {
                MEMORY[0x67688000] = 8962097;
                MEMORY[0x67687000] = v38;
              }
              JUMPOUT(0x6768800C);
            case 'd':
              v39 = dword_6768A000;
              if ( (_BYTE)dword_6768A000 == 0x90 )
              {
                dword_6768A000 = 8962097;
                dword_6768B000 = v39;
              }
              goto LABEL_161;
            case 'f':
              goto LABEL_463;
          }
          MEMORY[0] = 0;
        }
        v36 = dword_67681000;
        if ( (_BYTE)dword_67681000 == 0x90 )
        {
          dword_67681000 = 8962097;
          dword_67679000 = v36;
        }
      }
      switch ( (_BYTE)retaddr )
      {
        case 'a':
          v13 = MEMORY[0x67680000];
          if ( MEMORY[0x67680000] == 0x90 )
          {
            MEMORY[0x67680000] = 8962097;
            MEMORY[0x6767F000] = v13;
          }
          JUMPOUT(0x6768000C);
        case 'd':
          v14 = dword_67682000;
          if ( (_BYTE)dword_67682000 == 0x90 )
          {
            dword_67682000 = 8962097;
            dword_67683000 = v14;
          }
          goto LABEL_61;
        case 'f':
          goto LABEL_463;
      }
      MEMORY[0] = 0;
LABEL_48:
      v11 = dword_67679000;
      if ( (_BYTE)dword_67679000 == 0x90 )
      {
        dword_67679000 = 8962097;
        MEMORY[0x67671000] = v11;
      }
    }
    if ( (_BYTE)retaddr == 97 )
    {
      v3 = MEMORY[0x67678000];
      if ( MEMORY[0x67678000] == 0x90 )
      {
        MEMORY[0x67678000] = 8962097;
        MEMORY[0x67677000] = v3;
      }
      JUMPOUT(0x6767800C);
    }
    if ( (_BYTE)retaddr != 100 )
    {
      if ( (_BYTE)retaddr == 102 )
        goto LABEL_463;
      MEMORY[0] = 0;
LABEL_8:
      v1 = MEMORY[0x67671000];
      if ( MEMORY[0x67671000] == 0x90 )
      {
        MEMORY[0x67671000] = 8962097;
        MEMORY[0x67669000] = v1;
      }
      JUMPOUT(0x6767100C);
    }
    v4 = dword_6767A000;
    if ( (_BYTE)dword_6767A000 == 0x90 )
    {
      dword_6767A000 = 8962097;
      MEMORY[0x6767B000] = v4;
    }
    while ( 1 )
    {
      do
        v5 = sys_read(0, (char *)&retaddr, 1u);
      while ( (_BYTE)retaddr == 10 );
      if ( (_BYTE)retaddr == 119 )
        goto LABEL_28;
      if ( (_BYTE)retaddr != 115 )
        break;
      v7 = dword_67682000;
      if ( (_BYTE)dword_67682000 == 0x90 )
      {
        dword_67682000 = 8962097;
        dword_6768A000 = v7;
      }
      while ( 1 )
      {
        while ( 1 )
        {
          do
LABEL_61:
            v15 = sys_read(0, (char *)&retaddr, 1u);
          while ( (_BYTE)retaddr == 10 );
          if ( (_BYTE)retaddr == 119 )
            goto LABEL_68;
          if ( (_BYTE)retaddr != 115 )
            break;
          v17 = dword_6768A000;
          if ( (_BYTE)dword_6768A000 == 0x90 )
          {
            dword_6768A000 = 8962097;
            dword_67692000 = v17;
          }
          while ( 1 )
          {
            do
LABEL_161:
              v40 = sys_read(0, (char *)&retaddr, 1u);
            while ( (_BYTE)retaddr == 10 );
            if ( (_BYTE)retaddr == 119 )
              goto LABEL_168;
            if ( (_BYTE)retaddr != 115 )
              break;
            v42 = dword_67692000;
            if ( (_BYTE)dword_67692000 == 0x90 )
            {
              dword_67692000 = 8962097;
              dword_6769A000 = v42;
            }
            do
LABEL_261:
              v65 = sys_read(0, (char *)&retaddr, 1u);
            while ( (_BYTE)retaddr == 10 );
            if ( (_BYTE)retaddr != 119 )
            {
              switch ( (_BYTE)retaddr )
              {
                case 's':
                  v67 = dword_6769A000;
                  if ( (_BYTE)dword_6769A000 == 0x90 )
                  {
                    dword_6769A000 = 8962097;
                    MEMORY[0x676A2000] = v67;
                  }
                  goto LABEL_361;
                case 'a':
                  v68 = dword_67691000;
                  if ( (_BYTE)dword_67691000 == 0x90 )
                  {
                    dword_67691000 = 8962097;
                    MEMORY[0x67690000] = v68;
                  }
                  goto LABEL_241;
                case 'd':
                  v69 = MEMORY[0x67693000];
                  if ( MEMORY[0x67693000] == 0x90 )
                  {
                    MEMORY[0x67693000] = 8962097;
                    dword_67694000 = v69;
                  }
                  goto LABEL_471;
                case 'f':
                  goto LABEL_463;
              }
              MEMORY[0] = 0;
            }
            v66 = dword_6768A000;
            if ( (_BYTE)dword_6768A000 == 0x90 )
            {
              dword_6768A000 = 8962097;
              dword_67682000 = v66;
            }
          }
          switch ( (_BYTE)retaddr )
          {
            case 'a':
              v43 = dword_67689000;
              if ( (_BYTE)dword_67689000 == 0x90 )
              {
                dword_67689000 = 8962097;
                MEMORY[0x67688000] = v43;
              }
              goto LABEL_141;
            case 'd':
              v44 = dword_6768B000;
              if ( (_BYTE)dword_6768B000 == 0x90 )
              {
                dword_6768B000 = 8962097;
                dword_6768C000 = v44;
              }
              goto LABEL_181;
            case 'f':
              goto LABEL_463;
          }
          MEMORY[0] = 0;
LABEL_168:
          v41 = dword_67682000;
          if ( (_BYTE)dword_67682000 == 0x90 )
          {
            dword_67682000 = 8962097;
            dword_6767A000 = v41;
          }
        }
        if ( (_BYTE)retaddr == 97 )
        {
          v18 = dword_67681000;
          if ( (_BYTE)dword_67681000 == 0x90 )
          {
            dword_67681000 = 8962097;
            MEMORY[0x67680000] = v18;
          }
          goto LABEL_41;
        }
        if ( (_BYTE)retaddr != 100 )
          break;
        v19 = dword_67683000;
        if ( (_BYTE)dword_67683000 == 0x90 )
        {
          dword_67683000 = 8962097;
          dword_67684000 = v19;
        }
        while ( 1 )
        {
          while ( 1 )
          {
            do
              v20 = sys_read(0, (char *)&retaddr, 1u);
            while ( (_BYTE)retaddr == 10 );
            if ( (_BYTE)retaddr == 119 )
              goto LABEL_88;
            if ( (_BYTE)retaddr != 115 )
              break;
            v22 = dword_6768B000;
            if ( (_BYTE)dword_6768B000 == 0x90 )
            {
              dword_6768B000 = 8962097;
              MEMORY[0x67693000] = v22;
            }
            while ( 1 )
            {
              do
LABEL_181:
                v45 = sys_read(0, (char *)&retaddr, 1u);
              while ( (_BYTE)retaddr == 10 );
              switch ( (_BYTE)retaddr )
              {
                case 'w':
                  goto LABEL_188;
                case 's':
                  v47 = MEMORY[0x67693000];
                  if ( MEMORY[0x67693000] == 0x90 )
                  {
                    MEMORY[0x67693000] = 8962097;
                    dword_6769B000 = v47;
                  }
                  goto LABEL_471;
                case 'a':
                  v48 = dword_6768A000;
                  if ( (_BYTE)dword_6768A000 == 0x90 )
                  {
                    dword_6768A000 = 8962097;
                    dword_67689000 = v48;
                  }
                  goto LABEL_161;
              }
              if ( (_BYTE)retaddr != 100 )
                break;
              v49 = dword_6768C000;
              if ( (_BYTE)dword_6768C000 == 0x90 )
              {
                dword_6768C000 = 8962097;
                dword_6768D000 = v49;
              }
              while ( 1 )
              {
                do
LABEL_201:
                  v50 = sys_read(0, (char *)&retaddr, 1u);
                while ( (_BYTE)retaddr == 10 );
                if ( (_BYTE)retaddr == 119 )
                  goto LABEL_208;
                if ( (_BYTE)retaddr != 115 )
                  break;
                v52 = dword_67694000;
                if ( (_BYTE)dword_67694000 == 0x90 )
                {
                  dword_67694000 = 8962097;
                  dword_6769C000 = v52;
                }
                while ( 1 )
                {
                  do
LABEL_281:
                    v70 = sys_read(0, (char *)&retaddr, 1u);
                  while ( (_BYTE)retaddr == 10 );
                  if ( (_BYTE)retaddr == 119 )
                    goto LABEL_288;
                  if ( (_BYTE)retaddr != 115 )
                    break;
                  v72 = dword_6769C000;
                  if ( (_BYTE)dword_6769C000 == 0x90 )
                  {
                    dword_6769C000 = 8962097;
                    MEMORY[0x676A4000] = v72;
                  }
                  while ( 1 )
                  {
                    do
LABEL_401:
                      v100 = sys_read(0, (char *)&retaddr, 1u);
                    while ( (_BYTE)retaddr == 10 );
                    switch ( (_BYTE)retaddr )
                    {
                      case 'w':
                        goto LABEL_408;
                      case 's':
                        v102 = MEMORY[0x676A4000];
                        if ( MEMORY[0x676A4000] == 0x90 )
                        {
                          MEMORY[0x676A4000] = 8962097;
                          MEMORY[0x676AC000] = v102;
                        }
                        JUMPOUT(0x676A400C);
                      case 'a':
                        v103 = dword_6769B000;
                        if ( (_BYTE)dword_6769B000 == 0x90 )
                        {
                          dword_6769B000 = 8962097;
                          dword_6769A000 = v103;
                        }
                        while ( 1 )
                        {
                          do
                            v95 = sys_read(0, (char *)&retaddr, 1u);
                          while ( (_BYTE)retaddr == 10 );
                          if ( (_BYTE)retaddr == 119 )
                            goto LABEL_388;
                          if ( (_BYTE)retaddr == 115 )
                          {
                            v97 = MEMORY[0x676A3000];
                            if ( MEMORY[0x676A3000] == 0x90 )
                            {
                              MEMORY[0x676A3000] = 8962097;
                              MEMORY[0x676AB000] = v97;
                            }
                            JUMPOUT(0x676A300C);
                          }
                          if ( (_BYTE)retaddr != 97 )
                            break;
                          v98 = dword_6769A000;
                          if ( (_BYTE)dword_6769A000 == 0x90 )
                          {
                            dword_6769A000 = 8962097;
                            dword_67699000 = v98;
                          }
                          do
LABEL_361:
                            v90 = sys_read(0, (char *)&retaddr, 1u);
                          while ( (_BYTE)retaddr == 10 );
                          switch ( (_BYTE)retaddr )
                          {
                            case 'w':
                              goto LABEL_368;
                            case 's':
                              v92 = MEMORY[0x676A2000];
                              if ( MEMORY[0x676A2000] == 0x90 )
                              {
                                MEMORY[0x676A2000] = 8962097;
                                MEMORY[0x676AA000] = v92;
                              }
                              JUMPOUT(0x676A200C);
                            case 'a':
                              v93 = dword_67699000;
                              if ( (_BYTE)dword_67699000 == 0x90 )
                              {
                                dword_67699000 = 8962097;
                                MEMORY[0x67698000] = v93;
                              }
                              while ( 1 )
                              {
                                do
                                  v85 = sys_read(0, (char *)&retaddr, 1u);
                                while ( (_BYTE)retaddr == 10 );
                                if ( (_BYTE)retaddr != 119 )
                                {
                                  switch ( (_BYTE)retaddr )
                                  {
                                    case 's':
                                      v87 = MEMORY[0x676A1000];
                                      if ( MEMORY[0x676A1000] == 0x90 )
                                      {
                                        MEMORY[0x676A1000] = 8962097;
                                        MEMORY[0x676A9000] = v87;
                                      }
                                      JUMPOUT(0x676A100C);
                                    case 'a':
                                      v88 = MEMORY[0x67698000];
                                      if ( MEMORY[0x67698000] == 0x90 )
                                      {
                                        MEMORY[0x67698000] = 8962097;
                                        MEMORY[0x67697000] = v88;
                                      }
                                      JUMPOUT(0x6769800C);
                                    case 'd':
                                      v89 = dword_6769A000;
                                      if ( (_BYTE)dword_6769A000 == 0x90 )
                                      {
                                        dword_6769A000 = 8962097;
                                        dword_6769B000 = v89;
                                      }
                                      goto LABEL_361;
                                    case 'f':
                                      goto LABEL_463;
                                  }
                                  MEMORY[0] = 0;
                                }
                                v86 = dword_67691000;
                                if ( (_BYTE)dword_67691000 == 0x90 )
                                {
                                  dword_67691000 = 8962097;
                                  dword_67689000 = v86;
                                }
                                do
LABEL_241:
                                  v60 = sys_read(0, (char *)&retaddr, 1u);
                                while ( (_BYTE)retaddr == 10 );
                                if ( (_BYTE)retaddr == 119 )
                                  goto LABEL_248;
                                if ( (_BYTE)retaddr != 115 )
                                  break;
                                v62 = dword_67699000;
                                if ( (_BYTE)dword_67699000 == 0x90 )
                                {
                                  dword_67699000 = 8962097;
                                  MEMORY[0x676A1000] = v62;
                                }
                              }
                              switch ( (_BYTE)retaddr )
                              {
                                case 'a':
                                  v63 = MEMORY[0x67690000];
                                  if ( MEMORY[0x67690000] == 0x90 )
                                  {
                                    MEMORY[0x67690000] = 8962097;
                                    MEMORY[0x6768F000] = v63;
                                  }
                                  JUMPOUT(0x6769000C);
                                case 'd':
                                  v64 = dword_67692000;
                                  if ( (_BYTE)dword_67692000 == 0x90 )
                                  {
                                    dword_67692000 = 8962097;
                                    MEMORY[0x67693000] = v64;
                                  }
                                  goto LABEL_261;
                                case 'f':
                                  goto LABEL_463;
                              }
                              MEMORY[0] = 0;
LABEL_248:
                              v61 = dword_67689000;
                              if ( (_BYTE)dword_67689000 == 0x90 )
                              {
                                dword_67689000 = 8962097;
                                dword_67681000 = v61;
                              }
                              goto LABEL_141;
                          }
                          if ( (_BYTE)retaddr != 100 )
                          {
                            if ( (_BYTE)retaddr == 102 )
                              goto LABEL_463;
                            MEMORY[0] = 0;
LABEL_368:
                            v91 = dword_67692000;
                            if ( (_BYTE)dword_67692000 == 0x90 )
                            {
                              dword_67692000 = 8962097;
                              dword_6768A000 = v91;
                            }
                            goto LABEL_261;
                          }
                          v94 = dword_6769B000;
                          if ( (_BYTE)dword_6769B000 == 0x90 )
                          {
                            dword_6769B000 = 8962097;
                            dword_6769C000 = v94;
                          }
                        }
                        if ( (_BYTE)retaddr == 100 )
                        {
                          v99 = dword_6769C000;
                          if ( (_BYTE)dword_6769C000 == 0x90 )
                          {
                            dword_6769C000 = 8962097;
                            dword_6769D000 = v99;
                          }
                          goto LABEL_401;
                        }
                        if ( (_BYTE)retaddr == 102 )
                          goto LABEL_463;
                        MEMORY[0] = 0;
LABEL_388:
                        v96 = MEMORY[0x67693000];
                        if ( MEMORY[0x67693000] == 0x90 )
                        {
                          MEMORY[0x67693000] = 8962097;
                          dword_6768B000 = v96;
                        }
LABEL_471:
                        JUMPOUT(0x6769300C);
                    }
                    if ( (_BYTE)retaddr != 100 )
                      break;
                    v104 = dword_6769D000;
                    if ( (_BYTE)dword_6769D000 == 0x90 )
                    {
                      dword_6769D000 = 8962097;
                      dword_6769E000 = v104;
                    }
                    while ( 1 )
                    {
                      do
LABEL_421:
                        v105 = sys_read(0, (char *)&retaddr, 1u);
                      while ( (_BYTE)retaddr == 10 );
                      if ( (_BYTE)retaddr == 119 )
                        goto LABEL_428;
                      if ( (_BYTE)retaddr == 115 )
                      {
                        v107 = MEMORY[0x676A5000];
                        if ( MEMORY[0x676A5000] == 0x90 )
                        {
                          MEMORY[0x676A5000] = 8962097;
                          MEMORY[0x676AD000] = v107;
                        }
                        JUMPOUT(0x676A500C);
                      }
                      if ( (_BYTE)retaddr == 97 )
                        break;
                      if ( (_BYTE)retaddr != 100 )
                      {
                        if ( (_BYTE)retaddr != 102 )
                        {
                          MEMORY[0] = 0;
LABEL_428:
                          v106 = dword_67695000;
                          if ( (_BYTE)dword_67695000 == 0x90 )
                          {
                            dword_67695000 = 8962097;
                            dword_6768D000 = v106;
                          }
                          goto LABEL_301;
                        }
LABEL_463:
                        JUMPOUT(0x6767A000);
                      }
                      v109 = dword_6769E000;
                      if ( (_BYTE)dword_6769E000 == 0x90 )
                      {
                        dword_6769E000 = 8962097;
                        MEMORY[0x6769F000] = v109;
                      }
                      do
LABEL_441:
                        v110 = sys_read(0, (char *)&retaddr, 1u);
                      while ( (_BYTE)retaddr == 10 );
                      if ( (_BYTE)retaddr == 119 )
                        goto LABEL_448;
                      if ( (_BYTE)retaddr == 115 )
                      {
                        v112 = MEMORY[0x676A6000];
                        if ( MEMORY[0x676A6000] == 0x90 )
                        {
                          MEMORY[0x676A6000] = 8962097;
                          MEMORY[0x676AE000] = v112;
                        }
                        JUMPOUT(0x676A600C);
                      }
                      if ( (_BYTE)retaddr != 97 )
                      {
                        if ( (_BYTE)retaddr == 100 )
                        {
                          v114 = MEMORY[0x6769F000];
                          if ( MEMORY[0x6769F000] == 0x90 )
                          {
                            MEMORY[0x6769F000] = 8962097;
                            MEMORY[0x676A0000] = v114;
                          }
                          JUMPOUT(0x6769F00C);
                        }
                        if ( (_BYTE)retaddr != 102 )
                        {
                          MEMORY[0] = 0;
LABEL_448:
                          v111 = dword_67696000;
                          if ( (_BYTE)dword_67696000 == 0x90 )
                          {
                            dword_67696000 = 8962097;
                            MEMORY[0x6768E000] = v111;
                          }
                          goto LABEL_321;
                        }
                        goto LABEL_463;
                      }
                      v113 = dword_6769D000;
                      if ( (_BYTE)dword_6769D000 == 0x90 )
                      {
                        dword_6769D000 = 8962097;
                        dword_6769C000 = v113;
                      }
                    }
                    v108 = dword_6769C000;
                    if ( (_BYTE)dword_6769C000 == 0x90 )
                    {
                      dword_6769C000 = 8962097;
                      dword_6769B000 = v108;
                    }
                  }
                  if ( (_BYTE)retaddr == 102 )
                    goto LABEL_463;
                  MEMORY[0] = 0;
LABEL_408:
                  v101 = dword_67694000;
                  if ( (_BYTE)dword_67694000 == 0x90 )
                  {
                    dword_67694000 = 8962097;
                    dword_6768C000 = v101;
                  }
                }
                switch ( (_BYTE)retaddr )
                {
                  case 'a':
                    v73 = MEMORY[0x67693000];
                    if ( MEMORY[0x67693000] == 0x90 )
                    {
                      MEMORY[0x67693000] = 8962097;
                      dword_67692000 = v73;
                    }
                    goto LABEL_471;
                  case 'd':
                    v74 = dword_67695000;
                    if ( (_BYTE)dword_67695000 == 0x90 )
                    {
                      dword_67695000 = 8962097;
                      dword_67696000 = v74;
                    }
                    goto LABEL_301;
                  case 'f':
                    goto LABEL_463;
                }
                MEMORY[0] = 0;
LABEL_288:
                v71 = dword_6768C000;
                if ( (_BYTE)dword_6768C000 == 0x90 )
                {
                  dword_6768C000 = 8962097;
                  dword_67684000 = v71;
                }
              }
              if ( (_BYTE)retaddr != 97 )
              {
                if ( (_BYTE)retaddr == 100 )
                {
                  v54 = dword_6768D000;
                  if ( (_BYTE)dword_6768D000 == 0x90 )
                  {
                    dword_6768D000 = 8962097;
                    MEMORY[0x6768E000] = v54;
                  }
                  goto LABEL_221;
                }
                if ( (_BYTE)retaddr == 102 )
                  goto LABEL_463;
                MEMORY[0] = 0;
LABEL_208:
                v51 = dword_67684000;
                if ( (_BYTE)dword_67684000 == 0x90 )
                {
                  dword_67684000 = 8962097;
                  MEMORY[0x6767C000] = v51;
                }
                goto LABEL_101;
              }
              v53 = dword_6768B000;
              if ( (_BYTE)dword_6768B000 == 0x90 )
              {
                dword_6768B000 = 8962097;
                dword_6768A000 = v53;
              }
            }
            if ( (_BYTE)retaddr == 102 )
              goto LABEL_463;
            MEMORY[0] = 0;
LABEL_188:
            v46 = dword_67683000;
            if ( (_BYTE)dword_67683000 == 0x90 )
            {
              dword_67683000 = 8962097;
              MEMORY[0x6767B000] = v46;
            }
          }
          if ( (_BYTE)retaddr == 97 )
            break;
          if ( (_BYTE)retaddr != 100 )
          {
            if ( (_BYTE)retaddr == 102 )
              goto LABEL_463;
            MEMORY[0] = 0;
LABEL_88:
            v21 = MEMORY[0x6767B000];
            if ( MEMORY[0x6767B000] == 0x90 )
            {
              MEMORY[0x6767B000] = 8962097;
              MEMORY[0x67673000] = v21;
            }
LABEL_465:
            JUMPOUT(0x6767B00C);
          }
          v24 = dword_67684000;
          if ( (_BYTE)dword_67684000 == 0x90 )
          {
            dword_67684000 = 8962097;
            dword_67685000 = v24;
          }
          while ( 1 )
          {
            do
LABEL_101:
              v25 = sys_read(0, (char *)&retaddr, 1u);
            while ( (_BYTE)retaddr == 10 );
            if ( (_BYTE)retaddr == 119 )
              goto LABEL_108;
            if ( (_BYTE)retaddr == 115 )
            {
              v27 = dword_6768C000;
              if ( (_BYTE)dword_6768C000 == 0x90 )
              {
                dword_6768C000 = 8962097;
                dword_67694000 = v27;
              }
              goto LABEL_201;
            }
            if ( (_BYTE)retaddr == 97 )
              break;
            if ( (_BYTE)retaddr != 100 )
            {
              if ( (_BYTE)retaddr == 102 )
                goto LABEL_463;
              MEMORY[0] = 0;
LABEL_108:
              v26 = MEMORY[0x6767C000];
              if ( MEMORY[0x6767C000] == 0x90 )
              {
                MEMORY[0x6767C000] = 8962097;
                MEMORY[0x67674000] = v26;
              }
              JUMPOUT(0x6767C00C);
            }
            v29 = dword_67685000;
            if ( (_BYTE)dword_67685000 == 0x90 )
            {
              dword_67685000 = 8962097;
              MEMORY[0x67686000] = v29;
            }
            while ( 1 )
            {
              do
                v30 = sys_read(0, (char *)&retaddr, 1u);
              while ( (_BYTE)retaddr == 10 );
              if ( (_BYTE)retaddr == 119 )
                goto LABEL_128;
              if ( (_BYTE)retaddr != 115 )
                break;
              v32 = dword_6768D000;
              if ( (_BYTE)dword_6768D000 == 0x90 )
              {
                dword_6768D000 = 8962097;
                dword_67695000 = v32;
              }
              while ( 1 )
              {
                do
LABEL_221:
                  v55 = sys_read(0, (char *)&retaddr, 1u);
                while ( (_BYTE)retaddr == 10 );
                if ( (_BYTE)retaddr == 119 )
                  goto LABEL_228;
                if ( (_BYTE)retaddr != 115 )
                  break;
                v57 = dword_67695000;
                if ( (_BYTE)dword_67695000 == 0x90 )
                {
                  dword_67695000 = 8962097;
                  dword_6769D000 = v57;
                }
                while ( 1 )
                {
                  do
LABEL_301:
                    v75 = sys_read(0, (char *)&retaddr, 1u);
                  while ( (_BYTE)retaddr == 10 );
                  switch ( (_BYTE)retaddr )
                  {
                    case 'w':
                      goto LABEL_308;
                    case 's':
                      v77 = dword_6769D000;
                      if ( (_BYTE)dword_6769D000 == 0x90 )
                      {
                        dword_6769D000 = 8962097;
                        MEMORY[0x676A5000] = v77;
                      }
                      goto LABEL_421;
                    case 'a':
                      v78 = dword_67694000;
                      if ( (_BYTE)dword_67694000 == 0x90 )
                      {
                        dword_67694000 = 8962097;
                        MEMORY[0x67693000] = v78;
                      }
                      goto LABEL_281;
                  }
                  if ( (_BYTE)retaddr != 100 )
                    break;
                  v79 = dword_67696000;
                  if ( (_BYTE)dword_67696000 == 0x90 )
                  {
                    dword_67696000 = 8962097;
                    MEMORY[0x67697000] = v79;
                  }
                  do
LABEL_321:
                    v80 = sys_read(0, (char *)&retaddr, 1u);
                  while ( (_BYTE)retaddr == 10 );
                  if ( (_BYTE)retaddr == 119 )
                    goto LABEL_328;
                  if ( (_BYTE)retaddr == 115 )
                  {
                    v82 = dword_6769E000;
                    if ( (_BYTE)dword_6769E000 == 0x90 )
                    {
                      dword_6769E000 = 8962097;
                      MEMORY[0x676A6000] = v82;
                    }
                    goto LABEL_441;
                  }
                  if ( (_BYTE)retaddr != 97 )
                  {
                    if ( (_BYTE)retaddr == 100 )
                    {
                      v84 = MEMORY[0x67697000];
                      if ( MEMORY[0x67697000] == 0x90 )
                      {
                        MEMORY[0x67697000] = 8962097;
                        MEMORY[0x67698000] = v84;
                      }
                      JUMPOUT(0x6769700C);
                    }
                    if ( (_BYTE)retaddr == 102 )
                      goto LABEL_463;
                    MEMORY[0] = 0;
LABEL_328:
                    v81 = MEMORY[0x6768E000];
                    if ( MEMORY[0x6768E000] == 0x90 )
                    {
                      MEMORY[0x6768E000] = 8962097;
                      MEMORY[0x67686000] = v81;
                    }
LABEL_472:
                    JUMPOUT(0x6768E00C);
                  }
                  v83 = dword_67695000;
                  if ( (_BYTE)dword_67695000 == 0x90 )
                  {
                    dword_67695000 = 8962097;
                    dword_67694000 = v83;
                  }
                }
                if ( (_BYTE)retaddr == 102 )
                  goto LABEL_463;
                MEMORY[0] = 0;
LABEL_308:
                v76 = dword_6768D000;
                if ( (_BYTE)dword_6768D000 == 0x90 )
                {
                  dword_6768D000 = 8962097;
                  dword_67685000 = v76;
                }
              }
              switch ( (_BYTE)retaddr )
              {
                case 'a':
                  v58 = dword_6768C000;
                  if ( (_BYTE)dword_6768C000 == 0x90 )
                  {
                    dword_6768C000 = 8962097;
                    dword_6768B000 = v58;
                  }
                  goto LABEL_201;
                case 'd':
                  v59 = MEMORY[0x6768E000];
                  if ( MEMORY[0x6768E000] == 0x90 )
                  {
                    MEMORY[0x6768E000] = 8962097;
                    MEMORY[0x6768F000] = v59;
                  }
                  goto LABEL_472;
                case 'f':
                  goto LABEL_463;
              }
              MEMORY[0] = 0;
LABEL_228:
              v56 = dword_67685000;
              if ( (_BYTE)dword_67685000 == 0x90 )
              {
                dword_67685000 = 8962097;
                MEMORY[0x6767D000] = v56;
              }
            }
            if ( (_BYTE)retaddr != 97 )
            {
              if ( (_BYTE)retaddr == 100 )
              {
                v34 = MEMORY[0x67686000];
                if ( MEMORY[0x67686000] == 0x90 )
                {
                  MEMORY[0x67686000] = 8962097;
                  MEMORY[0x67687000] = v34;
                }
                JUMPOUT(0x6768600C);
              }
              if ( (_BYTE)retaddr == 102 )
                goto LABEL_463;
              MEMORY[0] = 0;
LABEL_128:
              v31 = MEMORY[0x6767D000];
              if ( MEMORY[0x6767D000] == 0x90 )
              {
                MEMORY[0x6767D000] = 8962097;
                MEMORY[0x67675000] = v31;
              }
              JUMPOUT(0x6767D00C);
            }
            v33 = dword_67684000;
            if ( (_BYTE)dword_67684000 == 0x90 )
            {
              dword_67684000 = 8962097;
              dword_67683000 = v33;
            }
          }
          v28 = dword_67683000;
          if ( (_BYTE)dword_67683000 == 0x90 )
          {
            dword_67683000 = 8962097;
            dword_67682000 = v28;
          }
        }
        v23 = dword_67682000;
        if ( (_BYTE)dword_67682000 == 0x90 )
        {
          dword_67682000 = 8962097;
          dword_67681000 = v23;
        }
      }
      if ( (_BYTE)retaddr == 102 )
        goto LABEL_463;
      MEMORY[0] = 0;
LABEL_68:
      v16 = dword_6767A000;
      if ( (_BYTE)dword_6767A000 == 0x90 )
      {
        dword_6767A000 = 8962097;
        MEMORY[0x67672000] = v16;
      }
    }
    if ( (_BYTE)retaddr != 97 )
    {
      if ( (_BYTE)retaddr == 100 )
      {
        v9 = MEMORY[0x6767B000];
        if ( MEMORY[0x6767B000] == 0x90 )
        {
          MEMORY[0x6767B000] = 8962097;
          MEMORY[0x6767C000] = v9;
        }
        goto LABEL_465;
      }
      if ( (_BYTE)retaddr == 102 )
        goto LABEL_463;
      MEMORY[0] = 0;
LABEL_28:
      v6 = MEMORY[0x67672000];
      if ( MEMORY[0x67672000] == 0x90 )
      {
        MEMORY[0x67672000] = 8962097;
        MEMORY[0x6766A000] = v6;
      }
      JUMPOUT(0x6767200C);
    }
    v8 = dword_67679000;
    if ( (_BYTE)dword_67679000 == 0x90 )
    {
      dword_67679000 = 8962097;
      MEMORY[0x67678000] = v8;
    }
  }
}
