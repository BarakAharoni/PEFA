# PEFA
PE File Analysis tool

![image](https://user-images.githubusercontent.com/97598628/164711678-677f8040-4757-462e-b3b1-bc0761078f69.png)


## Capabilities
```
* Load specific file for analysis
* Show important information about the PE file format
* Disassemble compiled executable in an interactive shell
* Find YARA rules that the file is compatible with

```

## Usage
1) Run the tool
` python pefa.py`

2) Loads the wanted file 
  Press `load` or `l` and enter file's full path.
  
  ![image](https://user-images.githubusercontent.com/97598628/164482200-986e4195-f1b0-42d1-b151-7f94b6e60f3f.png)
  
3) Choose your option! 
   You can use the Help menu.
   
5) `info` 

![image](https://user-images.githubusercontent.com/97598628/164711358-a9fabcda-2cca-48d4-ab75-596541ecdd5f.png)

6) `yara`

![image](https://user-images.githubusercontent.com/97598628/164711584-26baf59e-c382-4bc4-9172-8b8822a7f5d7.png)

7) `dis`

![image](https://user-images.githubusercontent.com/97598628/164711525-aa676b17-c59d-41aa-ab56-2ce52caf4649.png)

Allows to reverse-engineer the file start from its entry point, in an interactive disassembler.

![image](https://user-images.githubusercontent.com/97598628/164483197-71788813-c456-49d6-b06c-9aa855f5c364.png)


Copyright (c) 2022 Barak Aharoni.  All Rights Reserved.

