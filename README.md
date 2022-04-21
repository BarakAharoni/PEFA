# PEFA
PE File Analysis tool

```

██████╗ ███████╗███████╗ █████╗ 
██╔══██╗██╔════╝██╔════╝██╔══██╗
██████╔╝█████╗  █████╗  ███████║
██╔═══╝ ██╔══╝  ██╔══╝  ██╔══██║
██║     ███████╗██║     ██║  ██║
╚═╝     ╚══════╝╚═╝     ╚═╝  ╚═╝    

```

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

![image](https://user-images.githubusercontent.com/97598628/164481871-d9066844-fd6f-4796-8a08-a3695da56aa5.png)

2) Loads the wanted file 
  Press `load` or `l` and enter file's full path.
  ![image](https://user-images.githubusercontent.com/97598628/164482200-986e4195-f1b0-42d1-b151-7f94b6e60f3f.png)
3) Choose your option! 
   You can use the Help menu.
5) `info` 
![image](https://user-images.githubusercontent.com/97598628/164482542-3b9b86da-3cb7-4f60-a8f8-2eb1b17c034d.png)

6) `yara`
![image](https://user-images.githubusercontent.com/97598628/164482884-800ab5ae-0b63-469c-9af8-0b551a2663fa.png)

7) `dis`
![image](https://user-images.githubusercontent.com/97598628/164482959-fa38ce37-6650-4c3d-aa61-bf52feca8930.png)
Allows to reverse-engineer the file start from its entry point, in an interactive disassembler.
![image](https://user-images.githubusercontent.com/97598628/164483197-71788813-c456-49d6-b06c-9aa855f5c364.png)


Copyright (c) 2022 Barak Aharoni.  All Rights Reserved.

