# Spectre-attack

Performed a Spectre-attack in the virtual environment.

* Based on branch prediction & cache position.
  
## Spectre-attack

<img src="Animation.gif" width="300" height="200" />

## Solution

Add Assembler code

    asm volatile ("lfence":::"memory");

to prevent branch prediction.

<img src="Solution.gif" width="300" height="200" />