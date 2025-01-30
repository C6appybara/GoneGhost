# PROJECT: *GoneGhost*
![ProcVanish](https://64.media.tumblr.com/d30fe069cc48e11eeb31ae08293a159e/tumblr_nbtdxg9d6n1szf0nzo1_250.gif)

### Description
I have been working on this ring3 rootkit to hide processes, files/folders, registry keys and more. I have took inspiration from **@bytecode77** for his r77 rootkit.
There many more future changes that I want to make but because of my limited time, updates may take some time. 

## **FEATURES:**
- ✅ Hide processes via `NtQuerySystemInformation` hook.
- ✅ Hide Files/Folder via `NtQueryDirectoryFile` hook. (`NtQueryDirectoryFileEx` needs some work.)
- ✅ Hide registry keys from the registry via `NtEnumerateKey` and `NtEnumerateValueKey` hook.
- ✅ Using detours hooking library to hook these functions.
- ✅ Hiding files, folders, registry keys, and processes with prefix.

# Current task
  2. Indirect syscalls. 
  4. `if needed` api hashing
  5. String hashing

# Next up

**Work on evasive payload injector:** 
  1. Shellcode Reflective dll injection.


# Later date


