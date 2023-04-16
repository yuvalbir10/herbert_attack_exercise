import subprocess

print("Compiling...")
result = subprocess.run(["gcc", "-O0", "-std=gnu99", "-g", "alias_experiment.c", "-o", "mypoc"],stdout=subprocess.PIPE, stderr=subprocess.PIPE)
print(result.stdout.decode('utf-8')) # prints the stdout output
print(result.stderr.decode('utf-8')) # prints the stderr output

nAliasedTime = 0
nAliasedForward = 0

nNonAliasedTime = 0
nNonAliasedForward = 0

nNumberOfRuns = 20

print(f'Running average over {nNumberOfRuns} runs...\n')
#Aliased loop
for i in range(nNumberOfRuns):

    result = subprocess.run(["perf", "stat", "-e", "cpu/event=0x7,umask=0x1,name=ld_blocks_partial_address_alias/", "./mypoc" ,'0'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    nAliasedTime += int(result.stdout.decode('utf-8').split()[-1]) # prints the stdout output
    nAliasedForward += int(result.stderr.decode('utf-8').split()[6].replace(",","")) # prints the stderr output

#nonAliased loop
for i in range(nNumberOfRuns):
    result = subprocess.run(["perf", "stat", "-e", "cpu/event=0x7,umask=0x1,name=ld_blocks_partial_address_alias/", "./mypoc", "160"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    nNonAliasedTime += int(result.stdout.decode('utf-8').split()[-1]) # prints the stdout output
    nNonAliasedForward += int(result.stderr.decode('utf-8').split()[6].replace(",","")) # prints the stderr output
    
print(f' 0-Offset Aliasing Run Time: {nAliasedTime/nNumberOfRuns}')
print(f' 0-Offset `perf` Aliasing Counter: {nAliasedForward/nNumberOfRuns}')
print("\n")
print(f' 160-offset Run Time: {nNonAliasedTime/nNumberOfRuns}')
print(f' 160-offset `perf` Aliasing Counter: {nNonAliasedForward/nNumberOfRuns}')

