# Strudra

Welcome to Strudra, a way to craft Ghidra structs in python, using `ghidra_bridge`.

## Example
```python
import strudra
sd = strudra.Strudra()
# We can use _all_ structs from Ghidra, but let's add one just for this example.
sd.add_struct("struct test{ int test1; char test2[2]; };")
# Now you can access the `test` struct from ghidra.
# We can alread set values in the constructor
test_struct = sd["test"](test1=0x1337)
# We can use struct members by name or by offset
assert (test_struct.test == test_struct[0x0])
# Arrays work, too
test_struct.test2 = [0x42, 0x42]
# At the end, we can get the bytes value back
bytes(test_struct)
```

## How studra works

Strudra loads all structs from the Ghidra 
For this to work, you have to setup `ghidra_bridge` in Ghidra: https://github.com/justfoxing/ghidra_bridge/

Then, you can create instances of these structs, set values in these structs, and edit them.
Good if you want to interact with your target.
