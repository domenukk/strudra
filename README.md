# Strudra

Welcome to Strudra, a way to craft Ghidra structs in python, using `ghidra_bridge`.

```python
import strudra
sd = strudra.Strudra()
sd.add_struct("struct test{ int test1; char test2[2]; };")
# We can alread set values in the constructor
test_struct = sd["test"](test1=0x1337)
# We can use struct members by name or by offset
assert (test_struct.test == test_struct[0x0])
# Arrays work, too
test_struct.test2 = [0x42, 0x42]
# At the end, we can get the bytes value back
bytes(test_struct)