# Strudra

Welcome to Strudra, a way to craft Ghidra structs in python, using `ghidra_bridge`.

## Example
First, init Strudra - you can pass in a custom Ghidra Bridge here, if you like.

```python

from strudra import strudra

sd = strudra.Strudra()
```
We can use _all_ structs from Ghidra, but let's add one just for this example.
```python
sd.add_struct("struct test{ int test1; char test2[2]; };")
```
### Create a Strud
Now, we can access the new `test` struct from ghidra.
We can alread set values in the constructor
```python
test_struct = sd.test(test1=0x1337)
```
### We can use struct members by name or by offset
```python
assert (test_struct.test == test_struct[0x0])
```
### Arrays work, too
```python
test_struct.test2 = [0x42, 0x42]
```
### At the end, we can get the serialized bytes back, all members the correct byte order, and use it for example in pwntools.
```
bytes(test_struct)
```

## How studra works

Strudra loads all structs from the Ghidra 
For this to work, you have to setup `ghidra_bridge` in Ghidra: https://github.com/justfoxing/ghidra_bridge/

Then, you can create instances of these structs, set values in these structs, and edit them.
Good if you want to interact with your target.
