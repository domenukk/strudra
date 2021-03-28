# Strudra

Welcome to Strudra, a way to craft Ghidra structs in python, using `ghidra_bridge`.

It's quite convenient together with IPython, featuring tab completion, etc.
Also, it can import, and somewhat export (try `.to_cstruct_str()`) c structs from and to Ghidra.

## How Studra Works

Strudra loads all structs from Ghidra. 
For this to work, you have to setup `ghidra_bridge` in Ghidra: https://github.com/justfoxing/ghidra_bridge/

Then, you can create instances of these structs, set values in these structs, and serialize them.
Good if you want to interact with your target.


## How to Strud
First, install using `pip install --user strudra`.
Afterwards, you can init a Strudra object.
For this, you first have to [setup and start `ghidra_bridge`](https://github.com/justfoxing/ghidra_bridge#install-the-ghidra-bridge-package-and-server-scripts) in Ghidra.

Then, you can create a new strudra object.

```python
from strudra import strudra

sd = strudra.Strudra()
```

You can pass in a custom Ghidra Bridge here, if you like.
By default, it will serialize all data received from ghidra to `struds.json`, and reload from there, if Ghidra bridge is not available.
You can pass in a different `filename` to cache to, or `None` to disable caching.
You can even `force_from_file=True`, if you don't want any Ghdira interaction in subsequent runs.

We can now use _all_ structs from Ghidra, but let's add one just for this example.

```python
sd.add_struct("struct test{ int test1; char test2[2]; };")
```
### Creating a Strud
Now, we can access the new `test` struct from ghidra.
We can alread set values in the constructor
```python
test_struct = sd.test(test1=0x1337)
```
We can use struct members by name or by offset
```python
assert (test_struct.test == test_struct[0x0])
```
Arrays work, too!
```python
test_struct.test2 = [0x42, 0x42]
```

Oh, and nested structs are fine as well, just try it! ;)

### Reload
After having reversed new Structs in Ghidra, call `reload` on the `Strudra` object to get the latest updates.

### Serialize
At the end, we can get the serialized bytes back, all members the correct byte order, and use it for example in pwntools.
```
bytes(test_struct)
```

Enjoy a new reverse engineering experience.
