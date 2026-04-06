# Flag Keeper III

The app is a "flag keeper" service that prompts for a username and password. Looking at the source, the user's intended flow to get the flag is:
1. Authenticate successfully
2. Pass `SecurityCheck.check()`
3. `displayFlag()` gets called

But both steps 2 and 3 are broken on purpose — `SecurityCheck.check()` always returns `false`, and `displayFlag()` just prints `"This method is still under construction!"`. So even with valid credentials, you'd never get the flag through normal use.

**The Credentials**

From `Registry.java`, the credentials for `FK3Auth` are hardcoded as `Foobar`/`test123`. These don't help you get the flag due to the two broken steps above (red herring?).

---

The `FlagContainer` object contains all the metadata regarding storing a flag. Evidently its `toString()` method seems to reconstruct the flag in the format using a `StringBuilder`:`disorientation{` + the `ft` char array + `}`. Notably, it is **Serializable** so it can easily be stored in persistently as bytes in a file. As we are provided a `flag.bin` the obvious train of thought is that its the `FlagContainer` serialized as bytes.

**The Solve**
1. Deserialize `flag.bin` using Java's Serialization API (`ObjectInputStream`)
2. Print the `FlagContainer` object with the flag field.  Note `System.out.println` implicitly calls `toString()` which as mentioned earlier prints the flag in the flag format.

Note:
The `repo.jar` was needed on the classpath so Java could find the `FlagContainer` class definition during deserialization. Without it, Java wouldn't know how to reconstruct the object.

See `Solve.java` for details and compile/run using `run.sh`.
```bash
./run.sh
disorientation{tr*th-s3R1aL!s3d-!@#$%^&*}
```
