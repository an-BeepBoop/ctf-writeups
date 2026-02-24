# Flag Keeper III

The app is a "flag keeper" service that prompts for a username and password. Looking at the source, the intended flow to get the flag is:
1. Authenticate successfully
2. Pass `SecurityCheck.check()`
3. `displayFlag()` gets called

But both steps 2 and 3 are broken on purpose — `SecurityCheck.check()` always returns `false`, and `displayFlag()` just prints `"This method is still under construction!"`. So even with valid credentials, you'd never get the flag through normal use.

**The Credentials**

From `Registry.java`, the credentials for `FK3Auth` are hardcoded as `Foobar`/`test123`. These are a red herring — they work for authentication but don't help you get the flag due to the two broken steps above.

---

The flag was never in the running application at all — it was sitting in `flag.bin`, a serialized Java object. Java serialization (`ObjectInputStream`) is a way to save a live object to disk and reload it later. The challenge serialized a `FlagContainer` object containing the flag and stored it in this file, presumably for `displayFlag()` to eventually load and print.

**The Solve**

Since `FlagContainer` implements `Serializable` and its `toString()` method builds `disorientation{` + the `ft` char array + `}`, all we had to do was:
1. Deserialize `flag.bin` using `ObjectInputStream`
2. Call `toString()` on the result (which `System.out.println` does automatically)

The `repo.jar` was needed on the classpath so Java could find the `FlagContainer` class definition during deserialization — without it, Java wouldn't know how to reconstruct the object.

See `Solve.java` for details.
```bash
./run.sh
disorientation{tr*th-s3R1aL!s3d-!@#$%^&*}
```
