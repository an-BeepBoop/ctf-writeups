# Grade System v2 Changelog

January 29 2026

## Introducing Grade System v2

As you know, recently, a cyberattack took place against our v1 system. We'd like to thank the smart student who identified the attackers by exploiting another vulnerability on our system. Now that the integrity of students' grades are back, we now introduce grade system v2, which should patch all vulnerabilities involved.

## Changelog 

- All data from the old server has been migrated to this server.
- All grades are now held locally in an array in memory.
- Since grades value from 0 to 100, we implemented simple compression to the data by changing the type of the array to `char` instead of `int`. This means we only need 10,000 bytes rather than 40,000 bytes to hold student grades.
- There are now two access levels: admin/user. Users have read-only access and admins have read/write access.
- Admins require a password to log in, the password is loaded along with the grades in a `struct` when the program is initialised.
- Introduced welcome messages and other messages to guide users and system administrators use the system.