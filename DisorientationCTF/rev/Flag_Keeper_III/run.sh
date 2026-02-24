#!/usr/bin/env bash
javac -d out Solve.java
java -cp out:repo.jar Solve
