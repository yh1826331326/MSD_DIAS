# **Experimental Procedure**

1）The current code is suitable for ownership management and data auditing.

2）To use `jpbc-2.0.0.tar.gz` as the JPBC library dependency, you need to extract it and import it as a dependency in IntelliJ IDEA.

3）a.properties as curve configuration

4）After the environment is configured, update the file path in each Java source file to your current working directory. To complete the ownership or auditing experiment, run the following classes in sequence: `UKeyGen`, `Encrypted`, `SigmaGen`, `chal`, `Proof`, and `Verify`. The `Deduplication` class implements the data chunk deduplication algorithm.