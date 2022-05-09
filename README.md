# APKSignReader-Java

A modified [apksig](https://github.com/AndnixSH/apksig) tool to read signature from APK file. This is purposely used for [APKKiller](https://github.com/aimardcr/APKKiller), supports signature scheme v1 and up to v4. Unlike aimardcr's APKSignReader which can run for Android only, this tool can run on PC

### Requirements
- Java 8 or above
- Windows/Linux/macOS (Only tested on Windows)

### Usage
`java -jar APKSignReader.jar (apk file)`

![Screenshot](https://i.imgur.com/ELs1UUh.png)

### How to build JAR file

Use IntelliJ

Build -> Build artifacts... -> Build

When you run JAR file, you may get an error `Exception in thread "main" java.lang.SecurityException: Invalid signature file digest for Manifest main attributes`. You can fix it by opening jar as zip using 7zip
and delete the following files: `META-INF/*.DSA` `META-INF/*.RSA` and `META-INF/*.SF`. Only leave `MANIFEST.MF` alone

If you know a permanent fix or the other way to compile, please let me know

### Credits
- Google: https://android.googlesource.com/platform/tools/apksig/
- aimardcr: https://github.com/aimardcr/APKSignReader