# wrapper-z
A tool to decrypt Apple Music's music. An active subscription is required.
Modified by zesty-zesty. Enhanced multi-threading performance and stability.

Verified on listed platform:
1. Linux x86_64
2. macOS arm64
3. windows x86_64
4. windows arm64

# Install
Get the pre-built version from this project's Actions or releases. 

Or you can refer to the Actions configuration file for compilation.

# Run on Docker
Available for x86_64 and arm64.
Need to download prebuilt version from releases or actions.

Build image: `docker build --tag wrapper .`

Login: `docker run -v ./rootfs/data:/app/rootfs/data -p 10020:10020 -p 20020:20020 -e args="-L username:password -F -H 0.0.0.0" wrapper`


# Usage
```
Usage: wrapper [OPTION]...

  -h, --help              Print help and exit
  -V, --version           Print version and exit
  -H, --host=STRING         (default=`127.0.0.1')
  -D, --decrypt-port=INT    (default=`10020')
  -M, --m3u8-port=INT       (default=`20020')
  -P, --proxy=STRING        (default=`')
  -L, --login=STRING        (username:password)
  -F, --code-from-file      (default=off)
```

# Special thanks
- Anonymous, for providing the original version of this project and the legacy Frida decryption method.
- chocomint, for providing support for arm64 arch.
