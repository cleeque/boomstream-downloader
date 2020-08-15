# boomstream.com video downloader

The script downloads videos from boomstream.com streaming service.

## Encryption algorithm description

The service stores video chunks encrypted using HLS AES-128 algorithm. In order to decrypt
them AES initialization vector and 128-bit key are required. Initialization vector is encrypted
in the first part of `#EXT-X-MEDIA-READY` variable which is contained in m3u8 playlist using a
simple XOR operation. The key is supposed to be recevied via HTTP using a URL that starts with
`https://play.boomstream.com/api/process/` and contains a long hex key that can be computed
using session token and the second part of `#EXT-X-MEDIA-READY`.

## Usage

Spicify `--url` and `--pin` in command line arguments:

```bash
https://play.boomstream.com/TiAR7aDs?ppv=EswAWlFa --pin 123-456-789
```

You can also specify a resolution using `--resolution` command line argument:

```bash
https://play.boomstream.com/TiAR7aDs?ppv=EswAWlFa --pin 123-456-789 --resolution "640x360"
```

If resolution is not specified, the video with a highest one will be dowloaded.

## Requirements

* openssl
* curl
* python-requests
* lxml
* ffmpeg (for enconding ts -> mp4)

As the script was written and tested in Linux (specifically Ubuntu 18.04.4 LTS) it uses GNU/Linux
`cat` tool to merge the video pieces into one single file. I think this is the only thing that prevents
it from running in Windows. If you have time to make a PR to fix that I will really appreciate.