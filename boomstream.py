#!/usr/bin/env python3

import argparse
import json
import os
import re
import sys

from base64 import b64decode
from lxml.html import fromstring
import requests

XOR_KEY = 'bla_bla_bla'

headers = {
  'authority': 'play.boomstream.com',
  'pragma': 'no-cache',
  'cache-control': 'no-cache',
  'upgrade-insecure-requests': '1',
  'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.92 Safari/537.36',
  'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
  'sec-fetch-site': 'none',
  'sec-fetch-mode': 'navigate',
  'sec-fetch-user': '?1',
  'sec-fetch-dest': 'document',
  'accept-language': 'en-US,en;q=0.9,ru;q=0.8,es;q=0.7,de;q=0.6'}


class App(object):

    def __init__(self):
        parser = argparse.ArgumentParser(description='boomstream.com downloader')
        parser.add_argument('--url', type=str, required=True)
        parser.add_argument('--pin', type=str, required=True)
        parser.add_argument('--use-cache', action='store_true', required=False)
        parser.add_argument('--resolution', type=str, required=False)
        self.args = parser.parse_args()

    def get_token(self):
        if 'records' in self.config['mediaData'] and len(self.config['mediaData']['records']) > 0:
            return b64decode(self.config['mediaData']['records'][0]['token']).decode('utf-8')
        else:
            return b64decode(self.config['mediaData']['token']).decode('utf-8')

    def get_m3u8_url(self):
        if 'records' in self.config['mediaData'] and len(self.config['mediaData']['records']) > 0:
            return b64decode(self.config['mediaData']['records'][0]['links']['hls']).decode('utf-8')
        else:
            return b64decode(self.config['mediaData']['links']['hls']).decode('utf-8')

    def get_boomstream_config(self, page):
        """
        Evals value assigned to window.boomstreamConfig variable as JSON. This is ugly,
        but still better than using regular expressions to extract all needed variables
        from HTML page.
        """
        html = fromstring(page)
        result = None

        for script in html.xpath('//script[@type="text/javascript"]'):
            m = re.search("window.boomstreamConfig = ({.*});$", script.text_content(), flags=re.M)
            if m is not None:
                result = json.loads(m.group(1))

        if result is None:
            raise Exception("Could not get boomstreamConfig from the main page")

        with open('boomstream.config.json', 'wt') as f:
            del result["translations"]
            f.write(json.dumps(result, ensure_ascii=False, indent=4))

        return result

    def get_playlist(self, url):
        if self.args.use_cache and os.path.exists('boomstream.playlist.m3u8'):
            return open('boomstream.playlist.m3u8').read()

        r = requests.get(url, headers=headers)

        with open('boomstream.playlist.m3u8', 'wt') as f:
            f.write(r.text)

        return r.text

    def res2int(self, resolution):
        if 'x' in resolution:
            return int(resolution.split('x')[0]) * int(resolution.split('x')[1])
        else:
            return int(resolution)

    def extract_chunklist_urls(self, playlist):
        result = []
        resolution = None

        for line in playlist.split('\n'):
            if line.startswith('#EXT-X-STREAM-INF'):
                m = re.search(r'RESOLUTION=(\d+x\d+)', line)
                if m is not None:
                    resolution = m.group(1)
                else:
                    m = re.search(r'BANDWIDTH=(\d+)', line)
                    if m is not None:
                        resolution = m.group(1)
                    else:
                        raise Exception("Could not get resolution from EXT-X-STREAM-INF")
            elif resolution is not None:
                result.append([resolution, line, self.res2int(resolution)])
                resolution = None

        return result

    def get_chunklist(self, playlist):
        all_chunklists = self.extract_chunklist_urls(playlist)
        print(f"This video is available in the following resolutions: {', '.join(i[0] for i in all_chunklists)}")

        if self.args.resolution is not None:
            url = None
            for item in all_chunklists:
                if item[0] == self.args.resolution:
                    url = item[1]
                    break
            if url is None:
                raise Exception("Playlist for resolution specifeid is --resolution " \
                                "argument is not found")
        else:
            # If the resolution is not specified in args, pick the best one
            url = sorted(all_chunklists, key=lambda x: x[2])[-1][1]

        print(f"URL: {url}")

        if url is None:
            raise Exception("Could not find chunklist in playlist data")

        if self.args.use_cache and os.path.exists('boomstream.chunklist.m3u8'):
            return open('boomstream.chunklist.m3u8').read()

        r = requests.get(url, headers=headers)

        with open('boomstream.chunklist.m3u8', 'wt') as f:
            f.write(r.text)

        return r.text

    def get_xmedia_ready(self, chunklist):
        """
        X-MEDIA-READY contains a value that is used to calculate IV for AES-128 and a URL
        to obtain AES-128 encryption key.
        """
        for line in chunklist.split('\n'):
            if line.split(':')[0] == '#EXT-X-MEDIA-READY':
                return line.split(':')[1]

        raise Exception("Could not find X-MEDIA-READY")

    def decrypt(self, source_text, key):
        result = ''
        while len(key) < len(source_text):
            key += key

        for n in range(0, len(source_text), 2):
            c = int(source_text[n:n+2], 16) ^ ord(key[(int(n / 2))])
            result = result + chr(c)

        return result

    def encrypt(self, source_text, key):
        result = ''

        while len(key) < len(source_text):
            key += key

        for i in range(0, len(source_text)):
            result += f'{ord(source_text[i]) ^ ord(key[i]):02x}'

        return result

    def get_aes_key(self, xmedia_ready):
        """
        Returns IV and 16-byte key which will be used to decrypt video chunks
        """
        decr = self.decrypt(xmedia_ready, XOR_KEY)
        print(f'Decrypted X-MEDIA-READY: {decr}')

        key = None
        iv = ''.join([f'{ord(c):02x}' for c in decr[20:36]])

        key_url = 'https://play.boomstream.com/api/process/' + \
                  self.encrypt(decr[0:20] + self.token, XOR_KEY)

        print(f'key url = {key_url}')

        r = requests.get(key_url, headers=headers)
        key = r.text
        print(f"IV = {iv}")
        print(f"Key = {key}")
        return iv, key

    def download_chunks(self, chunklist, iv, key):
        i = 0

        if not os.path.exists(key):
            os.mkdir(key)

        # Convert the key to format suitable for openssl command-line tool
        hex_key = ''.join([f'{ord(c):02x}' for c in key])

        for line in chunklist.split('\n'):
            if not line.startswith('https://'):
                continue
            outf = os.path.join(key, f"{i:05d}.ts")
            if os.path.exists(outf):
                i += 1
                print(f"Chunk #{i} exists [{outf}]")
                continue
            print(f"Downloading chunk #{i}")
            os.system(f'curl -s "{line}" | openssl aes-128-cbc -K "{hex_key}" -iv "{iv}" -d > {outf}')
            i += 1

    def merge_chunks(self, key):
        """
        Merges all chunks into one file and encodes it to MP4
        """
        print("Merging chunks...")
        os.system(f"cat {key}/*.ts > {key}.ts")
        print("Encoding to MP4")
        os.system(f'ffmpeg -i {key}.ts -c copy "{self.get_title()}".mp4')

    def get_title(self):
        return self.config['entity']['title']

    def run(self):
        if self.args.use_cache and os.path.exists('result.html'):
            page = open('result.html').read()
        else:
            r = requests.get(self.args.url, headers=headers)

            with open('result.html', 'wt') as f:
                f.write(r.text)

            page = r.text

        self.config = self.get_boomstream_config(page)
        if len(self.config['mediaData']['records']) == 0:
            print("Video record is not available. Probably, the live streaming" \
                  "has not finished yet. Please, try to download once the translation" \
                  "is finished." \
                  "If you're sure that translation is finished, please create and issue" \
                  "in project github tracker and attach your boomstream.config.json file")
            return 1

        self.token = self.get_token()
        self.m3u8_url = self.get_m3u8_url()

        print(f"Token = {self.token}")
        print(f"Playlist: {self.m3u8_url}")

        playlist = self.get_playlist(self.m3u8_url)
        chunklist = self.get_chunklist(playlist)

        xmedia_ready = self.get_xmedia_ready(chunklist)

        print(f'X-MEDIA-READY: {xmedia_ready}')
        iv, key = self.get_aes_key(xmedia_ready)
        self.download_chunks(chunklist, iv, key)
        self.merge_chunks(key)

if __name__ == '__main__':
    app = App()
    sys.exit(app.run())
