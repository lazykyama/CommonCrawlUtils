# -*- coding: utf-8-unix -*-

import gzip
import logging

import chardet

LINE_DELIMITER=b'\r\n'
BLOCK_DELIMITER='{0}{0}WARC/1.0{0}'.format(
    LINE_DELIMITER.decode()).encode()

class EncodingDetectionError(Exception):
  def __init__(self, msg):
    Exception.__init__(self)
    self._msg = msg
  def __str__(self):
    return self._msg

class DecodingFailureError(Exception):
  def __init__(self, msg):
    Exception.__init__(self)
    self._msg = msg
  def __str__(self):
    return self._msg

class WetEntry(object):
    def __init__(self, block, headerkey_case_sensitive=True):
        header_tail_index = block.find(2*LINE_DELIMITER) + len(LINE_DELIMITER)
        body_head_index = header_tail_index + len(LINE_DELIMITER)

        self._header = self._parse_header(
            block[:header_tail_index], headerkey_case_sensitive)
        self._body = self._parse_body(block[body_head_index:])

    @property
    def header(self):
        return self._header
    @property
    def body(self):
        return self._body

    @property
    def encoding(self):
        return self._encoding

    def _parse_header(self, header_block, headerkey_case_sensitive):
        # NOTE: assumes that header block is encoded by ascii only.
        header_dict = {}
        for l in header_block.split(LINE_DELIMITER):
            l = l.decode()
            if len(l) == 0:
                continue

            kv = list(e.lstrip().rstrip() for e in l.split(':'))
            if len(kv) == 1:
                kv.append('')
            elif len(kv) > 2:
                kv = [kv[0], ':'.join(kv[1:])]
            assert len(kv) == 2, 'invalid key value: kv={}'.format(kv)

            key = kv[0] if headerkey_case_sensitive else kv[0].lower()
            value = kv[1]
            if key not in header_dict:
                header_dict[key] = []
            header_dict[key].append(value)

        return header_dict

    def _parse_body(self, body_block):
        detection = chardet.detect(body_block)
        if detection['confidence'] < 0.5:
            raise EncodingDetectionError(
                'low confidence encoding detection: {}'.format(detection['encoding']))

        self._encoding = detection['encoding']
        try:
            return body_block.decode(self._encoding)
        except:
            logging.error('fail to decode: detected encoding={}, conf={}'.format(
                self._encoding, detection['confidence']))
            raise DecodingFailureError('encoding:{}, partial block: {}'.format(
                self._encoding, body_block[:20]))

class Parser(object):
    def __init__(self):
        self._loaded_counter = 0
        self._skip_counter = 0

    @property
    def loaded_counter(self):
        return self._loaded_counter
    @property
    def skip_counter(self):
        return self._skip_counter

    def parse(self, filename, headerkey_case_sensitive=True):
        self._loaded_counter = 0
        self._skip_counter = 0
        buffering_size = 1024*4

        with gzip.open(filename, 'rb') as f:
            buf = b''
            for chunk in iter(lambda : f.read(buffering_size), b''):
                buf += chunk
                need_next_read = False
                while not need_next_read:
                    index = buf.find(BLOCK_DELIMITER)
                    if index == -1:
                        need_next_read = True
                        continue

                    try:
                        entry = WetEntry(buf[:index+len(LINE_DELIMITER)], 
                            headerkey_case_sensitive=headerkey_case_sensitive)
                        yield entry
                        self._loaded_counter += 1
                    except (EncodingDetectionError, DecodingFailureError) as e: 
                        logging.warn('{}'.format(e))
                        self._skip_counter += 1
                    finally:
                        buf = buf[index+(2*len(LINE_DELIMITER)):]

        if len(buf) > 0:
            try: 
                entry = WetEntry(buf, 
                    headerkey_case_sensitive=headerkey_case_sensitive)
                yield entry
                self._loaded_counter += 1
            except (EncodingDetectionError, DecodingFailureError) as e: 
                logging.warn('{}'.format(e))
                self._skip_counter += 1
            finally:
                buf = b''

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, 
        format='%(asctime)s [%(levelname)s] %(message)s')

    import sys
    import time
    import json
    if len(sys.argv) < 2:
        logging.error('need parse filename: {}'.format(sys.argv))
        sys.exit(1)

    parser = Parser()
    start_time = time.time()
    logging.info('start parse.')
    for e in parser.parse(sys.argv[1]):
        sys.stdout.write('{}\n'.format(
            json.dumps({'header': e.header, 'body': e.body})))

    logging.info('end parse: total time={}[sec.]'.format(
        time.time()-start_time))
    logging.info('#loaded entries={}, skip entries={}, skip ratio={}'.format(
        parser.loaded_counter, parser.skip_counter, 
        float(parser.skip_counter)/(parser.loaded_counter+parser.skip_counter)))
