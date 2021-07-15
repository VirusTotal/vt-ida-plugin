# Copyright 2020 Google Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

__author__ = 'gerardofn@virustotal.com'

import hashlib
import idautils
import logging
import os
import requests
import threading
from virustotal import config
from virustotal import defaults


class CheckSample(threading.Thread):

  def __init__(self, upload, path):
    self.auto_upload = upload
    self.input_file = path
    self.file_hash = None

    threading.Thread.__init__(self)

  def calculate_hash(self):
    """Return hash if the file hash has been properly calculated."""

    if os.path.isfile(self.input_file):
      hash_f = hashlib.sha256()
      logging.debug('[VT Plugin] Input file available.')
      with open(self.input_file, 'rb') as file_r:
        try:
          for file_buffer in iter(lambda: file_r.read(8192), b''):
            hash_f.update(file_buffer)
          self.file_hash = hash_f.hexdigest()
          logging.debug('[VT Plugin] Input file hash been calculated.')
        except:
          logging.debug('[VT Plugin] Can\'t load the input file.')
    else:
      logging.debug('[VT Plugin] Input file not available.')
      tmp_hash = idautils.GetInputFileMD5()
      if len(tmp_hash) != 32:
        logging.error('[VT Plugin] IDAPYTHON API returned a wrong hash value.')
      else:
        self.file_hash = tmp_hash

    if self.file_hash:
      return self.file_hash
    else:
      if self.auto_upload:
        logging.error('[VT Plugin] Input file hash error.')
      else:
        logging.debug('[VT Plugin] Input file hash error.')
      return None

  def check_file_missing_in_VT(self):
    """Return True if the file is not available at VirusTotal."""

    user_agent = 'IDA Pro VT Plugin checkhash - v'
    user_agent += defaults.VT_IDA_PLUGIN_VERSION
    headers = {
        'User-Agent': user_agent,
        'Accept': 'application/json'
    }

    url = 'https://www.virustotal.com/ui/files/%s' % self.file_hash

    logging.debug('[VT Plugin] Checking hash: %s', self.file_hash)
    try:
      response = requests.get(url, headers=headers)
    except:
      logging.error('[VT Plugin] Unable to connect to VirusTotal.com')
      return False

    if response.status_code == 404:  # file not found in VirusTotal
      return True
    elif response.status_code == 200:
      logging.debug('[VT Plugin] File already available in VirusTotal.')

    return False

  def upload_file_to_VT(self):
    """Upload input file to VirusTotal."""

    user_agent = 'IDA Pro VT Plugin upload - v' + defaults.VT_IDA_PLUGIN_VERSION
    if not config.API_KEY:
      headers = {
          'User-Agent': user_agent,
      }
    else:
      headers = {
          'User-Agent': user_agent,
          'x-apikey': config.API_KEY
      }

    norm_path = os.path.normpath(self.input_file)
    file_path, file_name = os.path.split(norm_path)

    if os.path.isfile(self.input_file):
      logging.info('[VT Plugin] Uploading input file to VirusTotal.')
      url = 'https://www.virustotal.com/ui/files'
      files = {'file': (file_name, open(self.input_file, 'rb'))}

      try:
        response = requests.post(url, files=files, headers=headers)
      except:
        logging.error('[VT Plugin] Unable to connect to VirusTotal.com')

      if response.ok:
        logging.debug('[VT Plugin] Uploaded successfully.')
      else:
        logging.error('[VT Plugin] Upload failed.')
    else:
      logging.error('[VT Plugin] Uploading error: input file path is invalid.')



