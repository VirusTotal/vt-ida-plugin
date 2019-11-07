
# Copyright 2019 Google Inc. All Rights Reserved.
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

import sys

import idaapi
import idautils
import logging
import requests

from vt_ida.config import *
from vt_ida.plugin_loader import *


if DEBUG:
  logging.basicConfig(
      stream=sys.stdout,
      level=logging.DEBUG,
      format='%(message)s'
      )
else:
  logging.basicConfig(
      stream=sys.stdout,
      level=logging.INFO,
      format='%(message)s'
      )

logging.info('\n** VT plugin for IDA Pro v0.2beta (c) Google, 2019')
logging.info('** VirusTotal integration plugin for Hex-Ray\'s IDA Pro 7')
logging.info('\n** Select area and right click to search on VTGrep.\n')

if not API_KEY:
  logging.info('[VT_Plugin] No API KEY defined in the \'config.py\' file. ')
elif AUTO_UPLOAD:
  file_hash = idautils.GetInputFileMD5()
  file_path = idaapi.get_input_file_path()
  file_name = idc.get_root_filename()
  params = {'apikey': '', 'resource': ''}
  params['apikey'] = API_KEY
  params['resource'] = file_hash
  url = 'https://www.virustotal.com/vtapi/v2/file/report'

  response = requests.get(url, params=params)
  if response.status_code == 200:
    json_data = response.json()
    if not json_data['response_code']:
      logging.debug('[VT_Plugin] Uploading sample with hash %s', file_hash)
      del params['resource']
      url = 'https://www.virustotal.com/vtapi/v2/file/scan'
      files = {'file': (file_name, open(file_path, 'rb'))}
      response = requests.post(url, files=files, params=params)

