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

import json
import logging
import requests
from virustotal import config


class CheckAPIKey():

  def __init__(self):
    self.private_api = False
    self.intelligence = False

    url = 'https://www.virustotal.com/api/v3/users/{}?attributes=privileges'.format(config.API_KEY)
    if config.API_KEY:
      headers = {
          'x-apikey': config.API_KEY
      }
      try:
        response = requests.get(url, headers=headers)
      except:
        logging.error('[VT Plugin] Unable to connect to VirusTotal.com')
      if response.ok:
        json_data = response.json()
        try:
          privileges = json_data['data']['attributes']['privileges']['private']
          if privileges['granted']:
            self.private_api = True
            logging.debug('[VT Plugin] Using private API key.')
          else:
            logging.debug('[VT Plugin] Using public API key.')
        except:
          pass
      else:
        logging.error('[VT Plugin] Cannot check user API key.')

  def private(self):
    return self.private_api

  def intelligence(self):
    return self.intelligence
