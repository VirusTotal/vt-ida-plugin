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

import ida_kernwin

class VTWidgets(object):

  @staticmethod
  def show_info(msg):
    ida_kernwin.info(msg)

  @staticmethod
  def show_warning(msg):
    ida_kernwin.warning(msg)

  @staticmethod
  def show_wait(msg):
    ida_kernwin.show_wait_box(msg)

  @staticmethod
  def hide_wait():
    ida_kernwin.hide_wait_box()


