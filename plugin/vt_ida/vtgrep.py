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

import idaapi
import idautils
import idc
import urllib
import webbrowser


class Bytes(object):
  """Class that represents a slice of bytes in a search query."""

  bytes_stream = ''

  def __init__(self, buf):
    self.bytes_stream = buf

  def append(self, qslice):
    if not isinstance(qslice, Bytes):
      self.bytes_stream += qslice
    else:
      self.bytes_stream += qslice.get()

  def get(self):
    return self.bytes_stream

  def len(self):
    return len(self.bytes_stream)

  def combine(self, next_object):
    if next_object:
      if isinstance(next_object, Bytes):
        self.append(next_object)
        return self
      else:
        if self.len() < 8:
          wcs_stream = '?' * self.len()
          next_object.append(wcs_stream)
          return next_object
        else: return -1
    else:
      if self.len() < 8:
        return self
      else: return -1


class WildCards(object):
  """Class that represents a slice of wildcards in a search query."""

  wcs_stream = ''
  packed = False

  def __init__(self, buf):
    self.wcs_stream = buf
    self.pack()

  def append(self, qslice):
    # slice can be a WildCards instance or a string of wildcards
    if not self.packed and not isinstance(qslice, WildCards):
      self.wcs_stream += qslice
      self.pack()
    else:
      if isinstance(qslice, WildCards):
        wcs_len = self.len() + qslice.len()
      else:
        wcs_len = self.len() + len(qslice)

      wcs_count = wcs_len / 2
      self.wcs_stream = '[{}]'.format(str(wcs_count)) + '?' * (wcs_len % 2)
      self.packed = True

  def get(self):
    return self.wcs_stream

  def len(self):
    str_len = 0
    if self.packed:
      wcs_len = self.wcs_stream.lstrip('[').rstrip(']')
      question_index = self.wcs_stream.find('?')
      if question_index != -1:
        str_len = int(wcs_len.rstrip(']?')) * 2
        str_len += 1
      else: str_len = int(wcs_len) * 2
      return str_len
    else: return len(self.wcs_stream)

  def pack(self):
    if not self.packed:
      wcs_len = len(self.wcs_stream)
      if wcs_len > 3:
        wcs_count = (wcs_len / 2)
        self.wcs_stream = '[{}]'.format(str(wcs_count)) + '?' * (wcs_len % 2)
        self.packed = True

  def combine(self, next_object):
    if next_object:
      if isinstance(next_object, Bytes):
        if next_object.len() < 8:
          wcs_stream = '?' * next_object.len()
          self.append(wcs_stream)
        else: return -1
      else: self.append(next_object)
    return self


class VTGrepSearch(object):
  """Implements all the methods to launch queries to VTGrep.

    This class implements the whole process of receiving a range of memory
    addresses as input, creating a string buffer with all the bytes in the
    range and transforming them (if desired) for wildcards to avoid memory
    references.
  """

  url = ''
  addr_start = 0
  addr_end = 0
  query_list = []
  _MIN_QUERY_SIZE = 7      # number of bytes
  _MAX_QUERY_SIZE = 1600

  def __init__(self, start, end):
    self.addr_start = start
    self.addr_end = end

  @staticmethod
  def _get_instruction_bytes_wildcarded(pattern, addr):
    """Replace bytes related to offsets and memory locations with wildcards."""

    inst_prefix = idc.GetManyBytes(addr, 1).encode('hex')

    if inst_prefix in ('0f', 'f2', 'f3'):
      # Opcode Prefix (Intel x86)
      pattern = idc.GetManyBytes(addr, 2).encode('hex')
      inst_num_bytes = 2
    else:
      pattern = inst_prefix  # No prefix is used
      inst_num_bytes = 1

    pattern += ' ' + '??' * (idc.ItemSize(addr) - inst_num_bytes) + ' '
    return pattern

  def _get_opcodes(self, addr):
    """Identify instruction replacing parameters with wildcards when needed."""

    OFFSETS = {idaapi.o_far, idaapi.o_mem}
    pattern = ''

    if idaapi.IDA_SDK_VERSION >= 700:
      op1_type = idc.get_operand_type(addr, 0)
      op2_type = idc.get_operand_type(addr, 1)
    else:
      op1_type = idc.GetOpType(addr, 0)
      op2_type = idc.GetOpType(addr, 1)

    inst_len = idc.ItemSize(addr)
    mnem = idautils.DecodeInstruction(addr)

    if op1_type in OFFSETS or op2_type in OFFSETS:
      pattern = self._get_instruction_bytes_wildcarded(pattern, addr)
    else:
      if ((mnem.itype == idaapi.NN_call) or
          (mnem.itype == idaapi.NN_jmp and op1_type != idaapi.o_near)):
        pattern = self._get_instruction_bytes_wildcarded(pattern, addr)
      else:
        pattern = idc.GetManyBytes(addr, inst_len).encode('hex')
    return pattern

  @staticmethod
  def _generate_slices(buf):
    """Read a string buffer and generates wildcards and bytes objects."""

    list_slices = buf.split()

    for qslice in list_slices:
      if qslice[0] == '?':
        yield WildCards(qslice)
      else:
        yield Bytes(qslice)

  def _create_query(self, buf):
    """Receives a string buffer and produces a query compatible with VTGrep."""

    query_slices = self._generate_slices(buf)
    query_list = []

    for current in query_slices:
      if not query_list:
        query_list.append(current)
      else:
        prev = len(query_list) - 1
        qslice = query_list[prev].combine(current)

        if qslice == -1:
          query_list.append(current)
        else:
          query_list[prev] = qslice

    buf = ''.join(str(element.get()) for element in query_list)
    return self._sanitize(query_list)

  def _sanitize(self, qlist):
    """Apply some checks to the current query before sending it to VTGrep.

    Args:
      qlist: list of slices that must be checked according to VTGrep syntax

        Checks performed:
        - No ending []
        - No consecutive [][]
        - No consecutive byte strings
        - At least 4 consecutive bytes
    """
    self.query_list = qlist
    modified = True

    while modified:
      modified = False
      query_len = len(qlist)
      qslice_index = 0

      for qslice_index in range(0, query_len):
        next_qslice_index = qslice_index + 1

        if (next_qslice_index) != query_len:
          next_qslice = self.query_list[next_qslice_index]
          qslice = self.query_list[qslice_index].combine(next_qslice)

          if qslice != -1:
            self.query_list[qslice_index] = qslice
            self.query_list.pop(next_qslice_index)
            modified = True
            break
        else:  # Last slice
          if self.query_list[qslice_index].combine(None) != -1:
            self.query_list.pop(qslice_index)
            modified = True
          break

    buf = ''.join(str(element.get()) for element in self.query_list)
    return buf

  def search(self, wildcards=False):
    """Process current selection and generate a query for VTGrep.

    Args:
      wildcards: boolean that decides the type of search to perform:
        True: search replacing offsets and memory locations with widlcards
        False: search for a sequence of bytes

    Checks the current bytes selected in IDA Pro, call the appropriate
    method for generating a valid query for VTGrep, and open the web browser to
    launch the query.
    """

    current = self.addr_start
    str_buf = ''

    if ((self.addr_start == idaapi.BADADDR) or (self.addr_end == idaapi.BADADDR)
        or (self.addr_end - self.addr_start) > self._MAX_QUERY_SIZE):
      print '[VT plugin] ERROR! Select a valid area to query VTGrep.'
    else:
      if wildcards:
        while current < self.addr_end:
          str_buf += self._get_opcodes(current)
          if idaapi.IDA_SDK_VERSION >= 700:
            current = idc.next_head(current)
          else:
            current = idc.NextHead(current)
        str_buf = self._create_query(str_buf)
      else:
        str_buf = idc.GetManyBytes(
            self.addr_start,
            self.addr_end - self.addr_start
            )

      if (self._MIN_QUERY_SIZE < len(str_buf.encode('hex')) and
          len(str_buf.encode('hex')) < self._MAX_QUERY_SIZE):

        str_buf = '{' + str_buf + '}'
        vtgrep_url = 'www.virustotal.com/gui/search/content:{}/files'
        self.url = 'https://{}'.format(urllib.quote(vtgrep_url.format(str_buf)))

        try:
          webbrowser.open_new(self.url)
        except Exception as e:
          print '[VT plugin] ERROR! While opening web browser: ' % e
        del self.query_list[:]
      else:
        print '[VT plugin] ERROR! Invalid query length.'
