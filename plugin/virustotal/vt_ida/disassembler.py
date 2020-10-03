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

import binascii
import ida_idp
import idaapi
import idautils
import idc
import logging


class Disassembler(object):

  @staticmethod
  def bad_address():
    return idaapi.BADADDR

  @staticmethod
  def next_address(addr):
    return idc.next_head(addr)

  @staticmethod
  def get_bytes(start_addr, end_addr):
    return idc.get_bytes(
        start_addr,
        end_addr - start_addr
        )

  @staticmethod
  def valid_address_range(start_addr, end_addr):
    if (start_addr == Disassembler.bad_address() or
        end_addr == Disassembler.bad_address()):
      return False
    else:
      return True

  @staticmethod
  def valid_range_size(start_addr, end_addr, max_size):
    if (end_addr - start_addr) > max_size:
      return False
    else:
      return True

  @staticmethod
  def wildcard_instruction(addr):
    """Replaces bytes related to memory addresses with wildcards.

    Args:
      addr: the address of the current instruction to be wildcarded

    Returns:
      String: hex-encoded representation of the bytes obtained at addr where
              all the operands that refers to memmory addresses are wildcarded.
    """

    pattern = ''
    mask = ida_idp.ph_calcrel(addr)  
    # IDA > 7.5 return a list, < 7.5 returns a byte object
    if idaapi.IDA_SDK_VERSION >= 750:
      mask_bytes = mask[0]
      mask_length = mask[1]
      mask_str = binascii.hexlify(mask_bytes).decode('utf-8')
    else:
      mask_str = binascii.hexlify(mask).decode('utf-8')

    logging.debug(
        '[VTGREP] Wildcarding: %s',
        idc.generate_disasm_line(addr, 0)
        )

    current_byte = 0
    index_instr = 0
    pattern = ' '

    while current_byte < len(mask_str):
      if mask_str[current_byte] != '0' or mask_str[current_byte+1] != '0':
        pattern += '?? '
      else:
        instr_bytes = idc.get_bytes(addr+index_instr, 1)
        pattern += binascii.hexlify(instr_bytes).decode('utf-8') + ' '
      current_byte += 2
      index_instr += 1

    logging.debug('[VTGREP] Wildcarded: %s', pattern)

    return pattern

  @staticmethod
  def get_opcodes(addr, strict):
    """Get current bytes of the instruction pointed at addr.

    Args:
      addr: address of the current instruction
      strict: be more restrictive when applying wildcards (True) or not (False)

    Returns:
      String: hex-encoded representation of the bytes obtained at addr
    """

    if strict:
      offsets_types = {idaapi.o_far, idaapi.o_mem, idaapi.o_imm}
    else:
      offsets_types = {idaapi.o_far, idaapi.o_mem}

    pattern = ''
    mnem = idautils.DecodeInstruction(addr)

    if mnem is not None:
      op1_type = mnem.Op1.type
      op2_type = mnem.Op2.type

      logging.debug(
          '[VTGREP] Instruction: %s  [%d, %d, %d]',
          idc.generate_disasm_line(addr, 0),
          mnem.itype,
          op1_type,
          op2_type
          )

      inst_len = idc.get_item_size(addr)
      drefs = [x for x in idautils.DataRefsFrom(addr)]

      # Checks if any operand constains a memory address
      if (drefs and
          ((op1_type == idaapi.o_imm) or (op2_type == idaapi.o_imm)) or
          op1_type in offsets_types or op2_type in offsets_types):
        pattern = Disassembler.wildcard_instruction(addr)
      # Checks if the instruction is a CALL (near or far) or
      # if it's a JMP (excluding near jumps)
      else:
        if ((mnem.itype == idaapi.NN_call) or
            (mnem.itype == idaapi.NN_jmp and op1_type != idaapi.o_near)):
          pattern = Disassembler.wildcard_instruction(addr)
        # In any other case, concatenate the raw bytes to the current string
        else:
          pattern = binascii.hexlify(idc.get_bytes(addr, inst_len))
          pattern = pattern.decode('utf-8')
      return pattern
    else: return 0

 