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

import logging
import json
import time
import os
import base64
import ida_kernwin


class VTReportWindow(object):
  visible = False
  include_knowledge = False

  def __init__(self):
    self._debugwindow.setupUi()
    self._debugwindow.pb_save_revision.clicked.connect(self._save_analysis)
    self._debugwindow.pb_save_knowledge.clicked.connect(self._save_knowledge)
    self._debugwindow.te_code.textChanged.connect(self._knowledge_updated)
    self._debugwindow.te_lesson.textChanged.connect(self._knowledge_updated)
    self._debugwindow.le_keywords_knowledge.textChanged.connect(self._knowledge_updated)
    self._debugwindow.te_description.textChanged.connect(self._analysis_updated)
    self._debugwindow.te_summary.textChanged.connect(self._analysis_updated)
    self._debugwindow.le_keywords_summary.textChanged.connect(self._analysis_updated)
    self._debugwindow.le_keywords_description.textChanged.connect(self._analysis_updated)

  def isVisible(self):
    return self.visible

  def _knowledge_updated(self):
    self.include_knowledge = True

  def _analysis_updated(self):
    self.ci_eval_expected_summary = self._debugwindow.te_summary.toPlainText()
    self.ci_eval_expected_description = self._debugwindow.te_description.toPlainText()

  def clean_view(self):
    self._debugwindow.le_sha256.clear()
    self._debugwindow.le_faddress.clear()
    self._debugwindow.le_codetype.clear()
    self._debugwindow.te_summary.clear()
    self._debugwindow.te_description.clear()
    self._debugwindow.te_code.clear()
    self._debugwindow.le_keywords_summary.clear()
    self._debugwindow.le_keywords_description.clear()
    self._debugwindow.le_keywords_knowledge.clear()
    self._debugwindow.cb_received.setChecked(False)
    self._debugwindow.cb_valid.setChecked(False)
    self._debugwindow.cb_complete.setChecked(False)

  def set_data(self, *args, **kwargs): 
    self.ci_sha256 = kwargs.get('sha256', None)
    self.ci_faddress = kwargs.get('faddress', None)
    self.ci_output_received = kwargs.get('output_received', False)
    self.ci_ctype = kwargs.get('ctype', 'disassembled')
    self.ci_AImodel = kwargs.get('AImodel', 'default')
    self.ci_code = kwargs.get('code', None)
    self.ci_code_encoded = kwargs.get('code_encoded', None)
    self.ci_eval_summary = kwargs.get('eval_summary', None)
    self.ci_eval_description = kwargs.get('eval_description', None)
    self.ci_eval_expected_summary = kwargs.get('eval_expected_summary', None)
    self.ci_eval_expected_description = kwargs.get('eval_expected_description', None)    
    self.ci_eval_error = kwargs.get('eval_error', None)
   
    exp_description = self.ci_eval_expected_description
    org_description = self.ci_eval_description
    exp_summary = self.ci_eval_expected_summary
    org_summary = self.ci_eval_summary

    if exp_description:
      self._debugwindow.te_description.setText(exp_description)
    else:
      self._debugwindow.te_description.setText(org_description)

    if exp_summary:
      self._debugwindow.te_summary.setText(exp_summary)       
    else:
      self._debugwindow.te_summary.setText(org_summary)

    self._debugwindow.le_sha256.setText(self.ci_sha256)
    self._debugwindow.le_faddress.setText(self.ci_faddress)
    self._debugwindow.le_codetype.setText(self.ci_ctype)
    self._debugwindow.te_code.setText(self.ci_code)

    if self.ci_output_received:
      self._debugwindow.cb_received.setChecked(True)

  def Show(self):
    self.visible = True
    self._debugwindow.show()
    
  def _save_analysis(self):
    b64_eo = ''
    
    if self.ci_eval_expected_summary or self.ci_eval_expected_description:
      expected_output = '{}\n\n{}\n'.format(self._debugwindow.te_summary.toPlainText(), self._debugwindow.te_description.toPlainText())
      b64_eo = base64.b64encode(expected_output.encode('utf-8'))
      b64_eo = b64_eo.decode('ascii')

    ci_dict = {'file_sha256': self.ci_sha256,
               'function_address': self.ci_faddress,
               'code': self._debugwindow.te_code.toPlainText(),
               'code_encoded': self.ci_code_encoded,
               'code_type': self.ci_ctype,
               'model_AI': self.ci_AImodel,
               'eval_summary': self.ci_eval_summary,
               'eval_summary_keywords': self._debugwindow.le_keywords_summary.text(),
               'eval_description': self.ci_eval_description,
               'eval_description_keywords': self._debugwindow.le_keywords_description.text(),
               'eval_analysis': self.ci_output_received,
               'eval_valid_analysis': self._debugwindow.cb_valid.isChecked(),
               'eval_complete_analysis': self._debugwindow.cb_complete.isChecked(),
               'eval_error': self.ci_eval_error,
               'expected_analysis': b64_eo 
              }
      
    filename = "evaluation_{hash}_{address}_{code_type}-{model}_{timestamp}.json".format(
        hash = self.ci_sha256, 
        address = self.ci_faddress,
        code_type = self.ci_ctype,
        model = self.ci_AImodel,
        timestamp = int(time.time())
    )
    
    filename_f = ida_kernwin.ask_file(1, filename, "Select file destination:")
                                        
    try:
      logging.info('[VT Plugin] File will be saved in: %s', os.getcwd())
      with open(filename_f, 'w', encoding='utf-8') as f:
        json.dump(ci_dict, f)
    except:
      logging.error('[VT Plugin] Error saving file: %s', filename_f)

  def _save_knowledge(self):
    lesson = self._debugwindow.te_lesson.toPlainText()
    code = self._debugwindow.te_code.toPlainText()
    b64_lesson =  base64.b64encode(lesson.encode('utf-8'))
    b64_lesson = b64_lesson.decode('ascii')
    b64_code = base64.b64encode(code.encode('utf-8'))
    b64_code = b64_code.decode('ascii')

    ci_dict = {'file_sha256': self.ci_sha256,
               'function_address': self.ci_faddress,
               'code': b64_code,
               'code_lesson': b64_lesson,
               'code_keywords': self._debugwindow.le_keywords_knowledge.text(),
               'code_type': self.ci_ctype,
               'model_AI': self.ci_AImodel,
               'eval_error': self.ci_eval_error
              }
    
    filename = "knowledge_{hash}_{address}_{code_type}-{model}_{timestamp}.json".format(
        hash = self.ci_sha256, 
        address = self.ci_faddress,
        code_type = self.ci_ctype,
        model = self.ci_AImodel,
        timestamp = int(time.time())
    )

    filename_f = ida_kernwin.ask_file(1, filename, "Select file destination:")

    try:
      logging.info('[VT Plugin] File will be saved in: %s', os.getcwd())
      with open(filename_f, 'w', encoding='utf-8') as f:
        json.dump(ci_dict, f)
    except:
      logging.error('[VT Plugin] Error saving file: %s', filename_f)
