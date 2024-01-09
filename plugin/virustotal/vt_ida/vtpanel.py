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

import idaapi
import ida_kernwin
from idaapi import PluginForm
from PyQt5 import QtCore, QtGui, QtWidgets
from virustotal.vt_ida.ui.panel import Ui_panelUI
import logging


class VTWidgets(object):

  @staticmethod
  def show_info(msg):
    ida_kernwin.info(msg)

  @staticmethod
  def show_warning(msg):
    ida_kernwin.warning(msg)


class VTPanel(PluginForm):
  private_api=False

  def set_privileges(self, privs):
    self.private_api=privs

  def OnCreate(self, form):
    """
    Called when the plugin form is created
    """
    self.parent = self.FormToPyQtWidget(form)
    self.__populateForm()
    
  def __populateForm(self):
    self.__panel = Ui_panelUI()
    self.__panel.setupUi(self.parent)
    self.__panel.retranslateUi(self.parent)

  def set_default_data(self, ci_report):
    _translate = QtCore.QCoreApplication.translate   
    self.__panel.tb_ci_summary.clear()
    self.__panel.tb_ci_summary.setText(ci_report)
    self.__panel.tb_ci_description.setText(ci_report)
  def OnClose(self, form):
    """
    Called when the plugin form is closed
    """
    pass

  def Show(self, title):
    """Creates the form is not created or focuses it if it was"""
    flags = (
      idaapi.PluginForm.WOPN_DP_RIGHT
      | idaapi.PluginForm.WOPN_MENU
      | idaapi.PluginForm.WOPN_PERSIST
    )
    return PluginForm.Show(self,
                           title,
                           options = flags)
