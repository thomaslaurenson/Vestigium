# !/usr/bin/python

"""
Author:  Thomas Laurenson
Email:   thomas@thomaslaurenson.com
Website: thomaslaurenson.com
Date:    2015/12/28

Description:
FilePathNormalizer.py is a Vestigium module to normalize the full path
of a file system artifact.

Copyright (c) 2015, Thomas Laurenson

###############################################################################
This file is part of Vestigium.

Vestigium is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
###############################################################################
"""

__version__ = "1.0.0"

import collections

################################################################################
class FilePathNormalizer():
    def __init__(self):
        """ Initialise FilePathNormalizer object. """
        self.variable_paths = collections.OrderedDict()
        self.variable_paths["programfiles"]    = ["Program Files",
                                                  "Program Files (x86)"]
        self.variable_paths["allusersprofile"] = ["Documents and Settings/All Users",
                                                  "ProgramData",
                                                  "Users/Public"]
        self.variable_paths["userprofile"]     = ["Users",
                                                  "Documents and Settings"]
        self.variable_paths["localappdata"]    = ["%USERPROFILE%/Local Settings/Application Data",
                                                  "%USERPROFILE%/AppData/Local"]
        self.variable_paths["appdata"]         = ["%USERPROFILE%/Application Data",
                                                  "%USERPROFILE%/AppData/Roaming"]
        self.variable_paths["startmenu"]       = ["%ALLUSERSPROFILE%/Start Menu",
                                                  "%ALLUSERSPROFILE%/Microsoft/Windows/Start Menu",
                                                  "%APPDATA%/Microsoft/Windows/Start Menu",
                                                  "%USERPROFILE%/Start Menu",
                                                  "%USERPROFILE%/%APPDATA%/Microsoft/Windows/Start Menu"]
        self.variable_paths["windir"]          = ["Windows",
                                                  "WINDOWS"]
        self.variable_paths["systemroot"]      = ["%WINDIR%/system32",
                                                  "%WINDIR%/System32"]
        self.variable_paths["prefetch"]        = ["%WINDIR%/prefetch",
                                                  "%WINDIR%/Prefetch"]
                                     
    def normalize(self, fullpath):
        """ Normalize a logical file system path value of a target file. """
        # Check root directory
        if fullpath.startswith("C:\\"):
            fullpath = fullpath[3:]

        # Check/replace backslash characters in path
        temp = fullpath.split("\\")
        fullpath = "/".join(temp)

        # Now, normalize full path
        for key in self.variable_paths:
            for name in self.variable_paths[key]:
                # Normalize Program Files path
                if key == "programfiles":
                    if fullpath.startswith(name):
                        fullpath = fullpath.replace(name, "%PROGRAMFILES%")
                # Normalize All Users path
                elif key == "allusersprofile":
                    if fullpath.startswith(name):
                        fullpath = fullpath.replace(name, "%ALLUSERSPROFILE%")
                # Normalize Local App Data path
                elif key == "localappdata":
                    if fullpath.startswith(name):
                        fullpath = fullpath.replace(name, "%LOCALAPPDATA%")
                # Normalize Windows directory path
                if key == "windir":
                    if fullpath.startswith(name):
                        fullpath = fullpath.replace(name, "%WINDIR%")
                # Normalize Windows System Root path
                if key == "systemroot":
                    if fullpath.startswith(name):
                        fullpath = fullpath.replace(name, "%SYSTEMROOT%")
                # Normalize Windows Prefecth path (and filename)
                if key == "prefetch":
                    if fullpath.startswith(name):
                        fullpath = fullpath.replace(name, "%PREFETCH%")
                        # Also normalise prefetch name (remove random number
                        # string suffix to allow path matching)
                        if fullpath.endswith(".pf"):
                            index = fullpath.index(".pf") - 9
                            fullpath = fullpath[0:index] + ".pf"
                # Normalize User Profile path (home directory)
                if key == "userprofile":
                    if fullpath.startswith(name):
                        fullpath = fullpath.replace(name, "%USERPROFILE%")
                        fullpath = fullpath.split("/")
                        # Remove <username> then re-join path string
                        if len(fullpath) > 1:
                            del fullpath[1]
                        fullpath = '/'.join(fullpath)
                # Normalize Local App Data path
                if key == "appdata":
                    if fullpath.startswith(name):
                        fullpath = fullpath.replace(name, "%APPDATA%")
                # Normalize Start Menu path
                if key == "startmenu":
                    if fullpath.startswith(name):
                        fullpath = fullpath.replace(name, "%STARTMENU%")
        return fullpath
