# !/usr/bin/python

"""
Author:  Thomas Laurenson
Email:   thomas@thomaslaurenson.com
Website: thomaslaurenson.com
Date:    2015/12/28

Description:
CellPathNormalizer.py is a Vestigium module to normalize the full path
of a Windows Registry artifact.

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

import codecs

try:
    import FilePathNormalizer
except ImportError:
    print('Error: CellPathNormalizer.py')
    print('       The FilePathNormalizer.py module is required.')
    print('       You can download from: https://github.com/thomaslaurenson/Vestigium')
    print('       Now Exiting...') 
    sys.exit(1)

################################################################################
class CellPathNormalizer():
    def __init__(self):
        """ Initialise CellPathNormalizer object. """
        self.file_path_normalizer = FilePathNormalizer.FilePathNormalizer()
        self.active_rootkey = None

    def normalize_profile_co(self, cellpath):
        """ Normalize the cellpath of the Profile CellObject (PCO). """
        normpath = cellpath
        # Remove Registry hive naming convention
        if normpath.startswith("HKLM\\"):
            normpath = normpath[5:]
        if normpath.startswith("HKU\\"):
            normpath = normpath[4:]
            #normpath = normpath.split("\\")
            #normpath[0] = "%SID%"
            #normpath = "\\".join(normpath)
            normpath = "NTUSER.DAT\\" + normpath
        return normpath

    def normalize_target_co_rootkey(self, cellpath, rootkey):
        """ 
        Normalize the cellpath rootkey of the Target CellObject (TCO), e.g.,
        Before: CMI-CreateHive{F10156BE-0E87-4EFB-969E-5DA29D131144}\ControlSet001\
        After:  SYSTEM\ControlSet001\
        """
        if cellpath:
            normpath = cellpath.split("\\")
            normpath[0] = rootkey
            normpath = "\\".join(normpath)
            return normpath

    def normalize_target_co(self, cellpath, rootkey):
        """ Normalize the cellpath of the Target CellObject (TCO). """       
        if cellpath:
            normpath = cellpath.split("\\")
        else:
            return cellpath
        
        #if rootkey == "NTUSER.DAT":
        #    if len(normpath) >= 2:
        #        normpath[1] = "%SID%"
        
        # Normalise SYSTEM Registry hive cellpath
        if rootkey == "SYSTEM":
            control_names = ["ControlSet001",
                             "ControlSet002",
                             "ControlSet003",
                             "CurrentControlSet",
                             "Clone"]
            # If path has "control set" name, normalise target path
            # See: http://support.microsoft.com/kb/100010
            #for name in control_names:
            if len(normpath) >= 2:
                if normpath[1] in control_names:
                    normpath[1] = "%CONTROLSET%"            

        normpath = "\\".join(normpath)
        return normpath
    

    """
    def normalize(self, co):

        normpath = co.cellpath
        normbasename = co.basename

        # Remove Registry hive naming convention
        if normpath.startswith("HKLM\\"):
            normpath = normpath[5:]
        if normpath.startswith("HKU\\"):
            normpath = normpath[4:]
            normpath = "NTUSER.DAT\\" + normpath

        # Remove cell basename and split the path
        if normpath == None or normbasename == None:
            co.normpath = None
            return

        # Remove the basename from the path, then split into a list
        if norm_path.endswith(co.basename):
            norm_path = norm_path[:norm_path.rfind(co.basename)]
        norm_path = norm_path.split("\\")
        # Remove rootkey, insert normalised rootkey, add rootkey attribute
        del norm_path[0:2]
        norm_path.insert(0, self.active_rootkey)
        co.rootkey = self.active_rootkey
        # If the basename is a file system location ("C:\"), perform
        # file system path normalization
        if norm_basename.startswith("C:\\"):
            norm_basename = self.normalize_basename(co.basename)
        # Normalize SOFTWARE hive entries
        # Hack fix for an upper case path in software hive
##        if (self.active_rootkey == "software" and
##            "{645FF040-5081-101B-9F08-00AA002F954E}" in norm_path):
##            if len(norm_path) > 4:
##                if norm_path[4] == "Shell":
##                    norm_path[4] = "shell"
##        # Normalize SYSTEM hive entries
##        if self.active_rootkey == "system":
##            control_names = ["ControlSet001",
##                             "ControlSet002",
##                             "ControlSet003",
##                             "CurrencontrolSet",
##                             "Clone"]
##            # If path has "control set" name, normalise target path
##            # See: http://support.microsoft.com/kb/100010
##            for name in control_names:
##                if len(norm_path) >= 2:
##                    if norm_path[1] == name:
##                        norm_path[1] = "%controlset%"
##                        if len(norm_path) >= 3:
##                            # Hack fix for uppercase
##                            if norm_path[2] == "Services":
##                                norm_path[2] = "services"
##            # Hack fix for TrueCrypt volume... fix!
##            if co.basename.startswith("\??\Volume"):
##                norm_basename = "\??\Volume"
        # Normalize NTUSER.DAT entries
##        if self.active_rootkey == "ntuser.dat":
##            # Fix user assist keys
##            if "UserAssist" in norm_path:
##                # Change the variable GUID value in the path
##                if len(norm_path) > 7:
##                    norm_path[7] = "%GUID%"
##                # Decrypt basename
##                if norm_basename.startswith("HRZR_EHACNGU:"):
##                    norm_basename = norm_basename.replace("HRZR_EHACNGU:", "")
##                norm_basename = codecs.decode(norm_basename, 'rot13')
##                if norm_basename.startswith("C:\\"):
##                    norm_basename = self.normalize_basename(norm_basename)
        # Re-join the path, set fixed path as "norm_cellpath" attribute
        norm_path = "\\".join(norm_path)
        norm_path = norm_path + norm_basename
        co.norm_cellpath = norm_path
    """
    def normalize_basename(self, basename):
        """ If the basename is a path, normalize using the normalize function
            from the FilePathNormalizer module. """
        norm_basename = basename[3:].replace('\\', '/')
        norm_basename = self.file_path_normalizer.normalize(norm_basename)
        return norm_basename        
