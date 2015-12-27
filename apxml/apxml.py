#!/usr/bin/env python3

"""
Author:  Thomas Laurenson
Email:   thomas@thomaslaurenson.com
Website: thomaslaurenson.com
Date:    2015/08/24

Description:
The apxml.py Python module is an Application Prog
parses an Application Profile XML (APXML file);
for example, TrueCrypt-7.1a-6.1.7601.apxml.

Copyright (c) 2015, Thomas Laurenson

###############################################################################
This program is free software: you can redistribute it and/or modify
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

>>> CHANGELOG:
    0.1.0       Base functionality ()

>>> TODO:

>>> NOTES:
    Added "REG_DWORD_LITTLE_ENDIAN" to Objects.py (line 2856)
    Added "REG_QWORD_LITTLE_ENDIAN" to Objects.py (line 

"""

__version__ = '0.1.0'

import os
import sys
import datetime
import collections
import xml.etree.ElementTree as ET

try:
    import Objects
except ImportError:
    print("Error: The Objects.py module is required to run this script")
    print("       You can download from: https://github.com/simsong/dfxml")
    print("       Now Exiting...")
    sys.exit(1)

##try:
##    import FixInvalidXMLTokens
##except ImportError:
##    print("Error: The FixInvalidXMLTokens.py module is required to run this script")
##    print("       You can download from: INSERT URL HERE")
##    print("       Now Exiting...")
##    sys.exit(1)    

if sys.version_info <= (3,0):
    raise RuntimeError("apxml.py requires Python 3.0 or above")

_all_phases = list()

################################################################################
# Helper methods
def _ET_tostring(e):
    """ Between Python 2 and 3, there are some differences in the ElementTree
        library's tostring() behavior.  One, the method balks at the "unicode"
        encoding in 2.  Two, in 2, the XML prototype's output with every
        invocation.  This method serves as a wrapper to deal with those
        issues. """
    if sys.version_info[0] < 3:
        tmp = ET.tostring(e, encoding="UTF-8")
        if tmp[0:2] == "<?":
            # Trim away first line; it's an XML prototype.
            # This only appears in Python 2's ElementTree output.
            return tmp[ tmp.find("?>\n")+3 : ]
        else:
            return tmp
    else:
        return ET.tostring(e, encoding="unicode")

def _qsplit(tagname):
    """ Returns namespace and local tag name as a pair. """
    _typecheck(tagname, str)
    if tagname[0] == "{":
        i = tagname.rfind("}")
        return (tagname[1:i], tagname[i+1:])
    else:
        return (None, tagname)

def _typecheck(obj, classinfo):
    """ Check the Object type. """
    if not isinstance(obj, classinfo):
        if isinstance(classinfo, tuple):
            raise TypeError("Expecting object to be one of the types %r." % (classinfo,))
        else:
            raise TypeError("Expecting object to be of type %r." % classinfo)

def _strcast(val):
    """ Convert value to string. """
    if val is None:
        return None
    return str(val)

def _intcast(val):
    """ Convert input integer or string to integer. Preserves NULLs. """
    if val is None:
        return None
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        if val[0] == "-":
            if val[1:].isdigit():
                return int(val)
        else:
            if val.isdigit():
                return int(val)

def _boolcast(val):
    """ Convert value to boolean object. """
    if val is None:
        return None
    elif val in [True, "True", "true"]:
        return True
    elif val in [False, "False", "false"]:
        return False

def _datecast(val):
    """ Convert string time value to datetime object. """
    if val is None:
        return None
    return datetime.datetime.strptime(val, "%Y-%m-%dT%H:%M:%SZ")


################################################################################
# APXML Object to store all application profile information
class APXMLObject(object):
    def __init__(self, *args, **kwargs):
        self.version = "'1.0.0'"
        self._namespaces = dict()

        # APXML header objects
        self.metadata = MetadataObject()
        self.creator = CreatorObject()
        self.rusage = RusageObject()

        # Lists for FileObjects and CellObjects
        self._files = []
        self._cells = []
        
        # Statistics object to store APXML file stats
        self.stats = StatisticsObject()

    _all_properties = set(["fileobject",
                           "cellobject"])

    def __iter__(self):
        """ Yields all FileObjects and CellObjects attached to this APXMLObject. """
        for f in self._files:
            yield f
        for r in self._cells:
            yield r

    def add_namespace(self, prefix, url):
        self._namespaces[prefix] = url
        ET.register_namespace(prefix, url)

    def iter_namespaces(self):
        """Yields (prefix, url) pairs of each namespace registered in this DFXMLObject."""
        for prefix in self._namespaces:
            yield (prefix, self._namespaces[prefix])        

    def append(self, value):
        if isinstance(value, Objects.FileObject):
            self._files.append(value)
        elif isinstance(value, Objects.CellObject):
            self._cells.append(value)
        else:
            raise TypeError("Type Error: %r." % type(value))

    def to_Element(self):
        outel = ET.Element("apxml")

        # Set APXML version
        if self.version:
            outel.attrib["version"] = str(self.version)

        # Set APXML Namespaces
        for prefix in self._namespaces:
            attrib_name = "xmlns"
            if prefix != "":
                attrib_name += ":" + prefix
            outel.attrib[attrib_name] = self._namespaces[prefix]

        # Set Metadata element
        tmpel0 = self.metadata.to_Element()
        outel.append(tmpel0)

        # Set Creator element
        tmpel0 = self.creator.to_Element()
        outel.append(tmpel0)

        # Append life cycle phases?!
        # Append FileObjects
        # Append CellObjects
        tmpel0 = self.objs_to_Element("install")
        tmpel1 = self.objs_to_Element("open")
        tmpel2 = self.objs_to_Element("close")
        tmpel3 = self.objs_to_Element("uninstall")
        tmpel4 = self.objs_to_Element("reboot")
        outel.append(tmpel0)
        outel.append(tmpel1)
        outel.append(tmpel2)
        outel.append(tmpel3)
        outel.append(tmpel4)

        # Set Rusage element
        tmpel0 = self.rusage.to_Element()
        outel.append(tmpel0)
        
        return outel

    def to_apxml(self):
        return _ET_tostring(self.to_Element())

    def objs_to_Element(self, phase):
        outel = ET.Element(phase)
        for fi in self._files:
            if fi.state == phase:
                outel.append(fi.to_Element())
        for cell in self._cells:
            if cell.state == phase:
                outel.append(cell.to_Element())                
        return outel

    def populate_from_Element(self, e, state):
        """ Populate FileObjects and CellObjects from an APXML child element. """
        _typecheck(e, (ET.Element, ET.ElementTree))
        (ns, tn) = _qsplit(e.tag)
        # Add the APXML child tag to a set of _all_phases
        #_all_phases.append(tn)
        #assert tn in _all_phases
        for ce in e.findall("./*"):
            (cns, ctn) = _qsplit(ce.tag)
            if ctn in self._all_properties:
                if ctn == "fileobject":
                    fi = Objects.FileObject()
                    fi.populate_from_Element(ce)
                    fi.state = state
                    self._files.append(fi)
                elif ctn == "cellobject":
                    cell = Objects.CellObject()
                    cell.populate_from_Element(ce)
                    cell.state = state
                    self._cells.append(cell)

    # version setter and getter
    @property
    def version(self):
        return self._version
    @version.setter
    def version(self, value):
        self._version = _strcast(value)


################################################################################
# Metadata Object to store DFXML metadata element information
class MetadataObject(object):
    def __init__(self, *args, **kwargs):
        self.app_name = kwargs.get("app_name")
        self.app_version = kwargs.get("app_version")
        self.type = kwargs.get("type")
        self.publisher = kwargs.get("publisher")

    _all_properties = set(["type",
                           "publisher",
                           "app_name",
                           "app_version"])

    def populate_from_Element(self, e):
        _typecheck(e, (ET.Element, ET.ElementTree))
        (ns, tn) = _qsplit(e.tag)
        assert tn in ["metadata"]
        for ce in e.findall("./*"):
            (cns, ctn) = _qsplit(ce.tag)
            if ctn in self._all_properties:
                if ctn == "app_name":
                    self.app_name = ce.text
                elif ctn == "app_version":
                    self.app_version = ce.text
                elif ctn == "type":
                    self.type = ce.text
                elif ctn == "publisher":
                    self.publisher = ce.text                    

    def to_Element(self):
        outel = ET.Element("metadata")
        for prop in self._all_properties:
            val = getattr(self, prop)
            # Skip NULL properties
            if val is None:
                continue
            # If element name is Dublin Core, prepent "dc:"
            if prop == "type" or prop == "publisher":
                prop = "dc:" + prop
            elem = ET.SubElement(outel, prop)
            elem.text = str(val)
        return outel

    def to_xml(self):
        return _ET_tostring(self.to_Element())

    # app_name setter and getter
    @property
    def app_name(self):
        return self._app_name
    @app_name.setter
    def app_name(self, value):
        self._app_name = _strcast(value)

    # app_version setter and getter
    @property
    def app_version(self):
        return self._app_version
    @app_version.setter
    def app_version(self, value):
        self._app_version = _strcast(value)

    # type setter and getter
    @property
    def type(self):
        return self._type
    @type.setter
    def type(self, value):
        self._type = _strcast(value)

    # publisher setter and getter
    @property
    def publisher(self):
        return self._publisher
    @publisher.setter
    def publisher(self, value):
        self._publisher = _strcast(value)        


################################################################################
# Creator Object to store DFXML creator element information
class CreatorObject(object):
    def __init__(self, *args, **kwargs):
        self.program = kwargs.get("program")
        self.version = kwargs.get("version")
        self.execution_environment = ExecutionEnvironmentObject()

    _all_properties = set(["program",
                           "version",
                           "execution_environment"])

    def populate_from_Element(self, e):
        _typecheck(e, (ET.Element, ET.ElementTree))
        (ns, tn) = _qsplit(e.tag)
        assert tn in ["creator"]
        for ce in e.findall("./*"):
            (cns, ctn) = _qsplit(ce.tag)
            if ctn in self._all_properties:
                if ctn == "program":
                    self.program = ce.text
                elif ctn == "version":
                    self.version = ce.text
                elif ctn == "execution_environment":
                    execution = ExecutionEnvironmentObject()
                    execution.populate_from_Element(ce)
                    self.execution_environment = execution

    def to_Element(self):
        outel = ET.Element("creator")
        for prop in self._all_properties:
            val = getattr(self, prop)
            # Skip NULL properties
            if val is None:
                continue
            # Append the execution environment element
            # Or just add SubElement
            if prop == "execution_environment":
                outel.append(self.execution_environment.to_Element())
            else:
                elem = ET.SubElement(outel, prop)
                elem.text = str(val)
        return outel

    def to_xml(self):
        return _ET_tostring(self.to_Element())
        
    # program setter and getter
    @property
    def program(self):
        return self._program
    @program.setter
    def program(self, value):
        self._program = _strcast(value)

    # version setter and getter
    @property
    def version(self):
        return self._version
    @version.setter
    def version(self, value):
        self._version = _strcast(value)


################################################################################
# Creator Object to store DFXML creator element information
class ExecutionEnvironmentObject(object):
    def __init__(self, *args, **kwargs):
        self.windows_version = kwargs.get("windows_version")
        self.command_line = kwargs.get("command_line")
        self.start_date = kwargs.get("start_date")

    _all_properties = set(["windows_version",
                           "command_line",
                           "start_date"])

    def populate_from_Element(self, e):
        _typecheck(e, (ET.Element, ET.ElementTree))
        (ns, tn) = _qsplit(e.tag)
        assert tn in ["execution_environment"]
        for ce in e.findall("./*"):
            (cns, ctn) = _qsplit(ce.tag)
            if ctn in self._all_properties:
                if ctn == "windows_version":
                    self.windows_version = ce.text
                elif ctn == "command_line":
                    self.command_line = ce.text
                elif ctn == "start_date":
                    self.start_date = ce.text

    def to_Element(self):
        outel = ET.Element("execution_environment")
        for prop in self._all_properties:
            val = getattr(self, prop)
            # Skip NULL properties
            if val is None:
                continue
            if prop == "start_date":
                elem = ET.SubElement(outel, prop)
                elem.text = datetime.datetime.strftime(val, "%Y-%m-%dT%H:%M:%SZ")
            else:
                elem = ET.SubElement(outel, prop)
                elem.text = str(val)
        return outel

    def to_xml(self):
        return _ET_tostring(self.to_Element())

    # windows_version setter and getter
    @property
    def windows_version(self):
        return self._windows_version
    @windows_version.setter
    def windows_version(self, value):
        self._windows_version = _strcast(value)

    # command_line setter and getter
    @property
    def command_line(self):
        return self._command_line
    @command_line.setter
    def command_line(self, value):
        self._command_line = _strcast(value)

    # start_date setter and getter
    @property
    def start_date(self):
        return self._start_date
    @start_date.setter
    def start_date(self, value):
        self._start_date = _datecast(value)
    
################################################################################
# Rusage Object to store DFXML metadata element information
class RusageObject(object):
    def __init__(self, *args, **kwargs):
        self.end_date = kwargs.get("end_date")

    _all_properties = set(["end_date"])

    def populate_from_Element(self, e):
        _typecheck(e, (ET.Element, ET.ElementTree))
        (ns, tn) = _qsplit(e.tag)
        assert tn in ["rusage"]
        for ce in e.findall("./*"):
            (cns, ctn) = _qsplit(ce.tag)
            if ctn in self._all_properties:
                if ctn == "end_date":
                    self.end_date = ce.text

    def to_Element(self):
        outel = ET.Element("rusage")
        for prop in self._all_properties:
            val = getattr(self, prop)
            # Skip NULL properties
            if val is None:
                continue
            if prop == "end_date":
                elem = ET.SubElement(outel, prop)
                elem.text = datetime.datetime.strftime(val, "%Y-%m-%dT%H:%M:%SZ")
            else:
                elem = ET.SubElement(outel, prop)
                elem.text = str(val)
        return outel

    def to_xml(self):
        return _ET_tostring(self.to_Element())

    # end_date setter and getter
    @property
    def end_date(self):
        return self._end_date
    @end_date.setter
    def end_date(self, value):
        self._end_date = _datecast(value)

################################################################################
# Rusage Object to store DFXML metadata element information
class StatisticsObject(object):
    def __init__(self, *args, **kwargs):
        self.cALL = 0       # Total APXML entries
        self.cFS = 0        # File system entry count
        self.cFSFiles = 0   # File system: FILE count
        self.cFSDirs = 0    # File system: DIR count
        self.cREG = 0       # Registry entry count
        self.cREGKeys = 0   # Registry: KEY count
        self.cREGValues = 0 # Registry: VALUE count

        self.cFSFilesState = collections.defaultdict(int)
        self.cFSFilesDelta = collections.defaultdict(int)
        self.cFSFilesStateDelta = collections.OrderedDict()
        for state in _all_phases:
            self.cFSFilesStateDelta[state] = []

        self.cFSDirsState = collections.defaultdict(int)
        self.cFSDirsDelta = collections.defaultdict(int)
        self.cFSDirsStateDelta = collections.OrderedDict()
        for state in _all_phases:
            self.cFSDirsStateDelta[state] = []
            
        self.cREGKeysState = collections.defaultdict(int)
        self.cREGKeysDelta = collections.defaultdict(int)
        self.cREGKeysStateDelta = collections.OrderedDict()
        for state in _all_phases:
            self.cREGKeysStateDelta[state] = []


        self.cREGValuesState = collections.defaultdict(int)
        self.cREGValuesDelta = collections.defaultdict(int)
        self.cREGValuesStateDelta = collections.OrderedDict()
        for state in _all_phases:
            self.cREGValuesStateDelta[state] = []

################################################################################
def generate_stats(apxml_obj):
    """ Generate statistics from an APXMLObject. """
    
    # Check if we have an APXMLObject
    if not isinstance(apxml_obj, APXMLObject):
        return
        
    # Create an object to hold stats information
    apxml_obj.stats = StatisticsObject()

    # Iterate over each FileObject and CellObject and collect stats
    for obj in apxml_obj:
        apxml_obj.stats.cALL += 1
        if isinstance(obj, Objects.FileObject):
            apxml_obj.stats.cFS += 1
            # Process file system file entry
            if obj.meta_type == 1:
                apxml_obj.stats.cFSFiles += 1
                apxml_obj.stats.cFSFilesState[obj.state] += 1
                for delta in obj.annos:
                    apxml_obj.stats.cFSFilesDelta[delta] += 1
                    apxml_obj.stats.cFSFilesStateDelta[obj.state].append(delta)
            # Process file system directory
            elif obj.meta_type == 2:
                apxml_obj.stats.cFSDirs += 1
                apxml_obj.stats.cFSDirsState[obj.state] += 1
                for delta in obj.annos:
                    apxml_obj.stats.cFSDirsDelta[delta] += 1
                    apxml_obj.stats.cFSDirsStateDelta[obj.state].append(delta)

        if isinstance(obj, Objects.CellObject):
            apxml_obj.stats.cREG += 1
            # Process Registry key
            if obj.name_type == "k": 
                apxml_obj.stats.cREGKeys += 1
                apxml_obj.stats.cREGKeysState[obj.state] += 1
                for delta in obj.annos:
                    apxml_obj.stats.cREGKeysDelta[delta] += 1
                    apxml_obj.stats.cREGKeysStateDelta[obj.state].append(delta)
            # Process Registry value
            elif obj.name_type == "v":
                apxml_obj.stats.cREGValues += 1
                apxml_obj.stats.cREGValuesState[obj.state] += 1
                for delta in obj.annos:
                    apxml_obj.stats.cREGValuesDelta[delta] += 1
                    apxml_obj.stats.cREGValuesStateDelta[obj.state].append(delta)
        
################################################################################
def iterparse(filename, events=("start", "end"), **kwargs):
    """ Generator. Parses an APXML document to an APXMLObject. """
    
    # APXML default XML tags
    _default_tags = ["apxml",
                     "metadata",
                     "type",
                     "publisher",
                     "app_name",
                     "app_version",
                     "program",
                     "version",
                     "windows_version",
                     "command_line",
                     "start_date",
                     "execution_environment",
                     "end_date",
                     "creator",
                     "fileobject",
                     "filename",
                     "filesize",
                     "meta_type",
                     "alloc_name",
                     "alloc_inode",
                     "hashdigest",
                     "cellobject",
                     "cellpath",
                     "basename",
                     "name_type",
                     "data_type",
                     "data",
                     "alloc",
                     "rusage"]

    # Check file input
    #fh = open(filename, "rb")          
    fh = open(filename, encoding='utf-16-le', errors='replace')
    #for line in fh:
    #    line = line.strip()
    #    print(line)
    apxml = APXMLObject()
    
    # Call ElementTree iterparse on APXML
    for (ETevent, elem) in ET.iterparse(fh, events=("start-ns", "start", "end")):

        #Track namespaces
        if ETevent == "start-ns":
            apxml.add_namespace(*elem)
            ET.register_namespace(*elem)
            continue
        
        # Split element to namespace and tag name
        (ns, ln) = _qsplit(elem.tag)
        
        # Process each XML tag
        if ETevent == "start":
            if ln == "metadata":
                metadata = MetadataObject()
                metadata.populate_from_Element(elem)
                apxml.metadata = metadata
            elif ln == "creator":
                creator = CreatorObject()
                creator.populate_from_Element(elem)
                apxml.creator = creator
            elif ln == "rusage":
                rusage = RusageObject()
                rusage.populate_from_Element(elem)
                apxml.rusage = rusage
        elif ETevent == "end":
            if ln not in _default_tags:
                _all_phases.append(ln)
                apxml.populate_from_Element(elem, ln)

    # All done, return the APXMLObject
    return apxml

################################################################################
################################################################################
if __name__=='__main__':
    import argparse
    parser = argparse.ArgumentParser()

    # Run unit tests
    # Test intcast method
    assert _intcast(-1) == -1
    assert _intcast("-1") == -1

    # Test qsplit method
    assert _qsplit("{http://www.w3.org/2001/XMLSchema}all") == ("http://www.w3.org/2001/XMLSchema","all")
    assert _qsplit("http://www.w3.org/2001/XMLSchema}all") == (None, "http://www.w3.org/2001/XMLSchema}all")

    # Test datecast method
    assert _datecast("2015-08-10T18:24:15Z") == datetime.datetime(2015, 8, 10, 18, 24, 15)

    print("\nModule tests passed.\n")
