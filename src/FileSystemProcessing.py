# !/usr/bin/python

"""
Author:  Thomas Laurenson
Email:   thomas@thomaslaurenson.com
Website: thomaslaurenson.com
Date:    2016/03/16

Description:
FileSystemMatching.py is a Vestigium module to perform file system analysis.

Copyright (c) 2016, Thomas Laurenson

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

import os
import sys
import logging
import platform
import datetime
import timeit
import io
import hashlib
import xml.dom.minidom
import collections
import subprocess

try:
    import FilePathNormalizer
except ImportError:
    print('Error: FileSystemProcessing.py')
    print('       The FilePathNormalizer.py module is required.')
    print('       You can download from: https://github.com/thomaslaurenson/Vestigium')
    print('       Now Exiting...')
    sys.exit(1)

try:
    import Objects
except ImportError:
    print('Error: FileSystemProcessing.py')
    print('       The Objects.py module is required.')
    print('       You can download from: https://github.com/simsong/dfxml')
    print('       Now Exiting...')
    sys.exit(1)

try:
    import dfxml
except ImportError:
    print('Error: FileSystemProcessing.py')
    print('       The dfxml.py module is required.')
    print('       You can download from: https://github.com/simsong/dfxml')
    print('       Now Exiting...')
    sys.exit(1)

try:
    import apxml
except ImportError:
    print('Error: FileSystemProcessing.py')
    print('       The apxml.py module is required.')
    print('       You can download from: https://github.com/thomaslaurenson/apxml')
    print('       Now Exiting...')
    sys.exit(1)

################################################################################
# Global hive file name variables
hive_names = ['ntuser.dat',
              'repair/sam',
              'repair/security',
              'repair/software',
              'repair/system',
              'system32/config/sam',
              'system32/config/security',
              'system32/config/software',
              'system32/config/system',
              'system32/config/components',
              'local settings/application data/microsoft/windows/usrclass.dat']

XMLNS_DELTA = "http://www.forensicswiki.org/wiki/Forensic_Disk_Differencing"

################################################################################
# Helper methods
def ptime(self, t):
    """ Return the requested time format. 't' is a dfxml time value. """
    if t is None:
        return "null"
    if self.timestamp:
        return str(t.timestamp())
    else:
        return str(t.iso8601())

def match_dir(tfo, pfo):
    """ Match a directory artifact. """
    return match_filename_norm(tfo, pfo) and match_allocation(tfo, pfo)

def match_file(tfo, pfo):
    """ Match a data file artifact. """
    if (match_filename_norm(tfo, pfo) and
        match_hash(tfo,pfo) and
        match_size(tfo, pfo) and
        match_allocation(tfo, pfo)):
        return 2
    elif (match_filename_norm(tfo, pfo) and
          match_allocation(tfo, pfo)):
        return 1
    else:
        return 0

def match_filename_norm(tfo, pfo):
    """ Compare fullpath of target fileobejct to profile filobject. """
    return tfo.filename_norm == pfo.filename_norm

def match_hash_sha1(tfo, pfo):
    """ Compare SHA-1 hash of target fileobejct to profile filobject. """
    return tfo.sha1 == pfo.sha1

def match_hash(tfo, pfo):
    """ Compare MD5 hash of target fileobejct to profile filobject. """
    return tfo.md5 == pfo.md5

def match_size(tfo, pfo):
    """ Compare SHA-1 hash of target fileobejct to profile filobject. """
    return tfo.filesize == pfo.filesize

def match_basename(tfo, pfo):
    """ Compare the basename of the target fileobejct to profile filobject. """
    return os.path.basename(tfo.filename) == os.path.basename(pfo.filename)

def match_allocation(tfo, pfo):
    """ Compare the allocation of the target fileobejct to profile filobject. """
    return tfo.is_allocated() == pfo.is_allocated()

def sha1_file(tfo):
    """ Helper method to calculate SHA-1 hash of extracted hive file. """
    hasher = hashlib.sha1()
    with open(tfo, 'rb') as f:
        buf = f.read()
        hasher.update(buf)
    return hasher.hexdigest()

def md5_file(tfo):
    """ Helper method to calculate MD5 hash of extracted hive file. """
    hasher = hashlib.md5()
    with open(tfo, 'rb') as f:
        buf = f.read()
        hasher.update(buf)
    return hasher.hexdigest()
    
################################################################################
class FileSystemProcessing():
    def __init__(self, imagefile=None, xmlfile=None, outputdir=None, profiles=None, ignore_dotdirs=False, timestamp=False):
        """ Initialise FileSystemProcessing object. """

        # Object variables
        self.imagefile = imagefile
        self.xmlfile = xmlfile
        self.profiles = profiles
        self.outputdir = outputdir
        self.ignore_dotdirs = ignore_dotdirs
        self.timestamp = timestamp

        # Print banner for file system processing
        #print("\n-----------------------------------")
        #print(">>> PERFORMING FILE SYSTEM ANALYSIS")
        #print("-----------------------------------")
        logging.info("\n-----------------------------------")
        logging.info(">>> PERFORMING FILE SYSTEM ANALYSIS")
        logging.info("-----------------------------------")

        # List of Profile FileObjects (PFOs)
        self.pfos = list()

        # Dictionary to store Profile FileObjects (PFOs)
        # self.pfos = { fullpath : [FileObject1, FileObject2 ... }
        self.pfos_dict = collections.defaultdict(list)

        # Set to store known file paths
        # self.pfos_filenames = { filename1, filename2 ...}
        self.pfos_filenames = set()

        # Dictionary to store SHA-1 hashes
        # self.pfos_hashes = { md5 : [FileObject1, FileObject2 ... }
        self.pfos_hashes = collections.defaultdict(list)

        # Store the Target Data Set in a DFXML object
        self.tds_dfxml = Objects.DFXMLObject()

        # Store the Profile FileObjects in a DFXML object
        self.pfo_dfxml = Objects.DFXMLObject()

        # Initialize the file path normalizer object
        self.file_path_normalizer = FilePathNormalizer.FilePathNormalizer()

        # Create a list for FileObjects matches
        self.matches = list()

        # Create a list of extracted hives
        self.hives = list()

        # Counter for target FileObjects to display progress
        self.target_file_count = 0
        self.target_dir_count = 0
        self.matches_count = 0
        self.allocated_count = 0
        self.unallocated_count = 0
        
        # Set disk image volume properties
        self.partition_offset = 0
        self.ftype_str = None
        self.imagefile_type = None
        
        # Set known file size for selective hashes
        self.known_filesizes = set()
        

    ###########################################################################
    def process_apxmls(self):
        """ Process Application Profiles (APXML documents). """
        print("\n>>> PERFORMING FILE SYSTEM ANALYSIS ...")
        print(">>> Processing application profiles ...")
        logging.info("\n>>> Application profile information:")

        # Process each target Application Profile XML (APXML) document
        for profile in self.profiles:
            print("  > Processing: %s" % os.path.basename(profile))
            apxml_obj = apxml.iterparse(profile)
            apxml.generate_stats(apxml_obj)
            for pfo in apxml_obj:
                if isinstance(pfo, Objects.FileObject):
                    """
                    # Add basename to FileObject
                    basename = obj.filename.split("\\")
                    obj.basename = basename[len(basename) - 1]

                    # Normalize the file path and append to FileObject
                    obj.filename_norm = file_path_normalizer.normalize(obj.filename)

                    # Use filename_norm to extract basename_norm
                    basename_norm = obj.filename_norm.split("/")
                    obj.basename_norm = basename_norm[len(basename_norm) - 1]

                    # Set the application name
                    obj.app_name = apxml_obj.metadata.app_name

                    # Add a orphan_name to only unallocated files
                    if not obj.is_allocated() and obj.meta_type == 1:
                        split = obj.filename.split("\\")
                        obj.orphan_name = "$OrphanFiles/" + split[len(split) - 1]
                    """
                    
                    # If a data file, add size to known_filesizes
                    if pfo.meta_type == 1 and pfo.filesize and pfo.filesize is not 0:
                        self.known_filesizes.add(pfo.filesize)

                    # Add Profile FileObject (PFO) to:
                    # 1) PFO list
                    # 2) PFO dictionary
                    # 3) PFO full path set
                    # 4) PFO SHA-1 dictionary
                    # 5) PFO DFXMLObject
                    self.pfos.append(pfo)
                    self.pfos_dict[pfo.filename_norm].append(pfo)
                    self.pfos_filenames.add(pfo.filename_norm)
                    if pfo.meta_type == 1 and pfo.md5 is not None:
                        self.pfos_hashes[pfo.md5].append(pfo)
                    self.pfo_dfxml.append(pfo)

                    # Log all profile entries (Application, State, Path)
                    logging.info("    %s\t%s\t%s" % (apxml_obj.metadata.app_name, pfo.app_state, pfo.filename_norm))

    ###########################################################################
    def dfxml_report_hives(self):
        """ Generate a DFXML report of extracted hive files. """
        dc = {"name" : os.path.basename(__file__),
              "type" : "Hash List",
              "date" : datetime.datetime.now().isoformat(),
              "os_sysname" : platform.system(),
              "os_sysname" : platform.system(),
              "os_release" : platform.release(),
              "os_version" : platform.version(),
              "os_host" : platform.node(),
              "os_arch" : platform.machine()}
        dfxml = Objects.DFXMLObject(command_line = " ".join(sys.argv),
                                    sources = [self.imagefile],
                                    dc = dc,
                                    files = self.hives)
        # Write a temp DFXML file, format it, then write to logfile
        temp_fi = io.StringIO(dfxml.to_dfxml())
        xml_fi = xml.dom.minidom.parse(temp_fi)
        report_fn = "ExtractedHiveFiles.xml"
        report_fn = os.path.join(self.outputdir, report_fn)
        logging.info("\n>>> DFXML Report for extracted Registry hives: %s\n" % report_fn)
        with open(report_fn, 'w') as f:
            f.write(xml_fi.toprettyxml(indent="  "))

    ###########################################################################
    def generate_icat_cmd(self, fo):
        """ Generate an icat command with arguments for target disk image. """
        
        # Set the icat command to invoke tool
        if platform.system() == "Windows":
            icat = "sleuthkit-4.1.3-win32" + os.sep + "bin" + os.sep + "icat.exe"
        else:
            icat = "icat"
            
        # Do a quick inode check
        if not fo.inode:
            return
            
        # Convert offset to start block
        offset = int(self.partition_offset/512)
            
        # Determine file system offset of disk image
        subp_command = [icat, 
                        "-o", str(offset),
                        "-i", str(self.imagefile_type),
                        "-f", str(self.ftype_str),
                        self.imagefile,
                        str(fo.inode)]
                        
        # Return the generated command
        return subp_command

    ###########################################################################
    def extract_fi(self, fo, out_path):
        """ Extract a file using icat tool. """
        
        # Set up the icat command using helper method
        subp_command = self.generate_icat_cmd(fo)

        # Write the stdout of the icat command to a file
        with open(out_path, 'wb') as f:
            subprocess.call(subp_command, stdout=f)
        f.close()
        
    ###########################################################################
    def extract_fi_hash_md5(self, fo):  
        """ Determine the MD5 hash value of icat output. """    

        # Set up the icat command using helper method
        subp_command = self.generate_icat_cmd(fo)
        
        # Execute icat command, capture output
        p = subprocess.Popen(subp_command, stdout=subprocess.PIPE)
      
        # Generate hash from icat output
        hasher = hashlib.md5()
        buf = p.stdout.read()
        hasher.update(buf)
        
        # Return the hash value
        return hasher.hexdigest()
        
    ###########################################################################
    def extract_hive(self, tfo):
        """ Extract a Windows Registry hive file from forensic disk image. """
        # Specify a new output file name (preserve the full path from disk image)
        out_fn = tfo.filename
        out_fn = out_fn.replace('/','-').replace(' ','-')
        out_dir = self.outputdir + os.sep + "hives" + os.sep
        out_path = os.path.join(out_dir, out_fn)

        # Check the output directory exists
        # This is the user specified directory with a 'hives' subdirectory
        if not os.path.exists(out_dir):
            os.makedirs(out_dir)

        # Extract the actual Registry hive file
        self.extract_fi(tfo, out_path)              
                     
        # Calculate the MD5 hash value of the extracted hive file
        tfo.md5 = self.extract_fi_hash_md5(tfo)                     
                                               
        # Check the SHA-1 of fileobject VS extracted hive
        # SHA-1 not used, but left here for legacy code
        if tfo.sha1 is not None:
            sha1 = sha1_file(out_path)
            if sha1 != tfo.sha1:
                print("\n      Warning: SHA-1 hash mismatch for extracted hive file...")
                print("      %s" % os.path.basename(out_path))
        # Check the MD5 of fileobject VS extracted hive
        elif tfo.md5 is not None:
            md5 = md5_file(out_path)
            if md5 != tfo.md5:
                print("\n      Warning: MD5 hash mismatch for extracted hive file...")
                print("      %s" % os.path.basename(out_path))

        # Add extracted hive file to 'hives' list
        self.hives.append(tfo)

    ###########################################################################
    def process_target(self):
        """ Parse the file system of the target data set. """
        print("\n>>> Processing target data set ...")
        logging.info("\n>>> DETECTED FILE SYSTEM ARTIFACTS:")

        if self.imagefile.endswith(".E01"):
            self.imagefile_type = "ewf"
        else:
            self.imagefile_type = "raw"

        # Process the target data set
        if self.xmlfile is not None:
            # If DFXML from fiwalk, parse using Objects.iterparse
            for (event, obj) in Objects.iterparse(self.xmlfile):
                if isinstance(obj, Objects.VolumeObject):
                    self.partition_offset = obj.partition_offset
                    self.ftype_str = obj.ftype_str
                    
                if isinstance(obj, Objects.FileObject):
                    self.process_target_fi(obj)
        else:
            # If IMAGEFILE, parse using Object.iterparse (but save a DFXML file)
            for (event, obj) in Objects.iterparse(self.imagefile):
                if isinstance(obj, Objects.VolumeObject):
                    self.partition_offset = obj.partition_offset
                    self.ftype_str = obj.ftype_str
                            
                if isinstance(obj, Objects.FileObject):
                    # Append target FileObject to master dfxml container
                    self.tds_dfxml.append(obj)
                    # Process the individual FileObject against target
                    self.process_target_fi(obj)

            # Save DFXML file: Format using minidom then write to file
            # print("\n  > Generating DFXML report of target file system...")
            # self.tds_dfxml.add_namespace("delta", XMLNS_DELTA)
            # temp_fi = io.StringIO(self.tds_dfxml.to_dfxml())
            # xml_fi = xml.dom.minidom.parse(temp_fi)
            # dfxml_report = xml_fi.toprettyxml(indent="  ")
            # basename = os.path.splitext(os.path.basename(self.imagefile))[0]
            # fn = self.outputdir + "/" + basename + ".xml"
            # with open(fn, "w", encoding="utf-8") as f:
                # f.write(dfxml_report)

        # Log all counts
        logging.info("\n>>> File System Counts:")
        logging.info("  > FILE COUNT: %d" % self.target_file_count)
        logging.info("  > DIR COUNT: %d" % self.target_dir_count)
        logging.info("  > ALLOC COUNT: %d" % self.allocated_count)
        logging.info("  > UNALLOC COUNT: %d" % self.unallocated_count)

    ###########################################################################
    def process_target_fi(self, tfo):
        """ Process each Target FileObject (TFO). """
        # File system count progress indicator
        if tfo.meta_type == 2:
            self.target_dir_count += 1
        elif tfo.meta_type == 1:
            self.target_file_count += 1
        sys.stdout.write("\r  > Dirs: {0:6}  Files: {1:6}  Matches: {2:4}".format(self.target_dir_count, self.target_file_count, self.matches_count));
        
        # Get an allocated vs unallocated count (for logging)
        if tfo.is_allocated():
            self.allocated_count += 1
        else:
            self.unallocated_count += 1
            
        # Check if file is to be generically excluded
        if tfo.filename:
            if (self.ignore_dotdirs and (tfo.filename.endswith("/.") or tfo.filename.endswith("/.."))):
                return            

        # Set an emply file name to solve None problems
        if not tfo.filename:
            tfo.filename = ""

        # If we have a filesize that matches a known filesize, generate hash
#        if tfo.filesize in self.known_filesizes:
#            tfo.md5 = self.extract_fi_hash_md5(tfo)
#            print("\n%s\t%s" % (tfo.md5, tfo.filename))

        # Extract hive file if found
        for hive_name in hive_names:
            if tfo.filename:
                fn = tfo.filename.lower()
            else:
                fn = ""
            if fn.endswith(hive_name) and tfo.is_allocated():
                # Do not extract a hive if it has 'repair' in filename
                # This is for performance enhancement, can be removed.
                if "repair" in fn:
                    return
                else:
                    self.extract_hive(tfo)

        # Normalize the TFO full path/filename
        if tfo.filename:
            tfo.filename_norm = self.file_path_normalizer.normalize(tfo.filename)

        # Add basename to TFO FileObject
        split = tfo.filename.split("/")
        tfo.basename = split[len(split) - 1]

        #### Start file system matching
        # 1) First check: Match directories and data files
        if tfo.filename_norm in self.pfos_dict:
            
            if tfo.meta_type == 1:
                tfo.md5 = self.extract_fi_hash_md5(tfo) 

            # Match file system directories
            if tfo.meta_type == 2:
                for pfo in self.pfos_dict[tfo.filename_norm]:
                    if match_dir(tfo, pfo):
                        tfo.annos = {"matched"}
                        tfo.original_fileobject = pfo
                        self.matches.append(tfo)
                        self.matches_count += 1
                        logging.info("  > DIRECTORY: %s\t%s" % (tfo.filename, tfo.is_allocated()))
                        logging.info("             : %s\t%s\t%s\t%s\t%s" % (pfo.filename_norm, pfo.md5, pfo.is_allocated(), pfo.app_name, pfo.app_state))
                        return

            # Match file system data files
            elif tfo.meta_type == 1:
                for pfo in self.pfos_dict[tfo.filename_norm]:                
                    rank = match_file(tfo, pfo)
                    if rank == 1:
                        tfo.annos = {"matched_soft"}
                        tfo.original_fileobject = pfo
                        self.matches.append(tfo)
                        self.matches_count += 1
                        logging.info("  > FILE SOFT: %s\t%s\t%s" % (tfo.filename, tfo.md5, tfo.is_allocated()))
                        logging.info("             : %s\t%s\t%s\t%s\t%s" % (pfo.filename_norm, pfo.md5, pfo.is_allocated(), pfo.app_name, pfo.app_state))
                        return
                    if rank == 2:
                        tfo.annos = {"matched"}
                        tfo.original_fileobject = pfo
                        self.matches.append(tfo)
                        self.matches_count += 1
                        logging.info("  > FILE HARD: %s\t%s\t%s" % (tfo.filename, tfo.md5, tfo.is_allocated()))
                        logging.info("             : %s\t%s\t%s\t%s\t%s" % (pfo.filename_norm, pfo.md5, pfo.is_allocated(), pfo.app_name, pfo.app_state))
                        return

        # 2) Second check: Match orphaned directories and data files ($OrphanFiles)
        elif not tfo.alloc:
            #print(tfo.filename)
            #pfo.orphan_name
            for pfos in self.pfos_dict.values():
                for pfo in pfos:
                    if (tfo.filename == pfo.orphan_name and
                        match_hash(tfo,pfo) and
                        match_size(tfo, pfo) and
                        match_allocation(tfo, pfo)):
                        tfo.annos = {"matched"}
                        tfo.original_fileobject = pfo
                        self.matches.append(tfo)
                        self.matches_count += 1
                        logging.info("  > FILE ORPH: %s\t%s\t%s" % (tfo.filename, tfo.md5, tfo.is_allocated()))
                        logging.info("             : %s\t%s\t%s\t%s\t%s" % (pfo.filename_norm, pfo.md5, pfo.is_allocated(), pfo.app_name, pfo.app_state))
                        return

        # 3) Third check: Perform a SHA-1 and basename check
        elif tfo.md5 in self.pfos_hashes:
            if tfo.meta_type == 1:
                for pfo in self.pfos_hashes[tfo.md5]:
                    if tfo.alloc == pfo.is_allocated() and tfo.basename == pfo.basename:
                        tfo.annos = {"matched"}
                        tfo.original_fileobject = pfo
                        self.matches.append(tfo)
                        self.matches_count += 1
                        logging.info("  > FILE MD5: %s\t%s\t%s" % (tfo.filename, tfo.md5, tfo.is_allocated()))
                        logging.info("             : %s\t%s\t%s\t%s\t%s" % (pfo.filename_norm, pfo.md5, pfo.is_allocated(), pfo.app_name, pfo.app_state))

    ###########################################################################
    def results(self):
        """ Print overview of results to log file. """
        logging.info("\n>>> File System Analysis Overview:")
        profile_states = [pfo.app_state for pfo in self.pfos]
        target_states = [tfo.original_fileobject.app_state for tfo in self.matches]
        for state in set(profile_states):
            logging.info("    {0:<20s} {1:5d} {2:10d}".format(state,
                                                       profile_states.count(state),
                                                       target_states.count(state)))

        # Provide more detailed results, log a list of:
        # 1) Detected results (app, state, path)
        # 2) Not Detected results (app, state, path)
        found = list()
        notfound = list()

        # Compare all PFOs against matched PFOs
        # Get a list of found PFOs
        # Get a list of notfound PFOs
        for pfo in self.pfo_dfxml:
            a_match = False
            for tfo in self.matches:
                diffs = Objects.FileObject.compare_to_other(pfo, tfo.original_fileobject)
                if not diffs:
                    found.append(pfo)
                    a_match = True
            if not a_match:
                notfound.append(pfo)

        # Log found PFOs
        logging.info("\n>>> File System Entries - Detected: %d" % len(found))
        for pfo in found:
            logging.info("    %s\t%s\t%s" % (pfo.app_name, pfo.app_state, pfo.filename_norm))

        # Log notfound PFOs
        logging.info("\n>>> File System Entries - NOT Detected: %d" % len(notfound))
        for pfo in notfound:
            logging.info("    %s\t%s\t%s" % (pfo.app_name, pfo.app_state, pfo.filename_norm))

    ###########################################################################
    def results_overview(self):
        """ Print overview of results to console. """
        print("\n>>> File System Analysis Overview:")
        profile_states = [pfo.app_state for pfo in self.pfos]
        target_states = [tfo.original_fileobject.app_state for tfo in self.matches]
        for state in set(profile_states):
            print("    {0:<20s} {1:5d} {2:10d}".format(state,
                                                       profile_states.count(state),
                                                       target_states.count(state)))

    ###########################################################################
    def dfxml_report(self):
        """ Generate a DFXML report of matches. """
        dc = {"name" : os.path.basename(__file__),
              "type" : "Vestigium Report",
              "date" : datetime.datetime.now().isoformat(),
              "os_sysname" : platform.system(),
              "os_sysname" : platform.system(),
              "os_release" : platform.release(),
              "os_version" : platform.version(),
              "os_host" : platform.node(),
              "os_arch" : platform.machine()}

        # Create a DFXML object to append matched files
        dfxml = Objects.DFXMLObject(command_line = " ".join(sys.argv),
                                    sources = [self.imagefile, self.xmlfile],
                                    dc = dc)

        # Add XML Name Space for "delta" attribute
        dfxml.add_namespace("delta", XMLNS_DELTA)

        # Add matched FileObjects to DFXMLObject
        for tfo in self.matches:
            # Quick hack fix for Python 2 problem with Byte_Runs element
            # where "if Byte_Run.type == 'resident'" the DFXML report cannot
            # be exported using DFXMLObject.to_dfxml()
            if sys.version_info < (3, 0):
                if (tfo.byte_runs[0].type == "resident" and
                    sys.version_info < (3, 0)):
                    tfo.byte_runs[0].type = None
            dfxml.append(tfo)

        # Make a DFXML file, and format using xmllint
        self.dfxml_report = self.outputdir + os.sep + "FileSystemMatching.xml"
        logging.info("\n>>> DFXML REPORT: %s" % self.dfxml_report)

        # Another Python 2 portability problem. If using Python 2, decode
        # the DFXMLObject.to_dfxml() output to unicode
        if sys.version_info < (3, 0):
            temp_xml = dfxml.to_dfxml().decode("unicode-escape")
            temp_report = io.StringIO(temp_xml)
        else:
            temp_report = io.StringIO(dfxml.to_dfxml())

        # Read StingIO file using minidom, then pretty print output
        xml_fi = xml.dom.minidom.parse(temp_report)
        with open(self.dfxml_report, 'w') as f:
            f.write(xml_fi.toprettyxml(indent="  "))
        f.close()

################################################################################
################################################################################
if __name__=="__main__":
    import argparse
    parser = argparse.ArgumentParser(description='''FileSystemProcessing.py''', formatter_class = argparse.RawTextHelpFormatter)
    parser.add_argument("imagefile",
                        help = "Target disk image")
    parser.add_argument('outputdir',
                        action = 'store',
                        help = 'Output directory')
    parser.add_argument("apxmls",
                        help = "Application Profile XML document(s)",
                        nargs = '+')
    parser.add_argument("--dfxml",
                        metavar = 'DFXML',
                        action = 'store',
                        help = "DFXML report previously generated using fiwalk")
    parser.add_argument("-d",
                        help = "Do not remove files ending with '/.' and '/..' \n(default is to remove these files)",
                        action = "store_false",
                        default = True)
    parser.add_argument("-t",
                        help = "Report all timestamps in Unix timestamp format \n(default timestamp format is ISO 8601)",
                        action="store_true")

    args = parser.parse_args()

    # Parse command line arguments
    imagefile = os.path.abspath(args.imagefile)
    outputdir = os.path.abspath(args.outputdir)
    profiles = args.apxmls
    xmlfile = args.dfxml
    ignore_dotdirs = args.d
    timestamp = args.t

    ##############################
    # Perform file system analysis
    ##############################
    fs = FileSystemProcessing.FileSystemProcessing(imagefile = imagefile,
                                           xmlfile = xmlfile,
                                           outputdir = outputdir,
                                           profiles = profiles,
                                           ignore_dotdirs = ignore_dotdirs,
                                           timestamp = timestamp)
    fs.process_apxmls()
    fs.process_target()
    fs.dfxml_report()
    fs.results()
    fs.results_overview()

    # Print overview of results
    print("\n\n-----------------------")
    print(">>> OVERVIEW OF RESULTS")
    print("-----------------------")
    fs.results_overview()
