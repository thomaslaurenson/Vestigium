# !/usr/bin/python

"""
Author:  Thomas Laurenson
Email:   thomas@thomaslaurenson.com
Website: thomaslaurenson.com
Date:    2016/02/12

Description:
Vestigium is a proof of concept implementation of an application  profiling
framework. The framework automates the detection of file system  and Windows
Registry entries. All digital artifacts associated with an application are
represented and processing automated by using the standardised DFXML, RegXML
and APXML forensic data abstractions.
Vestigium requires three inputs:
    1) Forensic image
    2) Output directory
    3) Application Profile XML (APXML) document(s)

USAGE EXAMPLE:
python3.4 Vestigium.py ~/TDS/1-install.raw /
                       ~/TDS/1-install-output /
                       ~/TDS/TrueCrypt-7.1a-6.1.7601-FINAL.apxml /
                       --dfxml ~/TDS/1-install.xml /
                       --hives ~/TDS/1-install/

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

import sys
import os
import timeit
import errno
import shutil
import glob
import logging
import datetime
import hashlib
import subprocess
import platform

# Append needed library paths
sys.path.append(r'src/')
sys.path.append(r'dfxml/')
sys.path.append(r'apxml/')

try:
    import FileSystemProcessing
except ImportError:
    print('Error: Vestigium.py')
    print('       The FileSystemProcessing.py module is required.')
    print('       Now Exiting...')
    sys.exit(1)

try:
    import RegistryProcessing
except ImportError:
    print('Error: Vestigium.py')
    print('       The RegistryProcessing.py module is required.')
    print('       Now Exiting...')
    sys.exit(1)

if sys.version_info <= (3,0):
    raise RuntimeError("Vestigium.py requires Python 3.0 or above")

################################################################################
# Helper Methods
def check_program(name):
    try:
        devnull = open(os.devnull)
        subprocess.Popen([name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).communicate()
    except OSError as e:
        if e.errno == os.errno.ENOENT:
            return False
    return True

################################################################################
################################################################################
if __name__=="__main__":
    import argparse
    parser = argparse.ArgumentParser(description='''
Vestigium is a proof of concept implementation of an application  profiling
framework. The framework automates the detection of file system  and Windows
Registry entries. All digital artifacts associated with an application are
represented and processing automated by using the standardised DFXML, RegXML
and APXML forensic data abstractions.
Vestigium requires three inputs:
    1) Forensic image
    2) Output directory
    3) Application Profile XML (APXML) document(s)

USAGE EXAMPLE:
python3.4 Vestigium.py ~/TDS/1-install.raw /
                       ~/TDS/1-install-output /
                       ~/TDS/TrueCrypt-7.1a-6.1.7601-FINAL.apxml /
                       --dfxml ~/TDS/1-install.xml /
                       --hives ~/TDS/1-install/''', formatter_class = argparse.RawTextHelpFormatter)
    parser.add_argument("imagefile",
                        help = "Target disk image")
    parser.add_argument('outputdir',
                        action = 'store',
                        help = 'Output directory')
    parser.add_argument("apxmls",
                        help = "Application Profile XML document(s)",
                        nargs = '+')
    parser.add_argument("-e",
                        help = "Experimental testing mode.",
                        action = 'store')
    parser.add_argument("--dfxml",
                        metavar = 'DFXML',
                        action = 'store',
                        help = "DFXML report previously generated using fiwalk")
    parser.add_argument("--hives",
                        metavar = 'HIVES',
                        action = 'store',
                        help = "Directory of hive files previously extracted using hivexml")
    parser.add_argument("-d",
                        help = "Do not remove files ending with '/.' and '/..' \n(default is to remove these files)",
                        action = "store_false",
                        default = True)
    parser.add_argument("-t",
                        help = "Report all timestamps in Unix timestamp format \n(default timestamp format is ISO 8601)",
                        action="store_true")
    parser.add_argument("-z",
                        help = "Zap (delete) the output directory if it exists",
                        action = "store_true",
                        default = False)

    args = parser.parse_args()
    
    # Parse command line arguments
    imagefile = os.path.abspath(args.imagefile)
    outputdir = os.path.abspath(args.outputdir)
    profiles = args.apxmls
    xmlfile = args.dfxml
    hives_dir = args.hives
    ignore_dotdirs = args.d
    timestamp = args.t
    zapdir = args.z
    mode = args.e

    # Operating system check with tool dependency check
    if platform.system() == "Windows":
        # fiwalk check
        fiwalk = "fiwalk" + os.sep + "fiwalk-0.6.3.exe"
        if not check_program(fiwalk):
            print('\nError: Vestigium.py')
            print('       The Vestigium.py module requires the fiwalk tool from The Sleuth Kit.')
            print('       Download: http://digitalcorpora.org/downloads/fiwalk/fiwalk-0.6.3.exe')
            print('       Now Exiting...')
            sys.exit(1)
        # CellXML-Registry check
        cellxml = "CellXML-Registry-1.2.1" + os.sep + "CellXML-Registry-1.2.1.exe"
        if not check_program(cellxml):
            print('\nError: Vestigium.py')
            print('       The Vestigium.py module requires the CellXML-Registry tool.')
            print('       Download: https://github.com/thomaslaurenson/CellXML-Registry')
            print('       Now Exiting...')
            sys.exit(1)
        # img_cat check
        img_cat = "sleuthkit-4.1.3-win32" + os.sep + "bin" + os.sep + "img_cat.exe"
        if not check_program(img_cat):
            print('\nError: Vestigium.py')
            print('       The Vestigium.py module requires the img_cat tool from TSK.')
            print('       Download: http://www.sleuthkit.org/sleuthkit/download.php')
            print('       Now Exiting...')
            sys.exit(1)
        # mmls check
        mmls = "sleuthkit-4.1.3-win32" + os.sep + "bin" + os.sep + "mmls.exe"
        if not check_program(mmls):
            print('\nError: Vestigium.py')
            print('       The Vestigium.py module requires the mmls tool from TSK.')
            print('       Download: http://www.sleuthkit.org/sleuthkit/download.php')
            print('       Now Exiting...')
            sys.exit(1)                           
                                
    elif platform.system() == "Linux":
        # fiwalk check
        if not check_program("fiwalk"):
            print('\nError: Vestigium.py')
            print('       The Vestigium.py module requires the fiwalk tool from The Sleuth Kit.')
            print('       Download: https://github.com/sleuthkit/sleuthkit')
            print('       Now Exiting...')
            sys.exit(1)
        # mmls check
        if not check_program("mmls"):
            print('\nError: Vestigium.py')
            print('       The Vestigium.py module requires the mmls tool from The Sleuth Kit.')
            print('       Download: https://github.com/sleuthkit/sleuthkit')
            print('       Now Exiting...')
            sys.exit(1)    
        # img_cat check
        if not check_program("img_cat"):
            print('\nError: Vestigium.py')
            print('       The Vestigium.py module requires the img_cat tool from The Sleuth Kit.')
            print('       Download: https://github.com/sleuthkit/sleuthkit')
            print('       Now Exiting...')
            sys.exit(1)
        # CellXML-Registry check, not available on Linux
        # Print error to inform user
        print('\nError: Vestigium.py')
        print('       The CellXML-Registry tool is required to parse Registry entries.')
        print('       You can continue, but without Registry support...')
        # Switch to just file system analysis
        cont = input('  > Continue processing? ([Y] or N): ')
        if cont.lower() == 'y' or cont.lower() == 'yes':
            mode = "file"
        else:
            print('    Now Exiting...')
            sys.exit(1)
            
    # Check evidence file (disk image) exists
    if not os.path.isfile(imagefile):
        print('\nError: Vestigium.py')
        print('       The supplied evidence file (disk image) does not exist.')
        print('       %s' % imagefile)
        print('       Now Exiting...')
        sys.exit(1)
    
    # Check evidence file (disk image) has valid partition table
    # Sometime fiwalk can run without a valid partition?!
    # Therefore, commented out
#    if os.path.isfile(imagefile):
#        if platform.system() == "Windows":
#            cwd = "sleuthkit-4.1.3-win32" + os.sep + "bin" + os.sep
#            cmd = [cwd + "mmls.exe"]
#        else:
#            cwd = os.getcwd()
#            cmd = ["mmls"]
#        cmd.append(imagefile)

#        try:
#            subprocess.check_output(cmd,
#                                    stderr=subprocess.STDOUT,
#                                    cwd=cwd)
#        except subprocess.CalledProcessError:
#            print('\nError: Vestigium.py')
#            print('       The supplied evidence file (disk image) does not have a valid partition.')
#            print('       %s' % imagefile)
#            print('       Now Exiting...')                
#            sys.exit(1)          
        
    # Check APXML files exist (there may be multiple)
    for profile in profiles:
        if not os.path.isfile(profile):
            print('\nError: Vestigium.py')
            print('       The supplied APXML file does not exist.')
            print('       %s' % profile)
            print('       Now Exiting...')
            sys.exit(1)        
        
    # Check dfxml file exists (if supplied)
    if xmlfile:
        if not os.path.isfile(xmlfile):
            print('\nError: Vestigium.py')
            print('       The supplied DFXML file does not exist.')
            print('       %s' % xmlfile)
            print('       Now Exiting...')
            sys.exit(1)

    # Check hives directory exists (if supplied)
    if hives_dir:
        if not os.path.isdir(hives_dir):
            print('\nError: Vestigium.py')
            print('       The supplied hives directory does not exist.')
            print('       %s' % hives_dir)
            print('       Now Exiting...')
            sys.exit(1)              
            
    # Create output folder (with error checking)
    if os.path.exists(outputdir) and os.path.isdir(outputdir):
        if zapdir:
            print('\n  > Error: The specified output directory already exists...')
            print('    %s' % outputdir)
            delete = input('  > Delete the existing directory? ([Y] or N): ')
            if delete.lower() == 'y' or delete.lower() == 'yes':
                shutil.rmtree(outputdir)
                os.makedirs(outputdir)
            else:
                print('    Now Exiting...')
                sys.exit(1)
        else:
            print('\n  > Error: The specified output directory already exists...')
            print('    %s' % outputdir)
            print('    Now Exiting...')
            sys.exit(1)
    else:
        os.makedirs(outputdir)
        
    # Start Vestigium timer
    base_start_time = timeit.default_timer()        

    # Set up logging, and write case information
    log = outputdir + os.sep + "vestigium.log"
    logging.basicConfig(filename = log,
                        level=logging.DEBUG,
                        format = '%(message)s')
    logging.info("Starting processing ...")
    logging.info("Start time: %s" % datetime.datetime.now())
    logging.info("\n>>> CASE INPUT INFORMATION:")
    logging.info("    Imagefile:        %s" % imagefile)
    logging.info("    Output (dir):     %s" % outputdir)
    logging.info("    Profile:          %s" % ', '.join(profiles))
    logging.info("    DFXML:            %s" % xmlfile)
    logging.info("    RegXML (dir):     %s" % hives_dir)
    logging.info("    Log file:         %s" % log)
    logging.info("    Ignore dotdirs:   %s" % ignore_dotdirs)
    logging.info("    Timestamp:        %s" % timestamp)
    logging.info("    Zap Output (dir): %s" % zapdir)

    # Testing mode, perform only file system or Registry analysis
    if (mode == 'file'):
        fs_start_time = timeit.default_timer()
        fs = FileSystemProcessing.FileSystemProcessing(imagefile = imagefile,
                                               xmlfile = xmlfile,
                                               outputdir = outputdir,
                                               profiles = profiles,
                                               ignore_dotdirs = ignore_dotdirs,
                                               timestamp = timestamp)
        fs.process_apxmls()
        fs.process_target()
        fs.dfxml_report_hives()
        fs.dfxml_report()
        fs.results()
        fs.results_overview()

        # All done, log processing timestamp   
        fs_elapsed = timeit.default_timer() - fs_start_time
        logging.info("\n>>> TIMED FS: Total time elapsed:    %s" % fs_elapsed)
        
        print("\n\n>>> Finished.\n")
        quit()

    if (mode == 'reg'):
        reg_start_time = timeit.default_timer() 
        reg = RegistryProcessing.RegistryProcessing(imagefile = imagefile,
                                    xmlfile = xmlfile,
                                    outputdir = outputdir,
                                    profiles = profiles,
                                    hives_dir = hives_dir,
                                    timestamp = timestamp)
        reg.process_apxmls()
        reg.parse_target()
        reg.regxml_report()
        reg.results()
        reg.results_overview()

        # All done, log processing timestamp   
        reg_elapsed = timeit.default_timer() - reg_start_time
        logging.info("\n>>> TIMED REG: Total time elapsed:    %s" % reg_elapsed)

        quit()

    # Normal tool operating starts here...
    ##############################
    # Perform file system analysis
    ##############################
    # Start file system timer
    fs_start_time = timeit.default_timer() 

    fs = FileSystemProcessing.FileSystemProcessing(imagefile = imagefile,
                                                   xmlfile = xmlfile,
                                                   outputdir = outputdir,
                                                   profiles = profiles,
                                                   ignore_dotdirs = ignore_dotdirs,
                                                   timestamp = timestamp)

    fs.process_apxmls()
    fs.process_target()
    fs.dfxml_report_hives()
    fs.dfxml_report()
    fs.results()
    
    # File system elapsed time
    fs_elapsed = timeit.default_timer() - fs_start_time
    
    hives_dir = outputdir + os.sep + "hives" + os.sep
    
    ###################################
    # Perform Windows Registry analysis
    ###################################
    # Start file system timer
    reg_start_time = timeit.default_timer() 
    reg = RegistryProcessing.RegistryProcessing(imagefile = imagefile,
                                                xmlfile = xmlfile,
                                                outputdir = outputdir,
                                                profiles = profiles,
                                                hives_dir = hives_dir,
                                                timestamp = timestamp)
    reg.process_apxmls()
    reg.parse_target()
    reg.regxml_report()
    reg.results()
    
    # Registry elapsed time
    reg_elapsed = timeit.default_timer() - reg_start_time

    # Print overview of results
    print("\n\n-----------------------")
    print(">>> OVERVIEW OF RESULTS")
    print("-----------------------")
    fs.results_overview()
    reg.results_overview()

    # All done, log processing timestamp   
    logging.info("\n>>> TIMED FS: Total time elapsed:    %s" % fs_elapsed)
    logging.info("\n>>> TIMED REG: Total time elapsed:    %s" % reg_elapsed)
    
    # Vestigium elapsed run time
    elapsed = timeit.default_timer() - base_start_time
    logging.info("\n>>> TIMED: Total time elapsed:    %s" % elapsed)

    print("\n\n>>> Finished.\n")
