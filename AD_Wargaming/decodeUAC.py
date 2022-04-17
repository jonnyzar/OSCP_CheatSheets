#!/usr/bin/python

'''
LICENCE:

    author: Yan Zaripov

    Copyright (C) <2022>
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

HOWTOUSE:

first get userAccountControl properties for each user

like so: ldapsearch -H ldap://10.10.10.xxx -x -LLL -W \
 -b "dc=xxx,dc=local" "(&(objectClass=*))" name userAccountControl

exctract UACs

if interesing UAC found, enumerate this user

'''

import sys, getopt

#those flags are typically exploitable
relevant_flags = {
        "ACCOUNTDISABLE":0x0002,
        "DONT_REQUIRE_PREAUTH":0x400000,
        "NOT_DELEGATED":0x100000,
        "TRUSTED_FOR_DELEGATION":0x80000,
        "TRUSTED_TO_AUTH_FOR_DELEGATION":0x1000000
        }

def indentFlag(uac):
   for key, value in relevant_flags.items():      
      if (value & uac):
         print("Security relevant flag found: ", key,
          " in ", uac)       


def main(argv):
   inputfile = ''
   try:
      opts, args = getopt.getopt(argv,"hi:o:",["ifile="])
   except getopt.GetoptError:
      print ('decodeUAC.py -i <inputfile>')
      sys.exit(2)
   for opt, arg in opts:
      if opt == '-h':
         print ('decodeUAC.py -i <inputfile with userAccountControl flag list>')
         sys.exit()
      elif opt in ("-i", "--ifile"):
         inputPath = arg

   #scan all UACs provided for interesting flags
   with open(inputPath, 'r') as inFile:
       for uac in inFile.readlines():
           uac = int(uac.strip("\n"))
           indentFlag(uac)
           #decode UAC by doing bith comparison

if __name__ == "__main__":
    main(sys.argv[1:])
