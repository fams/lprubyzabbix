add name=StrToMd5 owner=admin policy=\
    ftp,reboot,read,write,policy,test,password,sniff,sensitive source="# Strin\
    g message to MD5 Hash\
    \n# Creates a MD5 hash from a message string\
    \n# Version 1.00, 6/17/2012, Created by TealFrog\
    \n# Script tested and developed under MikroTik ROS 5.14 thru 5.17\
    \n#\
    \n# This software is identified as using and is based on the, \"RSA Data S\
    ecurity, \
    \n# Inc. MD5 Message-Digest Algorithm\".  This program is a derived work f\
    rom the RSA Data\
    \n# Security, Inc. MD5 Message-Digest Algorithm.\
    \n# See http://www.ietf.org/rfc/rfc1321.txt for further information.\
    \n#\
    \n# The author of this program makes no representations concerning either\
    \n# the merchantability of this software or the suitability of this\
    \n# software for any particular purpose or non-infringement.\
    \n# This program is provided \"as is\" without express or implied warranty\
    \_of any kind.\
    \n# The author makes no representations or warranties of any kind as to th\
    e \
    \n# completeness, accuracy, timeliness, availability, functionality and co\
    mpliance\
    \n# with applicable laws. By using this software you accept the risk that \
    the \
    \n# information may be incomplete or inaccurate or may not meet your needs\
    \_\
    \n# and requirements. The author shall not be liable for any damages or \
    \n# injury arising out of the use of this program. Use this program at you\
    r own risk. \
    \n#\
    \n# MD5 has been shown to not be collision resistant, as such MD5 is not s\
    uitable \
    \n# for certain applications involving security and/or cryptography, \
    \n# see http://en.wikipedia.org/wiki/Md5 for additional information.\
    \n#\
    \n# \$progName, Name of script, set appropriately\
    \n:global StrToMd5 do={\
    \n\
    \n:local progName \"StrToMd5\"\
    \n:local strMessage \$1\
    \n# \$arrMessages, An array containing one ore more string messages to cre\
    ate MD5 hash from \
    \n:local arrMessages ( \"ABCDEFGHIJKLMNOPQRSTUVWZYZ\",   \\\
    \n                     \"abcedefghijklmnopqrstuvwxyz\",  \\\
    \n                     \"The quick brown fox jumps over the lazy dog.\" )\
    \n\
    \n# \$strPrefix, Set to a prefix to add before MD5 hash, set \"\" for empt\
    y\
    \n:local strPrefix \"\"\
    \n\
    \n# \$strSuffix, Set to a suffix to add after MD5 hash, set \"\" for empty\
    \n:local strSuffix \"\"\
    \n\
    \n# Set \$Debug to 1 for additional output, set to zero to turn off debug\
    \n:local Debug \$2\
    \n\
    \n# \$strHexValues, Used to create hexadecimal output\
    \n:local strHexValues \"0123456789abcdef\"\
    \n# To have uppercase hexadecimal A-F use the next line instead of the abo\
    ve\
    \n# :local strHexValues \"0123456789ABCDEF\"\
    \n\
    \n# No futher modification required beyond this point unless customizing s\
    cript\
    \n# Start by defining constant values\
    \n\
    \n# ASCII Table \$CharSet[0..127]\
    \n:local arrCharSet ( \"\\00\", \"\\01\", \"\\02\", \"\\03\", \"\\04\", \"\
    \\05\", \"\\06\", \"\\07\", \\ \
    \n                    \"\\08\", \"\\09\", \"\\0A\", \"\\0B\", \"\\0C\", \"\
    \\0D\", \"\\0E\", \"\\0F\", \\ \
    \n                    \"\\10\", \"\\11\", \"\\12\", \"\\13\", \"\\14\", \"\
    \\15\", \"\\16\", \"\\17\", \\\
    \n                    \"\\18\", \"\\19\", \"\\1A\", \"\\1B\", \"\\1C\", \"\
    \\1D\", \"\\1E\", \"\\1F\", \\\
    \n                    \"\\20\", \"\\21\", \"\\22\", \"\\23\", \"\\24\", \"\
    \\25\", \"\\26\", \"\\27\", \\\
    \n                    \"\\28\", \"\\29\", \"\\2A\", \"\\2B\", \"\\2C\", \"\
    \\2D\", \"\\2E\", \"\\2F\", \\\
    \n                    \"\\30\", \"\\31\", \"\\32\", \"\\33\", \"\\34\", \"\
    \\35\", \"\\36\", \"\\37\", \\\
    \n                    \"\\38\", \"\\39\", \"\\3A\", \"\\3B\", \"\\3C\", \"\
    \\3D\", \"\\3E\", \"\\3F\", \\\
    \n                    \"\\40\", \"\\41\", \"\\42\", \"\\43\", \"\\44\", \"\
    \\45\", \"\\46\", \"\\47\", \\ \
    \n                    \"\\48\", \"\\49\", \"\\4A\", \"\\4B\", \"\\4C\", \"\
    \\4D\", \"\\4E\", \"\\4F\", \\\
    \n                    \"\\50\", \"\\51\", \"\\52\", \"\\53\", \"\\54\", \"\
    \\55\", \"\\56\", \"\\57\", \\\
    \n                    \"\\58\", \"\\59\", \"\\5A\", \"\\5B\", \"\\5C\", \"\
    \\5D\", \"\\5E\", \"\\5F\", \\\
    \n                    \"\\60\", \"\\61\", \"\\62\", \"\\63\", \"\\64\", \"\
    \\65\", \"\\66\", \"\\67\", \\\
    \n                    \"\\68\", \"\\69\", \"\\6A\", \"\\6B\", \"\\6C\", \"\
    \\6D\", \"\\6E\", \"\\6F\", \\\
    \n                    \"\\70\", \"\\71\", \"\\72\", \"\\73\", \"\\74\", \"\
    \\75\", \"\\76\", \"\\77\", \\\
    \n                    \"\\78\", \"\\79\", \"\\7A\", \"\\7B\", \"\\7C\", \"\
    \\7D\", \"\\7E\", \"\\7F\" ) \
    \n\
    \n# k[i] = floor(abs(sin(i + 1))  4294967296) \
    \n# Or just use the following table \$k[0..63]:\
    \n:local k ( 0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE, \\\
    \n           0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501, \\\
    \n           0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE, \\\
    \n           0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821, \\\
    \n           0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA, \\\
    \n           0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8, \\\
    \n           0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED, \\\
    \n           0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A, \\\
    \n           0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C, \\\
    \n           0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70, \\\
    \n           0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05, \\\
    \n           0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665, \\\
    \n           0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039, \\\
    \n           0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1, \\\
    \n           0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1, \\\
    \n           0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391 )\
    \n\
    \n:local a 0x67452301 \
    \n:local b 0xEFCDAB89\
    \n:local c 0x98BADCFE\
    \n:local d 0x10325476\
    \n\
    \n:local AA 0x67452301\
    \n:local BB 0xEFCDAB89\
    \n:local CC 0x98BADCFE\
    \n:local DD 0x10325476\
    \n\
    \n:local s1 (  7, 12, 17, 22 )\
    \n:local s2 (  5,  9, 14, 20 )\
    \n:local s3 (  4, 11, 16, 23 )\
    \n:local s4 (  6, 10, 15, 21 )\
    \n\
    \n:local i 0\
    \n:local j 0\
    \n:local x 0\
    \n:local S 0\
    \n:local T 0\
    \n:local lcv 0\
    \n:local tmp1 0\
    \n\
    \n:local arrMd5State []\
    \n:local arrWordArray []\
    \n:local ch \"\"\
    \n:local iByteCount 0\
    \n:local iCharVal 3\
    \n:local iDec 0\
    \n:local iHexDigit 8\
    \n:local iMd5State 0\
    \n:local lBytePosition 0\
    \n:local lMessageLength 0\
    \n:local lNumberOfWords 0        \
    \n:local lShiftedVal 0\
    \n:local lWordArray []\
    \n:local lWordArrLen 0\
    \n:local lWordCount 0\
    \n:local sHex \"\"\
    \n:local sMd5Hash \"\"\
    \n:local sMd5Output \"\"\
    \n:local strWordArray \"\"\
    \n\
    \n# Start of main program and message loop\
    \nif ( \$Debug > 0 ) do={\
    \n   :put \"\$progName: Running...\"\
    \n   :put \"\$progName: Message: \$strMessage\"\
    \n}\
    \n   :set ch \"\"\
    \n   :set lShiftedVal 0\
    \n   :set lWordCount 0\
    \n   :set iByteCount 0\
    \n   :set iCharVal 3\
    \n   :set lBytePosition 0\
    \n   :set lMessageLength [ :len \$strMessage ]\
    \n   :set lNumberOfWords ( ( ( ( \$lMessageLength + 8 ) / 64 ) + 1 ) * 16 \
    )        \
    \n   :set strWordArray \"\"\
    \n   :set arrWordArray []\
    \n\
    \n   # Convert to word array \
    \n   :for i from=1 to=(\$lNumberOfWords) do={\
    \n      :set strWordArray (\"0,\" . \$strWordArray)\
    \n   }\
    \n   :set strWordArray  [ :pick \$strWordArray 0 ( [ :len \$strWordArray ]\
    \_- 1 ) ]\
    \n   :set arrWordArray [ :toarray \$strWordArray ]\
    \n   \
    \n   :if ( \$Debug > 0 ) do={\
    \n      :put (\"\$progName: Message Length: \" . \$lMessageLength)\
    \n      :put (\"\$progName: Number of Words: \" . \$lNumberOfWords)\
    \n   }\
    \n   :while (\$iByteCount < \$lMessageLength) do={\
    \n      :set lWordCount (\$iByteCount / 4)\
    \n      :set lBytePosition ((\$iByteCount % 4) * 8)\
    \n         :if ((\$lBytePosition < 0) or (\$lBytePosition > 31)) do={\
    \n            :error ( \"\$progName: Error --  Calculating byte position \
    \" . \\\
    \n                \"# \$lBytePosition, must be 0 thru 31.\" )\
    \n         }\
    \n         :set ch [ :pick \$strMessage \$iByteCount ]\
    \n         :if ( [ :len [ :find \$arrCharSet \$ch ] ] > 0 ) do={\
    \n            :set iCharVal ([ :tonum [ :find \$arrCharSet \$ch ] ])\
    \n         } else={\
    \n            :error \"\$progName: Error -- Input contains undefined ASCII\
    \_value.\"\
    \n         }\
    \n         :if ( \$Debug > 0 ) do={\
    \n            :put ( \"\$progName: parsed character \\\$ch: '\$ch' \" . \\\
    \n              \"ASCII value \\\$iCharVal: \$iCharVal\" )\
    \n         }\
    \n         :set lShiftedVal (((\$iCharVal) << (\$lBytePosition)) | \\\
    \n                         ((\$iCharVal) >> (32-(\$lBytePosition))))\
    \n         :if (\$iByteCount = 0) do={\
    \n            :set lShiftedVal (([ :tonum \$lShiftedVal ] + 0) & 0xFFFFFFF\
    F)\
    \n            :set arrWordArray (([ :tonum \$lShiftedVal ]), \\\
    \n                             [ :pick \$arrWordArray 1 [ :len \$arrWordAr\
    ray] ])\
    \n         } else={\
    \n            :set lShiftedVal (([ :tonum [ :pick \$arrWordArray \$lWordCo\
    unt] ] + 0) | \\\
    \n                           ([ :tonum \$lShiftedVal ] + 0))\
    \n            :set lShiftedVal (([ :tonum \$lShiftedVal ] + 0) & 0xFFFFFFF\
    F)\
    \n            :set arrWordArray  ([ :pick \$arrWordArray 0 \$lWordCount ],\
    \_\$lShiftedVal, \\\
    \n               [ :pick \$arrWordArray ([ :tonum \$lWordCount ] + 1) [ :l\
    en \$arrWordArray] ])   \
    \n         }\
    \n         :set iByteCount ( \$iByteCount + 1 )\
    \n      }\
    \n      :set lWordCount ( \$iByteCount / 4 )\
    \n      :set lBytePosition ( ( \$iByteCount % 4 ) * 8 )\
    \n      :set lShiftedVal [ :pick \$arrWordArray \$lWordCount ]\
    \n      \
    \n      :set lShiftedVal ( ( [ :tonum [ :pick \$arrWordArray \$lWordCount \
    ] ] + 0 ) | \\\
    \n                         ( ( 0x80 << \$lBytePosition ) | \\\
    \n                       ( 0x80 >> ( 32 - \$lBytePosition ) ) ) ) \
    \n      \
    \n      :set arrWordArray  ( ( [ :pick \$arrWordArray 0 \$lWordCount ]  ),\
    \_ \\\
    \n                             [ :tonum \$lShiftedVal ], \\\
    \n                           ( [ :pick \$arrWordArray ( [ :tonum \$lWordCo\
    unt ] + 1 ) \\\
    \n                      [ :len \$arrWordArray ] ] ) ) \
    \n                      \
    \n      :set arrWordArray  [ :toarray ( ( [ :pick \$arrWordArray 0 (\$lNum\
    berOfWords - 2) ] ), \\\
    \n                                    ( ( ( [ :tonum \$lMessageLength ] + \
    0 ) << 3 ) | \\\
    \n                             ( ( [ :tonum \$lMessageLength ] + 0 ) >> 29\
    \_) ), \\\
    \n                             ( ( [ :tonum \$lMessageLength ] + 0 )  >> 2\
    9 ) ) ]\
    \n      :set lWordArray [ :toarray \$arrWordArray ]\
    \n      :set lWordArrLen ( ( [ :len \$lWordArray ] ) - 1 )\
    \n\
    \n   ### Main Loop ###\
    \n      :set tmp1 0\
    \n      :set x 0\
    \n      :set T 0\
    \n      :set S 0\
    \n      :set i 0\
    \n      :set j 0\
    \n      :for lcv from=0 to=( \$lWordArrLen ) step=16 do={\
    \n         :set a 0x67452301 \
    \n         :set b 0xEFCDAB89\
    \n         :set c 0x98BADCFE\
    \n         :set d 0x10325476\
    \n         :set AA [ :tonum \$a ]\
    \n         :set BB [ :tonum \$b ]\
    \n         :set CC [ :tonum \$c ]\
    \n         :set DD [ :tonum \$d ]\
    \n\
    \n     ### Round 1 ### \
    \n         :for i from=0 to=15 do={\
    \n            :set x ( [ :tonum [ :pick \$lWordArray ( \$i & 15 ) ] ] + 0 \
    )\
    \n            :set T ( [ :tonum [ :pick \$k \$i ] ] + 0 )\
    \n            :set S ( [ :tonum [ :pick \$s1 ( \$i & 3 ) ] ] + 0 )\
    \n     # Next line is an alternate mmethod, instead of the line after it  \
    \_  \
    \n     #         :set tmp1 ( ( ((\$b & \$c) | ((((\$b + 1) * -1)) & \$d)) \
    + \$a + \$T + \$x ) & 0xFFFFFFFF )\
    \n            :set tmp1 ( ( ( \$d ^ ( \$b & ( \$c ^ \$d ) ) ) + \$a + \$T \
    + \$x ) & 0xFFFFFFFF )\
    \n            :set tmp1 (((tmp1 << \$S ) | ((\$tmp1 >> (32 - \$S)))) & 0xF\
    FFFFFFF)\
    \n            :set tmp1 ( ( \$tmp1 + \$b ) & 0xFFFFFFFF )\
    \n            :if ( \$Debug > 0 ) do={         \
    \n               :put (\"\$progName: Round 1, Answer \\\$tmp1: \$tmp1\") \
    \n            }            \
    \n     # Rotate a,b,c,d params positions, e.g. d, a, b, c ... c, d, a, b .\
    .. b, c, d, a \
    \n     # and a gets new value from tmp1\
    \n            :set a ( ( [ :tonum \$d ] + 0 ) & 0xFFFFFFFF )\
    \n            :set d ( ( [ :tonum \$c ] + 0 ) & 0xFFFFFFFF )\
    \n            :set c ( ( [ :tonum \$b ] + 0 ) & 0xFFFFFFFF )\
    \n            :set b ( ( [ :tonum \$tmp1 ] + 0 ) & 0xFFFFFFFF )\
    \n         }\
    \n      \
    \n     ### Round 2 ###\
    \n         :set j 1\
    \n         :for i from=0 to=15 do={\
    \n            :set x ( [ :tonum [ :pick \$lWordArray ( ( [ :tonum \$j ] + \
    0 ) & 15 ) ] ] + 0 )\
    \n            :set T ( [ :tonum [ :pick \$k ( \$i + 16 ) ] ] + 0 )\
    \n            :set S ( [ :tonum [ :pick \$s2 ( \$i & 3 ) ] ] + 0 )\
    \n            :set tmp1 ( ( ( \$c ^ ( \$d & ( \$b ^ \$c ) ) ) + \$a + \$T \
    + \$x ) & 0xFFFFFFFF )\
    \n            :set tmp1 (((tmp1 << \$S ) | ((\$tmp1 >> (32 - \$S)))) & 0xF\
    FFFFFFF)\
    \n            :set tmp1 ( ( \$tmp1 + \$b ) & 0xFFFFFFFF )\
    \n            :if ( \$Debug > 0 ) do={         \
    \n               :put (\"\$progName: Round 2, Answer \\\$tmp1: \$tmp1\") \
    \n            }            \
    \n# Rotate a,b,c,d param positions, e.g. d, a, b, c ... c, d, a, b ... b, \
    c, d, a\
    \n            :set a ( ( [ :tonum \$d ] + 0 ) & 0xFFFFFFFF )\
    \n            :set d ( ( [ :tonum \$c ] + 0 ) & 0xFFFFFFFF )\
    \n            :set c ( ( [ :tonum \$b ] + 0 ) & 0xFFFFFFFF )\
    \n            :set b ( ( [ :tonum \$tmp1 ] + 0 ) & 0xFFFFFFFF )\
    \n            :set j ( \$j + 5 )\
    \n         }\
    \n         \
    \n### Round 3 ###\
    \n         :set j 5\
    \n         :for i from=0 to=15 do={\
    \n            :set x ( [ :tonum [ :pick \$lWordArray ( ( [ :tonum \$j ] + \
    0 ) & 15 ) ] ] + 0 )\
    \n            :set T ( [ :tonum [ :pick \$k ( \$i + 32 ) ] ] + 0 )\
    \n            :set S ( [ :tonum [ :pick \$s3 ( \$i & 3 ) ] ] + 0 )\
    \n            :set tmp1 ( ( ( \$b ^ \$c ^ \$d ) + \$a + \$T + \$x ) & 0xFF\
    FFFFFF )\
    \n            :set tmp1 (((tmp1 << \$S ) | ((\$tmp1 >> (32 - \$S)))) & 0xF\
    FFFFFFF)\
    \n            :set tmp1 ( ( \$tmp1 + \$b ) & 0xFFFFFFFF )\
    \n            :if ( \$Debug > 0 ) do={         \
    \n               :put (\"\$progName: Round 3, Answer \\\$tmp1: \$tmp1\") \
    \n            }            \
    \n# Rotate a,b,c,d param positions, e.g. d, a, b, c ... c, d, a, b ... b, \
    c, d, a\
    \n            :set a ( ( [ :tonum \$d ] + 0) & 0xFFFFFFFF )\
    \n            :set d ( ( [ :tonum \$c ] + 0) & 0xFFFFFFFF )\
    \n            :set c ( ( [ :tonum \$b ] + 0) & 0xFFFFFFFF )\
    \n            :set b ( ( [ :tonum \$tmp1 ] + 0) & 0xFFFFFFFF )\
    \n            :set j ( \$j + 3 )\
    \n         }\
    \n         \
    \n### Round 4 ###\
    \n         :set j 0\
    \n         :for i from=0 to=15 do={\
    \n            :set x ( [ :tonum [ :pick \$lWordArray ( ( [ :tonum \$j ] + \
    0 ) & 15 ) ] ] + 0 )\
    \n            :set T ( [ :tonum [ :pick \$k ( \$i + 48 ) ] ] + 0 )\
    \n            :set S ( [ :tonum [ :pick \$s4 ( \$i & 3 ) ] ] + 0 )\
    \n# Next line is alternate method to the line following     \
    \n#         :set tmp1 ( \$c ^ ( \$b | ( ( \$d & 0xFFFFFFFF ) ^ 0xFFFFFFFF \
    ) ) )\
    \n            :set tmp1 ( ( \$c ^ ( \$b | ( -1 * ( \$d + 1 ) ) ) ) & 0xFFF\
    FFFFF )\
    \n            :set tmp1 ( ( \$tmp1 + \$a + \$T + \$x ) & 0xFFFFFFFF )\
    \n            :set tmp1 ( ((tmp1 << \$S ) | ((\$tmp1 >> (32 - \$S)))) & 0x\
    FFFFFFFF )\
    \n            :set tmp1 ( ( \$tmp1 + \$b ) & 0xFFFFFFFF )\
    \n            :if ( \$Debug > 0 ) do={         \
    \n               :put (\"\$progName: Round 4, Answer \\\$tmp1: \$tmp1\") \
    \n            }            \
    \n# Rotate a,b,c,d param positions, e.g. d, a, b, c ... c, d, a, b ... b, \
    c, d, a\
    \n            :set a ( ( [ :tonum \$d ] + 0) & 0xFFFFFFFF )\
    \n            :set d ( ( [ :tonum \$c ] + 0) & 0xFFFFFFFF )\
    \n            :set c ( ( [ :tonum \$b ] + 0) & 0xFFFFFFFF )\
    \n            :set b ( ( [ :tonum \$tmp1 ] + 0) & 0xFFFFFFFF )\
    \n            :set j ( \$j + 7 )\
    \n         }      \
    \n         :set a ( ( \$a + \$AA ) & 0xFFFFFFFF )    \
    \n         :set b ( ( \$b + \$BB ) & 0xFFFFFFFF )    \
    \n         :set c ( ( \$c + \$CC ) & 0xFFFFFFFF )    \
    \n         :set d ( ( \$d + \$DD ) & 0xFFFFFFFF )    \
    \n      }\
    \n      :set arrMd5State [ :toarray \"\$a, \$b, \$c, \$d\" ]\
    \n      :set sMd5Hash \"\"\
    \n      :set sMd5Output \"\"\
    \n      :set iDec 0\
    \n      :set iMd5State 0\
    \n      :set sHex \"\"\
    \n      :for i from=0 to=3 do={\
    \n         :set iMd5State [ :pick \$arrMd5State \$i ]      \
    \n         :for j from=0 to=3 do={\
    \n           :set iMd5State ( [ :tonum \$iMd5State ] & 0xFFFFFFFF )\
    \n            :if ( \$j < 1 ) do={\
    \n               :set iDec ( [ :tonum \$iMd5State ] & 255 )\
    \n            } else={\
    \n             :set iDec ( ( \$iMd5State & 0x7FFFFFFE ) / ( 2 << ( ( \$j *\
    \_8 ) - 1 ) ) )\
    \n             :if ( ( \$iMd5State & 0x80000000 ) > 0 ) do={\
    \n                 :set iDec ( \$iDec | ( 0x40000000 /  ( 2 << ( ( \$j * 8\
    \_) - 2 ) ) ) )\
    \n               }\
    \n                :set iDec ( \$iDec & 0xFF ) \
    \n            } \
    \n              :set sHex \"\"\
    \n            :for k from=0 to=( 4 * ( \$iHexDigit - 1 ) ) step=4 do={\
    \n               :set sHex ( [ :pick [ :tostr \$strHexValues ] \\\
    \n                      ( ( \$iDec >> \$k ) & 0xF ) \\ \
    \n                   ( ( ( \$iDec >> \$k ) & 0xF ) + 1 ) ] . \$sHex ) \
    \n            }\
    \n              :set sHex [ :tostr \$sHex ]\
    \n           :set sHex [ :pick \$sHex ( [ :len \$sHex ] - 2 ) [ :len \$sHe\
    x ] ]\
    \n            :set sMd5Output ( \$sMd5Output . \$sHex )     \
    \n         }\
    \n   }\
    \n# Modify next line to customize MD5 output string     \
    \n   :put [( [ :tostr \$strPrefix ] . [ :tostr \$sMd5Output ] . [ :tostr \
    \$strSuffix ] )]\
    \nif ( \$Debug > 0 ) do={\
    \n  :put \"\$progName: Done.\"\
    \n}\
    \n}"
add name=sendtrap owner=admin policy=\
    ftp,reboot,read,write,policy,test,password,sniff,sensitive source=":global\
    \_sendTrap do={\
    \n    /system script run StrToMd5\
    \n    :global StrToMd5\
    \n    :global ZBXKEY\
    \n    :global ZBXURL\
    \n    :local api \$1\
    \n    :local query \$2 \
    \n    :local msg \"\$api:\$ZBXKEY:\$query\"\
    \n    #:put \$msg \
    \n    :local hmac [:pick [\$StrToMd5 \$msg] 1]\
    \n    #:put [\$hmac]\
    \n    :local query \"\$ZBXURL\$api\?\$query&key=\$hmac\"\
    \n    :put \$query\
    \n    #:put \$hmac\
    \n    /tool fetch mode=https \$query\
    \n    #:put [ :pick \$hmac 1 ]\
    \n    #:put [:pick \"abcde\" 1 3]\
    \n    #:\$StrToMd5 \"\$api:\$ZBXKEY:\$value\"\
    \n}"
