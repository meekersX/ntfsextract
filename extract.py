import struct
import subprocess
from datetime import datetime, timedelta, timezone

def displayTimestamp(us):
    us = int(round(us / 10.0)) - 11644473600000000
    try:
        return str(datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds = us))
    except:
        return "corrupt"


def parseStandardInformation(mftentry):
    # timestamps
    [creation_time, modification_time, metachange_time, access_time] = struct.unpack_from('<QQQQ', mftentry, 0)

    return creation_time, modification_time, metachange_time, access_time


def parseFileName(mftentry):
    # its character count not bytecount and utf16 so multiply by 2
    fn_length = mftentry[0x40] * 2

    # check if long or short. broken if not x01 or x02
    fn_type = mftentry[0x41]
    assert(fn_type == 1 or fn_type == 2)

    namestring = mftentry[0x42 : 0x42 + fn_length]

    # throws if can't decode
    return namestring.decode("UTF-16LE")

    ## ERROR not true, hardlinks?


def parseRuns(run_data):
    runs = []
    current_cluster = 0
    data_position = 0
    while run_data[data_position] != 0:
        length_size = run_data[data_position] & 0xF
        offset_size = run_data[data_position] >> 4
        data_position += 1
        length = int.from_bytes(run_data[data_position:data_position+length_size], byteorder='little', signed=False)
        data_position += length_size
        offset = int.from_bytes(run_data[data_position:data_position+offset_size], byteorder='little', signed=True)
        data_position += offset_size
        
        current_cluster += offset
        runs.append( (current_cluster, length) )

    return runs


def parseNonResident(mftentry):
    starting_vcn, last_vcn, data_run_offset, compression_unit_size, allocated_size, real_size, initialized_size = struct.unpack_from('<QQHH4xQQQ', mftentry, 0)
    #print(starting_vcn, last_vcn, data_run_offset, compression_unit_size, allocated_size, real_size, initialized_size)

    # must be 64 for nonresident, unnamed attribute
    assert(data_run_offset == 0x40)

    # compressed and sparse not implemented)
    assert(compression_unit_size == 0)
    assert(real_size == initialized_size)
    
    ## questions: what are vcns here used for, why is allocated_size so huge?
    return real_size, parseRuns(mftentry[0x30 :])


def parse_entry (mftentry, image):
    # offset of first attribute
    image.seek(0x14, 1)
    attribute_offset = struct.unpack('<H', image.read(2))[0]

    # seek to first attribute
    image.seek(attribute_offset - 0x14 - 2, 1)

    while True:
        attribute_type = struct.unpack('<I', image.read(4))[0]
        if attribute_type == 0xFFFFFFFF:
            break
        attribute_length, nonresident, name_length, name_offset, attribute_flags, attribute_id = struct.unpack('<IBBHHH', image.read(struct.calcsize('<IBBHHH')))
        
        ##print(hex(attribute_type), attribute_length)
        assert(nonresident == 0 or (nonresident == 1 and attribute_type == 0x80))

        # compressed (0x1), encrypted (0x4000), sparse (0x8000) not implemented
        assert(attribute_flags == 0)

        content_data = image.read(attribute_length - struct.calcsize('<IIBBHHH'))

        if nonresident == 0:
            content_length, content_offset, indexed = struct.unpack_from('<IHBx', content_data, 0)
            #print(content_length, content_offset, struct.calcsize('<IIBBHHHIHBx'))
            assert(content_offset == struct.calcsize('<IIBBHHHIHBx'))
            content_data = content_data[struct.calcsize('<IHBx') : struct.calcsize('<IHBx') + content_length]

        if attribute_type == 0x10:
            # standard_information
            assert(attribute_length == 96)
            stdinfo = parseStandardInformation(content_data)

        elif attribute_type == 0x30:
            # file_name
            if attribute_length < 90 or attribute_length > 1024:
                continue
            fileName = parseFileName(content_data)

        elif attribute_type == 0x80:
            # data
            data = parseNonResident(content_data)

    return fileName, data, stdinfo[0], stdinfo[1], stdinfo[2], stdinfo[3]

screenshots = open('screenshots.txt', 'r')
image = open(r'D:\Backup\search\backup_sda.img', 'rb')

# names = [screenshot.split(';')[1][20:-2] for screenshot in screenshots.readlines()]
# print(len(names))
# print(len(set(names)))

current_number = 0
found = {}

for screenshot in screenshots.readlines():
    current = screenshot.split(';')
    
    # get file info block
    image.seek(int(current[0])*512)
    mft_entry = image.read(1024)
    image.seek(-1024, 1)
    results = parse_entry(mft_entry, image)
    [fileName, (fileSize, runs), creation_time, modification_time, metachange_time, access_time] = results

    if fileName in found:
        if found[fileName][1] != results:
            print(found[fileName])
            print( (current[0], results) )
            assert(false)
        else:
            continue
    found[fileName] = (current[0], results)

    print(current_number, fileName)
    fileName = 'Recovered\\' + fileName
    output = open(fileName, 'w+b')
    for run in runs:
        image.seek(206848*512 + run[0]*4096)
        if fileSize < run[1]*4096:
            data = image.read(fileSize)
        else:
            data = image.read(run[1]*4096)
            fileSize -= run[1]*4096
        output.write(data)
    output.close()
    
    times = {
        'CreationTime': creation_time,
        'LastWriteTime': modification_time,
        'LastAccessTime': access_time
    }
    cmd = "powershell.exe -Command $i = (Get-Item " + fileName + ");"
    for key, value in times.items():
        cmd += "$i." + key + " = [DateTime]::FromFileTime(" + str(value) + ");"

    subprocess.run(cmd)

    current_number += 1
 