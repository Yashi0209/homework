
import argparse
import hashlib
import json
import os
import struct

def load_partition_types():
    with open("PartitionTypes.json", "r") as file:
        partition_types = json.load(file)
    return {str(pt["hex"]).upper(): pt["desc"] for pt in partition_types}
    
PARTITION_TYPES = load_partition_types()

def calculate_hashes(filename):
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()

    with open(filename, "rb") as file:
        while chunk := file.read(8192):
            md5_hash.update(chunk)
            sha256_hash.update(chunk)

    filename = os.path.basename(filename)

    with open(f"MD5-{filename}.txt", "w") as md5_file:
        md5_file.write(md5_hash.hexdigest())
    with open(f"SHA-256-{filename}.txt", "w") as sha256_file:
        sha256_file.write(sha256_hash.hexdigest())

def identify_partitioning_scheme(filename):
    with open(filename, "rb") as file:
        mbr_sector = file.read(512)
        if mbr_sector[-2:] == b"\x55\xAA":
            file.seek(512)
            gpt_header = file.read(92)
            if gpt_header[:8] == b"EFI PART":
                return "GPT"
            else:
                return "MBR"
        else:
            return "Unknown"

def extract_mbr_partition_table(filename):
    partitions = []
    with open(filename, "rb") as file:
        file.seek(446)  # Seek to the start of the partition table in MBR
        for _ in range(4):  # There are four entries
            entry = file.read(16)
            partitions.append(entry)
    return partitions

def mbr_partition_data(filename, partition_table, offsets):
    for i, (entry, offset) in enumerate(zip(partition_table, offsets), start=1):
        type_hex, start_sector, partition_size = (
            entry[4],
            struct.unpack("<I", entry[8:12])[0],
            struct.unpack("<I", entry[12:16])[0] - struct.unpack("<I", entry[8:12])[0],
        )
        type_desc = PARTITION_TYPES.get(f"{type_hex:02X}", "Unknown")

        print(f"{type_hex} {type_desc}, {start_sector}, {partition_size}")

        with open(filename, "rb") as file:
            file.seek(start_sector * 512)
            boot_record = file.read(512)

            print(f"Partition number: {i}")
            segment = boot_record[offset : offset + 16]
            hex_values = " ".join([f"{byte:02x}" for byte in segment])
            ascii_values = "".join(
                [chr(byte) if 32 <= byte <= 126 else "." for byte in segment]
            )

            print(f"16 bytes of boot record from offset {offset}: {hex_values}")
            print(f"ASCII:                                  {ascii_values}")

def gpt_partition_data(filename):
    with open(filename, "rb") as file:
        file.seek(512)
        gpt_header = file.read(92)
        partition_entries_start_lba = int.from_bytes(gpt_header[72:80], "little")
        number_of_partition_entries = int.from_bytes(gpt_header[80:84], "little")
        size_of_partition_entry = int.from_bytes(gpt_header[84:88], "little")

        file.seek(partition_entries_start_lba * 512)
        for i in range(number_of_partition_entries):
            entry = file.read(size_of_partition_entry)
            partition_type_guid = entry[:16]
            if partition_type_guid == b"\x00" * 16:
                continue

            starting_lba = int.from_bytes(entry[32:40], "little")
            ending_lba = int.from_bytes(entry[40:48], "little")
            partition_name = entry[56:128].decode("utf-16le").rstrip("\x00")

            print(f"Partition number: {i + 1}")
            print(f"Partition Type GUID: {partition_type_guid.hex()}")
            print(f"Starting LBA address in hex: 0x{starting_lba:X}")
            print(f"Ending LBA address in hex: 0x{ending_lba:X}")
            print(f"Starting LBA address in Decimal: {starting_lba}")
            print(f"Ending LBA address in Decimal: {ending_lba}")
            print(f"Partition name: {partition_name}")

def main():
    parser = argparse.ArgumentParser(description="Analyze MBR and GPT partitioned raw images.")
    parser.add_argument("-f", "--file", required=True, help="Path to the raw image file")
    parser.add_argument("-o", "--offset", type=int, nargs="+", required=False, help="Offset for reading boot record")
    args = parser.parse_args()

    filename = args.file
    offsets = args.offset

    calculate_hashes(filename)
    scheme = identify_partitioning_scheme(filename)
    print(f"Partitioning scheme identified: {scheme}")

    if scheme == "MBR":
        partition_table = extract_mbr_partition_table(filename)
        mbr_partition_data(filename, partition_table, offsets)
    elif scheme == "GPT":
        gpt_partition_data(filename)
    else:
        print("Unknown or unsupported partitioning scheme.")

if __name__ == "__main__":
    main()