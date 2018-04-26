//============================================================================
// Name        : CSE 469 Project.cpp
// Author      : Robert Stevens
// Version     :
// Copyright   : 
// Description :
//============================================================================

#include <iostream>
#include <iomanip>	//Needed to format output (specifically to pad numbers)
#include <fstream>	//Needed for file input/output operations
#include <string>	//Needed for using strings
#include <cstddef> 	//Needed for parsing file name

//Open-source crypto libraries; attributions in files
#include "md5.h"
#include "sha1.h"


using namespace std;

const int SECTOR_SIZE = 512;

//Take in an unsigned char array, and converts it to int, assuming little endian
//Need to input the size of the char array as the second parameter
int little_e_decoding(unsigned char* data, int size){
	int output = 0;

	for(int i=size-1; i>=0; i--){
		output = (output << 8) + data[i];
	}

	return output;
}

//Using the table from lecture 3, converts a hex code into the partition type's name
const char* get_partition_type(unsigned char code){
	const char* output;

	switch(code){

	case 0x01: output = "DOS 12-bit FAT"; break;
	case 0x04: output = "DOS 16-bit FAT for partitions smaller than 32MB"; break;
	case 0x05: output = "Extended partition"; break;
	case 0x06: output = "DOS 16-bit FAT for partitions larger than 32MB"; break;
	case 0x07: output = "NTFS"; break;
	case 0x08: output = "AIX bootable partition"; break;
	case 0x09: output = "AIX data partition"; break;
	case 0x0B: output = "DOS 32-bit FAT"; break;
	case 0x0C: output = "DOS 32-bit FAT for interrupt 13 support"; break;
	case 0x17: output = "Hidden NTFS partition (XP and earlier)"; break;
	case 0x1B: output = "Hidden FAT32 partition"; break;
	case 0x1E: output = "Hidden VFAT partition"; break;
	case 0x3C: output = "Partition Magic recovery partition"; break;
	case 0x66:
	case 0x67:
	case 0x68:
	case 0x69: output = "Novell partition"; break;
	case 0x81: output = "Linux"; break;
	case 0x82: output = "Linux swap partition"; break;
	case 0x83: output = "Linux native file systems"; break;
	case 0x86: output = "FAT16 volume/stripe set (Windows NT)"; break;
	case 0x87: output = "High Performance File System (HPFS) or NTFS volume/stripe set"; break;
	case 0xA5: output = "FreeBSD and BSD/386"; break;
	case 0xA6: output = "OpenBSD"; break;
	case 0xA9: output = "NetBSD"; break;
	case 0xC7: output = "Typical of a corrupted NTFS volume/stripe set"; break;
	case 0xEB: output = "BeOS"; break;

	default: output = "Partition code not found"; break;
	}

	return output;
}

//Checks to see if the given code is for a FAT volume. Returns true if so, false otherwise
bool is_FAT(int code){
	return code==0x04 || code==0x06 || code==0x0B || code==0x0C || code==0x1B;
}


//Takes in a partition record from the MBR.  Prints info to the screen.
//If partition is FAT16/32, it returns the sector address of the partition
int process_partition_record(unsigned char* record){

	//Get the relevant information from the record
	int partition_type = record[4];
	int partition_start = little_e_decoding(&record[8], 4);
	int partition_size = little_e_decoding(&record[12], 4);

	//Print the partition information to the console
	cout << "(" << hex << setfill('0') << setw(2) << partition_type << ") "
			<< get_partition_type(partition_type) << ", "
			<< dec << setfill('0') << setw(10) << partition_start << " "
			<< setfill('0') << setw(10) << partition_size << "\n";

	//Return address if FAT16/32, otherwise return 0
	int output = 0;
	if(is_FAT(partition_type)){
		output = partition_start;
	}
	return output;
}

void process_MBR(unsigned char* mbr, int* partitions){
	//First, a quick check to make sure there is a valid MBR.  If not, then do nothing
	if(mbr[0x01FE]!= 0x55 && mbr[0x01FF] != 0xAA){
		cout << "ERROR! MBR does not have a boot record signature. Signature found:"
				<< hex << mbr[0x01FE] << hex << mbr[0x01FF];
		for(int i=0;i<4;i++){
			partitions[i] = 0;
		}
		return;
	}

	//Print each partition's information, and get the starting address if it's FAT
	partitions[0] = process_partition_record(&mbr[0x01BE]) * SECTOR_SIZE;
	partitions[1] = process_partition_record(&mbr[0x01CE]) * SECTOR_SIZE;
	partitions[2] = process_partition_record(&mbr[0x01DE]) * SECTOR_SIZE;
	partitions[3] = process_partition_record(&mbr[0x01EE]) * SECTOR_SIZE;
}


//Processes a FAT volume boot record, printing information to the console
void process_FAT_vbr(unsigned char* vbr){

	//Get info on reserved area and cluster size
	int reserved_area_size = little_e_decoding(&vbr[14], 2);
	int reserved_area_end = reserved_area_size -1;
	int sectors_per_cluster = vbr[13];

	//Get info on the FAT tables
	int fat_area_start = reserved_area_size;
	int number_of_FATs = vbr[16];
	int size_of_FATs = little_e_decoding(&vbr[22], 2);
	if(size_of_FATs==0){
		size_of_FATs = little_e_decoding(&vbr[36], 4);
	}
	int fat_area_end = fat_area_start + (number_of_FATs * size_of_FATs);

	//Get info on the location of cluster 2, note that for FAT32, the root directory size is zero
	int root_dir_size = little_e_decoding(&vbr[17], 2);
	int first_sector_of_c2 = fat_area_end + root_dir_size;

	//Print out information
	cout << "Reserved area: Start sector: 0  Ending sector: "
			<< reserved_area_end << "  Size:  "
			<< reserved_area_size << " sectors" << "\n";
	cout << "Sectors per cluster:  " << sectors_per_cluster
			<< " sectors" << "\n";
	cout << "FAT area:  Start sector: " << fat_area_start
			<< " Ending sector: " << fat_area_end << "\n";
	cout << "# of FATs: " << number_of_FATs << "\n";
	cout << "The size of each FAT: " << size_of_FATs
			<< " sectors" << "\n";
	cout << "The first sector of cluster 2: " << first_sector_of_c2
			<< " sectors" << "\n";

}

//Given a filename, calculates the md5 hash of that file
//Returns a c_str containing the hex representation of that hash
char* calc_md5_hash(char* filename){
	char* hash_string = new char[33];		//Buffer to hold the hash

	ifstream image(filename, ios::in|ios::binary|ios::ate);
	if(image.is_open()){
		//Read the entire file into memory (includes error msg for too-large files)
		streampos size = image.tellg();
		char * block = new char[size];
		if(block == NULL){
			cout << "ERROR, could not load image into memory for md5 hash\n";
			break;
		}
		image.seekg(0, ios::beg);
		image.read(block, size);
		image.close();

		//Run the md5 algorithm on the image in memory
		md5::md5_t md5_worker = md5::md5_t(block, size);
		md5_worker.finish();
		md5_worker.get_string(hash_string);

		//Cleanup
		delete block;
		image.close();
	}
	else cout << "ERROR: FILE COULD NOT BE OPENED; HASH WILL BE RANDOM\n";

	return hash_string;
}

//Given a filename, calculates the SHA1 hash of that file
//Returns a string containing the hex representation of that hash
string calc_sha1_hash(char* filename){
	SHA1 sha1_worker = SHA1();
	string sha1_digest = sha1_worker.from_file(filename);
	return sha1_digest;
}

//Calculates the hashes for the image and stores them in the appropriate file
void process_hashes(char* filename){
	//Calculate the hashes
	char* md5_hash = calc_md5_hash(filename);
	string sha1_hash = calc_sha1_hash(filename);

	//Get the filenames to write to
	string path(filename);
	string only_name = path.substr(path.find_last_of("/\\")+1);
	string only_path = path.substr(0, path.find_last_of("/\\")+1);
	string md5_file = only_path + "MD5-" + only_name + ".txt";
	string sha1_file = only_path + "SHA1-" + only_name + ".txt";

	//Write the md5 file
	ofstream outfile;
	outfile.open(md5_file.c_str(), ios::out|ios::trunc);
	if(outfile.is_open()){
		outfile << md5_hash;
		outfile.close();
	} else cout << "ERROR: could not write to MD5 file\n";

	//Write the sha1 file
	outfile.open(sha1_file.c_str(), ios::out|ios::trunc);
	if(outfile.is_open()){
		outfile << sha1_hash;
		outfile.close();
	} else cout << "ERROR: could not write to SHA1 file\n";

}

int main(int argc, char** argv)
{

	//Checking for filename argument; exit program if not found
	if(argc <= 1){
		cout << "Error, input filename needed!\n";
		return 1;
	}
	char* filename = argv[1];

	//Calculate hashes
	process_hashes(filename);


	//Open the file
	ifstream image(filename, ios::binary);

	//If the file is open, begin to extract the information
	if(image.is_open()){

		//Read the MBR
		char* block = new char[512];
		image.read(block, 512);
		unsigned char* ublock = (unsigned char*) block;

		//Print info from MBR, and also get VBR addresses
		int* partitions = new int[4];
		process_MBR(ublock, partitions);

		//Go through the partitions and print FAT information if applicable
		for(int i=0; i<4; i++){
			if(partitions[i] != 0){
				//Read the partition's VBR
				image.seekg(partitions[i]);
				image.read(block, 512);
				ublock = (unsigned char*) block;

				//Print info from the partition's VBR
				cout << "\n\nPartition " << i << " is FAT16/32" << "\n";
				process_FAT_vbr(ublock);
			}
		}

		//Cleanup
		cout << "\n";
		delete[] block;
		image.close();
	}
	else cout << "Unable to open file " << argv[1] << "/n";


    return 0;
}
