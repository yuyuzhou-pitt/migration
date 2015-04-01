/* This file change the object file to shellcode string.
 *
 * Steps as below:
 * 1. generate the asm file from object file
 * 2. re-organize the asm file:
 *   2.1 move the init_module to the beginning
 *   2.2 add NOP placeholder for RIP restoring
 *   2.3 calculate the callq offset 
 * 3. change asm code to shellcode string
 * 4. calculate shellcode length 
 *
 * How to run:
 * $ g++ -std=c++11 -o obj2shell obj2shell.cc 
 * $ ./obj2shell -i printfunc.o -o printfunc.o.string 
 *
 * Input: 
 * kernel module object file (printfunc.o)
 *
 * Output:
 * 1. shellcode string (printfunc.o.string)
 * 2. shellcode length (printfunc.o.length) */

#include <iostream>
#include <fstream>
#include <cstdlib>
#include <regex>
#include <list>
#include <map>
//using namespace std;
#include <algorithm> 
#include <functional> 
#include <cctype>
#include <locale>

std::map<std::string, int> relocmap = {{"R_X86_64_32S", 0}, {"R_X86_64_PC32", 1}};

class ASMLine{
  public:
    std::string section; // the section name, such as .text
    std::string function; // the func name, such as: assert
    unsigned long long funcaddr; // the func addr, such as: 0000000000000090, will trans to hex
    unsigned int linenum; // better to be int, will trans to hexadecimal after calculation

    std::string linecode; // 31 c0                   xor    %eax,%eax
    std::string lineopt; 

    unsigned int reloctype; // 0: R_X86_64_32S
    std::string relocfunc; // .rodata.str1.1
    unsigned int relocoffset; // -0x4

    ASMLine(){
        funcaddr = 0;
        linenum = 0;
        reloctype = 0;
        relocoffset = 0;
    }
};

/* trim from start */
static inline std::string &ltrim(std::string &s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
    return s;
}

/* trim from end */
static inline std::string &rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
    return s;
}

/* trim from both ends */
static inline std::string &trim(std::string &s) {
    return ltrim(rtrim(s));
}

/* generate the asm file from object file */
void obj2asm(std::string input_file, std::string asm_file){
    std::string systemstr = std::string("objdump --insn-width=16 -dr ") + input_file + std::string(" > ") + asm_file;
    const char *sys_str = systemstr.c_str();
    std::system(sys_str);
}

/* update the asm file:
 * 1. move the init_module to the beginning
 * 2. add NOP placeholder for RIP restoring
 * 3. calculate the callq offset */
void update_asm(std::string asm_file){
    /* read the asm file */
    std::ifstream in_file;
    const char *asm_str = asm_file.c_str();
    in_file.open(asm_str);

    /* open file for writing */
    std::string updated_filename = ".obj.dump.updated";
    const char *updated_str = updated_filename.c_str();
    std::ofstream updated_file;
    updated_file.open(updated_str);

    /* map for the sections */
    std::map<std::string, std::list<ASMLine>> sections;
    std::list<ASMLine> section_lines;
    ASMLine asm_line;

    /* deal with lines */
    std::string line;
    while (std::getline(in_file, line)){
        std::cout << line << std::endl;

        /*Disassembly of section .text:*/
        std::regex e1 ("(Disassembly of section )(.*)(:)");
        /*0000000000000000 <printstr>:*/
        std::regex e2 ("([0-9a-f]*)( <)(.*)(>:)");
        /*   3:	48 c7 c2 ce ac 30 81          	mov    $0xffffffff8130acce,%rdx */
        std::regex e3 ("([ ]*)([0-9a-f]*)(:\t)([0-9a-f ]*)(\t)([a-z0-9]{1,8})(.*)");
        /*  			35: R_X86_64_PC32	printstr-0x4         */
        std::regex e4 ("([\t]*)([0-9a-f]*)(:[ ])(R_X86_64_(32S|PC32))(\t)([a-z0-9]{1,8})(-0x)([0-9a-f]*)");

        std::smatch sm1, sm2, sm3, sm4;    // same as std::match_results<string::const_iterator> sm;

        std::regex_match (line,sm1,e1);
        std::regex_match (line,sm2,e2);
        std::regex_match (line,sm3,e3);
        std::regex_match (line,sm4,e4);

        /* section[Disassembly of section ] [.text] [:] */
        if (sm1.size() > 0){
            section_lines.clear(); // clear the list for new section
            if (sections.find(sm1[2]) == sections.end()) {
                sections.insert(std::pair<std::string, std::list<ASMLine>>(sm1[2], section_lines));
                asm_line.section = sm1[2];
            }
        }
        /* funcp[0000000000000000] [ <] [printstr] [>:] */
        if (sm2.size() > 0){
            std::stringstream ss;
            ss << std::hex << sm2[1];
            ss >> asm_line.funcaddr;

            asm_line.function = sm2[3];

        }
        /* normal line[   ] [3] [:	] [48 c7 c2 ce ac 30 81                            ] [	] [mov] */
        if (sm3.size() > 0){
            std::stringstream ss;
            ss << std::hex << sm3[2];
            ss >> asm_line.linenum;

            std::string codes = sm3[4];
            asm_line.linecode = trim(codes);
            asm_line.lineopt = sm3[6];

            sections[asm_line.section].push_back(asm_line);
        }
        /* reloc line[			] [35] [: ] [R_X86_64_PC32] [PC32] [	] [printstr] [-0x] [4]  */
        if (sm4.size() > 0){
            std::stringstream ss;
            ss << std::hex << sm4[2];
            ss >> asm_line.linenum;

            asm_line.reloctype = relocmap[sm4[4]];
            asm_line.relocfunc = sm3[7];
            ss << std::hex << sm4[9];
            ss >> asm_line.relocoffset;

            sections[asm_line.section].push_back(asm_line);
        }

    }

    /* clean up */
    in_file.close();
    updated_file.close();
    //std::remove(asm_str);
}

/* change asm code to shellcode string*/
void asm2shell(std::string asm_file, std::string shell_file){
}

/* calculate shellcode length */
void shell_length(std::string asm_file, std::string shell_file){
}

int main(int argc, char *argv[]){
    /* check parameters numbers */
    if (argc < 5) {
        std::cerr << "Usage: ./obj2shell -i <obj-file.o> -o <shell-code.string>" << std::endl;
        return 1;
    }

    std::string asm_file = ".obj.dump";

    obj2asm(argv[2], asm_file);
    update_asm(asm_file);
    asm2shell(asm_file, argv[4]);
    shell_length(asm_file, argv[4]);

    return 0;
}
