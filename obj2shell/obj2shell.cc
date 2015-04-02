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
 * $ g++ -std=c++11 -Wall -Wextra -O2 -o obj2shell obj2shell.cc -g
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
#include <algorithm> 
#include <functional> 
#include <cctype>
#include <locale>

/* use a class to store each line */
class ASMLine{
  public:
    std::string section; // the section name, such as .text
    unsigned int section_id; // the section id
    std::string function; // the func name, such as: assert
    int func_addr; // the func addr, such as: 0000000000000090, will trans to hex
    //unsigned long long func_addr; // the func addr, such as: 0000000000000090, will trans to hex
    unsigned int line_num; // better to be int, will trans to hexadecimal after calculation

    std::string line_code; // 31 c0                   xor    %eax,%eax
    std::string line_opt; 

    unsigned int reloc_type; // 0: R_X86_64_32S
    std::string reloc_func; // .rodata.str1.1
    int reloc_offset; // -0x4

    /* initial value */
    ASMLine(){
        section_id = 0;
        func_addr = 0;
        line_num = 0;
        reloc_type = 0;
        reloc_offset = 0;
    }

    /* reset line except header (section, fucntion, func_addr) */
    void clear_content(){
        line_num = 0;
        line_code = "";
        line_opt = "";
        reloc_type = 0;
        reloc_func = "";
        reloc_offset = 0;
    }
}ASMLINE;

/* the section map for all the ASM lines */
std::map<std::string, std::list<ASMLine>> sections;
std::map<std::string, std::list<ASMLine>>::iterator sections_it;
/* the relocation type, 0 is reserved for no type */
std::map<std::string, int> reloc_map = {{"R_X86_64_32S", 1}, {"R_X86_64_PC32", 2}};
/* record the section address pair, for callq offset calculation */
std::map<int, std::string> section_map; //{{<section_id>, "<section>"}, ..}
std::map<int, std::string>::iterator sec_map_it;
/* record the function address pair, for callq offset calculation */
std::map<std::string, std::list<int>> func_map; // {{"<function>", [<func_addr>, <section_id>]}, ..}

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

/* convert string to hex */
int str2hex(std::string str){
    int hex_int;
    std::stringstream ss;
    ss << std::hex << str;
    ss >> hex_int;

    return hex_int;
}

/* generate the asm file from object file */
int obj2asm(std::string input_file, std::string asm_file){
    std::cout << "#### Generating ASM code from object file " << input_file << " ####" << std::endl;
    std::string systemstr = std::string("objdump --insn-width=16 -Dr ") + input_file + std::string(" > ") + asm_file;
    const char *sys_str = systemstr.c_str();
    std::system(sys_str);

    //std::cout << "#### Generating ASM code DONE! ####" << std::endl;
    return 0;
}

/* read asm file into map */
int asm2section(std::string asm_file){
    /* map for the sections */
    //std::map<std::string, std::list<ASMLine>> sections;
    std::list<ASMLine> section_lines;
    ASMLine asm_line;

    /* read the asm file */
    std::ifstream in_file;
    const char *asm_fp = asm_file.c_str();
    in_file.open(asm_fp);

    /* set id for each section, 0 reserved for .init.text*/
    int section_id = -1; // uninitialized value
    int section_num = 1;
    //std::cout << "#### Reading ASM code into a Map ####" << std::endl;
    /* deal with lines */
    std::string line;
    while (std::getline(in_file, line)){
        //std::cout << line << std::endl;

        /*Disassembly of section .text:*/
        std::regex e1 ("(Disassembly of section )(.*)(:)");
        /*0000000000000000 <printstr>:*/
        std::regex e2 ("([0-9a-f]*)( <)(.*)(>:)");
        /*   3:	48 c7 c2 ce ac 30 81          	mov    $0xffffffff8130acce,%rdx */
        std::regex e3 ("([ \t]*)([0-9a-f]*)(:[ \t]*)([0-9a-f ]*)([ \t]*)([a-z0-9()]{2,16})(.*)");
        /*  			35: R_X86_64_PC32	printstr-0x4         */
        std::regex e4 ("([ \t]*)([0-9a-f]*)(:[ \t]*)(R_X86_64_(32S|PC32))([ \t]*)([a-z0-9.]{2,16})([-+]*)([0x]*)([0-9a-f]*)");

        std::smatch sm1, sm2, sm3, sm4;    // same as std::match_results<string::const_iterator> sm;
        std::regex_match (line,sm1,e1);
        std::regex_match (line,sm2,e2);
        std::regex_match (line,sm3,e3);
        std::regex_match (line,sm4,e4);

        /* section[Disassembly of section ] [.text] [:] */
        if (sm1.size() > 0){
            std::cout << sm1[1] << sm1[2] << std::endl;

            /* reserve 0 for .init.text*/
            section_id = section_num;
            if(".init.text" == sm1[2]){
                section_id = 0;
            }

            /* insert into section map */
            section_lines.clear(); // clear the list for new section
            if (sections.find(sm1[2]) == sections.end()) {
                sections.insert(std::pair<std::string, std::list<ASMLine>>(sm1[2], section_lines));
                asm_line.section = sm1[2];
                asm_line.section_id = section_id;
            }
            else{
                section_num++;
            }

            /* record the section address pair, for callq offset calculation */
            if (section_map.find(section_id) == section_map.end()) {
                section_map.insert(std::pair<int, std::string>(section_id, sm1[2]));
            }
            else{
                std::cout << "ERROR: duplicated section found!" << std::endl;
            }

        }
        /* funcp[0000000000000000] [ <] [printstr] [>:] */
        if (sm2.size() > 0){
            std::cout << sm2[1] << " " << sm2[3] << std::endl;

            asm_line.func_addr = str2hex(sm2[1]);
            asm_line.function = sm2[3];

            /* record the function address pair, for callq offset calculation */
            if (func_map.find(asm_line.function) == func_map.end()) {
                func_map.insert(std::pair<std::string, std::list<int>>(asm_line.function, {asm_line.func_addr, section_id}));
            }
            else{
                std::cout << "ERROR: duplicated function found!" << std::endl;
            }
        }
        /* normal line[   ] [3] [:	] [48 c7 c2 ce ac 30 81                            ] [	] [mov] */
        if (sm3.size() > 0){
            //std::cout << sm3[2] << ":" << sm3[4] << ":" << sm3[6] << std::endl;
            int lineno = str2hex(sm3[2]);

            /* insert NOP into init_module for RIP restoring */
            if("init_module" == asm_line.function && "retq" == sm3[6]){
                for(int nop_i=0;nop_i<32;nop_i++){
                    asm_line.clear_content();
                    asm_line.line_num = lineno++;
                    asm_line.line_code = "90";
                    asm_line.line_opt = "nop";
                    
                    sections[asm_line.section].push_back(asm_line);
                }
            }

            asm_line.clear_content();
            asm_line.line_num = lineno;
            std::string codes = sm3[4];
            asm_line.line_code = trim(codes);
            asm_line.line_opt = sm3[6];

            sections[asm_line.section].push_back(asm_line);
        }
        /* reloc line[			] [35] [: ] [R_X86_64_PC32] [PC32] [	] [printstr] [-] [0x] [4]  */
        if (sm4.size() > 0){
            //std::cout << sm4[2] << ":" << sm4[4] << ":" << sm4[7] << ":" << sm4[9] << std::endl;
            asm_line.clear_content();
            asm_line.line_num = str2hex(sm4[2]);
            asm_line.reloc_type = reloc_map[sm4[4]];
            asm_line.reloc_func = sm4[7];
            if (sm4.size() > 7){
                asm_line.reloc_offset = str2hex(sm4[10]);
                if ("-" == sm4[8]) {
                    asm_line.reloc_offset = 0 - asm_line.reloc_offset;
                }
            }

            sections[asm_line.section].push_back(asm_line);
        }
    }

    //std::cout << "#### Reading file DONE! ####" << std::endl;
    std::cout << "#### Generating ASM code DONE! ####" << std::endl;

    /* clean up */
    in_file.close();
    //std::remove(asm_fp);
    
    return 0;
}

/*Calculate relocation offset:
 * 1. find all the sections between target_section and current_section: middle_section
 * 2. calculate the size of middle_section: sizeof(middle_section)
 * 3. offset = sizeof(middle_section) + (line_num) + (target_section - func_addr)
 *   target_section = func_map[function][1]
 *   func_addr = func_map[function][0] */
int clac_offset(ASMLine asm_line){
    int offset = 0;
    std::list<int> func_list = func_map[asm_line.reloc_func];

    unsigned int target_func_addr = func_list.front();
    unsigned int target_section = func_list.back();

    int min_id = std::min<unsigned int>(asm_line.section_id, target_section);
    int max_id = std::max<unsigned int>(asm_line.section_id, target_section);
    for (int sec=min_id; sec<max_id; sec++) {
        sec_map_it = section_map.find(sec);
        sections_it = sections.find(sec_map_it->second);
        offset += (sections_it->second).size();
    }
    offset += asm_line.line_num;
    sec_map_it = section_map.find(target_section);
    sections_it = sections.find(sec_map_it->second);
    offset += (sections_it->second).size() - target_func_addr;

    return offset;
}

/* write the sections map to file */
int section2shell(std::string shell_file){
    /* open file for writing */
    const char *shell_str = shell_file.c_str();
    std::ofstream shell_fp;
    shell_fp.open(shell_str);

    std::cout << "#### Writing file " << shell_file << "####" << std::endl;
    for (std::map<std::string, std::list<ASMLine>>::const_iterator it = sections.begin(); it != sections.end(); ++it){
        std::cout << "Writing " << it->first << "..." << std::endl;
        for (std::list<ASMLine>::const_iterator ci = sections[it->first].begin(); ci != sections[it->first].end(); ++ci){
            if ((*ci).reloc_type != 0){
                clac_offset(*ci);
            }
            /*std::cout << (*ci).line_code << std::endl;*/
            shell_fp << (*ci).section << ":" << (*ci).function << ":" \
                     << (*ci).line_num << ":" << (*ci).line_code << ":" << (*ci).line_opt << ":" \
                     << (*ci).reloc_type << ":" << (*ci).reloc_func << ":" << (*ci).reloc_offset << std::endl;
        }
    }

    std::cout << "#### Writing file DONE! ####" << std::endl;
    shell_fp.close();

    return 0;
}

/* calculate shellcode length */
int shell_length(std::string asm_file, std::string shell_file){
    return 0;
}

/* update the asm file:
* 1. move the init_module to the beginning
* 2. add 32 NOP as the placeholder for RIP restoring
* 3. calculate the callq offset */
int main(int argc, char *argv[]){
    /* check parameters numbers */
    if (argc < 5) {
        std::cerr << "Usage: ./obj2shell -i <obj-file.o> -o <shell-code.string>" << std::endl;
        return 1;
    }

    std::string asm_file = ".obj.dump";

    obj2asm(argv[2], asm_file);
    asm2section(asm_file);
    section2shell(argv[4]);
    shell_length(asm_file, argv[4]);

    return 0;
}
