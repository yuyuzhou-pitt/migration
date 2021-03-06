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
 * --------------------------------------------------------------
 * How to run:
 * $ g++ -std=c++0x -Wall -Wextra -O2 -o obj2shell obj2shell.cc
 * $ ./obj2shell -i ../PrintkModule/printfunc.o -o printfunc.o.string 
 *
 *
 * Input: 
 * kernel module object file (../PrintkModule/printfunc.o), compiled by:
 * $ cd ../PrintkModule/Makefile
 * $ make
 *
 * Output:
 * 1. shellcode string (printfunc.o.string)
 * 2. shellcode length (printfunc.o.length)
 *
 * ---------------------------------------------------------------
 * For debugging:
 * $ g++ -std=c++0x -Wall -Wextra -o obj2shell obj2shell.cc -g -O0
 * $ valgrind --leak-check=full --track-origins=yes ./obj2shell \
 *   -i ../PrintkModule/printkfunc.o -o printkfunc.o.string
 *
 * temp asm file: .obj.dump
 * */

#include <iostream>
#include <sstream>
#include <fstream>
#include <cstdlib>
#include <list>
#include <map>
#include <algorithm> 
#include <functional> 
#include <cctype>
#include <locale>
#include <iomanip>

#define KERNEL_STACK 2170658888 // kernel_stack 0xffffffff8161a048
#define DEBUG 1 // set 1 for debug info

/* use a class to store each line */
class ASMLine{
  public:
    std::string section; // the section name, such as .text
    unsigned int section_id; // the section id
    std::string function; // the func name, such as: assert
    int func_addr; // the func addr, such as: 0000000000000090, will trans to hex
    //unsigned long long func_addr; // the func addr, such as: 0000000000000090, will trans to hex
    unsigned int line_num; // better to be int, will trans to hexadecimal after calculation

    std::list<std::string> line_code; // 31 c0                   xor    %eax,%eax
    std::string line_opt; 

    unsigned int reloc_type; // 0: R_X86_64_32S
    std::string reloc_func; // .rodata.str1.1
    int reloc_offset; // -0x4

    /* initial value */
    ASMLine(){
        section_id = 0;
        func_addr = 0;
        line_num = 0;
        line_code = {};
        reloc_type = 0;
        reloc_offset = 0;
    }

    /* reset line except header (section, fucntion, func_addr) */
    void clear_content(){
        line_num = 0;
        line_code.clear();
        line_opt = "";
        reloc_type = 0;
        reloc_func = "";
        reloc_offset = 0;
    }
}ASMLINE;

/* the relocation type, 0 is reserved for no type */
std::map<std::string, int> reloc_map = {{"R_X86_64_32S", 1}, {"R_X86_64_PC32", 2}};
/* record the section address pair, for callq offset calculation */
std::map<int, std::string> section_map; //{{<section_id>, "<section>"}, ..}
/* record the function address pair, for callq offset calculation */
std::map<std::string, std::list<int>> func_map; // {{"<function>", [<func_addr>, <section_id>]}, ..}
//std::map<std::string, std::list<int>>::iterator func_map_it;
/* the section map for all the ASM lines */
std::map<std::string, std::list<ASMLine>> sections;

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
    int hex_int = 0;
    std::stringstream ss;
    ss << std::hex << str;
    ss >> hex_int;

    return hex_int;
}

/* split string into vector */
int split_list(const std::string &s, char delim, std::list<std::string> &elems) {
    std::stringstream ss(s);
    std::string item;
    elems.clear();
    while (std::getline(ss, item, delim)) {
        elems.push_back(item);
    }

    return 0;
}

/* split string into vector */
int split(const std::string &s, char delim, std::vector<std::string> &elems) {
    std::stringstream ss(s);
    std::string item;
    elems.clear();
    while (std::getline(ss, item, delim)) {
        elems.push_back(item);
    }

    return 0;
}

/* list to string */
int list2str(std::string &str, std::list<std::string> lst){
    std::stringstream ss("");
    std::list<std::string>::const_iterator iterator;
    for (iterator = lst.begin(); iterator != lst.end(); ++iterator) {
        ss << "\\x" << *iterator;
    }
    str = ss.str();

    return 0;
}

/* get section code size by section id */
int section_size(int section_id){
    /* p section_map: std::map with 5 elements
    *{[0] = ".init.text", [1] = ".text", [2] = ".rodata.str1.1", [3] = ".exit.text", [4] = ".comment"} */
    std::map<int, std::string>::iterator sm_it;
    sm_it = section_map.find(section_id); // got section name

    /* p sections std::map with 5 elements = 
    * {[".comment"] = std::list = {[0] = { <asm_line 0> }, [1] = { <asm_line 1> }, ... } 
    * [".rodata.str1.1"] = std::list = {[0] = { <asm_line 0> }, [1] = { <asm_line 1> }, ... */
    std::map<std::string, std::list<ASMLine>>::iterator sec_it;
    sec_it = sections.find(sm_it->second); // got section content list
    ASMLine tmp_line = (sec_it->second).back();

    /* 11:   20 4d 72 */
    return tmp_line.line_num + tmp_line.line_code.size();
}

/* generate the asm file from object file */
int obj2asm(std::string input_file, std::string asm_file){
    std::cout << "#### Generating ASM code from object file " << input_file << " ####" << std::endl;
    std::string systemstr = std::string("objdump --insn-width=16 -Dr ") + input_file + std::string(" > ") + asm_file;
    const char *sys_str = systemstr.c_str();
    std::system(sys_str);

    std::cout << "#### Generating ASM code DONE! ####" << std::endl;
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
    std::cout << "#### Parsing ASM code ####" << std::endl;
    /* deal with lines */
    std::string line;
    while (std::getline(in_file, line)){
        //std::cout << line << std::endl;
        std::vector<std::string> line_list;

        /*Disassembly of section .text:*/
        if (line.find("Disassembly of section") == 0){
            split(line, ' ', line_list);
            std::string section_name = line_list.back().substr(0, line_list.back().length() - 1);
            std::cout << "Disassembly of section " << section_name << std::endl;

            /* reserve 0 for .init.text*/
            section_id = section_num;
            if(".init.text" == section_name){
                section_id = 0;
            }
            else{
                section_num++;
            }

            /* insert into section map */
            section_lines.clear(); // clear the list for new section
            if (sections.find(section_name) == sections.end()) {
                sections.insert(std::pair<std::string, std::list<ASMLine>>(section_name, section_lines));
                asm_line.section = section_name;
                asm_line.section_id = section_id;
            }

            /* record the section address pair, for callq offset calculation */
            if (section_map.find(section_id) == section_map.end()) {
                section_map.insert(std::pair<int, std::string>(section_id, section_name));
            }
            else{
                std::cout << "ERROR: duplicated section found!" << std::endl;
            }

        }
        /*0000000000000000 <printstr>:*/
        else if (line.find("000") == 0){
            split(line, ' ', line_list);
            std::string function_name = line_list.back().substr(1, line_list.back().length() - 3);
            if ( DEBUG == 1 ){
                std::cout << line_list.front() << " " << function_name << std::endl;
            }

            asm_line.func_addr = str2hex(line_list.front());
            asm_line.function = function_name;

            /* record the function address pair, for callq offset calculation */
            if (func_map.find(asm_line.function) == func_map.end()) {
                std::list<int> addr_id = {asm_line.func_addr, section_id};
                func_map.insert(std::pair<std::string, std::list<int>>(asm_line.function, addr_id));
            }
            else{
                std::cout << "ERROR: duplicated function found: " << asm_line.function << std::endl;
            }
        }
        /* for lines with codes */
        else if (line.find("\t") != std::string::npos){
            split(line, '\t', line_list);
            std::string first_item = line_list.front();
            std::string last_item = line_list.back();

            /*   76:^I48 c7 c7 00 00 00 00 ^Imov    $0x0,%rdi$ */
            char delim = ' ';
            if (first_item.find(":") != std::string::npos){
                /* extract line num */
                std::vector<std::string> opt_list;
                split(last_item, delim, opt_list);

                std::string num_str_full = first_item.substr(0, first_item.length() - 1);
                std::string num_str = trim(num_str_full);
                int lineno = str2hex(num_str);
    
                /* insert NOP into init_module for RIP restoring */
                if("init_module" == asm_line.function && opt_list.front() == "retq"){
                    for(int nop_i=0;nop_i<32;nop_i++){
                        asm_line.clear_content();
                        asm_line.line_num = lineno++;
                        asm_line.line_code.push_back("90");
                        asm_line.line_opt = "nop";
                        
                        sections[asm_line.section].push_back(asm_line);
                    }
                }

                /* extract hex codes and instructions */
                asm_line.clear_content();
                asm_line.line_num = lineno;
                std::string codes = line_list[1];
                split_list(trim(codes), delim, asm_line.line_code);
                asm_line.line_opt = opt_list.front();
    
                /* insert line into sections map */
                sections[asm_line.section].push_back(asm_line);
            }
            /* ^I^I^Iafd: R_X86_64_PC32^Igva_to_hva-0x4$ */
            if (line.find("R_X86_64") != std::string::npos){
                asm_line.clear_content();

                /* get reloc line number */
                std::vector<std::string> num_type;
                std::vector<std::string> func_offset;

                delim = ':';
                split(line_list[3], delim, num_type);
                asm_line.line_num = str2hex(num_type.front());
                asm_line.reloc_type = reloc_map[trim(num_type.back())];

                /* get reloc function and offset */
                std::string reloc_func;
                std::string reloc_offset ("0");
                if(last_item.find("-0x") != std::string::npos){
                    delim = '-';
                }
                else if(last_item.find("+0x") != std::string::npos){
                    delim = '+';
                }

                /* extract relocation function and address */
                split(line_list.back(), delim, func_offset);
                reloc_func = func_offset.front();
                reloc_offset = func_offset.back().substr(2);

                asm_line.reloc_func = reloc_func;
                asm_line.reloc_offset = str2hex(reloc_offset);
                /* ignore the offset -0x4 */
                if ('-' == delim) {
                    asm_line.reloc_offset = 0;
                }
    
                /* insert line into sections map */
                sections[asm_line.section].push_back(asm_line);
            }
        } // end of else
    } // end of while

    std::cout << "#### Parsing ASM code DONE! ####" << std::endl;

    /* clean up */
    in_file.close();
    //std::remove(asm_fp);
    
    return 0;
}

/*Calculate relocation offset:
 * 1. find all the sections between target_section and current_section: middle_section
 * 2. calculate the size of middle_section: sizeof(middle_section)
 * 3. offset = (step 2) + (line_num) + (target_section - (func_addr+reloc_offset))
 *   target_section = func_map[function][1]
 *   func_addr = func_map[function][0] */
int calc_offset(ASMLine &asm_line){
    int offset = 0;
    int offset_sign = 1; // positive

    if(func_map.find(asm_line.reloc_func) == func_map.end()){
        std::cout << "ERROR: relocation function " << asm_line.reloc_func << " not found!" << std::endl;
        return -1;
    }
    else{
        /* 1. find all the sections between target_section and current_section: middle_section*/
        /* func_map std::map with 5 elements =
        * {[".comment"] = std::list = {[0] = 0, [1] = 4}, 
        *  [".rodata.str1.1"] = std::list = {[0] = 0, [1] = 2}, 
        *  ["cleanup_module"] = std::list = {[0] = 0, [1] = 3}, 
        *  ["init_module"] = std::list = {[0] = 0, [1] = 0}, 
        *  ["printstr"] = std::list = {[0] = 0, [1] = 1}}*/
        std::list<int> func_list = (func_map.find(asm_line.reloc_func))->second; // find relocation func
        /* func_list = {[0] = 0, [1] = 2} */
        unsigned int target_func_addr = func_list.front(); // key: func_addr
        unsigned int target_section = func_list.back(); // value: section id
    
        /*p asm_line
        *{section = ".init.text", section_id = 0, function = "init_module", func_addr = 0, 
        * line_num = 4, line_code = empty std::list, line_opt = "", 
        * reloc_type = 1, reloc_func = ".rodata.str1.1", reloc_offset = 0}*/
        int min_id = std::min<unsigned int>(asm_line.section_id, target_section);
        int max_id = std::max<unsigned int>(asm_line.section_id, target_section);

        /* 2. calculate the size of middle_section: sizeof(middle_section) */
        for (int sec=min_id+1; sec<max_id; sec++) {
            offset += section_size(sec);
        }
        /* 3. offset = (step 2) + (line_num) + (target_section - (func_addr+reloc_offset)) */
        /* if target section is above (negative):
        * offset += (line_num + 4) + (target_section - (func_addr+reloc_offset)) 
        * +4: address occupies 4 bytes*/
        if (asm_line.section_id > target_section){
            offset_sign = -1; // negtive
            offset += (asm_line.line_num + 4) + \
                (section_size(target_section) - (target_func_addr + asm_line.reloc_offset));
        }
        /* if target section is below:
        * offset += (this_section - (line_num + 4)) - (func_addr+reloc_offset)) 
        * +4: address occupies 4 bytes*/
        else if ( asm_line.section_id < target_section ) {
            offset += (section_size(asm_line.section_id) - (asm_line.line_num + 4)) + \
                (target_func_addr + asm_line.reloc_offset);
        }
        /* the same section (no middle sections) */
        else if ( asm_line.section_id == target_section ) {
            /* offset += (target_func_addr+reloc_offset) - (line_num + 4)
            * +4: address occupies 4 bytes*/
            offset += (target_func_addr + asm_line.reloc_offset) - (asm_line.line_num + 4);
        }

        return offset_sign * offset;
    }
}

/* update the callq offset according to calc_offset */
int update_offset(ASMLine &asm_line, int reloc_offset){
    /* convert int to hex: -70 = ffffffc9 */
    std::stringstream stream;
    stream << std::setfill ('0') << std::setw(8) << std::hex << reloc_offset;
    std::string hex_offset(stream.str());

    //std::cout << "hex_offset:" << hex_offset << std::endl;
    /* write hex back to asm_line */
    int hex_i = 0;
    std::list<std::string> &code_list = asm_line.line_code;
    std::list<std::string>::iterator current;
    /* go through the list backwards */
    for ( current = code_list.end(); current != code_list.begin();){   
        --current; // Unfortunately, you now need this here
        *current = hex_offset.substr(hex_i, 2); // 2 characters each time
        hex_i += 2;
        /* break if done */
        if(hex_i > 6){
            break;
        }
    }

    return 0;
}

/* write the sections map to file */
int section2shell(std::string shell_file){
    /* open file for writing */
    const char *shell_str = shell_file.c_str();
    std::ofstream shell_fp;
    shell_fp.open(shell_str);

    std::cout << "#### Writing shellcode string: " << shell_file << " ####" << std::endl;
    shell_fp << "\"" ;
    std::map<int, std::string>::iterator sec_map_it;
    for (sec_map_it = section_map.begin(); sec_map_it != section_map.end(); ++sec_map_it){
        std::cout << "Writing " << sec_map_it->second << "..." << std::endl;

        /* got the section */
        std::map<std::string, std::list<ASMLine>>::iterator sections_it;
        sections_it = sections.find(sec_map_it->second);

        /*update the callq offset*/
        std::list<ASMLine>::iterator ci;
        for (ci = (sections_it->second).begin(); ci != (sections_it->second).end(); ++ci){
            if ((*ci).reloc_type != 0){
                /* for kernel_stack, provide absolute address defined in system.map */
                if (((*ci).reloc_func == "kernel_stack")){
                    update_offset(*std::prev(ci), KERNEL_STACK);
                }
                /* else, do the calculation */
                else{
                    update_offset(*std::prev(ci), calc_offset(*ci));
                }
            }
        }

        /*write into shellcode file*/
        for (ci = sections[sec_map_it->second].begin(); ci != sections[sec_map_it->second].end(); ++ci){
            std::string code_str;
            list2str(code_str, (*ci).line_code);
            shell_fp << code_str;
            if (DEBUG == 1){
                std::cout << (*ci).section << ":" << (*ci).function << ":" \
                     << (*ci).line_num << ":" << code_str << ":" << (*ci).line_opt << ":" \
                     << (*ci).reloc_type << ":" << (*ci).reloc_func << ":" << (*ci).reloc_offset << std::endl;
            }
        }
    }
    shell_fp << "\"" << std::endl;

    std::cout << "#### Writing shellcode file DONE! ####" << std::endl;
    shell_fp.close();

    return 0;
}

/* calculate shellcode length */
int shell_length(std::string shell_file){
    int shellcode_length = 0;

    /* open file for writing */
    std::stringstream stream;
    stream << shell_file << ".length";
    std::string stream_str(stream.str());

    const char *shell_len = stream_str.c_str();
    std::ofstream shell_len_fp;
    shell_len_fp.open(shell_len);

    std::cout << "#### Writing shellcode length: " << shell_file << ".length ####" << std::endl;
    std::map<int, std::string>::iterator sec_it;
    for (sec_it = section_map.begin(); sec_it != section_map.end(); ++sec_it){
        shellcode_length += section_size(sec_it->first);
    }
    shell_len_fp << shellcode_length << std::endl;
    std::cout << "#### Writing shellcode length DONE! ####" << std::endl;
    shell_len_fp.close();

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
    shell_length(argv[4]);

    return 0;
}
