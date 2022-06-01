#ifndef _OLD_PDB_PARSER_LIB_H
#define _OLD_PDB_PARSER_LIB_H
#include <string>

namespace OldPDBMSDIAParser {

// parse the module's symbols and then return the virtual address rva of a
// function
size_t get_address_rva_from_symbol(std::string function_name,
                                   std::string pdb_full_path,
                                   /*OUT*/ size_t &sym_size);

// clear stored info
void clear_info();

} // namespace OldPDBMSDIAParser

#endif