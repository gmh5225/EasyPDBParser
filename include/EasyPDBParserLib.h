#ifndef _EASY_PDB_PARSER_LIB_H
#define _EASY_PDB_PARSER_LIB_H

#include <string>
#include <vector>

namespace EasyPDBParserLib {
struct Symbol {
  std::string SymbolName;
  unsigned int Rva;
  unsigned int Size;
};

class PDBParser {
public:
  PDBParser();
  virtual ~PDBParser() = default;

public:
  bool Parse(const char *PDBFilePath);
  const std::vector<Symbol> &GetSymbols() const;

public:
  Symbol GetSymbolByOldMsdia(const std::string FuncName);

protected:
  std::string mPDBFilePath;
  std::vector<Symbol> mSymbols;
};

} // namespace EasyPDBParserLib

#endif
