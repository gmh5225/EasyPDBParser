#include "EasyPDBParserLib.h"
#include <Examples/ExampleMemoryMappedFile.h>
#include <PDB.h>
#include <PDB_DBIStream.h>
#include <PDB_InfoStream.h>
#include <PDB_RawFile.h>
#include <algorithm>
#include <iostream>
#include <string>
#include <unordered_set>
#include <vector>

namespace EasyPDBParserLib {
namespace {
PDB_NO_DISCARD static bool IsError(PDB::ErrorCode errorCode) {
  switch (errorCode) {
  case PDB::ErrorCode::Success:
    return false;

  case PDB::ErrorCode::InvalidSuperBlock:
    printf("Invalid Superblock\n");
    return true;

  case PDB::ErrorCode::InvalidFreeBlockMap:
    printf("Invalid free block map\n");
    return true;

  case PDB::ErrorCode::InvalidSignature:
    printf("Invalid stream signature\n");
    return true;

  case PDB::ErrorCode::InvalidStreamIndex:
    printf("Invalid stream index\n");
    return true;

  case PDB::ErrorCode::UnknownVersion:
    printf("Unknown version\n");
    return true;
  }

  // only ErrorCode::Success means there wasn't an error, so all other paths
  // have to assume there was an error
  return true;
}

PDB_NO_DISCARD static bool HasValidDBIStreams(const PDB::RawFile &rawPdbFile,
                                              const PDB::DBIStream &dbiStream) {
  // check whether the DBI stream offers all sub-streams we need
  if (IsError(dbiStream.HasValidImageSectionStream(rawPdbFile))) {
    return false;
  }

  if (IsError(dbiStream.HasValidPublicSymbolStream(rawPdbFile))) {
    return false;
  }

  if (IsError(dbiStream.HasValidGlobalSymbolStream(rawPdbFile))) {
    return false;
  }

  if (IsError(dbiStream.HasValidSectionContributionStream(rawPdbFile))) {
    return false;
  }

  return true;
}
} // namespace

using FunctionSymbol = Symbol;
void ParseFunctionSymbols(
    const PDB::RawFile &rawPdbFile, const PDB::DBIStream &dbiStream,
    /*OUT*/ std::vector<FunctionSymbol> &functionSymbols) {
  functionSymbols.clear();

  // in order to keep the example easy to understand, we load the PDB data
  // serially. note that this can be improved a lot by reading streams
  // concurrently.

  // prepare the image section stream first. it is needed for converting section
  // + offset into an RVA
  const PDB::ImageSectionStream imageSectionStream =
      dbiStream.CreateImageSectionStream(rawPdbFile);

  // prepare the module info stream for grabbing function symbols from modules
  const PDB::ModuleInfoStream moduleInfoStream =
      dbiStream.CreateModuleInfoStream(rawPdbFile);

  // prepare symbol record stream needed by the public stream
  const PDB::CoalescedMSFStream symbolRecordStream =
      dbiStream.CreateSymbolRecordStream(rawPdbFile);

  // note that we only use unordered_set in order to keep the example code easy
  // to understand. using other hash set implementations like e.g. abseil's
  // Swiss Tables (https://abseil.io/about/design/swisstables) is *much* faster.
  std::unordered_set<uint32_t> seenFunctionRVAs;

  // start by reading the module stream, grabbing every function symbol we can
  // find. in most cases, this gives us ~90% of all function symbols already,
  // along with their size.
  {
    const PDB::ArrayView<PDB::ModuleInfoStream::Module> modules =
        moduleInfoStream.GetModules();

    for (const PDB::ModuleInfoStream::Module &module : modules) {
      if (!module.HasSymbolStream()) {
        continue;
      }

      const PDB::ModuleSymbolStream moduleSymbolStream =
          module.CreateSymbolStream(rawPdbFile);
      moduleSymbolStream.ForEachSymbol(
          [&functionSymbols, &seenFunctionRVAs,
           &imageSectionStream](const PDB::CodeView::DBI::Record *record) {
            // only grab function symbols from the module streams
            const char *name = nullptr;
            uint32_t rva = 0u;
            uint32_t size = 0u;
            if (record->header.kind ==
                PDB::CodeView::DBI::SymbolRecordKind::S_THUNK32) {
              if (record->data.S_THUNK32.thunk ==
                  PDB::CodeView::DBI::ThunkOrdinal::TrampolineIncremental) {
                // we have never seen incremental linking thunks stored inside a
                // S_THUNK32 symbol, but better safe than sorry
                name = "ILT";
                rva = imageSectionStream.ConvertSectionOffsetToRVA(
                    record->data.S_THUNK32.section,
                    record->data.S_THUNK32.offset);
                size = 5u;
              }
            } else if (record->header.kind ==
                       PDB::CodeView::DBI::SymbolRecordKind::S_TRAMPOLINE) {
              // incremental linking thunks are stored in the linker module
              name = "ILT";
              rva = imageSectionStream.ConvertSectionOffsetToRVA(
                  record->data.S_TRAMPOLINE.thunkSection,
                  record->data.S_TRAMPOLINE.thunkOffset);
              size = 5u;
            } else if (record->header.kind ==
                       PDB::CodeView::DBI::SymbolRecordKind::S_LPROC32) {
              name = record->data.S_LPROC32.name;
              rva = imageSectionStream.ConvertSectionOffsetToRVA(
                  record->data.S_LPROC32.section,
                  record->data.S_LPROC32.offset);
              size = record->data.S_LPROC32.codeSize;
            } else if (record->header.kind ==
                       PDB::CodeView::DBI::SymbolRecordKind::S_GPROC32) {
              name = record->data.S_GPROC32.name;
              rva = imageSectionStream.ConvertSectionOffsetToRVA(
                  record->data.S_GPROC32.section,
                  record->data.S_GPROC32.offset);
              size = record->data.S_GPROC32.codeSize;
            } else if (record->header.kind ==
                       PDB::CodeView::DBI::SymbolRecordKind::S_LPROC32_ID) {
              name = record->data.S_LPROC32_ID.name;
              rva = imageSectionStream.ConvertSectionOffsetToRVA(
                  record->data.S_LPROC32_ID.section,
                  record->data.S_LPROC32_ID.offset);
              size = record->data.S_LPROC32_ID.codeSize;
            } else if (record->header.kind ==
                       PDB::CodeView::DBI::SymbolRecordKind::S_GPROC32_ID) {
              name = record->data.S_GPROC32_ID.name;
              rva = imageSectionStream.ConvertSectionOffsetToRVA(
                  record->data.S_GPROC32_ID.section,
                  record->data.S_GPROC32_ID.offset);
              size = record->data.S_GPROC32_ID.codeSize;
            }

            if (rva == 0u) {
              return;
            }

            functionSymbols.push_back(FunctionSymbol{name, rva, size});
            seenFunctionRVAs.emplace(rva);
          });
    }
  }

  // we don't need to touch global symbols in this case.
  // most of the data we need can be obtained from the module symbol streams,
  // and the global symbol stream only offers data symbols on top of that, which
  // we are not interested in. however, there can still be public function
  // symbols we haven't seen yet in any of the modules, especially for PDBs that
  // don't provide module-specific information.

  // read public symbols
  const PDB::PublicSymbolStream publicSymbolStream =
      dbiStream.CreatePublicSymbolStream(rawPdbFile);
  {
    const PDB::ArrayView<PDB::HashRecord> hashRecords =
        publicSymbolStream.GetRecords();
    const size_t count = hashRecords.GetLength();

    for (const PDB::HashRecord &hashRecord : hashRecords) {
      const PDB::CodeView::DBI::Record *record =
          publicSymbolStream.GetRecord(symbolRecordStream, hashRecord);
      if ((PDB_AS_UNDERLYING(record->data.S_PUB32.flags) &
           PDB_AS_UNDERLYING(
               PDB::CodeView::DBI::PublicSymbolFlags::Function)) == 0u) {
        // ignore everything that is not a function
        continue;
      }

      const uint32_t rva = imageSectionStream.ConvertSectionOffsetToRVA(
          record->data.S_PUB32.section, record->data.S_PUB32.offset);
      if (rva == 0u) {
        // certain symbols (e.g. control-flow guard symbols) don't have a valid
        // RVA, ignore those
        continue;
      }

      // check whether we already know this symbol from one of the module
      // streams
      const auto it = seenFunctionRVAs.find(rva);
      if (it != seenFunctionRVAs.end()) {
        // we know this symbol already, ignore it
        continue;
      }

      // this is a new function symbol, so store it.
      // note that we don't know its size yet.
      functionSymbols.push_back(
          FunctionSymbol{record->data.S_PUB32.name, rva, 0u});
    }
  }

  // we still need to find the size of the public function symbols.
  // this can be deduced by sorting the symbols by their RVA, and then computing
  // the distance between the current and the next symbol. this works since
  // functions are always mapped to executable pages, so they aren't interleaved
  // by any data symbols.
  std::sort(functionSymbols.begin(), functionSymbols.end(),
            [](const FunctionSymbol &lhs, const FunctionSymbol &rhs) {
              return lhs.Rva < rhs.Rva;
            });

  const size_t symbolCount = functionSymbols.size();
  if (symbolCount != 0u) {
    size_t foundCount = 0u;

    // we have at least 1 symbol.
    // compute missing symbol sizes by computing the distance from this symbol
    // to the next. note that this includes "int 3" padding after the end of a
    // function. if you don't want that, but the actual number of bytes of the
    // function's code, your best bet is to use a disassembler instead.
    for (size_t i = 0u; i < symbolCount - 1u; ++i) {
      FunctionSymbol &currentSymbol = functionSymbols[i];
      if (currentSymbol.Size != 0u) {
        // the symbol's size is already known
        continue;
      }

      const FunctionSymbol &nextSymbol = functionSymbols[i + 1u];
      const size_t size = nextSymbol.Rva - currentSymbol.Rva;
      ++foundCount;
    }

    // we know have the sizes of all symbols, except the last.
    // this can be found by going through the contributions, if needed.
    FunctionSymbol &lastSymbol = functionSymbols[symbolCount - 1u];
    if (lastSymbol.Size != 0u) {
      // bad luck, we can't deduce the last symbol's size, so have to consult
      // the contributions instead. we do a linear search in this case to keep
      // the code simple.
      const PDB::SectionContributionStream sectionContributionStream =
          dbiStream.CreateSectionContributionStream(rawPdbFile);
      const PDB::ArrayView<PDB::DBI::SectionContribution> sectionContributions =
          sectionContributionStream.GetContributions();
      for (const PDB::DBI::SectionContribution &contribution :
           sectionContributions) {
        const uint32_t rva = imageSectionStream.ConvertSectionOffsetToRVA(
            contribution.section, contribution.offset);
        if (rva == 0u) {
          continue;
        }

        if (rva == lastSymbol.Rva) {
          lastSymbol.Size = contribution.size;
          break;
        }

        if (rva > lastSymbol.Rva) {
          // should have found the contribution by now
          break;
        }
      }
    }
  }
}

//////////////////////////////////////////////////////////////////////////////////
/// class function

PDBParser::PDBParser() { mSymbols.clear(); }

const std::vector<Symbol> &PDBParser::GetSymbols() const { return mSymbols; }

bool PDBParser::Parse(const char *PDBFilePath) {
  MemoryMappedFile::Handle PDBFile = MemoryMappedFile::Open(PDBFilePath);
  if (!PDBFile.baseAddress) {
    printf("Unable to open pdb file %s\n", PDBFilePath);
    return false;
  }

  if (IsError(PDB::ValidateFile(PDBFile.baseAddress))) {
    printf("Unable to validate pdb file %s\n", PDBFilePath);
    MemoryMappedFile::Close(PDBFile);
    return false;
  }

  const PDB::RawFile RawPdbFile = PDB::CreateRawFile(PDBFile.baseAddress);
  if (IsError(PDB::HasValidDBIStream(RawPdbFile))) {
    printf("Unable to validate DBI Stream\n");
    MemoryMappedFile::Close(PDBFile);
    return false;
  }

  const PDB::InfoStream infoStream(RawPdbFile);
  if (infoStream.UsesDebugFastLink()) {
    printf("PDB was linked using unsupported option /DEBUG:FASTLINK\n");
    MemoryMappedFile::Close(PDBFile);
    return false;
  }

  const PDB::DBIStream DbiStream = PDB::CreateDBIStream(RawPdbFile);
  if (!HasValidDBIStreams(RawPdbFile, DbiStream)) {
    printf("Unable to create DBI Stream\n");
    MemoryMappedFile::Close(PDBFile);
    return false;
  }

  ParseFunctionSymbols(RawPdbFile, DbiStream, mSymbols);
  if (mSymbols.empty()) {
    printf("Unable to parse function symbols\n");
    return false;
  }

  return true;
}

} // namespace EasyPDBParserLib

