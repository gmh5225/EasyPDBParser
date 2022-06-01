
#include "OldPDBMSDIAParser.h"

#ifdef _WIN32

// ONLY SUPPORT WINDOWS

#include "dia2.h"
#include <algorithm>
#include <atlbase.h>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <unordered_map>

#define MSDIA_DLL_NAME L"msdia140.dll"

// used with maps which take in std::strings so it compares in lowercase
struct map_comparator {
  bool operator()(const std::string &left, const std::string &right) const {
    return !_stricmp(left.c_str(), right.c_str());
  }
};

namespace OldPDBMSDIAParser {

typedef HRESULT(__stdcall *pDllGetClassObject)(_In_ REFCLSID rclsid,
                                               _In_ REFIID riid,
                                               _Out_ LPVOID *ppv);

// codeview debug struct, there is no fucking documentation so i had to search a
// bit big thanks to
// https://jpassing.com/2009/04/22/uniquely-identifying-a-modules-build/
struct codeview_info_t {
  ULONG CvSignature;
  GUID Signature;
  ULONG Age;
  char PdbFileName[ANYSIZE_ARRAY];
};

// access using module path, has pair with first being map of functions and
// their RVAs, and second being pdb path
static std::unordered_map<
    std::string,
    std::pair<std::unordered_map<std::string, uintptr_t>, std::string>,
    std::hash<std::string>, map_comparator>
    cached_info;

////////////////////////////////////////////////////////////////////////////////////////////////////
//// private function

HRESULT STDMETHODCALLTYPE NoRegCoCreate(const __wchar_t *dllName,
                                        REFCLSID rclsid, REFIID riid,
                                        void **ppv) {
  HRESULT hr;
  HMODULE hModule =
      LoadLibraryExW(dllName, nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
  pDllGetClassObject DllGetClassObject;
  if (hModule && (DllGetClassObject = (pDllGetClassObject)GetProcAddress(
                      hModule, "DllGetClassObject"))) {
    IClassFactory *classFactory;
    hr = DllGetClassObject(rclsid, IID_IClassFactory, (LPVOID *)&classFactory);
    if (SUCCEEDED(hr)) {
      hr = classFactory->CreateInstance(nullptr, riid, ppv);
      classFactory->AddRef();
    }
  } else {
    hr = GetLastError();
    if (hr > 0)
      hr |= REASON_LEGACY_API;
  }
  return hr;
}

size_t get_address_rva_from_symbol(std::string function_name,
                                   std::string pdb_path,
                                   /*OUT*/ size_t &sym_size) {
  // init com stuff
  {
    static auto has_initialized = false;

    if (!has_initialized) {
      CoInitialize(nullptr);
      has_initialized = true;
    }
  }

  auto &function_address = cached_info[pdb_path].first[function_name.data()];

  // check if we've already found this function
  if (function_address)
    return function_address;

  if (pdb_path.empty())
    return 0;

  // helper function to convert ASCII strings to UNICODE strings
  auto multibyte_to_widechar = [](std::string str) {
    std::wstring wide_text;
    wide_text.resize(str.length());

    std::transform(str.begin(), str.end(), wide_text.begin(),
                   [](char val) { return std::btowc(val); });

    return wide_text;
  };

  static CComPtr<IDiaSymbol> global = nullptr;
  if (!global) {
    // find debug info from pdb file
    CComPtr<IDiaDataSource> source;

    HRESULT hr = REGDB_E_CLASSNOTREG;

    hr = NoRegCoCreate(MSDIA_DLL_NAME, __uuidof(DiaSource),
                       __uuidof(IDiaDataSource),
                       reinterpret_cast<void **>(&source));
    if (FAILED(hr)) {
      // printf("AceSc:msdia140.dll load failed : %p\n", hr);
      return 0;
    }

    if (FAILED(hr)) {
      hr = CoCreateInstance(__uuidof(DiaSource), NULL, CLSCTX_INPROC_SERVER,
                            __uuidof(IDiaDataSource),
                            reinterpret_cast<void **>(&source));
    }
    if (FAILED(hr)) {
      return 0;
    }

    if (FAILED(
            source->loadDataFromPdb(multibyte_to_widechar(pdb_path).c_str())))
      return 0;
    CComPtr<IDiaSession> session;
    if (FAILED(source->openSession(&session)))
      return 0;

    if (FAILED(session->get_globalScope(&global)))
      return 0;
  }
  CComPtr<IDiaEnumSymbols> enum_symbols;
  CComPtr<IDiaSymbol> current_symbol;
  ULONG celt = 0;

  // filter the results so it only gives us symbols with the name we want
  if (FAILED(global->findChildren(
          /*SymTagNull*/ (SymTagEnum)0,
          multibyte_to_widechar(function_name).c_str(), nsNone, &enum_symbols)))
    return 0;
  // loop just in case? ive only ever seen this need to be a conditional
  while (SUCCEEDED(enum_symbols->Next(1, &current_symbol, &celt)) &&
         celt == 1) {
    DWORD relative_function_address;

    if (FAILED(current_symbol->get_relativeVirtualAddress(
            &relative_function_address)))
      continue;

    if (!relative_function_address)
      continue;

    function_address = relative_function_address;

    ULONGLONG length = 0;
    current_symbol->get_length(&length);
    sym_size = length;

    return relative_function_address;
  }

  return 0;
}

} // namespace OldPDBMSDIAParser
#endif
