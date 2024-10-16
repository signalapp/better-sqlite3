# ===
# This configuration defines the differences between Release and Debug builds.
# Some miscellaneous Windows settings are also defined here.
# ===

{
  'variables': { 'sqlite3%': '' },
  'target_defaults': {
    'default_configuration': 'Release',
    'msvs_settings': {
      'VCCLCompilerTool': {
        'ExceptionHandling': 1,
      },
    },
    'conditions': [
      ['target_arch == "x64"', {
        'variables': {
          'rust_arch%': 'x86_64',
        }
      }, {
        'variables': {
          'rust_arch%': 'aarch64',
        }
      }],
      ['OS == "win"', {
        'defines': ['WIN32'],
        'variables': {
          'openssl_root%': 'OpenSSL-win-<(target_arch)',
        }
      }],
    ],
    'configurations': {
      'Debug': {
        'defines!': [
          'NDEBUG',
        ],
        'defines': [
          'DEBUG',
          '_DEBUG',
          'SQLITE_DEBUG',
          'SQLITE_MEMDEBUG',
          'SQLITE_ENABLE_API_ARMOR',
          'SQLITE_WIN32_MALLOC_VALIDATE',
        ],
        'cflags': [
          '-O0',
        ],
        'xcode_settings': {
          'MACOSX_DEPLOYMENT_TARGET': '10.15',
          'GCC_OPTIMIZATION_LEVEL': '0',
          'GCC_GENERATE_DEBUGGING_SYMBOLS': 'YES',
        },
        'msvs_settings': {
          'VCLinkerTool': {
            'GenerateDebugInformation': 'true',
          },
        },
      },
      'Release': {
        'defines!': [
          'DEBUG',
          '_DEBUG',
        ],
        'defines': [
          'NDEBUG',
        ],
        'cflags': [
          '-O3',
        ],
        'xcode_settings': {
          'MACOSX_DEPLOYMENT_TARGET': '10.15',
          'GCC_OPTIMIZATION_LEVEL': '3',
          'GCC_GENERATE_DEBUGGING_SYMBOLS': 'NO',
          'DEAD_CODE_STRIPPING': 'YES',
          'GCC_INLINES_ARE_PRIVATE_EXTERN': 'YES',
          'OTHER_CPLUSPLUSFLAGS': ['-std=c++20', '-stdlib=libc++'],
          'GCC_ENABLE_CPP_EXCEPTIONS': 'NO',
          'GCC_SYMBOLS_PRIVATE_EXTERN': 'YES', # -fvisibility=hidden
          'LLVM_LTO': 'YES',
        },
      },
    },
  },
}
