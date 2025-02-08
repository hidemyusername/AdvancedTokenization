# AdvancedTokenization Fuzz Target

AdvancedTokenization is a fuzz target designed to detect inconsistencies in the tokenization of text strings. Its main goal is to compare two tokenization methods—an *advanced* tokenizer that handles quotes and escape sequences, and a *basic* tokenizer that splits the input on spaces (and other whitespace). By comparing the results (both in the number of tokens and via hash values using the djb2 algorithm), the target can trigger an intentional crash if the discrepancy exceeds predefined thresholds.

## Features

- **Advanced Tokenization:**  
  Processes strings with quotes and escape sequences to extract tokens accurately.

- **Basic Tokenization:**  
  Splits the input string into tokens based solely on whitespace (spaces, tabs, and newlines).

- **Differential Comparison:**  
  Compares the two tokenization outputs by:
  - Checking the difference in the number of tokens.
  - Comparing the hashes of the tokens.
  
  If the token count difference is greater than 1 or the hash difference exceeds 10% of the maximum hash value, the target triggers an intentional crash using `__builtin_trap()`.

- **Safe Memory Handling:**  
  Uses `safe_malloc`, `safe_realloc`, and `safe_free` functions that add "guard bytes" before and after allocated memory blocks to detect buffer overwrites.

## Requirements

- **Compiler:** Clang 10 or higher is recommended.
- **Sanitizers:** The target is built with AddressSanitizer and UndefinedBehaviorSanitizer to generate detailed crash reports.
- **LibFuzzer:** Integrated via `-fsanitize=fuzzer`.
- **Operating System:** Linux is assumed for OSS-Fuzz integration.

## Build Instructions

You can build the fuzz target using the provided build script or by running the following commands manually:

```bash
export CC=clang
export CFLAGS="-O1 -g"
export OUT=./out
mkdir -p $OUT

# Build with AddressSanitizer, UndefinedBehaviorSanitizer, and libFuzzer
$CC $CFLAGS -fsanitize=address,undefined -fsanitize=fuzzer advanced_fuzz_target.c -o $OUT/advanced_fuzz_target
