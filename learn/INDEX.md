# NeoDAX Learning Path - Index

67 files. 8 levels. Start at 00 and work forward.

## Level 0 - Foundation (files 00-07)
| File | Topic |
|------|-------|
| 00_introduction.md | Welcome and how to use this path |
| 01_what_is_binary_analysis.md | What binary analysis is and why it matters |
| 02_setting_up_neodax.md | Installation on Linux, macOS, Android |
| 03_your_first_binary.md | Running your first analysis |
| 04_understanding_elf_format.md | ELF binary format internals |
| 05_understanding_pe_format.md | Windows PE format internals |
| 06_understanding_macho_format.md | macOS Mach-O format internals |
| 07_binary_formats_comparison.md | ELF vs PE vs Mach-O side by side |

## Level 1 - Basic Analysis (files 10-18)
| File | Topic |
|------|-------|
| 10_cli_basics.md | All CLI flags and combinations |
| 11_reading_sections.md | Interpreting section output |
| 12_symbols_and_names.md | Symbols, stripping, PLT entries |
| 13_reading_disassembly.md | How to read disassembly output |
| 14_x86_64_primer.md | x86-64 assembly fundamentals |
| 15_arm64_primer.md | ARM64 assembly fundamentals |
| 16_riscv_primer.md | RISC-V RV64 assembly fundamentals |
| 17_string_extraction.md | ASCII and unicode string scanning |
| 18_entry_points_and_flow.md | Entry points and startup flow |

## Level 2 - Intermediate Analysis (files 20-28)
| File | Topic |
|------|-------|
| 20_functions_detection.md | How function detection works |
| 21_cross_references.md | Building and reading xrefs |
| 22_control_flow_graphs.md | CFG construction and reading |
| 23_cfg_in_practice.md | Practical CFG analysis techniques |
| 24_loop_detection.md | Dominator-based loop detection |
| 25_call_graphs.md | Call graph analysis |
| 26_switch_tables.md | Switch table detection |
| 27_unicode_strings.md | Unicode string extraction |
| 28_instruction_groups.md | Instruction classification |

## Level 3 - JavaScript API (files 30-38)
| File | Topic |
|------|-------|
| 30_js_api_introduction.md | API overview and installation |
| 31_loading_binaries_in_js.md | Load patterns and lifecycle |
| 32_working_with_sections.md | Section queries in JavaScript |
| 33_working_with_functions.md | Function queries in JavaScript |
| 34_disasm_json.md | Structured disassembly |
| 35_xrefs_in_js.md | Cross-reference queries |
| 36_analyze_pipeline.md | Full analysis pipeline |
| 37_typescript_usage.md | TypeScript types and usage |
| 38_async_patterns.md | Async and batch patterns |

## Level 4 - Advanced Analysis (files 40-46)
| File | Topic |
|------|-------|
| 40_entropy_analysis.md | Shannon entropy scanning |
| 41_packed_binary_detection.md | Detecting packed binaries |
| 42_recursive_descent.md | Recursive descent disassembly |
| 43_instruction_validity_filter.md | IVF for suspicious patterns |
| 44_hottest_functions.md | Most-called function analysis |
| 45_obfuscation_detection.md | Detecting obfuscation techniques |
| 46_symbol_demangling.md | C++ name demangling |

## Level 5 - Symbolic Execution and Decompilation (files 50-55)
| File | Topic |
|------|-------|
| 50_symbolic_execution_intro.md | What symbolic execution is |
| 51_ssa_lifting.md | SSA intermediate representation |
| 52_decompiler_output.md | Using the ARM64 decompiler |
| 53_reading_pseudo_c.md | Reading and interpreting pseudo-C |
| 54_arm64_emulator.md | The concrete ARM64 emulator |
| 55_emulator_use_cases.md | Practical emulator applications |

## Level 6 - Real World Reverse Engineering (files 60-66)
| File | Topic |
|------|-------|
| 60_analyzing_malware_basics.md | Safe, systematic malware analysis |
| 61_crackme_walkthrough.md | Full crackme analysis walkthrough |
| 62_finding_vulnerabilities.md | Identifying vulnerability patterns |
| 63_reverse_engineering_protocols.md | Understanding custom protocols |
| 64_android_binary_analysis.md | Android native libraries and JNI |
| 65_stripping_and_obfuscation.md | Working with stripped binaries |
| 66_daxc_snapshots.md | Saving and loading analysis state |

## Level 7 - Integration and Automation (files 70-76)
| File | Topic |
|------|-------|
| 70_rest_api_automation.md | REST API and external tool integration |
| 71_building_analysis_scripts.md | Reusable analysis scripts |
| 72_web_ui_usage.md | Web interface usage guide |
| 73_express_integration.md | Integrating into Express servers |
| 74_batch_analysis.md | Analyzing many binaries at once |
| 75_ci_cd_integration.md | CI/CD pipeline integration |
| 76_building_plugins.md | Building custom analysis plugins |

## Appendix (files 80-84)
| File | Topic |
|------|-------|
| 80_common_patterns_reference.md | Assembly patterns cheatsheet |
| 81_flag_quick_reference.md | All CLI flags in one place |
| 82_js_api_quick_reference.md | All JS API methods in one place |
| 83_architecture_cheatsheet.md | x86-64, ARM64, RISC-V side by side |
| 84_glossary.md | Definitions of all technical terms |
