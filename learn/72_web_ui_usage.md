# Web UI Usage

**Level:** 7 - Integration and Automation
**Prerequisites:** 71_building_analysis_scripts.md
**What You Will Learn:** How to use the NeoDAX web interface effectively for interactive analysis.

## Starting the Web UI

```bash
node js/server/server.js
# Then open: http://localhost:7070/ui
```

Or, if you are using the standalone web app:

```bash
node server.js
# Then open: http://localhost:3000
```

## Navigating the Interface

The web UI has a sidebar with analysis panels. In the single-command version, you type a file path directly in the header input and press Enter or click LOAD.

Once a binary is loaded, panels become available:

- **Overview:** Binary metadata, section/function/xref counts, hottest functions
- **Sections:** Full section table
- **Symbols:** Searchable symbol list
- **Functions:** Searchable function list with flags
- **Xrefs:** Cross-reference table
- **Disassembly:** Structured disassembly with section selector
- **Decompiler:** Pseudo-C output (ARM64)
- **Symbolic Exec:** Symbolic execution trace (ARM64)
- **Entropy:** Entropy scan output
- **Validity:** Instruction validity filter output
- **Strings:** ASCII and Unicode strings
- **Rec. Descent:** Recursive descent analysis

## Effective Analysis Workflow in the UI

1. Load the binary by typing its path.
2. Check the Overview for quick stats.
3. Check the Sections panel to understand the layout.
4. Check the Symbols panel to see what symbols are available.
5. Go to Functions and search for interesting names.
6. Select a function, switch to Disassembly, choose the section.
7. For ARM64, use the Decompiler panel for a higher-level view.
8. Use the Entropy panel to check for packing.

## Using Search in Tables

The Symbols and Functions panels have search fields. Type part of a name to filter instantly. This is useful when you are looking for a specific function in a binary with hundreds of detected functions.

## Client-Side Routing

The URL updates as you navigate between panels. You can bookmark a specific panel and return to it directly:

```
http://localhost:3000/disasm
http://localhost:3000/functions
http://localhost:3000/entropy
```

## Disassembly Panel Tips

Use the section selector to choose which section to disassemble. For most analysis, `.text` is correct.

Use the limit input to control how many instructions to load. For large functions, increase this.

Use the filter field to search within the disassembly for specific mnemonics or operands.

## Practice

1. Start the web server and open the UI.
2. Load `/bin/ls` by typing the path.
3. Navigate through each panel and note what each shows.
4. Use the function search to find a specific function by name.
5. Load the disassembly and filter for `call` instructions.

## Next

Continue to `73_express_integration.md`.
