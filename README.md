[![Publish Release](https://github.com/pdamian/mole/actions/workflows/release.yml/badge.svg)](https://github.com/pdamian/mole/actions/workflows/release.yml)
# Mole

<p align="center">
  <img src="https://drive.google.com/uc?export=view&id=1oToYEJyJOJtT9fgl7Pm4DuVloZGod5MO" style="width: 256px; max-width: 100%; height: auto" alt="Mole Logo"/>
</p>

**_Mole_** is a *Binary Ninja* plugin designed to identify **interesting paths** in binaries. It performs **static backward slicing** on variables using *Binary Ninja*'s [*Medium Level Intermediate Language* (*MLIL*)](https://docs.binary.ninja/dev/bnil-mlil.html) in its *Static Single Assignment* (*SSA*) form.

In *Mole*, a **path** refers to the flow of data between a defined source and sink. What constitutes an "interesting" path depends on the analysis goals. For instance, when searching for **vulnerabilities**, one might look for paths where untrusted inputs (sources) influence sensitive operations (sinks) in potentially dangerous ways.

The following list highlights some of *Mole*'s current **features**:
- **Operation Mode**: *Mole* can be run either within *Binary Ninja*'s UI or in headless mode. Headless mode is particularly useful for scripted analysis across a large number of binaries. Conversely, using *Mole* within the UI is ideal for closely investigating detected paths.
- **Path Identification**:
  - **Configuration**: *Mole* enables the definition of relevant source and sink functions in configuration files (see TODO). This provides flexibility in selecting sources and sinks based on the specific usage scenario.
  - **Exploration**: To better understand a path and examine its characteristics, all instructions along the path can be printed or visually highlighted within *Binary Ninja*. Additionally, a side-by-side comparison of two paths can be displayed to quickly identify differences. Similar to instructions, a path's sequence of function calls can be printed or even visualized as a graph.
  - **Grouping**: To facilitate the identification of similar paths, *Mole* supports multiple grouping strategies. Currently, paths can be grouped based on matching source and sink functions, or by identical call sequences. New custom grouping strategies can easily be added to extend and customize this functionality (see [Extension](./docs/03-Extension.md#path-grouping-strategy)).
  - **Persistence**: Discovered paths can be annotated for clarity or removed if deemed irrelevant. To preserve analysis progress, paths can be saved directly to the target binary's database (*Binary Ninja*'s `.bndb` format). Paths can also be exported - for example, when performing headless analysis across many binaries on a file system, allowing identified paths to be later imported for easier exploration within *Binary Ninja*.
- **Inter-Procedural Variable Slicing**: *Mole* supports slicing *MLIL variables* across function boundaries - a task that presents several challenges. For instance, statically determining a function's effective caller(s) is often difficult or even impossible. As a result, the implemented approach is an approximation. While not perfect, it performs reasonably well across a wide range of practical scenarios.
- **Basic Pointer Analysis**: *Mole* currently implements a simplified strategy for tracking pointer usage. Like inter-procedural slicing, this approach is a simplification with inherent limitations. Nevertheless, it performs well in many practical cases and is planned to be improved in future versions.

## Documentation
1. [Installation](./docs/01-Installation.md)
2. [Usage](./docs/02-Usage.md)
3. [Extension](./docs/03-Extension.md)

## Contribute or Share Your Experience
*Mole* is currently a **work in progress**. If you encounter a bug, have a useful new unit test that highlights a false positive or negative, or have a suggestion for a new feature, please consider opening an issue or contribute via pull request. Also note that the current [unit tests](./test/src/) have only been verified on `linux-x86_64` and `linux-armv7` binaries so far.

If you have an interesting **success story** - such as finding a vulnerability with the help of *Mole* - we would love to hear about it! Feel free to share your experience with us (TODO).

## Contributors
- [Damian Pfammatter](https://github.com/pdamian), [Cyber-Defense Campus (armasuisse S+T)](https://www.cydcampus.admin.ch/en)
- [Sergio Paganoni](https://github.com/wizche), [TODO]()