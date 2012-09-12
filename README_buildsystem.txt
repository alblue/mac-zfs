
 GNU make based build system for maczfs

This file describes the design and working of the new make based build
system. The general idea is to separate the technical build rules from
the build configuration, i.e. from the question which source files,
using which compiler flags, go into which build product, called
"toplevel-target" in the build system and this document.

The build configuration is specified in one or more individual files,
e.g. "Makefile-macosx" in the projects root directory or a sub
folder.  The actual file name does not matter.  These Makefiles can be
distributed to the source directories holding the main sources for
their toplevel-targets, however this complicates automatic dependency
tracking.  For automatic dependency handling, all toplevel-targets
must be know when building any of the targets.  This limitation could
be waived, but at the expense of a more complex dependency tracking.

The build rules itself are all stored in the single file
Makefile.Rules, which must live in the project root directory.  If
Makefile.rules is to be stored somewhere else, then the code block
calculation project root needs to be adjusted.

The build rules themselves are somewhat complex due to the fact that
we need to support multiple architectures and that the actual build
configuration for a toplevel-target may depend on the architecture
currently build.  Another source of complexity is that we use
convenient libraries ("archives", "dot a" files) to speed up
compilation.  These libraries must be build for each architecture and
then the right architecture must be linked into the executables.

The solution here has two steps:

First, the way how we specify the build configuration for a given
toplevel-target in its makefile and second how we construct the actual
compiler commands from the configuration.

Specifying the build configuration:

Each toplevel-target is described by a set of variables, which names
are constructed from the target's name.  Suppose we what to configure
a target "tget", then we need to define at least one variable called
"tget_SOURCES".  This variable get all the names of the source files
that make up the target, including path to the source file relative to
the project's root.  Similar, the variable "tget_LIBS" defines which
libraries (both convenient libraries local to the build and installed
libraries) are linked into the target.  For a complete list of
variables refere to the file "Makefile-template" in the project root
directory.

The variables which start simply with "tget_" define what is common
across all build configurations for a given toplevel-target.  For each
variable exist a variant that holds the architecture or configuration
specifics.  Suppose we have an architecture called "arch", and this
architecture requires an additional source file and an extra flag to
the compiler.  This extras would be specified as "tget_arch_SOURCES :=
extra_file.c" and "tget_arch_CFLAGS := -DARCHFLAG=xxx".  One can add
compiler flags, linker flags, extra search patch for headers (searched
before the common ones), extra source files and extra libraries.  the
file Makefile-template holds the complete list of recognized variables
and the rules which variables can have architecture specific additions
(i.e. tget_XXX and tget_arch_XXX are concatenated and passed to the
compiler) and which variables have only architecture specific
overrides (i.e. when tget_YYY and tget_arch_YYY are both specified,
then compiling / linking architecture 'arch' only sees tget_arch_YYY
while all other architectures see only tget_YYY (or their own
override).


Creating compiler commands:

Each makefile describing a build configuration includes at its very
end the file Makefile.Rules.  This file is a gnu make makefile and
transforms the variables defining the build configuration into real
make rules for the compiler and linker.

Makefile.Rules is composed from three parts, first a number of defines
(variable assignments) that describe various defaults and as most
important part define the architectures known to the system.  Second
part are templates for the actual build rules and the third part are
makefile commands that instantiate the templates.

Overview of Makefile.Rules templates:
 
The third part is in practice itself template based, with one or two
templates per type of toplevel-target.  These are named:

- exe_tpl for executables,

- kext_tpl for kernel extensions and

- lib_pre_tpl and lib_tpl for building libraries.  This is split into
  two templates, because tget_prep_libs_tpl, called from lib_tpl,
  needs to know which libraries in the project are build as dynamic
  ones.  This information is computed in tget_prep_arch, called from
  lib_pre_tpl.  The lib_pre_tpl is first called for all defined
  libraries in the project, which establishes for each library if it
  is build as a dynamic one.  Then lib_tpl is call for all defined
  libraries and uses the complete information to decide how to link
  each defined library against the other libraries in the project.


The templates in part two fall all into two categories:

a) First templates that really invoke the compiler or linker, these
are:

- obj_arch_tpl (compiling a single source file into a single object
  file using pattern rules),

- exe_arch_tpl (linking an executable),

- lib_arch_tpl (linking a dynamic and / or static library (this is the
  most complex one)),

- kext_arch_tpl (linking the binary of a kernel extension and
  construction the bundle).

b) Second templates that precompute variables needed by the compiler /
linker templates.  these are:

- tget_prep_tpl (preliminary work, determine which architectures to
  build)

-tget_prep_arch_tpl (expand all variables, this turns all tget_XXX
 tget_arch_XXX into tget_arch_XXX_ALL, which then hold the complete
 information for that combination of target 'tget' and architecture
 'arch')

- tget_prep_libs_tpl (compute which libraries are linked into target
  'tget' for each build architecture.  Decides if static or dynamic
  linking is done, which may be different for different architectures)

The remaining templates don't really fit into these categories, they
mostly encapsulate code needed in multiple places:

- tget_prep_obj_tpl (instantiate the obj_arch_tpl foreach source
  directory used in a target--architecture pair)

- tget_maketgets_tpl (define various make targets like 'clean'
  'install' etc.  here only the (mostly) empty toplevel-target rules
  are made, i.e. rules like "clean-tget: clean-tget-arch1
  clean-tget-arch2" that simply depend on the real rules in
  exe_arch_tpl and Co.)



Template details part one to three:

Defining an architecture:

Known architectures are defined by a set of variables starting all
with "ARCH_EXTRA_" followed by the architecture's name. Each
architecture is defined by three variables, CXXFLAGS, CFLAGS and
LDFLAGS. For example the architecture "x86_64" is defined by
"ARCH_EXTRA_x86_64_CFLAGS := -arch x86_64 -fPIC" and matching
definitions for CXXFLAGS and LDFLAGS.


Instantiating templates:

The actual build rules are constructed in two steps: First all the
sources, flags and libraries for each architecture and toplevel-target
are collected.  This step, done in tget_prep_tpl, tget_prep_arch_tpl
and tget_prep_libs_tpl, produces variables of the form tget_arch_XXX
where XXX names sources, libraries, flags and various intermediate
states.  The following variables are computed:

- tget_BUILD_ARCHS : all architectures for toplevel-target tget
  (tget_prep_tpl)

- tget_arch_SOURCES_ALL :  tget_SOURCES + tget_arch_SOURCES
  (tget_prep_arch_tpl)

- tget_arch_SRCDIRS_ALL : all directories containing sources for
  target "tget" in architecture "arch" (tget_prep_arch_tpl)

- tget_arch_OBJ_ALL : all object files going into target "tget" for
  architecture "arch" (tget_prep_arch_tpl)

- tget_arch_CFLAGS_ALL :  tget_CFLAGS + tget_arch_CFLAGS
  (tget_prep_arch_tpl)

- tget_arch_CXXFLAGS_ALL :  tget_CXXFLAGS + tget_arch_CXXFLAGS
  (tget_prep_arch_tpl)

- tget_arch_LDFLAGS_ALL :  tget_LDFLAGS + tget_arch_LDFLAGS
  (tget_prep_arch_tpl) 

- tget_arch_INCSYS_ALL :  tget_INCSYS + tget_arch_INCSYS
  (tget_prep_arch_tpl)

- tget_arch_INC_ALL :  tget_INC + tget_arch_INC
  (tget_prep_arch_tpl)

- tget_arch_LIBS_AR_OK : same as tget_arch_LIBS_ALL, but only those
  libraries for which static linking has been explicitly requested.
  Computed from tget_LIBS_AR and tget_arch_LIBS_AR plus libraries from
  tget_LIBS_DY and tget_arch_LIBS_DY that can't be linked dynamically.
  (tget_prep_libs_tpl)

- tget_arch_ARLIBS_OK_PATH : all libraries from tget_arch_LIBS_AR_OK
  including full path (tget_prep_libs_tpl)

- tget_arch_LIBS_DY_OK : same as tget_arch_LIBS_ALL, but only those
  libraries for which dynamic linking has been requested and is
  supported.  Computed from tget_LIBS_DY and tget_arch_LIBS_DY minus
  libraries that can't be linked dynamically.  (tget_prep_libs_tpl)

- tget_arch_DYLIBS_OK_PATH : all libraries from tget_arch_LIBS_DY_OK
  including full path (tget_prep_libs_tpl)

- tget_arch_DYLIBS_OK_L : the linker's '-lxxx' flag for all libraries
  from tget_arch_LIBS_AR_OK (tget_prep_libs_tpl)

- tget_arch_DYLIBS_OK_SEARCH : the linker's '-Lpath' flag for all
  libraries from tget_arch_LIBS_AR_OK (tget_prep_libs_tpl)

- tget_arch_LDLIBS_ALL : all shared libraries from the system
  (i.e. not build in the project) used by "tget" in architecture
  "arch" (tget_prep_arch_tpl)

- tget_arch_DYLIB_FIN : defines if the library 'tget' in architecture
  'arch' should be build as a dynamic library.  Taken from tget_DYLIB,
  overridden by tget_arch_DYLIB and possibly reset from
  ARCH_EXTRA_arch_DYLIBS_OK.  (tget_prep_arch_tpl)

- tget_arch_DYLIB_ORIG : content of tget_arch_DYLIB_FIN before
  possible override by ARCH_EXTRA_arch_DYLIBS_OK.
  (tget_prep_arch_tpl)

- tget_arch_VERS_FIN : library version of the library 'tget' in
  architecture 'arch'.  Taken from tget_VERS, overridden by
  tget_arch_VERS (tget_prep_arch_tpl)

- tget_arch_INSTHDRS_ALL : tget_INSTHDRS + tget_arch_INSTHDRS
  (tget_prep_arch_tpl)

- tget_arch_INSTHDRSDIR_FIN : tget_INSTHDRSDIR + tget_arch_INSTHDRSDIR
  (tget_prep_arch_tpl)

- tget_arch_DO_INST_HDRS : set to yes if tget_arch_INSTHDRS_ALL is
  non-empty.  (tget_prep_arch_tpl)

- tget_arch_INSTLIBDIR_FIN : tget_INSTLIBDIR, possibly overridden by
  tget_arch_INSTLIBDIR.   (tget_prep_arch_tpl)

- tget_arch_INSTEXEDIR_FIN : tget_INSTEXEDIR, possibly overridden by
  tget_arch_INSTEXEDIR.  (tget_prep_arch_tpl)

- tget_arch_INSTKEXTDIR_FIN : tget_INSTKEXTDIR, possibly overridden by
  tget_arch_INSTKEXTDIR.  (tget_prep_arch_tpl)

- tget_arch_INSTNAME_FIN : tget_INSTNAME, possibly overridden by
  tget_arch_INSTNAME.  (tget_prep_arch_tpl)

- tget_arch_INSTARLIB_FIN : tget_INSTARLIB, possibly overridden by
  tget_arch_INSTARLIB.  (tget_prep_arch_tpl)

- tget_arch_DESCRIPTION_FIN : tget_DESCRIPTION, possibly overridden by
  tget_arch_DESCRIPTION.  (tget_prep_arch_tpl)

- tget_arch_VERSION_FIN : tget_VERSION, possibly overridden by
  tget_arch_VERSION.  (tget_prep_arch_tpl)

- tget_arch_VERS_C_FIN : tget_VERS_C, possibly overridden by
  tget_arch_VERS_C.  (tget_prep_arch_tpl)

- tget_arch_KEXT_START_FIN : tget_KEXT_START, possibly overridden by
  tget_arch_KEXT_START.  (tget_prep_arch_tpl)

- tget_arch_KEXT_STOP_FIN : tget_KEXT_STOP, possibly overridden by
  tget_arch_KEXT_STOP.  (tget_prep_arch_tpl)

- tget_arch_KEXT_ID_FIN : tget_KEXT_ID, possibly overridden by
  tget_arch_KEXT_ID.  (tget_prep_arch_tpl)

- tget_arch_KEXT_DESCRIPTION_FIN : tget_KEXT_DESCRIPTION, possibly
  overridden by tget_arch_KEXT_DESCRIPTION.  (tget_prep_arch_tpl)

- tget_arch_KEXT_VERSION_FIN : tget_KEXT_VERSION, possibly overridden
  by tget_arch_KEXT_VERSION.  (tget_prep_arch_tpl)

- tget_arch_KEXT_PLIST_FIN : tget_KEXT_PLIST, possibly overridden by
  tget_arch_KEXT_PLIST.  (tget_prep_arch_tpl)

- tget_arch_KEXT_INFO_C_FIN : tget_KEXT_INFO_C, possibly overridden by
  tget_arch_KEXT_INFO_C.  (tget_prep_arch_tpl)

These variables are used in the compiler and linker rules, either
literally as sets or by iterating over their content to build
individual rules.  The following rules are constructed:

Compiling an object file (slightly simplified):

$(BUILDBASE)/tget_arch/%.o: path/%.c
	$(CC) -o $@ $< $(CFLAGS) $(ARCH_EXTRA_arch_CFLAGS)
	$(tget_arch_INCSYS_ALL) $(tget_arch_INC)
	$(tget_arch_CFLAGS_ALL) $(tget_INC)

This rule is generated multiple times, with "path" once set to each
directory in tget_arch_SRCDIRS.  Similar rules are constructed for C++
files ".cc" and ".cpp".  The template for compiling an object file is
defined in obj_arch_tpl, which is called from tget_prep_obj_tpl.  The
tget_prep_obj_tpl is split out from tget_prep_arch_tpl, because it
needs the content of tget_prep_arch_tpl fully instantiated before
running (variables defined inside a template are only available after
that template has been evaluated, i.e. run  through $(eval $(call ...)) ). 

Linking an executable (slightly simplified):

$(BUILDBASE)/tget_arch/tget: $(tget_arch_OBJ_ALL)
	$(CC) -o $@ $(tget_arch_OBJ_ALL)  $(LDFLAGS)
	$(ARCH_EXTRA_arch_LDFLAGS) $(tget_arch_LDFLAGS_ALL)
	$(tget_arch_ARLIBS_OK_PATH)  $(tget_arch_DYLIB_OK_SEARCH)
	$(tget_arch_DYLIBS_OK_L)  $(tget_arch_LDLIBS_ALL) 


This rule is generated once for each pair of toplevel-traget and
architecture. The template is defined in exe_arch_tpl. The
corresponding rule to link a library is defined in lib_arch_tpl, which
first unconditionally creates a static library and then, subject to
tget_arch_DYLIB_FIN additionally creates a dynamic library.

The rule for linking a static library is (slightly simplified):

$(BUILDBASE)/tget_arch/tget.a: $(tget_arch_OBJ_ALL) $(tget_arch_LIBS_AR_DY_OK_PATH)
	ar rs $@ $@.tax/* $(tget_arch_OBJ_ALL)

The directory $@.tax in above rule holds all object files of all
static libraries that should be linked into the library tget.  It is
populated by other commands in lib_arch_tpl.

The rule for linking a dynamic library is (slightly simplified):

$(BUILDBASE)/tget_arch/tget.dylib: $(tget_arch_OBJ_ALL)  $(tget_arch_ARLIBS_OK_PATH)
	libtool -dynamic -o $@ $(tget_arch_LDFLAGS_ALL)
	$(tget_arch_OBJ_ALL)  $(tget_arch_ARLIBS_OK_PATH)
	$(tget_arch_DYLIB_OK_SEARCH) $(tget_arch_DYLIBS_OK_L)
	$(tget_arch_LDLIBS_ALL)

Linking a kernel extension follows exactly the pattern of linking an
executable.


Makefile.Rules generates a lot more internal rules, mostly within the
exe_arch_tpl, lib_arch_tpl and kext_arch_tpl.  These other rules serve
for automated dependency tracking and for computing intermediates
needed to build or execute the above shown rules.


Call tree for template instantiation:

- for each member of ALL_EXE
  - call exe_tpl
    - call tget_prep_tpl
    - for each architecture
      - call call tget_prep_arch_tpl
      end for each
    - for each architecture
      - call call tget_prep_libs_tpl
      end for each
    - for each architecture
      - call tget_prep_obj_tpl
        - for each source directory of target in architecture
          - call obj_arch_tpl
          end for each
      end for each
    - for each architecture
      - call call exe_arch_tpl
      end for each
    - call tget_maketgets_tpl

Libraries and kernel extension follow the same structure, only the
exe_* templates are replaced by lib_* and kext_*.


# EOF
