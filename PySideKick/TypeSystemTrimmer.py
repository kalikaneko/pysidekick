#  Copyright (c) 2009-2010, Cloud Matrix Pty. Ltd.
#  All rights reserved; available under the terms of the BSD License.
"""

PySideKick.TypeSystemTrimmer:  trim down the size of your PySide binary
=======================================================================


This module defines the class TypeSystemTrimmer, which can help you trim down
the size of your PySide binaries by exluding classes and methods that are
not used by your code.  This might be useful if you're distributing frozen
applications with PySide.


When executed as a script, this module will analyse the objects exported by
a given PySide module, find those that aren't actually used by any of the
given scripts, and print an apiextractor typessytem file that will exclude
those objects.  So this:

    python -m PySideKick.TypeSystemTrimmer QtGui /path/to/myscript.py

Might output something like this:

    <typesystem package="PySide.QtGui">
      <rejection class="QAccessibleEvent" field-name="AcceptDropsChange" />
      <rejection class="QAccessibleEvent" field-name="AccessibilityHelp" />
      ...lots more of these...
      <rejection class="QApplication" function-name="applicationDirPath" />
      ...lots more of these...
    </typesystem>

This typesystem file can then be used to rebuild PySide without bindings for
the functionality that is not used by your application.

"""

import sys
import re
import tokenize
import modulefinder

import PySide.QtCore


#  This is the type of all objects wrapped by Shiboken.
#  Unfortunately there's no "Shiboken" module from which to import it.
SbkObjectType = type(PySide.QtCore.QObject)


#  Simple regular expression for matching valid python identifiers.
_identifier_re = re.compile("^"+tokenize.Name+"$")
is_identifier = _identifier_re.match


class TypeSystemTrimmer(object):
    """Class for automatically generating a reduced PySide typesystem.

    Instances of this class are capable of introspecting a PySide module
    and determining which of its exported objects are not used in a given
    application.  It can then generate a typesystem specification file to
    exlude these objects from a future build process.

    The TypeSystemTrimmer uses a ModuleFinder object to find all the python
    module used by an application, and then does a dumb string-matching search
    to find out what parts of PySide it uses.  A more sophisticated type
    inference may be done in the future, but for now we err on the side of
    caution.
    """

    #  List names used internally by the PySide bindings.
    #  We must not reject these!
    #  It would be better to filter by classname as well but this
    #  simple list does the trick for now.
    SPECIAL_NAMES = ("metaObject","setBit","insert","value","addAction",)

    #  List of classes with pure virtual methods.
    #  Shiboken fails to build unless a concrete implementation is provided
    #  for each pure virtual method.  Eventually we should check for this
    #  by introspecting the Qt API, and only keep the virtuals instead of
    #  keeping *everything* on the class.
    ABSTRACT_CLASSES = ("QIODevice","QTextCodec","QVariantAnimation",
                        "QIconEngineV2","QIconEngine","QGraphicsItem",
                        "QGraphicsLayoutItem","QFactoryInterface",
                        "QGraphicsLayout","QImageIOHandler","QInputContext",
                        "QItemEditorCreatorBase","QLayoutItem","QLayout",
                        "QPaintDevice","QPixmap",)

    #  List of classes that the hand-written PySide bindings modify.
    #  Rejecting these disrupts the hand-written bindings, so we don't
    #  reject them until we can work out a way forward.
    MODIFIED_CLASSES = ("QItemSelection",)

    def __init__(self,mf=None):
        if mf is None:
            mf = modulefinder.ModuleFinder()
        self.mf = mf

    def run_script(self,pathname):
        """Examine the given script for modules to load."""
        self.mf.run_script(pathname)

    def load_file(self,pathname):
        """Examine the given file for modules to load."""
        self.mf.load_file(pathname)

    def print_typesystem(self,mod):
        """Print trimmed typesystem file to stdout.

        This method generates a trimmed typesystem file for the given PySide
        module object, based on the scripts loaded into the trimmer so far.
        It then prints the XML to stdout.
        """
        self.write_typesystem(mod,sys.stdout)

    def write_typesystem(self,mod,fp):
        """Write trimmed typesystem file to a file.

        This method generates a trimmed typesystem file for the given PySide
        module object, based on the scripts loaded into the trimmer so far.
        It then writes the XML to the given file-like object.
        """
        #  Get set of all possible method names used in the program.
        #  This covers both "object.name" and "getattr(object,'name')" which
        #  should be enough for the vast majority of programs.
        names = set(self.SPECIAL_NAMES)
        for m in self.mf.modules.itervalues():
            if m.__code__ is None:
                continue
            for name in m.__code__.co_names:
                names.add(name)
            for const in m.__code__.co_consts:
                if isinstance(const,basestring) and is_identifier(const):
                    names.add(name)
        #  Find any methods not in the above set, and reject them.
        #  Unless they're one of many many exceptions, of course.
        fp.write("<typesystem package='%s'>\n" % (mod.__name__,))
        for classnm in dir(mod):
            #  Abstract classes can't be rejected yet.
            if "abstract" in classnm.lower():
                continue
            if classnm in self.ABSTRACT_CLASSES:
                continue
            if classnm in self.MODIFIED_CLASSES:
                continue
            classobj = getattr(mod,classnm)
            #  If it's not a shiboken object, don't bother.
            if type(classobj) is not SbkObjectType:
                continue
            #  TODO: ideally, we'd reject the entire class if it's not
            #  used.  However, this requires introspecting the Qt API
            #  to determine if it might be used for return values or
            #  argument type coercion.
            for methnm in dir(classobj):
                #  Don't bother with private methods.
                if methnm.startswith("_"):
                    continue
                #  Don't reject names that the application might be using.
                #  This is very coarse-grained but it's a good start.
                if methnm in names:
                    continue
                methobj = getattr(classobj,methnm)
                #  Write out the rejection record.
                #  It might be a field or a function - the below seems like
                #  sensible heuristic to get started with.
                fp.write("    <rejection class='%s'" % (classnm,))
                if not callable(methobj) or isinstance(methobj,type):
                    fp.write(" field-name='%s'" % (methnm,))
                else:
                    fp.write(" function-name='%s'" % (methnm,))
                fp.write(" />\n")
        fp.write("</typesystem>\n")


if __name__ == "__main__":
    tst = TypeSystemTrimmer()
    mod = __import__(sys.argv[1],fromlist=["*"])
    for script in sys.argv[2:]:
        tst.run_script(script)
    tst.print_typesystem(mod)


