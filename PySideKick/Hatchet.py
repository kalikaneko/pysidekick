"""

PySideKick.Hatchet:  hack frozen PySide apps down to size
=========================================================


Hatchet is a tool for reducing the size of frozen PySide applications, by
re-building the PySide binaries to include only those classes and functions
that are actually used by the application.

In its simplest use, you give Hatchet the path to a frozen python application
and let it work its magic:

    python -m PySideKick.Hatchet /path/to/frozen/app

You might want to go for a coffee while it runs, or maybe even a pizza -- it
will take a while.  Here are the things Hatchet will do to your frozen app:

    * extract all the identifiers used throughout the application.
    * from this, calculate the set of all PySide classes and methods that the
      application might refer to.
    * download and unpack the latest PySide sources.
    * hack the PySide sources to build only those classes and methods used
      by the application.
    * configure the PySide sources with some additional tricks to reduce
      the final size of the binaries
    * build the new PySide binaries and insert them into the application.

The result can be a substantial reduction in the frozen application size.
I've seen a reduction of over 10 megabytes against a naively-compiled
PySide binary.

For finer control over the details of the binary-hacking process, you can
use and customize the "Hatchet" class.  See its docstring for more details.

"""

import sys
import os
import imp
import re
import zipfile
import tarfile
import tempfile
import tokenize
import shutil
import modulefinder
import urlparse
import urllib
import urllib2
import hashlib
import subprocess
from xml.dom import minidom
from collections import deque
from distutils import sysconfig


#  Download details for the latest PySide release.
PYSIDE_SOURCE_URL = "http://www.pyside.org/files/pyside-qt4.7+1.0.0~beta1.tar.bz2"
PYSIDE_SOURCE_MD5 = "73ab2b92c66c86bedabc72481ed00868"


#  Classes that must not be hacked out of the PySide binary.
#  These are used for various things internally.
KEEP_CLASSES = set((
    "QApplication",
    "QWidget",
    "QFlag",
    "QFlags",
    "QBuffer",
))


#  Methods that must not be hacked off of various objects.
#  Mostly this is voodoo to stop things from segfaulting.
KEEP_METHODS = {
    "*": ("metaObject",  # much breakage ensues if this is missing!
          "devType",     # rejecting this segfaults on by linux box
          "metric",      # without this fonts don't display correctly
         ),
    "QBitArray": ("setBit",),
    "QByteArray": ("insert",),
    # there's some pointer casting magic that breaks when rejecting these
    "QPixmap": ("*",),
    "QImage": ("*",),
    "QPicture": ("*",),
    "QX11Info": ("*",),
}


#  Simple regular expression for matching valid python identifiers.
_identifier_re = re.compile("^"+tokenize.Name+"$")
is_identifier = _identifier_re.match


class Hatchet(object):
    """Class for hacking unused code out of the PySide binaries."""

    def __init__(self,appdir,mf=None,tdb=None):
        self.appdir = appdir
        if mf is None:
            mf = modulefinder.ModuleFinder()
        self.mf = mf
        if tdb is None:
            tdb = TypeDB()
        self.tdb = tdb

    def hack(self):
        """Hack away at the PySide binary for this frozen application.

        This method is the main entry-point for using the Hatchet class.
        It will examine the frozen application to find out what classes and
        methods it uses, then replace its PySide modules with new binaries
        hacked down to exclude useless code 
        """
        self.add_directory(self.appdir)
        tdir = tempfile.mkdtemp()
        try:
            sourcefile = self.fetch_pyside_source()
            sourcedir = self.unpack_tarball(sourcefile,tdir)
            self.hack_pyside_source(sourcedir)
            self.build_pyside_source(sourcedir)
            self.copy_hacked_pyside_modules(sourcedir,self.appdir)
        finally:
            shutil.rmtree(tdir)

    def add_script(self,pathname):
        """Add an additional script for the frozen application.

        This method adds the specified script to the internal modulefinder.
        It and all of its imports will be examined for pyside-related
        identifiers that must not be hacked out of the binary.
        """
        self.mf.run_script(pathname)

    def add_zipfile(self,pathname):
        """Add an additional python zipfile for the frozen application.

        This method adds the specified zipfile to the internal modulefinder.
        All of its contained python modules, along with their imports, will
        be examined for pyside-related identifiers that must not be hacked
        out of the binary.
        """
        tdir = tempfile.mkdtemp()
        if not tdir.endswith(os.path.sep):
            tdir += os.path.sep
        try:
            zf = zipfile.ZipFile(pathname,"r")
            try:
                for nm in zf.namelist():
                    dstnm = os.path.join(tdir,nm)
                    if not dstnm.startswith(tdir):
                       continue
                    if not os.path.isdir(os.path.dirname(dstnm)):
                        os.makedirs(os.path.dirname(dstnm))
                    with open(dstnm,"w") as f:
                        f.write(zf.read(nm))
            finally:
                zf.close()
            self.add_directory(tdir)
        finally:
            shutil.rmtree(tdir)

    def add_directory(self,pathname,fqname=""):
        """Add an additional python directory for the frozen application.

        This method adds the specified directory to the internal modulefinder.
        All of its contained python files, along with their imports, will be
        examined for pyside-related identifiers that must not be hacked out
        of the binary.
        """
        for nm in os.listdir(pathname):
            subpath = os.path.join(pathname,nm)
            if os.path.isdir(subpath):
                for ininm in ("__init__.py","__init__.pyc",):
                    inipath = os.path.join(subpath,ininm)
                    if os.path.exists(inipath):
                        self.mf.load_package(fqname + nm,subpath)
                        self.add_directory(subpath,fqname + nm + ".")
                        break
                else:
                    self.add_directory(subpath)
            else:
                if nm.endswith(".py"):
                    self._add_py_file(subpath,fqname)
                elif nm.endswith(".pyc"):
                    self._add_pyc_file(subpath,fqname)
                elif nm.endswith(".zip"):
                    self.add_zipfile(subpath)

    def _add_py_file(self,pathname,pkgname):
        """Add an additional python source file for the frozen application.

        This internal method adds the specified *.py file to the modulefinder.
        It and all of its imports will be examined for pyside-related
        identifiers that must not be hacked out of the binary.
        """
        nm = os.path.basename(pathname)
        base,ext = os.path.splitext(nm)
        fp = open(pathname,"rt")
        stuff = (ext, "r", imp.PY_SOURCE,)
        self.mf.load_module(pkgname + base,fp,pathname,stuff)

    def _add_pyc_file(self,pathname,pkgname):
        """Add an additional python bytecode file for the frozen application.

        This internal method adds the specified *.pyc file to the modulefinder.
        It and all of its imports will be examined for pyside-related
        identifiers that must not be hacked out of the binary.
        """
        nm = os.path.basename(pathname)
        base,ext = os.path.splitext(nm)
        fp = open(pathname,"rb")
        stuff = (ext, "r", imp.PY_COMPILED,)
        self.mf.load_module(pkgname + base,fp,pathname,stuff)

    def find_rejections(self):
        """Find classes and methods that can be rejected from PySide.

        This method examines the code in use by the application, and finds
        useless classes and methods that can be hacked out of the Pyside
        binary.  It generates tuples of the form ("ClassName",) for useless
        classes, and the form ("ClassName","methodName",) for useless methods
        on otherwise useful classes.
        """
        #  Find all python identifiers used in the application.
        #  It's a wide net, it's easier than type inference! ;-)
        used_ids = set()
        for m in self.mf.modules.itervalues():
            if m.__code__ is not None:
                self.find_identifiers_in_code(m.__code__,used_ids)
        #  Begin from the set of all classes used directly in the code,
        #  and all of their base classes.
        useful_classes = set()
        for classnm in self.tdb.iterclasses():
            if classnm in used_ids:
                for sclassnm in self.tdb.superclasses(classnm):
                    if sclassnm not in useful_classes:
                        print "USEFUL CLASS", repr(sclassnm)
                        useful_classes.add(sclassnm)
        #  Now iteratively expand that set with possible return types of any
        #  methods called on the useful classes.
        todo_classes = deque(useful_classes)
        while todo_classes:
            classnm = todo_classes.popleft()
            print "CHECKING", classnm, "[", len(todo_classes), "more to do ]"
            kept_methods = set(self.find_kept_methods(classnm))
            for methnm in self.tdb.itermethods(classnm):
                if methnm in used_ids or methnm in kept_methods:
                    print "CHECKING", classnm, methnm
                    for rtype in self.tdb.relatedtypes(classnm,methnm):
                        for sclassnm in self.tdb.superclasses(rtype):
                            if sclassnm not in useful_classes:
                                print "USEFUL CLASS", repr(sclassnm)
                                useful_classes.add(sclassnm)
                                todo_classes.append(sclassnm)
        #  Now we can reject any class that's not useful, and any method
        #  on a useful class that is not used in the code.
        for classnm in self.tdb.iterclasses():
            if classnm not in useful_classes and classnm not in KEEP_CLASSES:
                yield (classnm,)
            elif "*" not in KEEP_METHODS.get(classnm,()):
                kept_methods = set(self.find_kept_methods(classnm))
                for methnm in self.tdb.itermethods(classnm):
                    if methnm in used_ids:
                        continue
                    if methnm in kept_methods:
                        continue
                    yield (classnm,methnm,)

    def find_kept_methods(self,classnm):
        """Find all methods that must be kept for the given class."""
        for methnm in self.tdb.itermethods(classnm):
            if methnm in KEEP_METHODS.get(classnm,()):
                yield methnm
            if methnm in KEEP_METHODS.get("*",()):
                yield methnm
            if methnm == classnm:
                yield methnm
            #  Shiboken doesn't like it when we reject methods
            #  that have a pure virtual override somewhere in the
            #  inheritence chain.  This should probably be fixed
            #  in shiboken, but we work around it for now.
            #  TODO: is this just superstition on my part?
            for sclassnm in self.tdb.superclasses(classnm):
                if self.tdb.ispurevirtual(sclassnm,methnm):
                    yield methnm
                    break

    def find_identifiers_in_code(self,code,ids=None):
        """Find any possible identifiers used by the given code.

        This method performs a simplistic search for the identifiers used in
        the given code object.  It will detect attribute accesses and the use
        of getattr with a constant string, but can't do anything fancy about
        names created at runtime.  It will also find plenty of false positives.

        The set of all identifiers used in the code is returned.  If the
        argument 'ids' is not None, it is taken to be the set that is being
        built (mostly this is for easy recursive walking of code objects).
        """
        if ids is None:
            ids = set()
        for name in code.co_names:
            ids.add(name)
        for const in code.co_consts:
            if isinstance(const,basestring) and is_identifier(const):
                ids.add(const)
            elif isinstance(const,type(code)):
                self.find_identifiers_in_code(const,ids)
        return ids

    def fetch_pyside_source(self):
        """Fetch the sources for latest pyside version.

        This method fetches the sources for the latest pyside version.
        If the environment variable PYSIDEKICK_DOWNLOAD_CACHE is set then
        we first look there for a cached version.  PIP_DOWNLOAD_CACHE is
        used as a fallback location.
        """
        cachedir = os.environ.get("PYSIDEKICK_DOWNLOAD_CACHE",None)
        if cachedir is None:
            cachedir = os.environ.get("PIP_DOWNLOAD_CACHE",None)
        if cachedir is not None:
            if not os.path.isdir(cachedir):
                os.makedirs(cachedir)
        nm = os.path.basename(urlparse.urlparse(PYSIDE_SOURCE_URL).path)
        cachefile = os.path.join(cachedir,nm)
        #  Use cached version is it has correct md5.
        if os.path.exists(cachefile):
            md5 = hashlib.md5()
            with open(cachefile,"r") as f:
                data = f.read(1024*32)
                while data:
                    md5.update(data)
                    data = f.read(1024*32)
            if md5.hexdigest() != PYSIDE_SOURCE_MD5:
                print >>sys.stderr, "BAD MD5 FOR",cachefile
                print >>sys.stderr, md5.hexdigest(),"!=",PYSIDE_SOURCE_MD5
                os.unlink(cachefile)
        #  Download if we can't use the cached version
        if not os.path.exists(cachefile):
            print >>sys.stderr, "DOWNLOADING",PYSIDE_SOURCE_URL
            fIn = urllib2.urlopen(PYSIDE_SOURCE_URL)
            try:
                 with open(cachefile,"wb") as fOut:
                    shutil.copyfileobj(fIn,fOut)
            finally:
                fIn.close()
            md5 = hashlib.md5()
            with open(cachefile,"r") as f:
                data = f.read(1024*32)
                while data:
                    md5.update(data)
                    data = f.read(1024*32)
            if md5.hexdigest() != PYSIDE_SOURCE_MD5:
                print >>sys.stderr, "BAD MD5 FOR",cachefile
                print >>sys.stderr, md5.hexdigest(),"!=",PYSIDE_SOURCE_MD5
                raise RuntimeError("corrupted download: %s" % (url,))
        return cachefile

    def unpack_tarball(self,sourcefile,destdir):
        """Unpack the given tarball into the given directory.

        This method unpacks the given tarball file into the given directory.
        It returns the path to the "root" directory of the tarball, i.e. the
        first directory that contains an actual file.  This is usually the
        directory you want for e.g. building a source distribution.
        """
        tf = tarfile.open(sourcefile,"r:*")
        if not destdir.endswith(os.path.sep):
            destdir += os.path.sep
        try:
            for nm in tf.getnames():
                destpath = os.path.abspath(os.path.join(destdir,nm))
                #  Since we've checked the MD5 we should be safe from
                #  malicious filenames, but you can't be too careful...
                if not destpath.startswith(destdir):
                    raise RuntimeError("tarball contains malicious paths!")
            tf.extractall(destdir)
        finally:
            tf.close()
        rootdir = destdir
        names = os.listdir(rootdir)
        while len(names) == 1:
            rootdir = os.path.join(rootdir,names[0])
            names = os.listdir(rootdir)
        return rootdir
 
    def hack_pyside_source(self,sourcedir):
        """Hack useless code out of the given PySide source directory.

        This is where the fun happens!  We generate a list of classes and
        methods to reject from the build, and modify the PySide source dir
        to make it happen.  This involves two steps:

            * adding <rejection> elements to the typesystem files
            * removing <class>_wrapper.cpp entries from the makefiles

        """
        #  Find all rejections and store them for quick reference.
        reject_classes = set()
        reject_methods = {}
        num_rejected_methods = 0
        for rej in self.find_rejections():
            print "REJECT", rej
            if len(rej) == 1:
               reject_classes.add(rej[0])
            else:
               num_rejected_methods += 1
               reject_methods.setdefault(rej[0],set()).add(rej[1])
        print "rejecting %s classes, %d methods" % (len(reject_classes),num_rejected_methods,)
        #  Find each top-level module directory and patch the contained files.
        psdir = os.path.join(sourcedir,"PySide")
        moddirs = []
        for modnm in os.listdir(psdir):
            if not modnm.startswith("Qt"):
                continue
            moddir = os.path.join(psdir,modnm)
            if os.path.isdir(moddir):
                #  Add <rejection> records for each class and method.
                #  Also strip any modifications to rejected functions.
                def adjust_typesystem_file(dom):
                    tsnode = None
                    for c in dom.childNodes:
                        if c.nodeType != c.ELEMENT_NODE:
                            continue
                        if c.tagName == "typesystem":
                            tsnode = c
                            break
                    else:
                        return dom
                    #  Adjust the existings decls to meet our needs
                    TYPE_TAGS = ("enum-type","value-type","object-type",)
                    for cn in list(tsnode.childNodes):
                        if cn.nodeType != c.ELEMENT_NODE:
                            continue
                        if cn.tagName in TYPE_TAGS:
                            #  Remove delcaration of any rejected classes.
                            clsnm = cn.getAttribute("name")
                            if clsnm in reject_classes:
                                tsnode.removeChild(cn)
                                continue
                            #  Remove any modifications for rejected methods
                            if clsnm not in reject_methods:
                                continue
                            FUNC_TAGS = ("modify-function","add-function",)
                            for mfn in list(cn.childNodes):
                                if mfn.nodeType != c.ELEMENT_NODE:
                                    continue
                                if mfn.tagName in FUNC_TAGS:
                                    sig = mfn.getAttribute("signature")
                                    fnm = sig.split("(")[0]
                                    if fnm in reject_methods[clsnm]:
                                        cn.removeChild(mfn)
                    #  Add explicit rejection records.
                    for cls in reject_classes:
                        rn = dom.createElement("rejection")
                        rn.setAttribute("class",cls)
                        tsnode.appendChild(rn)
                        nl = dom.createTextNode("\n")
                        tsnode.appendChild(nl)
                    for (cls,nms) in reject_methods.iteritems():
                        for nm in nms:
                            rn = dom.createElement("rejection")
                            rn.setAttribute("class",cls)
                            rn.setAttribute("function-name",nm)
                            tsnode.appendChild(rn)
                            rn = dom.createElement("rejection")
                            rn.setAttribute("class",cls)
                            rn.setAttribute("field-name",nm)
                            tsnode.appendChild(rn)
                            nl = dom.createTextNode("\n")
                            tsnode.appendChild(nl)
                    return dom
                for (dirnm,_,filenms) in os.walk(moddir):
                    for filenm in filenms:
                        if filenm.startswith("typesystem_") and "xml" in filenm:
                            tsfile = os.path.join(dirnm,filenm)
                            self.patch_xml_file(adjust_typesystem_file,tsfile)
                #  Remove rejected classes from the build deps list
                remaining_sources = []
                def dont_build_class(lines):
                    for ln in lines:
                        for rejcls in reject_classes:
                            if rejcls.lower()+"_" in ln:
                                if "wrapper.cpp" in ln:
                                    if "_module_wrapper.cpp" not in ln:
                                        break
                            if rejcls in ln and "check_qt_class" in ln:
                                break
                        else:
                            if "wrapper.cpp" in ln:
                                remaining_sources.append(ln)
                            yield ln
                self.patch_file(dont_build_class,moddir,"CMakeLists.txt")
                #  If there aren't any sources left to build in that module,
                #  remove it from the main PySide build file.
                if len(remaining_sources) < 2:
                    def dont_build_module(lines):
                        for ln in lines:
                            if modnm not in ln:
                                yield ln
                    print "NOT BUILDING MODULE", modnm
                    self.patch_file(dont_build_module,psdir,"CMakeLists.txt")

    def patch_file(self,patchfunc,*paths):
        """Patch the given file by applying a line-filtering function.

        This method allows easy patching of a build file by applying a
        python function.

        The specified "pathfunc" must be a line filtering function - it takes
        as input the sequence of lines from the file, and outputs a modified
        sequence of lines.
        """
        filepath = os.path.join(*paths)
        print "PATCHING", filepath
        mod = os.stat(filepath).st_mode
        (fd,tf) = tempfile.mkstemp()
        try:
            os.close(fd)
            with open(tf,"wt") as fOut:
                with open(filepath,"rt") as fIn:
                    for ln in patchfunc(fIn):
                        fOut.write(ln)
                fOut.flush()
            os.chmod(tf,mod)
            if sys.platform == "win32":
                os.unlink(filepath)
        except:
            os.unlink(tf)
            raise
        else:
            os.rename(tf,filepath)

    def patch_xml_file(self,patchfunc,*paths):
        """Patch the given file by applying an xml-filtering function.

        This method allows easy patching of a build file by applying a
        python function.

        The specified "pathfunc" must be an xml filtering function - it takes
        as input a DOM object and returns a modified DOM.
        """
        filepath = os.path.join(*paths)
        print "PATCHING", filepath
        mod = os.stat(filepath).st_mode
        with open(filepath,"rt") as fIn:
            xml = minidom.parse(fIn)
        xml = patchfunc(xml)
        (fd,tf) = tempfile.mkstemp()
        try:
            os.close(fd)
            xmlstr = xml.toxml().encode("utf8")
            with open(tf,"wt") as fOut:
                fOut.write(xmlstr)
                fOut.flush()
            os.chmod(tf,mod)
            if sys.platform == "win32":
                os.unlink(filepath)
        except:
            os.unlink(tf)
            raise
        else:
            os.rename(tf,filepath)

    def build_pyside_source(self,sourcedir):
        """Build the PySide sources in the given directory.

        This is a simple wrapper around PySide's `cmake; make;` build process.
        For it to work, you must have the necessary tools installed on your
        system (e.g. cmake, shiboken)
        """
        olddir = os.getcwd()
        os.chdir(sourcedir)
        try:
            #  Here we have some more tricks for getting smaller binaries:
            #     * CMAKE_BUILD_TYPE=MinSizeRel, to enable -Os
            #     * -fno-exceptions, to skip generation of stack-handling code
            #  We also try to use compiler options from python so that the
            #  libs will match as closely as possible.
            env = os.environ.copy()
            env.setdefault("CC",sysconfig.get_config_var("CC"))
            env.setdefault("CXX",sysconfig.get_config_var("CXX"))
            cxxflags = sysconfig.get_config_var("CFLAGS")
            cxxflags += " " + env.get("CXXFLAGS","")
            cxxflags += " -fno-exceptions"
            env["CXXFLAGS"] = cxxflags
            subprocess.check_call((
                "cmake",
                "-DCMAKE_BUILD_TYPE=MinSizeRel",
                "-DCMAKE_VERBOSE_MAKEFILE=ON",
                "-DBUILD_TESTS=False",
                "-DPYTHON_EXECUTABLE="+sys.executable,
                "-DPYTHON_INCLUDE_DIR="+sysconfig.get_python_inc()
            ),env=env)
            subprocess.check_call((
                "make",
            ),env=env)
        finally:
            os.chdir(olddir)

    def copy_hacked_pyside_modules(self,sourcedir,destdir):
        """Copy PySide modules from build dir back into the frozen app."""
        #  Find all the build modules we're able to copy over
        psdir = os.path.join(sourcedir,"PySide")
        modules = []
        for modnm in os.listdir(psdir):
            if modnm.startswith("Qt"):
                if modnm.endswith(".so") or modnm.endswith(".pyd"):
                    modules.append(modnm)
        #  Search for similarly-named files in the destdir and replace them
        for (dirnm,_,filenms) in os.walk(destdir):
            for filenm in filenms:
                filepath = os.path.join(dirnm,filenm)
                if not filenm.endswith(".so") and not filenm.endswith(".pyd"):
                    continue
                if "PySide" not in filepath:
                    continue
                for modnm in modules:
                    if filepath.endswith(modnm):
                        newfilepath = os.path.join(psdir,modnm)
                        self.copy_linker_paths(filepath,newfilepath)
                        print "REPLACING", filepath, "WITH", modnm
                        os.unlink(filepath)
                        shutil.copy2(newfilepath,filepath)

    if sys.platform == "darwin":
        def copy_linker_paths(self,srcfile,dstfile):
            srclinks = _bt("otool","-L",srcfile).strip().split("\n")
            dstlinks = _bt("otool","-L",dstfile).strip().split("\n")
            for dstlink in dstlinks:
                if "compatibility version" not in dstlink:
                    continue
                dstlibpath = dstlink.strip().split()[0]
                dstlibname = os.path.basename(dstlibpath)
                for srclink in srclinks:
                    if "compatibility version" not in srclink:
                        continue
                    srclibpath = srclink.strip().split()[0]
                    srclibname = os.path.basename(srclibpath)
                    if srclibname == dstlibname:
                        _do("install_name_tool","-change",
                            dstlibpath,srclibpath,dstfile)
                        break
    elif "linux" in sys.platform:
        def copy_linker_paths(self,srcfile,dstfile):
            rpath = None
            for ln in _bt("readelf","-d",srcfile):
                if "RPATH" in ln and "Library rpath:" in ln:
                    rpath = ln.rsplit("[",1).split("]",0)
                    break
            if rpath is not None:
                do("patchelf","--set-rpath",rpath,dstfile)
    else:
        def copy_linker_paths(self,srcfile,dstfile):
            pass



def _do(*cmdline):
    subprocess.check_call(cmdline)


def _bt(*cmdline):
    """Execute the command, returning stdout.

    "bt" is short for "backticks"; hopefully its use is obvious to shell
    scripters and the like.
    """
    p = subprocess.Popen(cmdline,stdout=subprocess.PIPE)
    output = p.stdout.read()
    retcode = p.wait()
    if retcode != 0:
        raise subprocess.CalledProcessError(retcode,cmdline)
    return output


class TypeDB(object):
    """PySide type database.

    A TypeDB instance encapsulates some basic information about the PySide API
    and can be used to query e.g. what classes are available or what methods
    are on a class.

    The current implementation gets this information in what might seem like
    a very silly way - it pokes around in the online API documentation.  This
    has the advantage of being very quick to code up, and not requiring any
    external dependencies.

    If PySide starts shipping with bindings for apiextractor, I'll write a
    new version of this class to use those instead.

    Besides, parsing data out of the API docs isn't as fragile as it might
    sound.  The docs are themselves generated by parsing the source code, so
    they have more than enough internal structure to support simple queries.
    """

    RE_CLASS_LINK=re.compile(r"<a href=\"(\w+).html\">(\w+)</a>")
    RE_METHOD_LINK=re.compile(r"<a href=\"(\w+).html\#([\w\-\.]+)\">(\w+)</a>")

    def __init__(self,root_url="http://doc.qt.nokia.com/4.7/"):
        if not root_url.endswith("/"):
            root_url += "/"
        self.root_url = root_url

    _url_cache = {}
    def _read_url(self,url):
        """Read the given URL, possibly using cached version."""
        url = urlparse.urljoin(self.root_url,url)
        try:
            return self._url_cache[url]
        except KeyError:
            pass
        cachedir = os.environ.get("PYSIDEKICK_DOWNLOAD_CACHE",None)
        if cachedir is None:
            cachedir = os.environ.get("PIP_DOWNLOAD_CACHE",None)
        if cachedir is None:
            cachefile = None
        else:
            cachedir = os.path.join(cachedir,"QtDocTypeDB")
            if not os.path.isdir(cachedir):
                os.makedirs(cachedir)
            cachefile = os.path.join(cachedir,urllib.quote(url,""))
            missingcachefile = os.path.join(cachedir,
                                            "missing-"+urllib.quote(url,""))
        if cachefile is not None:
            try:
                with open(cachefile,"rb") as f:
                    self._url_cache[url] = f.read()
                    return self._url_cache[url]
            except EnvironmentError:
                if os.path.exists(missingcachefile):
                    msg = "not found: " + url
                    raise urllib2.HTTPError(url,"404",msg,{},None)
        f = None
        try:
            f = urllib2.urlopen(url)
            data = f.read()
        except urllib2.HTTPError, e:
            if "404" in str(e) and cachefile is not None:
                open(missingcachefile,"w").close()
            raise
        finally:
            if f is not None:
                f.close()
        if cachefile is not None:
            with open(cachefile,"wb") as f:
               f.write(data)
        self._url_cache[url] = data
        return data

    def _get_linked_classes(self,data):
        """Extract all class names linked to from the given HTML data."""
        for match in self.RE_CLASS_LINK.finditer(data):
            if match.group(1) == match.group(2).lower():
                yield match.group(2)

    def _get_linked_methods(self,data):
        """Extract all method names linked to from the given HTML data."""
        for match in self.RE_METHOD_LINK.finditer(data):
            if match.group(3) in match.group(2):
                yield match.group(3)

    def _canonical_class_names(self,classnm):
        """Get all canonical class names implied by the given identifier.

        This is a simple trick to decode common typedefs (e.g. QObjectList)
        into their respective concrete classes (e.g. QObject and QList).
        """
        if self.isclass(classnm):
            yield classnm
        else:
            if classnm == "T":
                #  This appears as a generic template type variable
                pass
            elif classnm.endswith("List"):
                #  These are usually typedefs for a QList<T>
                yield classnm[:-4]
                yield "QList"

    def iterclasses(self):
        """Iterator over all available class names."""
        #  These classes seem to be missing from the online docs.
        #  They are in the docs on the PySide website, I should probably
        #  move to parsing those instead.
        yield "QTextStreamManipulator"
        yield "QScriptExtensionInterface"
        #  Everything else is conventienly listed on the "classes" page.
        classlist = self._read_url("classes.html")
        for ln in classlist.split("\n"):
            ln = ln.strip()
            if ln.startswith("<dd>"):
                for classnm in self._get_linked_classes(ln):
                    yield classnm
                    break

    def isclass(self,classnm):
        """Check whether the given name is indeed a class."""
        if classnm == "QTextStreamManipulator":
            return True
        if classnm == "QScriptExtensionInterface":
            return True
        try:
            self._read_url(classnm.lower()+"-members.html")
        except urllib2.HTTPError, e:
            if "404" not in str(e):
                raise
            return False
        else:
            return True

    def superclasses(self,classnm):
        """Get all superclasses for a given class."""
        yield classnm
        docstr = self._read_url(classnm.lower()+".html")
        for ln in docstr.split("\n"):
            ln = ln.strip()
            if "Inherits" in ln:
                for supcls in self._get_linked_classes(ln):
                    for cname in self._canonical_class_names(supcls):
                        for supsupcls in self.superclasses(cname):
                            yield supsupcls

    def subclasses(self,classnm):
        """Get all subclasses for a given class."""
        yield classnm
        docstr = self._read_url(classnm.lower()+".html")
        for ln in docstr.split("\n"):
            ln = ln.strip()
            if "Inherited by" in ln:
                for subcls in self._get_linked_classes(ln):
                    for cname in self._canonical_class_names(subcls):
                        yield cname
                        for subsubcls in self.subclasses(cname):
                            yield subsubcls

    def itermethods(self,classnm):
        """Iterator over all methods on a given class."""
        #  These methods are missing from the online docs.
        if classnm == "QAbstractItemModel":
            yield "decodeData"
            yield "encodeData"
        if classnm == "QScriptExtensionInterface":
            yield "initialize"
            return
        docstr = self._read_url(classnm.lower()+"-members.html")
        for ln in docstr.split("\n"):
            ln = ln.strip()
            if ln.startswith("<li class=\"fn\">"):
                for methnm in self._get_linked_methods(ln):
                    yield methnm

    def relatedtypes(self,classnm,methnm):
        """Get all possible return types for a method.

        Given a classname and methodname, this method returns the set of all
        class names that are "related to" the specified method.  Basically,
        these are the classes that can be passed to the method as arguments
        or returned as values.
        """
        if classnm == "QAbstractItemModel":
            if methnm in ("decodeData","encodeData",):
                yield "QModelIndexList"
                yield "QDataStream"
            return
        if classnm == "QScriptExtensionInterface":
            if methnm in ("initialize",):
                yield "QScriptEngine"
            return
        docstr = self._read_url(classnm.lower()+"-members.html")
        for ln in docstr.split("\n"):
            ln = ln.strip()
            if ln.startswith("<li class=\"fn\">"):
                if ">"+methnm+"<" not in ln:
                    continue
                methsig = ln.rsplit("</b>",1)[-1][:-5]
                #  The method signature can contain plently of C++
                #  junk, e.g. template instatiations and inner classes.
                #  We try our best to split them up into individual names.
                for word in methsig.split():
                   if word.endswith(","):
                       word = word[:-1]
                   word = word.split("::")[0]
                   if word.isalnum() and word[0].isupper():
                       for cname in self._canonical_class_names(word):
                           yield cname

    def ispurevirtual(self,classnm,methnm):
        """Check whether a given method is a pure virtual method."""
        #  Pure virtual methods have a "= 0" at the end of their signature.
        docstr = self._read_url(classnm.lower()+".html")
        for ln in docstr.split("\n"):
            ln = ln.strip()
            if ln.startswith("<tr><td class=\"memItemLeft "):
                if ">"+methnm+"<" not in ln:
                    continue
                if "= 0</td>" in ln:
                    return True
        return False



def hack(appdir):
    """Convenience function for hacking a frozen PySide app down to size.

    This function is a simple convenience wrapper that creates a Hatchet
    instance and calls its main "hack" method.
    """
    h = Hatchet(appdir)
    h.hack()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print >>sys.stderr, "usage:  Hatchet /path/to/frozen/app"    
        sys.exit(1)
    if not os.path.isdir(sys.argv[1]):
        print >>sys.stderr, "error: not a directory:", sys.argv[1]   
        sys.exit(1)
    hack(sys.argv[1])


