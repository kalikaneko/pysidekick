
import os
import re
import urllib
import urllib2
from urlparse import urljoin

RE_BASIC_TAG = re.compile(r"<[^>]+>")
RE_CLASS_LINK = re.compile(r"<a href=\"(\w+).html\">(\w+)</a>")
RE_METHOD_LINK = re.compile(r"<a href=\"(\w+).html\#([\w\-\.]+)\">(\w+)</a>")


class TypeDB(object):
    """PySide type database.

    This class encapsulates some basic information about the PySide/Qt API.
    An instance of this class is used by the Hatchet object when deciding
    what classes and methods it can hack out of the binary.
    """

    def iterclasses(self):
        """Iterator over all class names."""
        raise NotImplementedError

    def superclasses(self,classnm):
        """Get all superclasses for a given class."""
        raise NotImplementedError

    def subclasses(self,classnm):
        """Get all subclasses for a given class."""
        raise NotImplementedError

    def itermethods(self,classnm):
        """Iterator over all methods on a given class."""
        raise NotImplementedError

    def relatedtypes(self,classnm,methnm):
        """Get all possible types used by this method."""
        raise NotImplementedError

    def ispurevirtual(self,classnm,methnm):
        """Check whether a given method is a pure virtual method."""
        raise NotImplementedError


class QtDocTypeDB(TypeDB):
    """TypeDB implementation parsing info from the online Qt docs.

    This is quite possibly the silliest way to get API information - scraping
    through the docs on a remote website.  The advantage is that it's easy
    to get up and running.

    Eventually I'd like to replace this with a python interface to the
    apiextractor library, but it's good enough for now.
    """

    def __init__(self,root_url="http://doc.qt.nokia.com/4.7/"):
        if not root_url.endswith("/"):
            root_url += "/"
        self.root_url = root_url

    _url_cache = {}
    def _read_url(self,url):
        """Read the given URL, possibly using cached version."""
        url = urljoin(self.root_url,url)
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

    def _split_by_html(self,data):
        """Split the given text by HTML tags, to give just the contents."""
        return RE_BASIC_TAG.split(data)

    def _get_linked_classes(self,data):
        """Extract all class names linked to from the given HTML data."""
        for match in RE_CLASS_LINK.finditer(data):
            if match.group(1) == match.group(2).lower():
                yield match.group(2)

    def _get_linked_methods(self,data):
        """Extract all class names linked to from the given HTML data."""
        for match in RE_METHOD_LINK.finditer(data):
            if match.group(3) in match.group(2):
                yield match.group(3)

    def _canonical_class_names(self,classnm):
        if self.isclass(classnm):
            yield classnm
        else:
            if classnm == "T":
                pass
            elif classnm.endswith("List"):
                yield classnm[:-4]
                yield "QList"

    def iterclasses(self):
        """Iterator over all class names."""
        yield "QTextStreamManipulator"
        yield "QScriptExtensionInterface"
        classlist = self._read_url("classes.html")
        for ln in classlist.split("\n"):
            ln = ln.strip()
            if ln.startswith("<dd>"):
                for classnm in self._get_linked_classes(ln):
                    yield classnm
                    break

    def isclass(self,classnm):
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
        """Get all possible return types for a method."""
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
                for word in methsig.split():
                   if word.endswith(","):
                       word = word[:-1]
                   word = word.split("::")[0]
                   if word.isalnum() and word[0].isupper():
                       for cname in self._canonical_class_names(word):
                           yield cname

    def ispurevirtual(self,classnm,methnm):
        """Check whether a given method is a pure virtual method."""
        docstr = self._read_url(classnm.lower()+".html")
        for ln in docstr.split("\n"):
            ln = ln.strip()
            if ln.startswith("<tr><td class=\"memItemLeft "):
                if ">"+methnm+"<" not in ln:
                    continue
                if "= 0</td>" in ln:
                    return True
        return False


