implement Httpd;

include "sys.m";
include "draw.m";
include "arg.m";
include "bufio.m";
	bufio: Bufio;
	Iobuf: import bufio;
include "daytime.m";
include "env.m";
include "string.m";
include "exception.m";
include "keyring.m";
include "security.m";
include "encoding.m";
include "sh.m";
include "mhttp.m";

sys: Sys;
daytime: Daytime;
env: Env;
exc: Exception;
keyring: Keyring;
random: Random;
str: String;
base64: Encoding;
sh: Sh;
http: Http;

print, sprint, fprint, fildes: import sys;
Url, Req, Resp, Hdrs, HTTP_10, HTTP_11, encodepath: import http;
OPTIONS, GET, HEAD, POST, PUT, DELETE, TRACE, CONNECT: import http;
prefix: import str;


Op: adt {
	id, now:	int;
	keepalive:	int;
	chunked:	int;
	length:		big;
	fd:	ref Sys->FD;
	rhost, rport, lhost, lport:	string;
	req:	ref Req;
	resp:	ref Resp;
};

cgitimeoutsecs: con 3*60;

dflag, hflag, lflag: int;
cachesecs := 0;
addr := "net!localhost!8000";
webroot := "";
environment: list of (string, string);
indexfiles: list of string;
redirs: list of (string, string);
auths: list of (string, string, string);
credempty: string;

Httpd: module {
	init:	fn(nil: ref Draw->Context, args: list of string);
};

types := array[] of {
	(".pdf",	"application/pdf"),
	(".html",	"text/html; charset=utf-8"),
	(".htm",	"text/html; charset=utf-8"),
	(".txt",	"text/plain; charset=utf-8"),
	(".diff",	"text/plain; charset=utf-8"),
	(".patch",	"text/plain; charset=utf-8"),
	(".ps",		"application/postscript"),
	(".torrent",	"application/x-bittorrent"),
	(".dvi",	"application/x-dvi"),
	(".tar.gz",	"application/x-tgz"),
	(".tgz",	"application/x-tgz"),
	(".gz",		"application/x-gzip"),
	(".tar",	"application/x-tar"),
	(".mp3",	"audio/mpeg"),
	(".ogg",	"application/ogg"),
	(".jpg",	"image/jpeg"),
	(".gif",	"image/gif"),
	(".png",	"image/png"),
	(".css",	"text/css"),
	(".js",		"text/javascript; charset=utf-8"),
	(".c",		"text/plain; charset=utf-8"),
	(".b",		"text/plain; charset=utf-8"),
	(".h",		"text/plain; charset=utf-8"),
	(".sh",		"text/plain; charset=utf-8"),
	(".orig",	"text/plain; charset=utf-8"),
	(".conf",	"text/plain; charset=utf-8"),
	(".avi",	"video/x-msvideo"),
	(".bz2",	"application/x-bzip"),
	(".tex",	"text/plain; charset=utf-8"),
	(".mp4",	"video/mp4"),
	(".mpg",	"video/mpeg"),
};

Eok:			con 200;
Emovedpermanently:	con 301;
Enotmodified:		con 304;
Ebadrequest:		con 400;
Eunauthorized:		con 401;
Enotfound:		con 404;
Emethodnotallowed:	con 405;
Elengthrequired:	con 411;
Epreconditionfailed:	con 412;
Ebadmediatype:		con 415;
Enotsatisfiable:	con 416;
Eexpectationfailed:	con 417;
Eservererror:		con 500;
Enotimplemented:	con 501;
Ebadversion:		con 505;

statusmsgs := array[] of {
	(100,		"Continue"),
	(200,		"OK"),
	(206,		"Partial Content"),
	(301,		"Moved Permanently"),
	(304,		"Not Modified"),
	(400,		"Bad Request"),
	(401,		"Unauthorized"),
	(403,		"Forbidden"),
	(404,		"Object Not Found"),
	(405,		"Method Not Allowed"),
	(411,		"Length Required"),
	(412,		"Precondition Failed"),
	(415,		"Unsupported Media Type"),
	(416,		"Requested Range Not Satisfiable"),
	(417,		"Expectation Failed"),
	(500,		"Internal Server Error"),
	(501,		"Not Implemented"),
	(505,		"HTTP Version Not Supported"),
};

# relevant known request headers whose values are not allowed to be concatenated (not a full bnf #-rule)
nomergeheaders := array[] of {
	# these two would be useful to merge.  alas, it is not allowed by rfc2616, section 4.2, last paragraph
	"if-match",
	"if-none-match",

	"authorization",
	"content-length",
	"content-type",
	"host",
	"if-modified-since",
	"if-range",
	"if-unmodified-since",
	"range",
};

idch: chan of int;
randch: chan of int;
killch: chan of int;
killschedch: chan of (int, int, chan of int);
excch: chan of (int, chan of string);

timefd: ref Sys->FD;
errorfd: ref Sys->FD;
accessfd: ref Sys->FD;

Cgi, Scgi: con iota;
cgitypes := array[] of {"cgi", "scgi"};
cgipaths: list of (string, string, int);

cgispawnch: chan of (string, string, string, ref Req, ref Op, big, chan of (ref Sys->FD, ref Sys->FD, string));
scgidialch: chan of (string, chan of (ref Sys->FD, string));

init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	arg := load Arg Arg->PATH;
	bufio = load Bufio Bufio->PATH;
	env = load Env Env->PATH;
	daytime = load Daytime Daytime->PATH;
	keyring = load Keyring Keyring->PATH;
	exc = load Exception Exception->PATH;
	random = load Random Random->PATH;
	str = load String String->PATH;
	base64 = load Encoding Encoding->BASE64PATH;
	sh = load Sh Sh->PATH;
	http = load Http Http->PATH;
	http->init(bufio);

	arg->init(args);
	arg->setusage(arg->progname()+" [-dhl] [-A path realm user:pass] [-C cachesecs] [-a addr] [-c path command] [-i indexfile] [-r orig new] [-s path addr] [-t extention mimetype] webroot");
	while((c := arg->opt()) != 0)
		case c {
		'A' =>	auths = (arg->earg(), arg->earg(), base64->enc(array of byte arg->earg()))::auths;
		'C' =>	cachesecs = int arg->earg();
		'a' =>	addr = arg->earg();
		'c' =>	cgipaths = (arg->earg(), arg->earg(), Cgi)::cgipaths;
		'd' =>	dflag++;
		'h' =>	hflag++;
		'i' =>	indexfiles = arg->earg()::indexfiles;
		'l' =>	lflag++;
			http->debug = 1;
		'r' =>	redirs = (arg->earg(), arg->earg())::redirs;
		's' =>	cgipaths = (arg->earg(), arg->earg(), Scgi)::cgipaths;
		't' =>	(extension, mimetype) := (arg->earg(), arg->earg());
			ntypes := array[len types+1] of (string, string);
			ntypes[0] = (extension, mimetype);
			ntypes[1:] = types;
			types = ntypes;
		* =>	arg->usage();
		}
	args = arg->argv();
	if(len args != 1)
		arg->usage();
	webroot = hd args;
	indexfiles = rev(indexfiles);
	redirs = rev2(redirs);
	auths = rev3(auths);
	credempty = base64->enc(array of byte ":");

	environment = env->getall();

	sys->pctl(Sys->FORKNS, nil);
	if(sys->chdir(webroot) != 0)
		fail(sprint("chdir webroot %s: %r", webroot));

	timefd = sys->open("/dev/time", Sys->OREAD);
	if(timefd == nil)
		fail(sprint("open /dev/time: %r"));

	errorfd = sys->open("/services/logs/httpderror", Sys->ORDWR);
	accessfd = sys->open("/services/logs/httpdaccess", Sys->ORDWR);
	if(errorfd != nil)
		sys->seek(errorfd, big 0, Sys->SEEKEND);
	if(accessfd != nil)
		sys->seek(accessfd, big 0, Sys->SEEKEND);

	idch = chan[8] of int;
	spawn idgen();
	randch = chan of int;
	spawn randgen();
	killch = chan of int;
	killschedch = chan of (int, int, chan of int);
	spawn killer();
	excch = chan of (int, chan of string);
	spawn exceptsetter();

	cgispawnch = chan of (string, string, string, ref Req, ref Op, big, chan of (ref Sys->FD, ref Sys->FD, string));
	spawn cgispawner();

	scgidialch = chan of (string, chan of (ref Sys->FD, string));
	spawn scgidialer();

	(aok, aconn) := sys->announce(addr);
	if(aok != 0)
		fail(sprint("announce %s: %r", addr));
	say("announed to "+addr);
	for(;;) {
		(lok, lconn) := sys->listen(aconn);
		if(lok != 0)
			fail(sprint("listen %s: %r", addr));
		dfd := sys->open(lconn.dir+"/data", Sys->ORDWR);
		if(dfd != nil)
			spawn httpserve(dfd, lconn.dir);
		else
			say(sprint("opening data file: %r"));
		lconn.dfd = nil;
	}
}

idgen()
{
	id := 0;
	for(;;)
		idch <-= id++;
}

randgen()
{
	for(;;)
		randch <-= random->randomint(Random->NotQuiteRandom);
}

killer()
{
	for(;;)
	alt {
	pid := <-killch =>
		kill(pid);
	(pid, timeout, respch) := <-killschedch =>
		spawn timeoutkill(pid, timeout, respch);
	}
}

timeoutkill(pid, timeout: int, respch: chan of int)
{
	respch <-= sys->pctl(0, nil);
	sys->sleep(timeout);
	kill(pid);
}

exceptsetter()
{
	for(;;) {
		(pid, respch) := <-excch;
		err: string;
		fd := sys->open(sprint("/prog/%d/ctl", pid), Sys->OWRITE);
		if(fd == nil || fprint(fd, "exceptions notifyleader") == -1)
			err = sprint("setting exception handling for pid %d: %r", pid);
		respch <-= err;
	}
}

cgispawner()
{
	for(;;) {
		(cmd, path, cgipath, req, op, length, replych) := <-cgispawnch;
		spawn cgispawn(cmd, path, cgipath, req, op, length, replych);
	}
}

cgispawn(cmd, path, cgipath: string, req: ref Req, op: ref Op, length: big, replych: chan of (ref Sys->FD, ref Sys->FD, string))
{
	fd0 := array[2] of ref Sys->FD;
	fd1 := array[2] of ref Sys->FD;
	fd2 := array[2] of ref Sys->FD;
	if(sys->pipe(fd0) != 0 || sys->pipe(fd1) != 0 || sys->pipe(fd2) != 0) {
		replych <-= (nil, nil, sprint("pipe: %r"));
		return;
	}
	spawn errlogger(fd2[0]);

	if(sys->pctl(Sys->NEWFD|Sys->FORKNS|Sys->FORKENV, fd0[1].fd::fd1[1].fd::fd2[1].fd::nil) < 0) {
		replych <-= (nil, nil, sprint("pctl newfd: %r"));
		return;
	}
	for(l := cgivars(path, cgipath, req, op, length, nil); l != nil; l = tl l)
		env->setenv((hd l).t0, (hd l).t1);

	if(sys->dup(fd0[1].fd, 0) == -1 || sys->dup(fd1[1].fd, 1) == -1 || sys->dup(fd2[1].fd, 2) == -1) {
		say(sprint("dup: %r"));
		replych <-= (nil, nil, sprint("dup: %r"));
		return;
	}
	replych <-= (fd0[0], fd1[0], nil);
	fd0 = fd1 = fd2 = nil;
	err := sh->system(nil, cmd);
	if(err != nil)
		chat(-1, sprint("cgispawn, cmd %q: %s", cmd, err));
}

errlogger(fd: ref Sys->FD)
{
	for(;;) {
		n := sys->read(fd, d := array[Sys->ATOMICIO] of byte, len d);
		if(n < 0)
			die(-1, sprint("reading stderr: %r"));
		if(n == 0)
			break;
		say(string d[:n]);
	}
}

scgidialer()
{
	for(;;) {
		(scgiaddr, replychan) := <-scgidialch;
		spawn scgidial(scgiaddr, replychan);
	}
}

scgidial(scgiaddr: string, replychan: chan of (ref Sys->FD, string))
{
	(ok, conn) := sys->dial(scgiaddr, nil);
	if(ok < 0) {
		say(sprint("dialing scgid %s: %r", scgiaddr));
		replychan <-= (nil, "dialing scgid failed");
	} else
		replychan <-= (conn.dfd, nil);
}

httpserve(fd: ref Sys->FD, conndir: string)
{
	id := <-idch;
	chat(id, "httpserve");

	(lhost, lport) := readaddr(id, conndir+"/local");
	(rhost, rport) := readaddr(id, conndir+"/remote");
	chat(id, sprint("connect from %s:%s to %s:%s", rhost, rport, lhost, lport));

	sys->pctl(Sys->NEWPGRP, nil);
	exc->setexcmode(Exception->NOTIFYLEADER);
	pid := sys->pctl(Sys->NEWNS|Sys->NODEVS, nil);

	b := bufio->fopen(fd, Bufio->OREAD);
	if(b == nil)
		die(id, sprint("bufio open: %r"));

	op := ref Op(id, 0, 0, 0, big 0, fd, rhost, rport, lhost, lport, nil, nil);

	for(nsrvs := 0; ; nsrvs++) {
		if(nsrvs > 0 && !op.keepalive)
			break;

		if(sys->chdir("/") != 0)
			break;

		op.chunked = op.keepalive = 0;
		op.length = big 0;
		httptransact(pid, b, op);
	}
}

httptransact(pid: int, b: ref Iobuf, op: ref Op)
{
	id := op.now;
	op.now = readtime();
	hdrs := Hdrs.new(("server", "nhttpd/0")::nil);

	killschedch <-= (pid, 3*60*1000, respch := chan of int);
	killpid := <-respch;

	(req, rerr) := Req.read(b);
	hdrs.add("date", httpdate(op.now));
	if(rerr != nil) {
		hdrs.add("connection", "close");
		op.resp = Resp.mk(HTTP_10, nil, nil, hdrs);
		responderrmsg(op, Ebadrequest, "Bad Request: parsing message: "+rerr);
		killch <-= killpid;
		die(id, "reading request: "+rerr);
	}
	if(req.major != 1) {
		hdrs.add("connection", "close");
		op.resp = Resp.mk(HTTP_10, nil, nil, hdrs);
		responderrmsg(op, Ebadversion, sprint("HTTP Version Not Supported: version requested is HTTP/%d.%d", req.major, req.minor));
		killch <-= killpid;
		die(id, sprint("unsupported http version, HTTP/%d.%d", req.major, req.minor));
	}
	killch <-= killpid;
	chat(id, sprint("request: method %q url %q version %q", http->methodstr(req.method), req.url.pack(), sprint("HTTP/%d.%d", req.major, req.minor)));
	op.req = req;

	# all values besides "close" are supposedly header names, not important
	(contoks, conerr) := tokenize(req.h.getlist("connection"));
	op.keepalive = req.version() >= HTTP_11 && conerr == nil && !listhas(listlower(contoks), "close");
	op.resp = resp := Resp.mk(req.version(), "200", "OK", hdrs);

	# tell client if it is sending ambiguous requests: duplicate headers of the important kind
	for(i := 0; i < len nomergeheaders; i++)
		if(len req.h.findall(nomergeheaders[i]) > 1)
			return responderrmsg(op, Ebadrequest, sprint("Bad Request: You sent duplicate headers for \"%s\"", nomergeheaders[i]));

	# we are not a proxy, this indicates a client credentials...
	if(req.h.has("proxy-authorization", nil))
		return responderrmsg(op, Ebadrequest, "Bad Request: You sent Proxy-Authorization credentials");

	if(req.version() >= HTTP_11 && !req.h.has("host", nil))
		return responderrmsg(op, Ebadrequest, "Bad Request: Missing header \"Host\".");

	case req.method {
	GET or HEAD or POST =>
		;
	TRACE =>
		hdrs.add("content-type", "message/http");
		return responderrmsg(op, Eok, req.pack());

	OPTIONS =>
		# xxx should be based on path
		hdrs.add("allow", "OPTIONS, GET, HEAD, POST, TRACE");
		hdrs.add("accept-ranges", "bytes");
		return responderrmsg(op, Eok, nil);

	PUT or DELETE =>
		# note: when implementing these, complete support for if-match and if-none-match, and much more probably
		return responderrmsg(op, Enotimplemented, "Not Implemented: PUT and DELETE are not supported");

	* =>
		return responderrmsg(op, Enotimplemented, "Unknown Method: "+http->methodstr(req.method));
	}

	path := pathsanitize(req.url.path);
	chat(id, "path is "+path);

	# we ignore the port in the host-header.  this is illegal according to rfc2616, but using it is just silly.
	# also, we violate rfc2616 by sending 404 "not found" when the host doesn't exist.
	# we should send 400 "bad request" then, but that is just silly too.
	(havehost, hostdir) := req.h.find("host");
	if(!havehost) {
		hostdir = "_default";
	} else {
		(hostdir, nil) = str->splitstrl(hostdir, ":");
		if(str->drop(hostdir, "0-9a-zA-Z.-") != nil || str->splitstrl(hostdir, "..").t1 != nil)
			return responderrmsg(op, Enotfound, nil);
	}
	if(hflag && sys->chdir(hostdir) != 0) {
		hostdir = "_default";
		if(havehost && sys->chdir(hostdir) != 0)
			return responderrmsg(op, Enotfound, nil);
	}

	haveauth := needauth := 0;
	realm: string;
	which, cred: string;
	(which, cred) = str->splitstrr(req.h.get("authorization"), " ");
	if(str->tolower(which) != "basic ")
		cred = nil;
	for(a := auths; !haveauth && a != nil; a = tl a) {
		(apath, arealm, acred) := hd a;
		if(prefix(apath, path)) {
			needauth = 1;
			realm = arealm;
			haveauth = cred == acred;
		}
	}
	if(needauth && !haveauth) {
		resp.h.add("www-authenticate", sprint("Basic realm=\"%s\"", realm));	# xxx doublequote-quote realm?
		return responderrmsg(op, Eunauthorized, nil);
	}
	if(req.h.has("authorization", nil) && !needauth && cred != credempty) {
		resp.h.add("www-authenticate", sprint("Basic realm=\"authentication not allowed\""));
		return responderrmsg(op, Eunauthorized, "You sent authorization credentials which is not allowed by this resource.  Please use an empty username and password or do not send authorization credentials altogether.");
	}

	for(r := redirs; r != nil; r = tl r) {
		(orig, new) := hd r;
		if(orig == path) {
			resp.h.set("location", new);
			new = htmlescape(new);
			return responderrmsg(op, Emovedpermanently, sprint("Moved Permanently: moved to <a href=\"%s\">%s</a>", new, new));
		}
	}

	# if path is cgi-handled, let cgi() handle the request
	if(((cgipath, cgiaction, cgitype) := findcgi(path)).t1 != nil) {
		timeo := cgitimeoutsecs*1000;
		donech := chan of int;
		spawn timeout(op, timeo, timeoch := chan of int, donech);
		timeopid := <- timeoch;
		spawn cgi(path, op, cgipath, cgiaction, cgitype, timeopid, timeoch, donech);
		<-donech;
		return;
	}

	# path is one of:  plain file, directory (either listing or plain index file)
	dfd := sys->open("."+path, Sys->OREAD);
	if(dfd != nil)
		(dok, dir) := sys->fstat(dfd);
	if(dir.mode&Sys->DMDIR && path[len path-1] == '/') {
		for(l := indexfiles; l != nil; l = tl l) {
			ipath := "."+path+hd l;
			(iok, idir) := sys->stat(ipath);
			if(iok != 0)
				continue;
			ifd := sys->open(ipath, Sys->OREAD);
			if(ifd == nil)
				return responderrmsg(op, Enotfound, nil);
			dfd = ifd;
			dok = iok;
			dir = idir;
			path += hd l;
			break;
		}
	}
	if(dfd == nil || dok != 0 || (dir.mode&Sys->DMDIR) && (!lflag || path != nil && path[len path-1] != '/'))
		return responderrmsg(op, Enotfound, nil);

	if(req.method == POST) {
		resp.h.add("allow", "GET, HEAD, OPTIONS");
		return responderrmsg(op, Emethodnotallowed, "POST not allowed");
	}

	resp.h.add("last-modified", httpdate(dir.mtime));
	tag := etag(path, op, dir);
	resp.h.add("etag", tag);

	ifmatch := req.h.get("if-match");
	if(req.version() >= HTTP_11 && ifmatch != nil && !etagmatch(req.version(), tag, ifmatch, 1))
		return responderrmsg(op, Epreconditionfailed, sprint("Precondition Failed: etags %s, specified with If-Match did not match", htmlescape(ifmatch)));

	ifmodsince := parsehttpdate(req.h.get("if-modified-since"));
	chat(id, sprint("ifmodsince, %d, mtime %d", ifmodsince, dir.mtime));
	# http/1.0, head and if-modified-since: rfc1945#8.1;  unsupported date value can safely be ignored.
	if(!(req.version() == HTTP_10 && req.method == HEAD) && ifmodsince && dir.mtime <= ifmodsince)
		return responderr(op, Enotmodified);

	ifnonematch := req.h.get("if-none-match");
	if(req.version() >= HTTP_11 && ifnonematch != nil && req.method == GET && etagmatch(req.version(), tag, ifnonematch, 0))
		return responderr(op, Enotmodified);

	# unsupported date value causes a "precondition failed"
	ifunmodsince := parsehttpdate(ifunmodsincestr := req.h.get("if-unmodified-since"));
	chat(id, sprint("ifunmodsince, %d", ifunmodsince));
	if(req.version() >= HTTP_11 && (ifunmodsince && dir.mtime > ifunmodsince || ifunmodsincestr != nil && !ifunmodsince))
		return responderrmsg(op, Epreconditionfailed, sprint("Precondition Failed: object has been modified since %s", req.h.get("if-unmodified-since")));

	if(cachesecs)
		resp.h.add("cache-control", maxage(path));

	if(dir.mode & Sys->DMDIR)
		listdir(path, op, dfd);
	else
		plainfile(path, op, dfd, dir, tag);
}

plainfile(path: string, op: ref Op, dfd: ref Sys->FD, dir: Sys->Dir, tag: string)
{
	id := op.id;
	req := op.req;
	resp := op.resp;

	chat(id, "doing plain file");
	ct := gettype(path);
	resp.h.add("content-type", ct);
	op.length = dir.length;
	resp.h.add("content-length", string op.length);

	(valid, ranges) := parserange(req.version(), req.h.get("range"), dir);
	if(!valid) {
		resp.h.add("content-range", sprint("bytes */%bd", dir.length));
		return responderrmsg(op, Enotsatisfiable, nil);
	}
	bound := "";
	ifrange := req.h.get("if-range");
	# unsupported date value can safely be ignored.
	if(ranges != nil && (ifrange == nil
	                     || ifrange[0] == '"' && tag == ifrange
	                     || dir.mtime <= parsehttpdate(ifrange))) {
		if(len ranges == 1) {
			(start, end) := hd ranges;
			resp.h.add("content-range", sprint("bytes %bd-%bd/%bd", start, end-big 1, dir.length));
		} else {
			bound = sha1(array of byte (string <-randch+","+string op.now));
			resp.h.set("content-type", "multipart/byteranges; boundary="+bound);
			op.chunked = resp.version() >= HTTP_11;
		}
		resp.st = "206";
		resp.stmsg = "partial content";
	} else
		ranges = (big 0, dir.length)::nil;

	accesslog(op);

	rerr := hresp(resp, op.fd, op.keepalive, op.chunked);
	if(rerr != nil)
		die(id, "writing response: "+rerr);

	if(req.method == HEAD)
		return;

	for(; ranges != nil; ranges = tl ranges) {
		(off, end) := hd ranges;
		if(bound != nil)
			hwrite(op, array of byte sprint("--%s\r\ncontent-type: %s\r\ncontent-range: bytes %bd-%bd/%bd\r\n\r\n", bound, ct, off, end-big 1, dir.length));
		while(off < end) {
			want := int (end-off);
			if(want > Sys->ATOMICIO)
				want = Sys->ATOMICIO;
			n := sys->pread(dfd, d := array[want] of byte, len d, off);
			if(n < 0)
				die(id, sprint("reading file: %r"));
			if(n == 0)
				break;
			off += big n;
			hwrite(op, d[:n]);
		}
		if(bound != nil)
			hwrite(op, array of byte "\r\n");
	}
	hwriteeof(op);
}

listdir(path: string, op: ref Op, dfd: ref Sys->FD)
{
	id := op.id;
	resp := op.resp;

	chat(id, "doing directory listing");
	resp.h.add("content-type", "text/html; charset=utf-8");
	op.chunked = resp.version() >= HTTP_11;

	accesslog(op);

	rerr := hresp(resp, op.fd, op.keepalive, op.chunked);
	if(rerr != nil)
		die(id, "writing response: "+rerr);

	if(op.req.method == HEAD)
		return;

	begin := mkhtmlstart("listing for "+path) + sprint("<h1>listing for %s</h1><hr/><table><tr><th>last modified</th><th>size</th><th>name</th></tr>\n", pathurls(path));
	hwrite(op, array of byte begin);
	for(;;) {
		(nd, d) := sys->dirread(dfd);
		if(nd < 0)
			die(id, sprint("reading dir: %r"));
		if(nd == 0)
			break;
		html := "";
		for(i := 0; i < nd && i < len d; i++) {
			name := d[i].name;
			if(d[i].mode & Sys->DMDIR)
				name += "/";
			html += sprint("<tr><td class=\"mtime\">%s</td><td class=\"size\">%bd</td><td class=\"name\"><a href=\"%s\">%s</a></td></tr>\n", daytime->filet(op.now, d[i].mtime), d[i].length, htmlescape(encodepath(name)), htmlescape(name));
		}
		hwrite(op, array of byte html);
	}
	end := sprint("</table><hr/></body></html>\n");
	hwrite(op, array of byte end);
	hwriteeof(op);
}

timeout(op: ref Op, timeo: int, timeoch, donech: chan of int)
{
	timeoch <-= sys->pctl(Sys->NEWPGRP, nil);
	opid := <-timeoch;
	sys->sleep(timeo);
	chat(op.id, sprint("timeout %d ms for request, killing handler pid %d, timeopid %d", timeo, opid, sys->pctl(0, nil)));
	killch <-= opid;
	responderrmsg(op, Eservererror, "Response could not be generated in time.");
	donech <-= 0;
}

cgi(path: string, op: ref Op, cgipath, cgiaction: string, cgitype, timeopid: int, cgich, donech: chan of int)
{
	npid := sys->pctl(Sys->NEWPGRP, nil);
	if(npid < 0) {
		killch <-= timeopid;
		chat(op.id, sprint("pctl newpgr: %r"));
		responderrmsg(op, Eservererror, nil);
	}
	excch <-= (npid, respch := chan of string);
	err := <-respch;
	if(err != nil) {
		killch <-= timeopid;
		chat(op.id, sprint("setting exception notify leader: %s", err));
		responderrmsg(op, Eservererror, nil);
	} else {
		# catch exceptions (e.g. when writing to remote fails), to make sure our caller can return
		{ _cgi(path, op, cgipath, cgiaction, cgitype, timeopid, cgich); }
		exception {
		* =>	;
		}
	}
	donech <-= 0;
}

_cgi(path: string, op: ref Op, cgipath, cgiaction: string, cgitype, timeopid: int, cgich: chan of int)
{
	cgich <-= sys->pctl(0, nil);

	id := op.id;
	req := op.req;
	resp := op.resp;

	# we are taking a short cut here to avoid feeding the bloat monster:  parsing transfer-coding is too involved for us.
	length := big 0;
	if(req.method == POST) {
		transferenc := req.h.getlist("transfer-encoding");
		if(req.version() >= HTTP_11 && transferenc != nil && transferenc != "identity")
			return responderrmsg(op, Enotimplemented, "Not Implemented: Transfer-Encodings other than identity (i.e. no transfer encoding) are not supported (note: Only single values in the simplest syntax are accepted)");

		if(req.h.has("content-length", nil)) {
			lengthstr := req.h.get("content-length");
			if(lengthstr == nil || str->drop(lengthstr, "0-9") != "")
				return responderrmsg(op, Ebadrequest, "Bad Request: Invalid Content-Length: "+lengthstr);
			length = big lengthstr;
		} else {
			e := Elengthrequired;
			emsg: string;
			if(req.version() == HTTP_10) {
				# rfc1945#7.2.2
				e = Ebadrequest;
				emsg = "Bad Request: Missing header Content-Length";
			}
			return responderrmsg(op, e, emsg);
		}

		contentenc := req.h.getlist("content-encoding");
		if(contentenc != nil && contentenc != "identity")
			return responderrmsg(op, Enotimplemented, "Not Implemented: Content-Encoding other than identity (i.e. no content encoding) are not supported (note: Only single values in the simplest syntax are accepted)");

		if(req.version() >= HTTP_11 && (expect := req.h.getlist("expect")) != nil) {
			# we are not compliant here, values such as "100-continue, " are valid and must be treated as "100-continue"
			# however, that is too much of a pain to parse (well, it gets much more complex, for no good reason).
			# tough luck sir bloat!
			if(str->tolower(expect) != "100-continue")
				return responderrmsg(op, Eexpectationfailed, sprint("Unrecognized Expectectation: %q (note: Only single values in the simplest syntax are accepted)", expect));
			fprint(op.fd, "HTTP/1.1 100 Continue\r\n\r\n");
		}
	}

	chat(id, sprint("handling cgi request, cgipath %q cgiaction %q cgitype %s, pid %d timeopid %d", cgipath, cgiaction, cgitypes[cgitype], sys->pctl(0, nil), timeopid));

	fd0, fd1: ref Sys->FD;
	if(cgitype == Scgi) {
		scgidialch <-= (cgiaction, replychan := chan of (ref Sys->FD, string));
		(sfd, serr) := <-replychan;
		if(serr != nil)
			return responderrmsg(op, Eservererror, nil);

		sreq := scgirequest(path, cgipath, req, op, length);
		if(sys->write(sfd, sreq, len sreq) != len sreq) {
			chat(id, sprint("write scgi request: %r"));
			return responderrmsg(op, Eservererror, nil);
		}
		fd0 = fd1 = sfd;
	} else {
		err: string;
		cgispawnch <-= (cgiaction, path, cgipath, req, op, length, replych := chan of (ref Sys->FD, ref Sys->FD, string));
		(fd0, fd1, err) = <-replych;
		if(err != nil) {
			chat(id, "cgispawn: "+err);
			return responderrmsg(op, Eservererror, nil);
		}
	}

	if(length > big 0)
		spawn cgifunnel(op.fd, fd0, length);

	sb := bufio->fopen(fd1, Bufio->OREAD);
	if(sb == nil) {
		chat(id, sprint("bufio fopen cgi fd: %r"));
		return responderrmsg(op, Eservererror, nil);
	}

	l := sb.gets('\n');
	killch <-= timeopid;
	if(!prefix("status:", str->tolower(l))) {
		chat(id, "bad cgi response line: "+l);
		return responderrmsg(op, Eservererror, nil);
	}
	l = str->drop(l[len "status:":], " \t");
	(resp.st, resp.stmsg) = str->splitstrl(l, " ");
	if(resp.stmsg != nil)
		resp.stmsg = droptl(resp.stmsg[1:], " \t\r\n");
	if(len resp.st != 3 || str->drop(resp.st, "0-9") != "") {
		chat(id, "bad cgi response line: "+l);
		return responderrmsg(op, Eservererror, nil);
	}

	accesslog(op);

	(hdrs, rerr) := Hdrs.read(sb);
	if(rerr != nil) {
		chat(id, "reading cgi headers: "+rerr);
		return responderrmsg(op, Eservererror, nil);
	}
	elength := big -1;
	if(hdrs.has("content-length", nil)) {
		elengthstr := hdrs.get("content-length");
		if(elengthstr == nil || str->drop(elengthstr, "0-9") != "") {
			chat(id, "bad cgi content-length header: "+elengthstr);
			return responderrmsg(op, Eservererror, nil);
		}
		elength = big elengthstr;
	}
	for(hl := hdrs.all(); hl != nil; hl = tl hl)
		resp.h.add((hd hl).t0, (hd hl).t1);

	op.chunked = elength == big -1 && resp.version() >= HTTP_11;
	rerr = hresp(resp, op.fd, op.keepalive, op.chunked);
	if(rerr != nil) {
		chat(id, "writing response: "+rerr);
		return;
	}

	if(req.method == HEAD)
		return;

	for(;;) {
		n := sb.read(d := array[Sys->ATOMICIO] of byte, len d);
		if(n < 0)
			die(id, sprint("reading file: %r"));
		if(n == 0) {
			if(elength > big 0)
				die(id, "bad cgi body, message shorter than content-length specified");
			break;
		}
		if(elength > big 0) {
			if(big n > elength)
				die(id, "bad cgi body, message longer than content-length specified");
			elength -= big n;
		}
		hwrite(op, d[:n]);
	}
	hwriteeof(op);
	chat(id, "request done");
}

cgifunnel(fd, sfd: ref Sys->FD, length: big)
{
	while(length > big 0) {
		n := sys->read(fd, d := array[Sys->ATOMICIO] of byte, len d);
		if(n < 0)
			fail(sprint("fail:cgi read: %r"));
		if(n == 0)
			fail(sprint("fail:cgi read: premature eof"));
		if(sys->write(sfd, d, n) != n)
			fail(sprint("fail:cgi write: %r"));
		length -= big n;
	}
}

hresp(resp: ref Resp, fd: ref Sys->FD, keepalive, chunked: int): string
{
	if(keepalive)
		resp.h.add("connection", "keep-alive");
	else
		resp.h.add("connection", "close");
	if(chunked) {
		resp.h.add("transfer-encoding", "chunked");
		resp.h.del("content-length", nil);
	}
	return resp.write(fd);
}

hwrite(op: ref Op, d: array of byte)
{
	if(len d == 0)
		return;

	if(op.chunked) {
		length := array of byte sprint("%x\r\n", len d);
		nd := array[len length+len d+2] of byte;
		nd[:] = length;
		nd[len length:] = d;
		nd[len length+len d:] = array of byte "\r\n";
		d = nd;
	}
	if(sys->write(op.fd, d, len d) != len d)
		fail(sprint("writing response data: %r"));
}

hwriteeof(op: ref Op)
{
	if(op.chunked)
		fprint(op.fd, "0\r\n\r\n");
}

respond(op: ref Op, st: int, errmsgstr: string, ct: string)
{
	resp := op.resp;
	resp.st = string st;
	resp.stmsg = statusmsg(st);
	if(ct != nil)
		resp.h.set("content-type", ct);

	op.chunked = 0;
	errmsg := array of byte errmsgstr;
	op.length = big len errmsg;
	if(!(st >= 100 && st < 200 || st == 204 || st == 304))
		resp.h.set("content-length", string op.length);

	err := hresp(resp, op.fd, op.keepalive, op.chunked);
	if(err != nil)
		die(op.id, "writing error response: "+err);

	if(errmsgstr != nil && (op.req == nil || op.req.method != HEAD)) {
		hwrite(op, errmsg);
		hwriteeof(op);
	}

	accesslog(op);
}

responderr(op: ref Op, st: int)
{
	return respond(op, st, nil, nil);
}

responderrmsg(op: ref Op, st: int, errmsg: string)
{
	if(errmsg == nil)
		errmsg = statusmsg(st);
	return respond(op, st, mkhtml(sprint("%d - %s", st, errmsg)), "text/html; charset=utf-8");
}

mkhtmlstart(msg: string): string
{
	return sprint("<html><head><style type=\"text/css\">h1 { font-size: 1.4em; } td, th { padding-left: 1em; padding-right: 1em; } td.mtime, td.size { text-align: right; }</style><title>%s</title></head><body>", htmlescape(msg));
}

mkhtml(msg: string): string
{
	return mkhtmlstart(msg)+sprint("<h1>%s</h1></body></html>\n", htmlescape(msg));
}

etag(path: string, op: ref Op, dir: Sys->Dir): string
{
	host := op.req.h.get("host");
	if(host == nil)
		host = "_default";
	return "\""+sha1(array of byte sprint("%d,%d,%s,%s,%s", dir.qid.vers, dir.mtime, host, op.lport, path))+"\"";
}

maxage(nil: string): string
{
	return sprint("maxage=%d", cachesecs);
}

accesslog(op: ref Op)
{
	length := "";
	if(!op.chunked)
		length = string op.length;
	if(accessfd != nil && op.req != nil)
		fprint(accessfd, "%d %d %s!%s %s!%s %q %q %q %q %q %q %q\n", op.id, op.now, op.rhost, op.rport, op.lhost, op.lport, http->methodstr(op.req.method), op.req.url.pack(), sprint("HTTP/%d.%d", op.req.major, op.req.minor), op.resp.st, op.resp.stmsg, length, op.req.h.get("user-agent"));
}

findcgi(path: string): (string, string, int)
{
	for(l := cgipaths; l != nil; l = tl l)
		if(str->prefix((hd l).t0, path))
			return hd l;
	return (nil, nil, 0);
}

htmlescape(s: string): string
{
	r := "";
	for(i := 0; i < len s; i++)
		case s[i] {
		'<' =>	r += "&lt;";
		'>' =>	r += "&gt;";
		'&' =>	r += "&amp;";
		'"' =>	r += "&quot;";
		* =>	r += s[i:i+1];
		}
	return r;
}

pathsanitize(path: string): string
{
	say("path sanitize: "+path);
	trailslash := path != nil && path[len path-1] == '/';

	(nil, elems) := sys->tokenize(path, "/");
	say(sprint("path nelems: %d", len elems));
	r: list of string;
	for(; elems != nil; elems = tl elems)
		if(hd elems == ".")
			continue;
		else if(hd elems == "..") {
			if(r != nil)
				r = tl r;
		} else
			r = hd elems::r;
	s := "";	
	for(; r != nil; r = tl r)
		s = "/"+hd r+s;
	if(trailslash || s == "")
		s += "/";
	return s;
}

pathurls(s: string): string
{
	say("pathurls: "+s);
	(nil, l) := sys->tokenize(s, "/");
	r := "";
	i := 0;
	path := "./";
	for(l = rev(l); l != nil; l = tl l) {
		r = sprint(" <a href=\"%s\">%s/</a>", path, htmlescape(hd l))+r;
		if(i == 0)
			path = "../";
		else
			path += "../";
		i += 1;
	}
	r = sprint("<a href=\"%s\">/</a>", path)+r;
	return r;
}

cgivars(path, cgipath: string, req: ref Req, op: ref Op, length: big, environ: list of (string, string)): list of (string, string)
{
	servername := req.h.get("host");
	if(servername == nil)
		servername = op.lhost;
	pathinfo := path[len cgipath:];
	return	("CONTENT_LENGTH",	string length)::
		("GATEWAY_INTERFACE",	"CGI/1.1")::
		("SERVER_PROTOCOL",	http->versionstr(req.version()))::
		("SERVER_NAME",		servername)::
		("SCGI",		"1")::
		("REQUEST_METHOD",	http->methodstr(req.method))::
		("REQUEST_URI",		path)::
		("SCRIPT_NAME",		path)::
		("PATH_INFO",		pathinfo)::
		("PATH_TRANSLATED",	pathinfo)::
		("QUERY_STRING",	req.url.query)::
		("SERVER_ADDR",		op.lhost)::
		("SERVER_PORT",		op.lport)::
		("REMOTE_ADDR",		op.rhost)::
		("REMOTE_PORT",		op.rport)::
		environ;
}

scgirequest(path, scgipath: string, req: ref Req, op: ref Op, length: big): array of byte
{
	l := cgivars(path, scgipath, req, op, length, environment);
	s := "";
	for(h := l; h != nil; h = tl h)
		s += (hd h).t0+"\0"+(hd h).t1+"\0";
	for(h = req.h.all(); h != nil; h = tl h)
		s += cgivar((hd h).t0)+"\0"+(hd h).t1+"\0";
	return netstring(s);
}

cgivar(s: string): string
{
	r := "HTTP_";
	for(i := 0; i < len s; i++)
		if(s[i] != '-')
			r[len r] = s[i];
		else
			r[len r] = '_';
	return str->toupper(r);
}

netstring(s: string): array of byte
{
	return array of byte (sprint("%d:", len s)+s+",");
}

suffix(suf, s: string): int
{
	if(len suf > len s)
		return 0;
	return suf == s[len s-len suf:];
}

gettype(path: string): string
{
	for(i := 0; i < len types; i++)
		if(suffix(types[i].t0, path))
			return types[i].t1;
	if(!has(path, '.'))
		return "text/plain; charset=utf-8";
	return "application/octet-stream";
}

days := array[] of {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
months := array[] of {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

httpdate(t: int): string
{
	tm := daytime->gmt(t);
	return sprint("%s, %02d %s %d %02d:%02d:%02d GMT", days[tm.wday], tm.mday, months[tm.mon], tm.year+1900, tm.hour, tm.min, tm.sec);
}

readtoken(s: string): (string, string, string)
{
	for(i := 0; i < len s; i++)
		if(s[i] < ' ')
			return (nil, nil, "invalid control characters found");
		else if(str->in(s[i], "()<>@,;:\\\"/[]?={} \t"))
			break;
	return (s[:i], s[i:], nil);
}

tokenize(s: string): (list of string, string)
{
	token, err: string;
	l: list of string;
	for(;;) {
		(token, s, err) = readtoken(s);
		if(err != nil)
			return (nil, err);
		if(token != nil)
			l = token::l;
		s = str->drop(s, " \t");
		if(s == nil)
			break;
		if(s[0] != ',')
			return (nil, "expected comma as separator");
		s = str->drop(s[1:], " \t");
	}
	return (rev(l), nil);
}

# for http/1.1 a backslash may be used for escaping, not for http/1.0
readqs(s: string, v: int): (string, string, string)
{
	if(s == nil)
		return (nil, nil, nil);
	if(s[0] != '"')
		return (nil, s, nil);
	r := "\"";
	for(i := 1; i < len s; i++)
		if(s[i] < ' ')
			return (nil, nil, "invalid control character found inside quoted string");
		else if(v >= HTTP_11 && s[i] == '\\' && i+1 < len s && s[i+1] == '"')
			r[len r] = s[++i];
		else {
			r[len r] = s[i];
			if(s[i] == '"')
				return (r, s[i+1:], nil);
		}
	return (nil, nil, "quoted string not ended");
}

tokenizeqs(s: string, v: int): (list of string, string)
{
	r: list of string;
	qs, err: string;
	for(;;) {
		(qs, s, err) = readqs(s, v);
		if(err != nil)
			return (nil, err);
		if(qs != nil)
			r = qs::r;
		s = str->drop(s, " \t");
		if(s == nil)
			break;
		if(s[0] != ',')
			return (nil, "expected comma as separator");
		s = str->drop(s[1:], " \t");
	}
	return (rev(r), nil);
}

# i'm not going to parse three different date formats where a simple unix epoch integer would have sufficed.
# death to the bloat monster!
parsehttpdate(s: string): int
{
	mday, mon, year, hour, min, sec: int;

	(n, tokens) := sys->tokenize(s, " ");
	if(n != 6 || len hd tokens != 4 || (hd tokens)[3] != ',' || index(days, (hd tokens)[:3]) < 0)
		return 0;
	say("got a bit");
	if((mon = index(months, hd tl tl tokens)) < 0)
		return 0;
	say("got a month");
	(hn, htokens) := sys->tokenize(hd tl tl tl tl tokens, ":");
	if(hn != 3)
		return 0;
	say("got time");
	mday = int hd tl tokens;
	year = int hd tl tl tl tokens;
	hour = int hd htokens;
	min = int hd tl htokens;
	sec = int hd tl tl htokens;

	# last arg should be seconds offset for timezone, "luckily" http allows only gmt...
	return daytime->tm2epoch(ref Daytime->Tm(sec, min, hour, mday, mon, year-1900, 0, 0, s[1:], 0));
}

parserange(version: int, range: string, dir: Sys->Dir): (int, list of (big, big))
{
	if(range == nil || !(version >= HTTP_11))
		return (1, nil);

	if(!str->prefix("bytes", range))
		return (0, nil);
	range = range[len "bytes":];
	range = str->drop(range, " \t");
	if(!str->prefix("=", range))
		return (0, nil);
	range = str->drop(range[1:], " \t");

	r: list of (big, big);
	valid := 0;
	for(l := sys->tokenize(range, ",").t1; l != nil; l = tl l) {
		s := strip(hd l, " \t");
		if(s == nil)
			continue;
		if(s[0] == '-') {
			# single (negative) byte offset relative to end of file
			s = str->drop(s[1:], " \t");
			if(s == nil || str->drop(s, "0-9") != nil)
				return (1, nil);
			if(big s != big 0)
				valid = 1;
			i := dir.length - big s;
			if(i < big 0)
				i = big 0;
			if(i >= dir.length)
				i = dir.length - big 1;
			chat(0, sprint("adding single, (%bd, %bd)", i, dir.length));
			r = (i, dir.length)::r;
		} else {
			(first, last) := str->splitstrl(s, "-");
			if(stripws(str->drop(first, "0-9")) != nil || last == nil || str->drop(stripws(last[1:]), "0-9") != nil)
				return (1, nil);
			f := big first;
			e := dir.length;
			last = stripws(last[1:]);
			if(last != nil)
				e = big last+big 1;
			if(e > dir.length)
				e = dir.length;
			if(f > e)
				return (1, nil);
			if(f < dir.length)
				valid = 1;
			r = (f, e)::r;
			chat(0, sprint("adding two, (%bd, %bd)", f, e));
		}
	}
	return (valid, rev1(r));
}

etagmatch(version: int, etag: string, etagstr: string, strong: int): int
{
	if(etagstr == "*")
		return 1;
	(l, err) := tokenizeqs(etagstr, version);
	if(err != nil)
		return 0;	# xxx respond with "bad request"?
	for(; l != nil; l = tl l)
		if(hd l == etag && (!strong || !str->prefix("W/", hd l)))
			return 1;
	return 0;
}

statusmsg(code: int): string
{
	for(i := 0; i < len statusmsgs && statusmsgs[i].t0 <= code; i++)
		if(code == statusmsgs[i].t0)
			return statusmsgs[i].t1;
	raise sprint("missing status message for code %d", code);
}

strip(s, cl: string): string
{
	return droptl(str->drop(s, cl), cl);
}

stripws(s: string): string
{
	return strip(s, " \t");
}

droptl(s, cl: string): string
{
	while(s != nil && str->in(s[len s-1], cl))
		s = s[:len s-1];
	return s;
}

index(a: array of string, s: string): int
{
	for(i := 0; i < len a; i++)
		if(a[i] == s)
			return i;
	return -1;
}

readaddr(id: int, path: string): (string, string)
{
	(s, err) := readfileline(path, 256);
	if(err != nil)
		die(id, err);
	(lhost, lport) := str->splitstrl(s, "!");
	if(lport != nil)
		lport = lport[1:];
	return (lhost, lport);
}

readfileline(path: string, maxsize: int): (string, string)
{
	fd := sys->open(path, Sys->OREAD);
	if(fd == nil)
		return (nil, sprint("open %s: %r", path));
	n := sys->read(fd, buf := array[maxsize] of byte, len buf);
	if(n < 0)
		return (nil, sprint("read %s: %r", path));
	s := string buf[:n];
	if(s != nil && s[len s-1] == '\n')
		s = s[:len s-1];
	return (s, nil);
}

readtime(): int
{
	n := sys->pread(timefd, d := array[64] of byte, len d, big 0);
	if(n < 0)
		fail(sprint("reading time: %r"));
	return int ((big string d[:n])/big 1000000);
}

byte2str(a: array of byte): string
{
	s := "";
	for(i := 0; i < len a; i++)
		s += sys->sprint("%02x", int a[i]);
	return s;
}

sha1(a: array of byte): string
{
	r := array[keyring->SHA1dlen] of byte;
	keyring->sha1(a, len a, r, nil);
	return byte2str(r);
}

listlower(l: list of string): list of string
{
	r: list of string;
	for(; l != nil; l = tl l)
		r = str->tolower(hd l)::r;
	return rev(r);
}

listhas(l: list of string, s: string): int
{
	for(; l != nil; l = tl l)
		if(hd l == s)
			return 1;
	return 0;
}

has(s: string, c: int): int
{
	for(i := 0; i < len s; i++)
		if(s[i] == c)
			return 1;
	return 0;
}

rev3(l: list of (string, string, string)): list of (string, string, string)
{
	r: list of (string, string, string);
	for(; l != nil; l = tl l)
		r = hd l::r;
	return r;
}

rev2(l: list of (string, string)): list of (string, string)
{
	r: list of (string, string);
	for(; l != nil; l = tl l)
		r = hd l::r;
	return r;
}

rev1(l: list of (big, big)): list of (big, big)
{
	r: list of (big, big);
	for(; l != nil; l = tl l)
		r = hd l::r;
	return r;
}

rev[T](l: list of T): list of T
{
	r: list of T;
	for(; l != nil; l = tl l)
		r = hd l::r;
	return r;
}

kill(pid: int)
{
	fd := sys->open(sprint("/prog/%d/ctl", pid), Sys->OWRITE);
	if(fd != nil)
		fprint(fd, "kill");
}

say(s: string)
{
	if(dflag)
		fprint(fildes(2), "%s\n", s);
	if(errorfd != nil)
		fprint(errorfd, "%s\n", s);
}

chat(id: int, s: string)
{
	say(string id+" "+s);
}

die(id: int, s: string)
{
	fail(string id+" "+s);
}

fail(s: string)
{
	fprint(fildes(2), "%s\n", s);
	raise "fail:"+s;
}
