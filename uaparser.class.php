<?php
/**
 * Standalone PHP class to identify browser, engine, OS, CPU, and device type/model based on the User Agent.
 * All detection rules are based on regular expressions stored in uaparser.class.json.
 * If a user agent is not provided to the constructor - it will be auto-detected by PHP.
 * If a user agent is provided to the constructor - it will be used.
 */
class UAParser {
	/**
	 * Private variable to store the User Agent for the current class instance.
	 */
	private $userAgent;

	/**
	 * Static variable used to store mappings.
	 */
	private static $mapping = [
		'safari' => [
			'1.0' => '/8',
			'1.2' => '/1',
			'1.3' => '/3',
			'2.0' => '/412',
			'2.0.2' => '/416',
			'2.0.3' => '/417',
			'2.0.4' => '/419',
		],
		'windows' => [
			'ME' => '4.90',
			'NT 3.11' => 'NT3.51',
			'NT 4.0' => 'NT4.0',
			'2000' => 'NT 5.0',
			'XP' => ['NT 5.1', 'NT 5.2'],
			'Vista' => 'NT 6.0',
			'7' => 'NT 6.1',
			'8' => 'NT 6.2',
			'8.1' => 'NT 6.3',
			'10' => ['NT 6.4', 'NT 10.0'],
			'RT' => 'ARM',
		],
	];

	/**
	 * Private static variable used to store all regular expressions used to determine browser, device, os, etc.
	 * It is filled with contents from the JSON file when the class is used at least once.
	 */
	private static $regexes = [
		'browser' => [
			['/\\b(?:crmo|crios)\\/([\\w\\.]+)/i'],
			['version', ['name', 'Chrome']],
			['/edg(?:e|ios|a)?\\/([\\w\\.]+)/i'],
			['version', ['name', 'Edge']],
			[
				'/(opera mini)\\/([-\\w\\.]+)/i',
				'/(opera [mobiletab]{3,6})\\b.+version\\/([-\\w\\.]+)/i',
				'/(opera)(?:.+version\\/|[\\/ ]+)([\\w\\.]+)/i',
			],
			['name', 'version'],
			['/opios[\\/ ]+([\\w\\.]+)/i'],
			['version', ['name', 'Opera Mini']],
			['/\\bopr\\/([\\w\\.]+)/i'],
			['version', ['name', 'Opera']],
			[
				'/(kindle)\\/([\\w\\.]+)/i',
				'/(lunascape|maxthon|netfront|jasmine|blazer)[\\/ ]?([\\w\\.]*)/i',
				'/(avant |iemobile|slim)(?:browser)?[\\/ ]?([\\w\\.]*)/i',
				'/(ba?idubrowser)[\\/ ]?([\\w\\.]+)/i',
				'/(?:ms|\\()(ie) ([\\w\\.]+)/i',
				'/(flock|rockmelt|midori|epiphany|silk|skyfire|ovibrowser|bolt|iron|vivaldi|iridium|phantomjs|bowser|quark|qupzilla|falkon|rekonq|puffin|brave|whale|qqbrowserlite|qq|duckduckgo)\\/([-\\w\\.]+)/i',
				'/(weibo)__([\\d\\.]+)/i',
			],
			['name', 'version'],
			['/(?:\\buc? ?browser|(?:juc.+)ucweb)[\\/ ]?([\\w\\.]+)/i'],
			['version', ['name', 'UC Browser']],
			['/microm.+\\bqbcore\\/([\\w\\.]+)/i', '/\\bqbcore\\/([\\w\\.]+).+microm/i'],
			['version', ['name', 'WeChat(Win) Desktop']],
			['/micromessenger\\/([\\w\\.]+)/i'],
			['version', ['name', 'WeChat']],
			['/konqueror\\/([\\w\\.]+)/i'],
			['version', ['name', 'Konqueror']],
			['/trident.+rv[: ]([\\w\\.]{1,9})\\b.+like gecko/i'],
			['version', ['name', 'IE']],
			['/yabrowser\\/([\\w\\.]+)/i'],
			['version', ['name', 'Yandex']],
			['/(avast|avg)\\/([\\w\\.]+)/i'],
			[['name', '/(.+)/', '$1 Secure Browser'], 'version'],
			['/\\bfocus\\/([\\w\\.]+)/i'],
			['version', ['name', 'Firefox Focus']],
			['/\\bopt\\/([\\w\\.]+)/i'],
			['version', ['name', 'Opera']],
			['/coc_coc\\w+\\/([\\w\\.]+)/i'],
			['version', ['name', 'Coc Coc']],
			['/dolfin\\/([\\w\\.]+)/i'],
			['version', ['name', 'Dolphin']],
			['/coast\\/([\\w\\.]+)/i'],
			['version', ['name', 'Opera Coast']],
			['/miuibrowser\\/([\\w\\.]+)/i'],
			['version', ['name', 'MIUI Browser']],
			['/fxios\\/([-\\w\\.]+)/i'],
			['version', ['name', 'Firefox']],
			['/\\bqihu|(qi?ho?o?|360)browser/i'],
			[['name', '360 Browser']],
			['/(oculus|samsung|sailfish|huawei)browser\\/([\\w\\.]+)/i'],
			[['name', '/(.+)/', '$1 Browser'], 'version'],
			['/(comodo_dragon)\\/([\\w\\.]+)/i'],
			[['name', '/_/', ' '], 'version'],
			[
				'/(electron)\\/([\\w\\.]+) safari/i',
				'/(tesla)(?: qtcarbrowser|\\/(20\\d\\d\\.[-\\w\\.]+))/i',
				'/m?(qqbrowser|baiduboxapp|2345Explorer)[\\/ ]?([\\w\\.]+)/i',
			],
			['name', 'version'],
			['/(metasr)[\\/ ]?([\\w\\.]+)/i', '/(lbbrowser)/i', '/\\[(linkedin)app\\]/i'],
			['name'],
			['/((?:fban\\/fbios|fb_iab\\/fb4a)(?!.+fbav)|;fbav\\/([\\w\\.]+);)/i'],
			[['name', 'Facebook app browser'], 'version'],
			[
				'/safari (line)\\/([\\w\\.]+)/i',
				'/\\b(line)\\/([\\w\\.]+)\\/iab/i',
				'/(chromium|instagram)[\\/ ]([-\\w\\.]+)/i',
			],
			['name', 'version'],
			['/\\bgsa\\/([\\w\\.]+) .*safari\\//i'],
			['version', ['name', 'Google Search Application']],
			['/headlesschrome(?:\\/([\\w\\.]+)| )/i'],
			['version', ['name', 'Chrome Headless']],
			['/ wv\\).+(chrome)\\/([\\w\\.]+)/i'],
			[['name', 'Chrome WebView'], 'version'],
			['/droid.+ version\\/([\\w\\.]+)\\b.+(?:mobile safari|safari)/i'],
			['version', ['name', 'Android Browser']],
			['/(chrome|omniweb|arora|[tizenoka]{5} ?browser)\\/v?([\\w\\.]+)/i'],
			['name', 'version'],
			['/version\\/([\\w\\.\\,]+) .*mobile\\/\\w+ (safari)/i'],
			['version', ['name', 'Mobile Safari']],
			['/version\\/([\\w(\\.|\\,)]+) .*(mobile ?safari|safari)/i'],
			['version', 'name'],
			['/webkit.+?(mobile ?safari|safari)(\\/[\\w\\.]+)/i'],
			['name', ['version', 'mapping', 'safari']],
			['/(webkit|khtml)\\/([\\w\\.]+)/i'],
			['name', 'version'],
			['/(navigator|netscape\\d?)\\/([-\\w\\.]+)/i'],
			[['name', 'Netscape'], 'version'],
			['/mobile vr; rv:([\\w\\.]+)\\).+firefox/i'],
			['version', ['name', 'Firefox Reality']],
			[
				'/ekiohf.+(flow)\\/([\\w\\.]+)/i',
				'/(swiftfox)/i',
				'/(icedragon|iceweasel|camino|chimera|fennec|maemo browser|minimo|conkeror|klar)[\\/ ]?([\\w\\.\\+]+)/i',
				'/(seamonkey|k-meleon|icecat|iceape|firebird|phoenix|palemoon|basilisk|waterfox)\\/([-\\w\\.]+)$/i',
				'/(firefox)\\/([\\w\\.]+)/i',
				'/(mozilla)\\/([\\w\\.]+) .+rv\\:.+gecko\\/\\d+/i',
				'/(polaris|lynx|dillo|icab|doris|amaya|w3m|netsurf|sleipnir|obigo|mosaic|(?:go|ice|up)[\\. ]?browser)[-\\/ ]?v?([\\w\\.]+)/i',
				'/(links) \\(([\\w\\.]+)/i',
			],
			['name', 'version'],
		],
		'cpu' => [
			['/(?:(amd|x(?:(?:86|64)[-_])?|wow|win)64)[;\\)]/i'],
			[['architecture', 'amd64']],
			['/(ia32(?=;))/i'],
			[['architecture', 'utilLowerize']],
			['/((?:i[346]|x)86)[;\\)]/i'],
			[['architecture', 'ia32']],
			['/\\b(aarch64|arm(v?8e?l?|_?64))\\b/i'],
			[['architecture', 'arm64']],
			['/\\b(arm(?:v[67])?ht?n?[fl]p?)\\b/i'],
			[['architecture', 'armhf']],
			['/windows (ce|mobile); ppc;/i'],
			[['architecture', 'arm']],
			['/((?:ppc|powerpc)(?:64)?)(?: mac|;|\\))/i'],
			[['architecture', '/ower/', '', 'utilLowerize']],
			['/(sun4\\w)[;\\)]/i'],
			[['architecture', 'sparc']],
			[
				'/((?:avr32|ia64(?=;))|68k(?=\\))|\\barm(?=v(?:[1-7]|[5-7]1)l?|;|eabi)|(?=atmel )avr|(?:irix|mips|sparc)(?:64)?\\b|pa-risc)/i',
			],
			[['architecture', 'utilLowerize']],
		],
		'device' => [
			['/mozilla\\/5.0 \\(linux; ; \\) applewebkit\\/ \\(khtml, like gecko\\) chrome\\/ mobile safari\\//i'],
			[['model', 'Unknown'], ['vendor', 'Generic Android'], ['type', 'mobile']],
			['/\\b(sch-i[89]0\\d|shw-m380s|sm-[pt]\\w{2,4}|gt-[pn]\\d{2,4}|sgh-t8[56]9|nexus 10)/i'],
			['model', ['vendor', 'Samsung'], ['type', 'tablet']],
			['/\\b((?:s[cgp]h|gt|sm)-\\w+|galaxy nexus)/i', '/samsung[- ]([-\\w]+)/i', '/sec-(sgh\\w+)/i'],
			['model', ['vendor', 'Samsung'], ['type', 'mobile']],
			['/\\((ip(?:hone|od)[\\w ]*);/i'],
			['model', ['vendor', 'Apple'], ['type', 'mobile']],
			[
				'/\\((ipad);[-\\w\\),; ]+apple/i',
				'/applecoremedia\\/[\\w\\.]+ \\((ipad)/i',
				'/\\b(ipad)\\d\\d?,\\d\\d?[;\\]].+ios/i',
			],
			['model', ['vendor', 'Apple'], ['type', 'tablet']],
			['/\\b((?:ag[rs][23]?|bah2?|sht?|btv)-a?[lw]\\d{2})\\b(?!.+d\\/s)/i'],
			['model', ['vendor', 'Huawei'], ['type', 'tablet']],
			[
				'/(?:huawei|honor)([-\\w ]+)[;\\)]/i',
				'/\\b(nexus 6p|\\w{2,4}e?-[atu]?[ln][\\dx][012359c][adn]?)\\b(?!.+d\\/s)/i',
			],
			['model', ['vendor', 'Huawei'], ['type', 'mobile']],
			[
				'/\\b(poco[\\w ]+)(?: bui|\\))/i',
				'/\\b; (\\w+) build\\/hm\\1/i',
				'/\\b(hm[-_ ]?note?[_ ]?(?:\\d\\w)?) bui/i',
				'/\\b(redmi[\\-_ ]?(?:note|k)?[\\w_ ]+)(?: bui|\\))/i',
				'/\\b(mi[-_ ]?(?:a\\d|one|one[_ ]plus|note lte|max|cc)?[_ ]?(?:\\d?\\w?)[_ ]?(?:plus|se|lite)?)(?: bui|\\))/i',
			],
			[['model', '/_/', ' '], ['vendor', 'Xiaomi'], ['type', 'mobile']],
			['/\\b(mi[-_ ]?(?:pad)(?:[\\w_ ]+))(?: bui|\\))/i'],
			[['model', '/_/', ' '], ['vendor', 'Xiaomi'], ['type', 'tablet']],
			['/; (\\w+) bui.+ oppo/i', '/\\b(cph[12]\\d{3}|p(?:af|c[al]|d\\w|e[ar])[mt]\\d0|x9007|a101op)\\b/i'],
			['model', ['vendor', 'OPPO'], ['type', 'mobile']],
			['/vivo (\\w+)(?: bui|\\))/i', '/\\b(v[12]\\d{3}\\w?[at])(?: bui|;)/i'],
			['model', ['vendor', 'Vivo'], ['type', 'mobile']],
			['/\\b(rmx[12]\\d{3})(?: bui|;|\\))/i'],
			['model', ['vendor', 'Realme'], ['type', 'mobile']],
			[
				'/\\b(milestone|droid(?:[2-4x]| (?:bionic|x2|pro|razr))?:?( 4g)?)\\b[\\w ]+build\\//i',
				'/\\bmot(?:orola)?[- ](\\w*)/i',
				'/((?:moto[\\w\\(\\) ]+|xt\\d{3,4}|nexus 6)(?= bui|\\)))/i',
			],
			['model', ['vendor', 'Motorola'], ['type', 'mobile']],
			['/\\b(mz60\\d|xoom[2 ]{0,2}) build\\//i'],
			['model', ['vendor', 'Motorola'], ['type', 'tablet']],
			['/((?=lg)?[vl]k\\-?\\d{3}) bui| 3\\.[-\\w; ]{10}lg?-([06cv9]{3,4})/i'],
			['model', ['vendor', 'LG'], ['type', 'tablet']],
			[
				'/(lm(?:-?f100[nv]?|-[\\w\\.]+)(?= bui|\\))|nexus [45])/i',
				'/\\blg[-e;\\/ ]+((?!browser|netcast|android tv)\\w+)/i',
				'/\\blg-?([\\d\\w]+) bui/i',
			],
			['model', ['vendor', 'LG'], ['type', 'mobile']],
			['/(ideatab[-\\w ]+)/i', '/lenovo ?(s[56]000[-\\w]+|tab(?:[\\w ]+)|yt[-\\d\\w]{6}|tb[-\\d\\w]{6})/i'],
			['model', ['vendor', 'Lenovo'], ['type', 'tablet']],
			['/(?:maemo|nokia).*(n900|lumia \\d+)/i', '/nokia[-_ ]?([-\\w\\.]*)/i'],
			[['model', '/_/', ' '], ['vendor', 'Nokia'], ['type', 'mobile']],
			['/(pixel c)\\b/i'],
			['model', ['vendor', 'Google'], ['type', 'tablet']],
			['/droid.+; (pixel[\\daxl ]{0,6})(?: bui|\\))/i'],
			['model', ['vendor', 'Google'], ['type', 'mobile']],
			[
				'/droid.+ (a?\\d[0-2]{2}so|[c-g]\\d{4}|so[-gl]\\w+|xq-a\\w[4-7][12])(?= bui|\\).+chrome\\/(?![1-6]{0,1}\\d\\.))/i',
			],
			['model', ['vendor', 'Sony'], ['type', 'mobile']],
			['/sony tablet [ps]/i', '/\\b(?:sony)?sgp\\w+(?: bui|\\))/i'],
			[['model', 'Xperia Tablet'], ['vendor', 'Sony'], ['type', 'tablet']],
			['/ (kb2005|in20[12]5|be20[12][59])\\b/i', '/(?:one)?(?:plus)? (a\\d0\\d\\d)(?: b|\\))/i'],
			['model', ['vendor', 'OnePlus'], ['type', 'mobile']],
			['/(alexa)webm/i', '/(kf[a-z]{2}wi)( bui|\\))/i', '/(kf[a-z]+)( bui|\\)).+silk\\//i'],
			['model', ['vendor', 'Amazon'], ['type', 'tablet']],
			['/((?:sd|kf)[0349hijorstuw]+)( bui|\\)).+silk\\//i'],
			[['model', '/(.+)/', 'Fire Phone $1'], ['vendor', 'Amazon'], ['type', 'mobile']],
			['/(playbook);[-\\w\\),; ]+(rim)/i'],
			['model', 'vendor', ['type', 'tablet']],
			['/\\b((?:bb[a-f]|st[hv])100-\\d)/i', '/\\(bb10; (\\w+)/i'],
			['model', ['vendor', 'BlackBerry'], ['type', 'mobile']],
			['/(?:\\b|asus_)(transfo[prime ]{4,10} \\w+|eeepc|slider \\w+|nexus 7|padfone|p00[cj])/i'],
			['model', ['vendor', 'Asus'], ['type', 'tablet']],
			['/ (z[bes]6[027][012][km][ls]|zenfone \\d\\w?)\\b/i'],
			['model', ['vendor', 'Asus'], ['type', 'mobile']],
			['/(nexus 9)/i'],
			['model', ['vendor', 'HTC'], ['type', 'tablet']],
			[
				'/(htc)[-;_ ]{1,2}([\\w ]+(?=\\)| bui)|\\w+)/i',
				'/(zte)[- ]([\\w ]+?)(?: bui|\\/|\\))/i',
				'/(alcatel|geeksphone|nexian|panasonic|sony(?!-bra))[-_ ]?([-\\w]*)/i',
			],
			['vendor', ['model', '/_/', ' '], ['type', 'mobile']],
			['/droid.+; ([ab][1-7]-?[0178a]\\d\\d?)/i'],
			['model', ['vendor', 'Acer'], ['type', 'tablet']],
			['/droid.+; (m[1-5] note) bui/i', '/\\bmz-([-\\w]{2,})/i'],
			['model', ['vendor', 'Meizu'], ['type', 'mobile']],
			['/\\b(sh-?[altvz]?\\d\\d[a-ekm]?)/i'],
			['model', ['vendor', 'Sharp'], ['type', 'mobile']],
			[
				'/(blackberry|benq|palm(?=\\-)|sonyericsson|acer|asus|dell|meizu|motorola|polytron)[-_ ]?([-\\w]*)/i',
				'/(hp) ([\\w ]+\\w)/i',
				'/(asus)-?(\\w+)/i',
				'/(microsoft); (lumia[\\w ]+)/i',
				'/(lenovo)[-_ ]?([-\\w]+)/i',
				'/(jolla)/i',
				'/(oppo) ?([\\w ]+) bui/i',
			],
			['vendor', 'model', ['type', 'mobile']],
			[
				'/(archos) (gamepad2?)/i',
				'/(hp).+(touchpad(?!.+tablet)|tablet)/i',
				'/(kindle)\\/([\\w\\.]+)/i',
				'/(nook)[\\w ]+build\\/(\\w+)/i',
				'/(dell) (strea[kpr\\d ]*[\\dko])/i',
				'/(le[- ]+pan)[- ]+(\\w{1,9}) bui/i',
				'/(trinity)[- ]*(t\\d{3}) bui/i',
				'/(gigaset)[- ]+(q\\w{1,9}) bui/i',
				'/(vodafone) ([\\w ]+)(?:\\)| bui)/i',
			],
			['vendor', 'model', ['type', 'tablet']],
			['/(surface duo)/i'],
			['model', ['vendor', 'Microsoft'], ['type', 'tablet']],
			['/droid [\\d\\.]+; (fp\\du?)(?: b|\\))/i'],
			['model', ['vendor', 'Fairphone'], ['type', 'mobile']],
			['/(u304aa)/i'],
			['model', ['vendor', 'AT&T'], ['type', 'mobile']],
			['/\\bsie-(\\w*)/i'],
			['model', ['vendor', 'Siemens'], ['type', 'mobile']],
			['/\\b(rct\\w+) b/i'],
			['model', ['vendor', 'RCA'], ['type', 'tablet']],
			['/\\b(venue[\\d ]{2,7}) b/i'],
			['model', ['vendor', 'Dell'], ['type', 'tablet']],
			['/\\b(q(?:mv|ta)\\w+) b/i'],
			['model', ['vendor', 'Verizon'], ['type', 'tablet']],
			['/\\b(?:barnes[& ]+noble |bn[rt])([\\w\\+ ]*) b/i'],
			['model', ['vendor', 'Barnes & Noble'], ['type', 'tablet']],
			['/\\b(tm\\d{3}\\w+) b/i'],
			['model', ['vendor', 'NuVision'], ['type', 'tablet']],
			['/\\b(k88) b/i'],
			['model', ['vendor', 'ZTE'], ['type', 'tablet']],
			['/\\b(nx\\d{3}j) b/i'],
			['model', ['vendor', 'ZTE'], ['type', 'mobile']],
			['/\\b(gen\\d{3}) b.+49h/i'],
			['model', ['vendor', 'Swiss'], ['type', 'mobile']],
			['/\\b(zur\\d{3}) b/i'],
			['model', ['vendor', 'Swiss'], ['type', 'tablet']],
			['/\\b((zeki)?tb.*\\b) b/i'],
			['model', ['vendor', 'Zeki'], ['type', 'tablet']],
			['/\\b([yr]\\d{2}) b/i', '/\\b(dragon[- ]+touch |dt)(\\w{5}) b/i'],
			[['vendor', 'Dragon Touch'], 'model', ['type', 'tablet']],
			['/\\b(ns-?\\w{0,9}) b/i'],
			['model', ['vendor', 'Insignia'], ['type', 'tablet']],
			['/\\b((nxa|next)-?\\w{0,9}) b/i'],
			['model', ['vendor', 'NextBook'], ['type', 'tablet']],
			['/\\b(xtreme\\_)?(v(1[045]|2[015]|[3469]0|7[05])) b/i'],
			[['vendor', 'Voice'], 'model', ['type', 'mobile']],
			['/\\b(lvtel\\-)?(v1[12]) b/i'],
			[['vendor', 'LvTel'], 'model', ['type', 'mobile']],
			['/\\b(ph-1) /i'],
			['model', ['vendor', 'Essential'], ['type', 'mobile']],
			['/\\b(v(100md|700na|7011|917g).*\\b) b/i'],
			['model', ['vendor', 'Envizen'], ['type', 'tablet']],
			['/\\b(trio[-\\w\\. ]+) b/i'],
			['model', ['vendor', 'MachSpeed'], ['type', 'tablet']],
			['/\\btu_(1491) b/i'],
			['model', ['vendor', 'Rotor'], ['type', 'tablet']],
			['/(shield[\\w ]+) b/i'],
			['model', ['vendor', 'Nvidia'], ['type', 'tablet']],
			['/(sprint) (\\w+)/i'],
			['vendor', 'model', ['type', 'mobile']],
			['/(kin\\.[onetw]{3})/i'],
			[['model', '/\\./', ' '], ['vendor', 'Microsoft'], ['type', 'mobile']],
			['/droid.+; (cc6666?|et5[16]|mc[239][23]x?|vc8[03]x?)\\)/i'],
			['model', ['vendor', 'Zebra'], ['type', 'tablet']],
			['/droid.+; (ec30|ps20|tc[2-8]\\d[kx])\\)/i'],
			['model', ['vendor', 'Zebra'], ['type', 'mobile']],
			['/(ouya)/i', '/(nintendo) ([wids3utch]+)/i'],
			['vendor', 'model', ['type', 'console']],
			['/droid.+; (shield) bui/i'],
			['model', ['vendor', 'Nvidia'], ['type', 'console']],
			['/(playstation [345portablevi]+)/i'],
			['model', ['vendor', 'Sony'], ['type', 'console']],
			['/\\b(xbox(?: one)?(?!; xbox))[\\); ]/i'],
			['model', ['vendor', 'Microsoft'], ['type', 'console']],
			['/smart-tv.+(samsung)/i'],
			['vendor', ['type', 'smarttv']],
			['/hbbtv.+maple;(\\d+)/i'],
			[['model', '/^/', 'SmartTV'], ['vendor', 'Samsung'], ['type', 'smarttv']],
			['/(nux; netcast.+smarttv|lg (netcast\\.tv-201\\d|android tv))/i'],
			[['vendor', 'LG'], ['type', 'smarttv']],
			['/(apple) ?tv/i'],
			['vendor', ['model', 'Apple TV'], ['type', 'smarttv']],
			['/crkey/i'],
			[['model', 'Chromecast'], ['vendor', 'Google'], ['type', 'smarttv']],
			['/droid.+aft(\\w)( bui|\\))/i'],
			['model', ['vendor', 'Amazon'], ['type', 'smarttv']],
			['/\\(dtv[\\);].+(aquos)/i', '/(aquos-tv[\\w ]+)\\)/i'],
			['model', ['vendor', 'Sharp'], ['type', 'smarttv']],
			['/(bravia[\\w ]+)( bui|\\))/i'],
			['model', ['vendor', 'Sony'], ['type', 'smarttv']],
			['/(mitv-\\w{5}) bui/i'],
			['model', ['vendor', 'Xiaomi'], ['type', 'smarttv']],
			[
				'/\\b(roku)[\\dx]*[\\)\\/]((?:dvp-)?[\\d\\.]*)/i',
				'/hbbtv\\/\\d+\\.\\d+\\.\\d+ +\\([\\w ]*; *(\\w[^;]*);([^;]*)/i',
			],
			[['vendor', 'utilTrim'], ['model', 'utilTrim'], ['type', 'smarttv']],
			['/\\b(android tv|smart[- ]?tv|opera tv|tv; rv:)\\b/i'],
			[['type', 'smarttv']],
			['/((pebble))app/i'],
			['vendor', 'model', ['type', 'wearable']],
			['/droid.+; (glass) \\d/i'],
			['model', ['vendor', 'Google'], ['type', 'wearable']],
			['/droid.+; (wt63?0{2,3})\\)/i'],
			['model', ['vendor', 'Zebra'], ['type', 'wearable']],
			['/(quest( 2)?)/i'],
			['model', ['vendor', 'Facebook'], ['type', 'wearable']],
			['/(tesla)(?: qtcarbrowser|\\/[-\\w\\.]+)/i'],
			['vendor', ['type', 'embedded']],
			['/droid .+?; ([^;]+?)(?: bui|\\) applew).+? mobile safari/i'],
			['model', ['type', 'mobile']],
			['/droid .+?; ([^;]+?)(?: bui|\\) applew).+?(?! mobile) safari/i'],
			['model', ['type', 'tablet']],
			['/\\b((tablet|tab)[;\\/]|focus\\/\\d(?!.+mobile))/i'],
			[['type', 'tablet']],
			['/(phone|mobile(?:[;\\/]| [ \\w\\/\\.]*safari)|pda(?=.+windows ce))/i'],
			[['type', 'mobile']],
			['/(android[-\\w\\. ]{0,9});.+buil/i'],
			['model', ['vendor', 'Generic']],
		],
		'engine' => [
			['/windows.+ edge\\/([\\w\\.]+)/i'],
			['version', ['name', 'EdgeHTML']],
			['/webkit\\/537\\.36.+chrome\\/(?!27)([\\w\\.]+)/i'],
			['version', ['name', 'Blink']],
			[
				'/(presto)\\/([\\w\\.]+)/i',
				'/(webkit|trident|netfront|netsurf|amaya|lynx|w3m|goanna)\\/([\\w\\.]+)/i',
				'/ekioh(flow)\\/([\\w\\.]+)/i',
				'/(khtml|tasman|links)[\\/ ]\\(?([\\w\\.]+)/i',
				'/(icab)[\\/ ]([23]\\.[\\d\\.]+)/i',
			],
			['name', 'version'],
			['/rv\\:([\\w\\.]{1,9})\\b.+(gecko)/i'],
			['version', 'name'],
		],
		'os' => [
			['/microsoft (windows) (vista|xp)/i'],
			['name', 'version'],
			[
				'/(windows) nt 6\\.2; (arm)/i',
				'/(windows (?:phone(?: os)?|mobile))[\\/ ]?([\\d\\.\\w ]*)/i',
				'/(windows)[\\/ ]?([ntce\\d\\. ]+\\w)(?!.+xbox)/i',
			],
			['name', ['version', 'mapping', 'windows']],
			['/(win(?=3|9|n)|win 9x )([nt\\d\\.]+)/i'],
			[['name', 'Windows'], ['version', 'mapping', 'windows']],
			['/ip[honead]{2,4}\\b(?:.*os ([\\w]+) like mac|; opera)/i', '/cfnetwork\\/.+darwin/i'],
			[['version', '/_/', '.'], ['name', 'iOS']],
			['/(mac os x) ?([\\w\\. ]*)/i', '/(macintosh|mac_powerpc\\b)(?!.+haiku)/i'],
			[['name', 'Mac OS'], ['version', '/_/', '.']],
			['/droid ([\\w\\.]+)\\b.+(android[- ]x86|harmonyos)/i'],
			['version', 'name'],
			['/mozilla\\/5.0 \\(linux; ; \\) applewebkit\\/ \\(khtml, like gecko\\) chrome\\/ mobile safari\\//i'],
			[['name', 'Android'], ['version', 'Unknown']],
			[
				'/(android|webos|qnx|bada|rim tablet os|maemo|meego|sailfish)[-\\/ ]?([\\w\\.]*)/i',
				'/(blackberry)\\w*\\/([\\w\\.]*)/i',
				'/(tizen|kaios)[\\/ ]([\\w\\.]+)/i',
				'/\\((series40);/i',
			],
			['name', 'version'],
			['/\\(bb(10);/i'],
			['version', ['name', 'BlackBerry']],
			['/(?:symbian ?os|symbos|s60(?=;)|series60)[-\\/ ]?([\\w\\.]*)/i'],
			['version', ['name', 'Symbian']],
			['/mozilla\\/[\\d\\.]+ \\((?:mobile|tablet|tv|mobile; [\\w ]+); rv:.+ gecko\\/([\\w\\.]+)/i'],
			['version', ['name', 'Firefox OS']],
			['/web0s;.+rt(tv)/i', '/\\b(?:hp)?wos(?:browser)?\\/([\\w\\.]+)/i'],
			['version', ['name', 'webOS']],
			['/crkey\\/([\\d\\.]+)/i'],
			['version', ['name', 'Chromecast']],
			['/(cros) [\\w]+ ([\\w\\.]+\\w)/i'],
			[['name', 'Chromium OS'], 'version'],
			[
				'/(nintendo|playstation) ([wids345portablevuch]+)/i',
				'/(xbox); +xbox ([^\\);]+)/i',
				'/\\b(joli|palm)\\b ?(?:os)?\\/?([\\w\\.]*)/i',
				'/(mint)[\\/\\(\\) ]?(\\w*)/i',
				'/(mageia|vectorlinux)[; ]/i',
				'/([kxln]?ubuntu|debian|suse|opensuse|gentoo|arch(?= linux)|slackware|fedora|mandriva|centos|pclinuxos|red ?hat|zenwalk|linpus|raspbian|plan 9|minix|risc os|contiki|deepin|manjaro|elementary os|sabayon|linspire)(?: gnu\\/linux)?(?: enterprise)?(?:[- ]linux)?(?:-gnu)?[-\\/ ]?(?!chrom|package)([-\\w\\.]*)/i',
				'/(hurd|linux) ?([\\w\\.]*)/i',
				'/(gnu) ?([\\w\\.]*)/i',
				'/\\b([-frentopcghs]{0,5}bsd|dragonfly)[\\/ ]?(?!amd|[ix346]{1,2}86)([\\w\\.]*)/i',
				'/(haiku) (\\w+)/i',
			],
			['name', 'version'],
			['/(sunos) ?([\\w\\.\\d]*)/i'],
			[['name', 'Solaris'], 'version'],
			[
				'/((?:open)?solaris)[-\\/ ]?([\\w\\.]*)/i',
				'/(aix) ((\\d)(?=\\.|\\)| )[\\w\\.])*/i',
				'/\\b(beos|os\\/2|amigaos|morphos|openvms|fuchsia|hp-ux)/i',
				'/(unix) ?([\\w\\.]*)/i',
			],
			['name', 'version'],
		],
	];

	/**
	 * Constructor.
	 * If a user agent is provided to the constructor - it will be used.
	 * If a user agent is not provided to the constructor - it will be auto-detected by PHP.
	 * @param string $userAgent - user agent for this instance
	 */
	function __construct($userAgent = null) {
		if (empty($userAgent)) {
			$this->userAgent = $_SERVER['HTTP_USER_AGENT'];
		} else {
			$this->userAgent = $userAgent;
		}
	}

	/**
	 * Static helper used to determine major browser version from the full version.
	 * @param string $version - full version string to determine major version
	 * @return string
	 */
	private static function parseMajor($version) {
		if (gettype($version) === 'string') {
			$exploded = explode('.', preg_replace('/[^\d\.]/', '', $version));
			return $exploded[0];
		}
		return '';
	}

	/**
	 * Static helper used to determine if one string is contained in another (case insensitive).
	 * @param string $str1
	 * @param string $str2
	 * @return boolean
	 */
	private static function utilHas($str1, $str2) {
		return strrpos(strtolower($str2), strtolower($str1)) !== false;
	}

	/**
	 * Static helper used to trim variables from white-spaces.
	 * @param string $str
	 * @return string
	 */
	private static function utilTrim($str) {
		return trim($str);
	}

	/**
	 * Static helper used to turn strings to lowercase.
	 * @param string $str
	 * @return string
	 */
	private static function utilLowerize($str) {
		return strtolower($str);
	}

	/**
	 * Static helper used to find the correct value based on some mapping.
	 * @param string $str - string to search for in the map
	 * @param array $map - map to use
	 * @return string
	 */
	private static function mapperStr($str, $map) {
		foreach ($map as $i => $useless) {
			if (gettype($map[$i]) === 'array' && count($map[$i]) > 0) {
				for ($j = 0; $j < count($map[$i]); $j++) {
					if (self::utilHas($map[$i][$j], $str)) {
						return $i;
					}
				}
			} elseif (self::utilHas($map[$i], $str)) {
				return $i;
			}
		}
		return $str;
	}

	/**
	 * Main method used to loop all regular expressions and try to find a match.
	 * @param string $element - element where the variables will be stored (passed by reference).
	 * @param array $regularExpressions - list of regular expressions to search for a match.
	 */
	private function mapperRegularExpressions(&$element, $regularExpressions) {
		$matches = null;
		$i = 0;
		while ($i < count($regularExpressions) && !$matches) {
			$regex = $regularExpressions[$i];
			$props = $regularExpressions[$i + 1];
			$j = $k = 0;
			while ($j < count($regex) && !$matches) {
				$regExpString = $regex[$j++];
				preg_match($regExpString, $this->userAgent, $matches);
				if (count($matches)) {
					for ($p = 0; $p < count($props); $p++) {
						$k++;
						$match = isset($matches[$k]) ? $matches[$k] : null;
						$q = $props[$p];
						if (gettype($q) === 'array') {
							if (count($q) === 2) {
								if (method_exists($this, $q[1])) {
									$element[$q[0]] = call_user_func([$this, $q[1]], $match);
								} else {
									$element[$q[0]] = $q[1];
								}
							} elseif (count($q) === 3) {
								if ($q[1] === 'mapping') {
									$element[$q[0]] = $match ? self::mapperStr($match, self::$mapping[$q[2]]) : '';
								} else {
									$element[$q[0]] = $match ? preg_replace($q[1], $q[2], $match) : '';
								}
							} elseif (count($q) == 4) {
								$element[$q[0]] = $match
									? call_user_func([$this, $q[3]], preg_replace($q[1], $q[2], $match))
									: '';
							}
						} else {
							$element[$q] = !empty($match) ? $match : '';
						}
					}
				}
			}
			$i += 2;
		}
	}

	/**
	 * Method used to get the browser information.
	 * @return array
	 */
	function getBrowser() {
		$browser = [
			'name' => '',
			'version' => '',
			'major' => '',
		];
		$this->mapperRegularExpressions($browser, self::$regexes['browser']);
		if (strtolower($browser['name']) === 'baidu' || strtolower($browser['name']) === 'baidubrowser') {
			$browser['name'] = 'Baidu';
		} elseif (strtolower($browser['name']) === 'mozilla') {
			$browser['name'] = 'Firefox';
		} elseif (strtolower($browser['name']) === 'nokiabrowser') {
			$browser['name'] = 'Nokia Browser';
		} elseif (strtolower($browser['name']) === 'ie') {
			$browser['name'] = 'Internet Explorer';
		} elseif (strtolower($browser['name']) === 'qq' || strtolower($browser['name']) === 'qqbrowser') {
			$browser['name'] = 'QQ Browser';
		}
		$browser['major'] = $browser['version'] == '' ? '' : self::parseMajor($browser['version']);
		return $browser;
	}

	/**
	 * Method used to get the CPU information.
	 * @return array
	 */
	function getCPU() {
		$cpu = [
			'architecture' => '',
		];
		$this->mapperRegularExpressions($cpu, self::$regexes['cpu']);
		return $cpu;
	}

	/**
	 * Method used to get the device information.
	 * @return array
	 */
	function getDevice() {
		$device = [
			'vendor' => '',
			'model' => '',
			'type' => '',
		];
		$this->mapperRegularExpressions($device, self::$regexes['device']);
		$os = $this->getOS();
		if ($device['type'] === '' && $os['name'] === 'Android') {
			$device['vendor'] = 'Generic Android';
			$device['type'] = 'mobile';
		}
		if ($device['vendor'] === 'Samsung' && $device['model'] === 'Browser') {
			$device['model'] = 'Unknown';
		}
		if (strpos($device['model'], ';') !== false) {
			$device['model'] = substr($device['model'], 0, strpos($device['model'], ';'));
		}
		return $device;
	}

	/**
	 * Method used to get the engine information.
	 * @return array
	 */
	function getEngine() {
		$engine = [
			'name' => '',
			'version' => '',
		];
		$this->mapperRegularExpressions($engine, self::$regexes['engine']);
		return $engine;
	}

	/**
	 * Method used to get the OS information.
	 * @return array
	 */
	function getOS() {
		$os = [
			'name' => '',
			'version' => '',
		];
		$this->mapperRegularExpressions($os, self::$regexes['os']);
		$os['version'] = '' . $os['version'];
		return $os;
	}

	/**
	 * Getter used to get the current user agent.
	 * @return string
	 */
	function getUA() {
		return $this->userAgent;
	}

	/**
	 * Method used to get all information at once.
	 * @return array
	 */
	function getResult() {
		return [
			'ua' => $this->getUA(),
			'browser' => $this->getBrowser(),
			'engine' => $this->getEngine(),
			'os' => $this->getOS(),
			'device' => $this->getDevice(),
			'cpu' => $this->getCPU(),
		];
	}
}
