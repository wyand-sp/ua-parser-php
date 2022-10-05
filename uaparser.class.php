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
			[
				'/(opera\\smini)\\/([\\w\\.-]+)/i',
				'/(opera\\s[mobiletab]+).+version\\/([\\w\\.-]+)/i',
				'/(opera).+version\\/([\\w\\.]+)/i',
				'/(opera)[\\/\\s]+([\\w\\.]+)/i',
			],
			['name', 'version'],
			['/(opios)[\\/\\s]+([\\w\\.]+)/i'],
			[['name', 'Opera Mini'], 'version'],
			['/\\s(opr)\\/([\\w\\.]+)/i'],
			[['name', 'Opera'], 'version'],
			['/\\s(opt)\\/([\\w\\.]+)/i'],
			[['name', 'Opera'], 'version'],
			[
				'/(kindle)\\/([\\w\\.]+)/i',
				'/(lunascape|maxthon|netfront|jasmine|blazer)[\\/\\s]?([\\w\\.]+)*/i',
				'/(avant\\s|iemobile|slim|baidu)(?:browser)?[\\/\\s]?([\\w\\.]*)/i',
				'/(?:ms|\\()(ie)\\s([\\w\\.]+)/i',
				'/(rekonq)\\/([\\w\\.]+)*/i',
				'/(chromium|flock|rockmelt|midori|epiphany|silk|skyfire|ovibrowser|bolt|iron|vivaldi|iridium|phantomjs|bowser)\\/([\\w\\.-]+)/i',
			],
			['name', 'version'],
			['/(trident).+rv[:\\s]([\\w\\.]+).+like\\sgecko/i'],
			[['name', 'Internet Explorer'], 'version'],
			['/(edge)\\/((\\d+)?[\\w\\.]+)/i'],
			['name', 'version'],
			['/(yabrowser)\\/([\\w\\.]+)/i'],
			[['name', 'Yandex'], 'version'],
			['/(puffin)\\/([\\w\\.]+)/i'],
			[['name', 'Puffin'], 'version'],
			['/((?:[\\s\\/])uc?\\s?browser|(?:juc.+)ucweb)[\\/\\s]?([\\w\\.]+)/i'],
			[['name', 'UC Browser'], 'version'],
			['/(micromessenger)\\/([\\w\\.]+)/i'],
			[['name', 'WeChat'], 'version'],
			['/(QQ)\\/([\\d\\.]+)/i'],
			[['name', 'QQ Browser'], 'version'],
			['/m?(qqbrowser)[\\/\\s]?([\\w\\.]+)/i'],
			[['name', 'QQ Browser'], 'version'],
			['/xiaomi\\/miuibrowser\\/([\\w\\.]+)/i'],
			['version', ['name', 'MIUI Browser']],
			['/;fbsv\\/([\\w\\.]+);/i'],
			['version', ['name', 'Facebook app browser']],
			['/;fbav\\/([\\w\\.]+);/i'],
			['version', ['name', 'Facebook app browser']],
			['/\\s(instagram)\\s([\\w\\.]+)/i'],
			[['name', 'Instagram app browser'], 'version'],
			['/headlesschrome(?:\\/([\\w\\.]+)|\\s)/i'],
			['version', ['name', 'Chrome Headless']],
			['/\\swv\\).+(chrome)\\/([\\w\\.]+)/i'],
			[['name', '/(.+)/', "$1 WebView"], 'version'],
			['/((?:oculus|samsung)browser)\\/([\\w\\.]+)/i'],
			[['name', '/(.+(?:g|us))(.+)/', "$1 $2"], 'version'],
			['/android.+version\\/([\\w\\.]+)\\s+(?:mobile\\s?safari|safari)*/i'],
			['version', ['name', 'Android Browser']],
			['/(chrome|omniweb|arora|[tizenoka]{5}\\s?browser)\\/v?([\\w\\.]+)/i'],
			['name', 'version'],
			['/(dolfin)\\/([\\w\\.]+)/i'],
			[['name', 'Dolphin'], 'version'],
			['/((?:android.+)crmo|crios)\\/([\\w\\.]+)/i'],
			[['name', 'Chrome'], 'version'],
			['/(coast)\\/([\\w\\.]+)/i'],
			[['name', 'Opera Coast'], 'version'],
			['/fxios\\/([\\w\\.-]+)/i'],
			['version', ['name', 'Firefox']],
			['/version\\/([\\w\\.]+).+?mobile\\/\\w+\\s(safari)/i'],
			['version', ['name', 'Mobile Safari']],
			['/version\\/([\\w\\.]+).+?(mobile\\s?safari|safari)/i'],
			['version', 'name'],
			['/webkit.+?(gsa)\\/([\\w\\.]+).+?(mobile\\s?safari|safari)(\\/[\\w\\.]+)/i'],
			[['name', 'Google Search Application'], 'version'],
			['/webkit.+?(mobile\\s?safari|safari)(\\/[\\w\\.]+)/i'],
			['name', ['version', 'mapping', 'safari']],
			['/(konqueror)\\/([\\w\\.]+)/i', '/(webkit|khtml)\\/([\\w\\.]+)/i'],
			['name', 'version'],
			['/(navigator|netscape)\\/([\\w\\.-]+)/i'],
			[['name', 'Netscape'], 'version'],
			[
				'/(swiftfox)/i',
				'/(icedragon|iceweasel|camino|chimera|fennec|maemo\\sbrowser|minimo|conkeror)[\\/\\s]?([\\w\\.\\+]+)/i',
				'/(firefox|seamonkey|k-meleon|icecat|iceape|firebird|phoenix)\\/([\\w\\.-]+)/i',
				'/(mozilla)\\/([\\w\\.]+).+rv\\:.+gecko\\/\\d+/i',
				'/(polaris|lynx|dillo|icab|doris|amaya|w3m|netsurf|sleipnir)[\\/\\s]?([\\w\\.]+)/i',
				'/(links)\\s\\(([\\w\\.]+)/i',
				'/(gobrowser)\\/?([\\w\\.]+)*/i',
				'/(ice\\s?browser)\\/v?([\\w\\._]+)/i',
				'/(mosaic)[\\/\\s]([\\w\\.]+)/i',
			],
			['name', 'version'],
		],
		'cpu' => [
			['/(?:(amd|x(?:(?:86|64)[_-])?|wow|win)64)[;\\)]/i'],
			[['architecture', 'amd64']],
			['/(ia32(?=;))/i'],
			[['architecture', 'utilLowerize']],
			['/((?:i[346]|x)86)[;\\)]/i'],
			[['architecture', 'ia32']],
			['/windows\\s(ce|mobile);\\sppc;/i'],
			[['architecture', 'arm']],
			['/((?:ppc|powerpc)(?:64)?)(?:\\smac|;|\\))/i'],
			[['architecture', '/ower/', '', 'utilLowerize']],
			['/(sun4\\w)[;\\)]/i'],
			[['architecture', 'sparc']],
			[
				'/((?:avr32|ia64(?=;))|68k(?=\\))|arm(?:64|(?=v\\d+;))|(?=atmel\\s)avr|(?:irix|mips|sparc)(?:64)?(?=;)|pa-risc)/i',
			],
			[['architecture', 'utilLowerize']],
		],
		'device' => [
			['/mozilla\\/5.0 \\(linux; ; \\) applewebkit\\/ \\(khtml, like gecko\\) chrome\\/ mobile safari\\//i'],
			[['model', 'Unknown'], ['vendor', 'Generic Android'], ['type', 'mobile']],
			['/\\((ipad|playbook);[\\w\\s\\);-]+(rim|apple)/i'],
			['model', 'vendor', ['type', 'tablet']],
			['/applecoremedia\\/[\\w\\.]+ \\((ipad)/'],
			['model', ['vendor', 'Apple'], ['type', 'tablet']],
			['/(apple\\s{0,1}tv)/i'],
			[['model', 'Apple TV'], ['vendor', 'Apple']],
			[
				'/(archos)\\s(gamepad2?)/i',
				'/(hp).+(touchpad)/i',
				'/(hp).+(tablet)/i',
				'/(kindle)\\/([\\w\\.]+)/i',
				'/\\s(nook)[\\w\\s]+build\\/(\\w+)/i',
				'/(dell)\\s(strea[kpr\\s\\d]*[\\dko])/i',
			],
			['vendor', 'model', ['type', 'tablet']],
			['/(kf[A-z]+)\\sbuild\\/[\\w\\.]+.*silk\\//i'],
			['model', ['vendor', 'Amazon'], ['type', 'tablet']],
			['/\\((ip[honed|\\s\\w*]+);.+(apple)/i'],
			['model', 'vendor', ['type', 'mobile']],
			['/\\((ip[honed|\\s\\w*]+);/i'],
			['model', ['vendor', 'Apple'], ['type', 'mobile']],
			[
				'/(blackberry)[\\s-]?(\\w+)/i',
				'/(blackberry|benq|palm(?=\\-)|sonyericsson|acer|asus|dell|meizu|motorola|polytron)[\\s_-]?([\\w-]+)*/i',
				'/(hp)\\s([\\w\\s]+\\w)/i',
				'/(asus)-?(\\w+)/i',
			],
			['vendor', 'model', ['type', 'mobile']],
			['/\\(bb10;\\s(\\w+)/i'],
			['model', ['vendor', 'BlackBerry'], ['type', 'mobile']],
			['/android.+(transfo[prime\\s]{4,10}\\s\\w+|eeepc|slider\\s\\w+|nexus 7|padfone)/i'],
			['model', ['vendor', 'Asus'], ['type', 'tablet']],
			['/(sony)\\s(tablet\\s[ps])\\sbuild\\//i', '/(sony)?(?:sgp.+)\\sbuild\\//i'],
			[['vendor', 'Sony'], ['model', 'Xperia Tablet'], ['type', 'tablet']],
			['/android.+\\s([c-g]\\d{4}|so[-l]\\w+)\\sbuild\\//i'],
			['model', ['vendor', 'Sony'], ['type', 'mobile']],
			['/\\s(ouya)\\s/i', '/(nintendo)\\s([wids3u]+)/i'],
			['vendor', 'model', ['type', 'console']],
			['/android.+;\\s(shield)\\sbuild/i'],
			['model', ['vendor', 'Nvidia'], ['type', 'console']],
			['/(playstation\\s[34portablevi]+)/i'],
			['model', ['vendor', 'Sony'], ['type', 'console']],
			['/(lenovo)\\s?(S(?:5000|6000)+(?:[-][\\w+]))/i'],
			['vendor', 'model', ['type', 'tablet']],
			[
				'/(htc)[;_\\s-]+([\\w\\s]+(?=\\))|\\w+)*/i',
				'/(zte)-(\\w+)*/i',
				'/(alcatel|geeksphone|lenovo|nexian|panasonic|(?=;\\s)sony)[_\\s-]?([\\w-]+)*/i',
			],
			['vendor', ['model', '/_/', ' '], ['type', 'mobile']],
			['/(nexus\\s9)/i'],
			['model', ['vendor', 'HTC'], ['type', 'tablet']],
			['/d\\/huawei([\\w\\s-]+)[;\\)]/i', '/(nexus\\s6p)/i'],
			['model', ['vendor', 'Huawei'], ['type', 'mobile']],
			['/(microsoft);\\s(lumia[\\s\\w]+)/i'],
			['vendor', 'model', ['type', 'mobile']],
			['/[\\s\\(;](xbox(?:\\sone)?)[\\s\\);]/i'],
			['model', ['vendor', 'Microsoft'], ['type', 'console']],
			[
				'/\\s(milestone|droid(?:[2-4x]|\\s(?:bionic|x2|pro|razr))?(:?\\s4g)?)[\\w\\s]+build\\//i',
				'/mot[\\s-]?(\\w+)*/i',
				'/(XT\\d{3,4}) build\\//i',
				'/(nexus\\s6)/i',
			],
			['model', ['vendor', 'Motorola'], ['type', 'mobile']],
			['/android.+\\s(mz60\\d|xoom[\\s2]{0,2})\\sbuild\\//i'],
			['model', ['vendor', 'Motorola'], ['type', 'tablet']],
			['/hbbtv\\/\\d+\\.\\d+\\.\\d+\\s+\\([\\w\\s]*;\\s*(\\w[^;]*);([^;]*)/i'],
			[['vendor', 'utilTrim'], ['model', 'utilTrim'], ['type', 'smarttv']],
			['/hbbtv.+maple;(\\d+)/i'],
			[['model', '/^/', 'SmartTV'], ['vendor', 'Samsung'], ['type', 'smarttv']],
			['/\\(dtv[\\);].+(aquos)/i'],
			['model', ['vendor', 'Sharp'], ['type', 'smarttv']],
			['/android.+((sch-i[89]0\\d|shw-m380s|gt-p\\d{4}|gt-n\\d+|sgh-t8[56]9|nexus 10))/i', '/((SM-T\\w+))/i'],
			[['vendor', 'Samsung'], 'model', ['type', 'tablet']],
			['/smart-tv.+(samsung)/i'],
			['vendor', ['type', 'smarttv'], 'model'],
			[
				'/((s[cgp]h-\\w+|gt-\\w+|galaxy\\snexus|sm-\\w[\\w\\d]+))/i',
				'/(sam[sung]*)[\\s-]*(\\w+-?[\\w-]*)*/i',
				'/sec-((sgh\\w+))/i',
			],
			[['vendor', 'Samsung'], 'model', ['type', 'mobile']],
			['/sie-(\\w+)*/i'],
			['model', ['vendor', 'Siemens'], ['type', 'mobile']],
			['/(maemo|nokia).*(n900|lumia\\s\\d+)/i', '/(nokia)[\\s_-]?([\\w-]+)*/i'],
			[['vendor', 'Nokia'], 'model', ['type', 'mobile']],
			['/android\\s3\\.[\\s\\w;-]{10}(a\\d{3})/i'],
			['model', ['vendor', 'Acer'], ['type', 'tablet']],
			['/android.+([vl]k\\-?\\d{3})\\s+build/i'],
			['model', ['vendor', 'LG'], ['type', 'tablet']],
			['/android\\s3\\.[\\s\\w;-]{10}(lg?)-([06cv9]{3,4})/i'],
			[['vendor', 'LG'], 'model', ['type', 'tablet']],
			['/(lg) netcast\\.tv/i'],
			['vendor', 'model', ['type', 'smarttv']],
			['/(nexus\\s[45])/i', '/lg[e;\\s\\/-]+(\\w+)*/i', '/android.+lg(\\-?[\\d\\w]+)\\s+build/i'],
			['model', ['vendor', 'LG'], ['type', 'mobile']],
			['/android.+(ideatab[a-z0-9\\-\\s]+)/i'],
			['model', ['vendor', 'Lenovo'], ['type', 'tablet']],
			['/linux;.+((jolla));/i'],
			['vendor', 'model', ['type', 'mobile']],
			['/((pebble))app\\/[\\d\\.]+\\s/i'],
			['vendor', 'model', ['type', 'wearable']],
			['/android.+;\\s(oppo)\\s?([\\w\\s]+)\\sbuild/i'],
			['vendor', 'model', ['type', 'mobile']],
			['/crkey/i'],
			[['model', 'Chromecast'], ['vendor', 'Google']],
			['/android.+;\\s(glass)\\s\\d/i'],
			['model', ['vendor', 'Google'], ['type', 'wearable']],
			['/android.+;\\s(pixel c)\\s/i'],
			['model', ['vendor', 'Google'], ['type', 'tablet']],
			['/android.+;\\s(pixel xl|pixel)\\s/i'],
			['model', ['vendor', 'Google'], ['type', 'mobile']],
			[
				"/android.+(\\w+)\\s+build\\/hm\\1/i",
				'/android.+(hm[\\s\\-_]*note?[\\s_]*(?:\\d\\w)?)\\s+build/i',
				'/android.+(mi[\\s\\-_]*(?:one|one[\\s_]plus|note lte)?[\\s_]*(?:\\d\\w)?)\\s+build/i',
				'/android.+(redmi[\\s\\-_]*(?:note)?(?:[\\s_]*[\\w\\s]+)?)\\s+build/i',
			],
			[['model', '/_/', ''], ['vendor', 'Xiaomi'], ['type', 'mobile']],
			['/android.+(mi[\\s\\-_]*(?:pad)?(?:[\\s_]*[\\w\\s]+)?)\\s+build/i'],
			[['model', '/_/', ''], ['vendor', 'Xiaomi'], ['type', 'tablet']],
			['/android.+;\\s(m[1-5]\\snote)\\sbuild/i'],
			['model', ['vendor', 'Meizu'], ['type', 'tablet']],
			['/android.+a000(1)\\s+build/i'],
			['model', ['vendor', 'OnePlus'], ['type', 'mobile']],
			['/android.+[;\\/]\\s*(RCT[\\d\\w]+)\\s+build/i'],
			['model', ['vendor', 'RCA'], ['type', 'tablet']],
			['/android.+[;\\/]\\s*(Venue[\\d\\s]*)\\s+build/i'],
			['model', ['vendor', 'Dell'], ['type', 'tablet']],
			['/android.+[;\\/]\\s*(Q[T|M][\\d\\w]+)\\s+build/i'],
			['model', ['vendor', 'Verizon'], ['type', 'tablet']],
			['/android.+[;\\/]\\s+(Barnes[&\\s]+Noble\\s+|BN[RT])(V?.*)\\s+build/i'],
			[['vendor', 'Barnes & Noble'], 'model', ['type', 'tablet']],
			['/android.+[;\\/]\\s+(TM\\d{3}.*\\b)\\s+build/i'],
			['model', ['vendor', 'NuVision'], ['type', 'tablet']],
			['/android.+[;\\/]\\s*(zte)?.+(k\\d{2})\\s+build/i'],
			[['vendor', 'ZTE'], 'model', ['type', 'tablet']],
			['/android.+[;\\/]\\s*(gen\\d{3})\\s+build.*49h/i'],
			['model', ['vendor', 'Swiss'], ['type', 'mobile']],
			['/android.+[;\\/]\\s*(zur\\d{3})\\s+build/i'],
			['model', ['vendor', 'Swiss'], ['type', 'tablet']],
			['/android.+[;\\/]\\s*((Zeki)?TB.*\\b)\\s+build/i'],
			['model', ['vendor', 'Zeki'], ['type', 'tablet']],
			[
				'/(android).+[;\\/]\\s+([YR]\\d{2}x?.*)\\s+build/i',
				'/android.+[;\\/]\\s+(Dragon[\\-\\s]+Touch\\s+|DT)(.+)\\s+build/i',
			],
			[['vendor', 'Dragon Touch'], 'model', ['type', 'tablet']],
			['/android.+[;\\/]\\s*(NS-?.+)\\s+build/i'],
			['model', ['vendor', 'Insignia'], ['type', 'tablet']],
			['/android.+[;\\/]\\s*((NX|Next)-?.+)\\s+build/i'],
			['model', ['vendor', 'NextBook'], ['type', 'tablet']],
			['/android.+[;\\/]\\s*(Xtreme\\_?)?(V(1[045]|2[015]|30|40|60|7[05]|90))\\s+build/i'],
			[['vendor', 'Voice'], 'model', ['type', 'mobile']],
			['/android.+[;\\/]\\s*(LVTEL\\-?)?(V1[12])\\s+build/i'],
			[['vendor', 'LvTel'], 'model', ['type', 'mobile']],
			['/android.+[;\\/]\\s*(V(100MD|700NA|7011|917G).*\\b)\\s+build/i'],
			['model', ['vendor', 'Envizen'], ['type', 'tablet']],
			['/android.+[;\\/]\\s*(Le[\\s\\-]+Pan)[\\s\\-]+(.*\\b)\\s+build/i'],
			['vendor', 'model', ['type', 'tablet']],
			['/android.+[;\\/]\\s*(Trio[\\s\\-]*.*)\\s+build/i'],
			['model', ['vendor', 'MachSpeed'], ['type', 'tablet']],
			['/android.+[;\\/]\\s*(Trinity)[\\-\\s]*(T\\d{3})\\s+build/i'],
			['vendor', 'model', ['type', 'tablet']],
			['/android.+[;\\/]\\s*TU_(1491)\\s+build/i'],
			['model', ['vendor', 'Rotor'], ['type', 'tablet']],
			['/android.+(KS(.+))\\s+build/i'],
			['model', ['vendor', 'Amazon'], ['type', 'tablet']],
			['/android.+(Gigaset)[\\s\\-]+(Q.+)\\s+build/i'],
			['vendor', 'model', ['type', 'tablet']],
			['/(android.+)[;\\/].+build/i'],
			['model', ['vendor', 'Generic Android']],
		],
		'engine' => [
			['/windows.+\\sedge\\/([\\w\\.]+)/i'],
			['version', ['name', 'EdgeHTML']],
			[
				'/(presto)\\/([\\w\\.]+)/i',
				'/(webkit|trident|netfront|netsurf|amaya|lynx|w3m)\\/([\\w\\.]+)/i',
				'/(khtml|tasman|links)[\\/\\s]\\(?([\\w\\.]+)/i',
				'/(icab)[\\/\\s]([23]\\.[\\d\\.]+)/i',
			],
			['name', 'version'],
			['/rv\\:([\\w\\.]+).*(gecko)/i'],
			['version', 'name'],
		],
		'os' => [
			['/microsoft\\s(windows)\\s(vista|xp)/i'],
			['name', 'version'],
			[
				'/(windows)\\snt\\s6\\.2;\\s(arm)/i',
				'/(windows\\sphone(?:\\sos)*)[\\s\\/]?([\\d\\.\\s]+\\w)*/i',
				'/(windows\\smobile|windows)[\\s\\/]?([ntce\\d\\.\\s]+\\w)/i',
			],
			['name', ['version', 'mapping', 'windows']],
			['/(win(?=3|9|n)|win\\s9x\\s)([nt\\d\\.]+)/i'],
			[['name', 'Windows'], ['version', 'mapping', 'windows']],
			['/\\((bb)(10);/i'],
			[['name', 'BlackBerry'], 'version'],
			['/mozilla\\/5.0 \\(linux; ; \\) applewebkit\\/ \\(khtml, like gecko\\) chrome\\/ mobile safari\\//i'],
			[['name', 'Android'], ['version', 'Unknown']],
			[
				'/(blackberry)\\w*\\/?([\\w\\.]+)*/i',
				'/(tizen)[\\/\\s]([\\w\\.]+)/i',
				'/(android|webos|palm\\sos|qnx|bada|rim\\stablet\\sos|meego|contiki)[\\/\\s-]?([\\w\\.]+)*/i',
				'/linux;.+(sailfish);/i',
			],
			['name', 'version'],
			['/(symbian\\s?os|symbos|s60(?=;))[\\/\\s-]?([\\w\\.]+)*/i'],
			[['name', 'Symbian'], 'version'],
			['/\\((series40);/i'],
			['name'],
			['/mozilla.+\\(mobile;.+gecko.+firefox/i'],
			[['name', 'Firefox OS'], 'version'],
			[
				'/(nintendo|playstation)\\s([wids34portablevu]+)/i',
				'/(mint)[\\/\\s\\(]?(\\w+)*/i',
				'/(mageia|vectorlinux)[;\\s]/i',
				'/(joli|[kxln]?ubuntu|debian|[open]*suse|gentoo|(?=\\s)arch|slackware|fedora|mandriva|centos|pclinuxos|redhat|zenwalk|linpus)[\\/\\s-]?(?!chrom)([\\w\\.-]+)*/i',
				'/(hurd|linux)\\s?([\\w\\.]+)*/i',
				'/(gnu)\\s?([\\w\\.]+)*/i',
			],
			['name', 'version'],
			['/(cros)\\s[\\w]+\\s([\\w\\.]+\\w)/i'],
			[['name', 'Chromium OS'], 'version'],
			['/(sunos)\\s?([\\w\\.]+\\d)*/i'],
			[['name', 'Solaris'], 'version'],
			['/\\s([frentopc-]{0,4}bsd|dragonfly)\\s?([\\w\\.]+)*/i'],
			['name', 'version'],
			['/(haiku)\\s(\\w+)/i'],
			['name', 'version'],
			['/cfnetwork\\/.+darwin/i', '/ip[honead]+(?:.*os\\s([\\w]+)\\slike\\smac|;\\sopera)/i'],
			[['version', '/_/', '.'], ['name', 'iOS']],
			['/(mac\\sos\\sx)\\s?([\\w\\s\\.]+\\w)*/i', '/(macintosh|mac(?=_powerpc)\\s)/i'],
			[['name', 'Mac OS'], ['version', '/_/', '.']],
			[
				'/((?:open)?solaris)[\\/\\s-]?([\\w\\.]+)*/i',
				'/(aix)\\s((\\d)(?=\\.|\\)|\\s)[\\w\\.]*)*/i',
				'/(plan\\s9|minix|beos|os\\/2|amigaos|morphos|risc\\sos|openvms)/i',
				'/(unix)\\s?([\\w\\.]+)*/i',
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
	 * @param string $regularExpressions - list of regular expressions to search for a match.
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
		if (strtolower($browser['name']) === 'baidu') {
			$browser['name'] = 'Baidu';
		} elseif (strtolower($browser['name']) === 'mozilla') {
			$browser['name'] = 'Firefox';
		} elseif (strtolower($browser['name']) === 'nokiabrowser') {
			$browser['name'] = 'Nokia Browser';
		} elseif (strtolower($browser['name']) === 'ie') {
			$browser['name'] = 'Internet Explorer';
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
