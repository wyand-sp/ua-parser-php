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
	private static $mapping = array(
		'safari' => array (
			'1.0' => '/8',
			'1.2' => '/1',
			'1.3' => '/3',
			'2.0' => '/412',
			'2.0.2' => '/416',
			'2.0.3' => '/417',
			'2.0.4' => '/419'
		),
		'windows' => array (
			'ME' => '4.90',
			'NT 3.11' => 'NT3.51',
			'NT 4.0' => 'NT4.0',
			'2000' => 'NT 5.0',
			'XP' => array('NT 5.1', 'NT 5.2'),
			'Vista' => 'NT 6.0',
			'7' => 'NT 6.1',
			'8' => 'NT 6.2',
			'8.1' => 'NT 6.3',
			'10' => array('NT 6.4', 'NT 10.0'),
			'RT' => 'ARM'
		)
	);

	/**
	 * Private static variable used to store all regular expressions used to determine browser, device, os, etc.
	 * It is filled with contents from the JSON file when the class is used at least once.
	 */
	private static $regexes = null;

	/**
	 * Constructor.
	 * If a user agent is provided to the constructor - it will be used.
	 * If a user agent is not provided to the constructor - it will be auto-detected by PHP.
	 * If the $regexes variable is empty - it will be filled from uaparser.class.json.
	 * @param string $userAgent - user agent for this instance
	 */
	function __construct($userAgent = null) {
		if (empty(self::$regexes)) {
			self::$regexes = json_decode(
				file_get_contents(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'uaparser.class.json'),
				true
			);
		}
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
			return explode('.', preg_replace('/[^\d\.]/', '', $version))[0];
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
			} else if (self::utilHas($map[$i], $str)) {
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
									$element[$q[0]] = call_user_func(array($this, $q[1]), $match);
								} else {
									$element[$q[0]] = $q[1];
								}
							} else if (count($q) === 3) {
								if ($q[1] === 'mapping') {
									$element[$q[0]] = $match ? self::mapperStr($match, self::$mapping[$q[2]]) : '';
								} else {
									$element[$q[0]] = $match ? preg_replace($q[1], $q[2], $match) : '';
								}
							} else if (count($q) == 4) {
								$element[$q[0]] = $match ? call_user_func(array($this, $q[3]), preg_replace($q[1], $q[2], $match)) : '';
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
		$browser = array(
			'name' => '',
			'version' => '',
			'major' => ''
		);
		$this->mapperRegularExpressions($browser, self::$regexes['browser']);
		if (strtolower($browser['name']) === 'baidu') {
			$browser['name'] = 'Baidu';
		} else if (strtolower($browser['name']) === 'mozilla') {
			$browser['name'] = 'Firefox';
		} else if (strtolower($browser['name']) === 'nokiabrowser') {
			$browser['name'] = 'Nokia Browser';
		} else if (strtolower($browser['name']) === 'ie') {
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
		$cpu = array(
			'architecture' => ''
		);
		$this->mapperRegularExpressions($cpu, self::$regexes['cpu']);
		return $cpu;
	}

	/**
	 * Method used to get the device information.
	 * @return array
	 */
	function getDevice() {
		$device = array(
			'vendor' => '',
			'model' => '',
			'type' => ''
		);
		$this->mapperRegularExpressions($device, self::$regexes['device']);
		return $device;
	}

	/**
	 * Method used to get the engine information.
	 * @return array
	 */
	function getEngine() {
		$engine = array(
			'name' => '',
			'version' => ''
		);
		$this->mapperRegularExpressions($engine, self::$regexes['engine']);
		return $engine;
	}

	/**
	 * Method used to get the OS information.
	 * @return array
	 */
	function getOS() {
		$os = array(
			'name' => '',
			'version' => ''
		);
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
		return array(
			'ua' => $this->getUA(),
			'browser' => $this->getBrowser(),
			'engine' => $this->getEngine(),
			'os' => $this->getOS(),
			'device' => $this->getDevice(),
			'cpu' => $this->getCPU()
		);
	}
}