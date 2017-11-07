<?php
/**
 *
 */
class UAParser {
	/**
	 *
	 */
	private $userAgent;

	/**
	 *
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
	 *
	 */
	private static $regexes = null;

	/**
	 *
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
	 * @return string
	 */
	private static function parseMajor($version) {
		if (gettype($version) === 'string') {
			return explode('.', preg_replace('/[^\d\.]/', '', $version))[0];
		}
		return 'undefined';
	}

	/**
	 * @return boolean
	 */
	private static function utilHas($str1, $str2) {
		return strrpos(strtolower($str2), strtolower($str1)) !== false;
	}

	/**
	 * @return string
	 */
	private static function utilTrim($str) {
		return trim($str);
	}

	/**
	 * @return string
	 */
	private static function utilLowerize($str) {
		return strtolower($str);
	}

	/**
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
	 *
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
									$element[$q[0]] = $match ? self::mapperStr($match, self::$mapping[$q[2]]) : 'undefined';
								} else {
									$element[$q[0]] = $match ? preg_replace($q[1], $q[2], $match) : 'undefined';
								}
							} else if (count($q) == 4) {
								$element[$q[0]] = $match ? call_user_func(array($this, $q[3]), preg_replace($q[1], $q[2], $match)) : 'undefined';
							}
						} else {
							$element[$q] = !empty($match) ? $match : 'undefined';
						}
					}
				}
			}
			$i += 2;
		}
	}

	/**
	 * @return array
	 */
	function getBrowser() {
		$browser = array(
			'name' => 'undefined',
			'version' => 'undefined',
			'major' => 'undefined'
		);
		$this->mapperRegularExpressions($browser, self::$regexes['browser']);
		$browser['major'] = $browser['version'] == 'undefined' ? 'undefined' : self::parseMajor($browser['version']);
		return $browser;
	}

	/**
	 * @return array
	 */
	function getCPU() {
		$cpu = array(
			'architecture' => 'undefined'
		);
		$this->mapperRegularExpressions($cpu, self::$regexes['cpu']);
		return $cpu;
	}

	/**
	 * @return array
	 */
	function getDevice() {
		$device = array(
			'vendor' => 'undefined',
			'model' => 'undefined',
			'type' => 'undefined'
		);
		$this->mapperRegularExpressions($device, self::$regexes['device']);
		return $device;
	}

	/**
	 * @return array
	 */
	function getEngine() {
		$engine = array(
			'name' => 'undefined',
			'version' => 'undefined'
		);
		$this->mapperRegularExpressions($engine, self::$regexes['engine']);
		return $engine;
	}

	/**
	 * @return array
	 */
	function getOS() {
		$os = array(
			'name' => 'undefined',
			'version' => 'undefined'
		);
		$this->mapperRegularExpressions($os, self::$regexes['os']);
		$os['version'] = '' . $os['version'];
		return $os;
	}

	/**
	 * @return string
	 */
	function getUA() {
		return $this->userAgent;
	}

	/**
	 * @return array
	 */
	function getResult() {
		return array(
			'ua' => $this->getUA($this->userAgent),
			'browser' => $this->getBrowser($this->userAgent),
			'engine' => $this->getEngine($this->userAgent),
			'os' => $this->getOS($this->userAgent),
			'device' => $this->getDevice($this->userAgent),
			'cpu' => $this->getCPU($this->userAgent)
		);
	}
}