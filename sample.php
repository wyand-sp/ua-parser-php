<?php
include(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'uaparser.class.php');

/**
 * Sample code using UAParser with user agent passed to the constructor.
 */
$sampleOne = new UAParser('Mozilla/5.0 (Linux; Android 5.0.2; SAMSUNG SM-G925F Build/LRX22G) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/3.0 Chrome/38.0.2125.102 Mobile Safari/537.36');
print_r($sampleOne->getResult());

/**
 * Sample code using UAParser with user agent auto-detection.
 */
$sampleTwo = new UAParser();
print_r($sampleTwo->getBrowser());
print_r($sampleTwo->getCPU());
print_r($sampleTwo->getDevice());
print_r($sampleTwo->getOS());
print_r($sampleTwo->getEngine());