<?php
include(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'uaparser.class.php');

$sampleOne = new UAParser('Mozilla/5.0 (Linux; Android 5.0.2; SAMSUNG SM-G925F Build/LRX22G) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/3.0 Chrome/38.0.2125.102 Mobile Safari/537.36');
print_r($sampleOne->getResult());

$sampleTwo = new UAParser();
print_r($sampleOne->getBrowser());
print_r($sampleOne->getCPU());
print_r($sampleOne->getDevice());
print_r($sampleOne->getOS());
print_r($sampleOne->getEngine());
