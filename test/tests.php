<?php
include(dirname(__FILE__) . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'uaparser.class.php');

$testsBrowser = json_decode(file_get_contents('browser-test.json'), true);
foreach($testsBrowser as $single) {
	$actual = (new UAParser($single['ua']))->getBrowser();
	if (json_encode($actual) !== json_encode($single['expect'])) {
		echo 'Failed getBrowser on ' . $single['ua'] . "\n";
		echo json_encode($actual) . "\n";
		echo json_encode($single['expect']) . "\n\n";
	}
}

$testsCpu = json_decode(file_get_contents('cpu-test.json'), true);
foreach($testsCpu as $single) {
	$actual = (new UAParser($single['ua']))->getCPU();
	if (json_encode($actual) !== json_encode($single['expect'])) {
		echo 'Failed getCPU on ' . $single['ua'] . "\n";
		echo json_encode($actual) . "\n";
		echo json_encode($single['expect']) . "\n\n";
	}
}

$testsDevice = json_decode(file_get_contents('device-test.json'), true);
foreach($testsDevice as $single) {
	$actual = (new UAParser($single['ua']))->getDevice();
	if (json_encode($actual) !== json_encode($single['expect'])) {
		echo 'Failed getDevice on ' . $single['ua'] . "\n";
		echo json_encode($actual) . "\n";
		echo json_encode($single['expect']) . "\n\n";
	}
}

$testsOS = json_decode(file_get_contents('os-test.json'), true);
foreach($testsOS as $single) {
	$actual = (new UAParser($single['ua']))->getOS();
	if (json_encode($actual) !== json_encode($single['expect'])) {
		echo 'Failed getOS on ' . $single['ua'] . "\n";
		echo json_encode($actual) . "\n";
		echo json_encode($single['expect']) . "\n\n";
	}
}

$testsEngine = json_decode(file_get_contents('engine-test.json'), true);
foreach($testsEngine as $single) {
	$actual = (new UAParser($single['ua']))->getEngine();
	if (json_encode($actual) !== json_encode($single['expect'])) {
		echo 'Failed getEngine on ' . $single['ua'] . "\n";
		echo json_encode($actual) . "\n";
		echo json_encode($single['expect']) . "\n\n";
	}
}

echo 'Done';