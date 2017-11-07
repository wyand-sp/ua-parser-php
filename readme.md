# uaparser.class.php

Standalone PHP class to identify browser, engine, OS, CPU, and device type/model based on the User Agent. This class aims to identify detailed type of web browser, layout engine, operating system, cpu architecture, and device type/model, entirely from user-agent string.

Initially developed as **ua-parser-js** by Faisal Salman (https://github.com/faisalman/ua-parser-js) as a JS module. Rewritten in PHP by Damyan Stanchev.

# Sample usage

```php
$sampleOne = new UAParser('Mozilla/5.0 (Linux; Android 5.0.2; SAMSUNG SM-G925F Build/LRX22G) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/3.0 Chrome/38.0.2125.102 Mobile Safari/537.36');
print_r($sampleOne->getResult());
```

```php
$sampleTwo = new UAParser();
print_r($sampleTwo->getBrowser());
print_r($sampleTwo->getCPU());
print_r($sampleTwo->getDevice());
print_r($sampleTwo->getOS());
print_r($sampleTwo->getEngine());
```

# License

Dual licensed under GPLv2 & MIT

- Copyright © 2017 Damyan Stanchev <<damyan.stanchev@gmail.com>>
- Copyright © 2012-2016 Faisal Salman <<fyzlman@gmail.com>>

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
