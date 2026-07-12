<?php
// Deliberately vulnerable PHP deserialization fixture.
// unserialize() on raw, attacker-controlled POST body — the exact bug class
// deserialization-prober.ts's PHP path detects. Real Guzzle 6.5.8 / Monolog
// 1.27.1 (both genuinely vulnerable versions, pinned on purpose in
// composer.json with --no-blocking) are autoloaded below so phpggc's
// Guzzle/RCE1 and Monolog/RCE4 gadget chains actually fire their __destruct()
// magic method during unserialize() instead of producing an inert
// __PHP_Incomplete_Class object.
require __DIR__ . '/vendor/autoload.php';

$body = file_get_contents('php://input');
try {
    $obj = @unserialize($body);
    if ($obj === false && $body !== 'b:0;') {
        http_response_code(200);
        echo "unserialize(): Error at offset 0 of " . strlen($body) . " bytes";
    } else {
        http_response_code(200);
        echo "deserialized: " . gettype($obj);
    }
} catch (\Throwable $e) {
    http_response_code(200);
    echo "error: " . $e->getMessage();
}
