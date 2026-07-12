<?php
// Deliberately vulnerable file upload fixture — no extension filtering, no
// content-type validation, saves the uploaded file verbatim into a
// web-servable directory. Run via the PHP CLI built-in server, which
// executes any .php file it serves directly (including ones we just wrote
// to disk), so an uploaded webshell here genuinely runs — the exact bug
// class file-upload-webshell-prober.ts detects via its arithmetic canary.
//
// Run: php -S 0.0.0.0:5004 -t . index.php
if ($_SERVER['REQUEST_URI'] === '/upload' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_FILES['file'])) {
        http_response_code(400);
        echo json_encode(["error" => "file field required"]);
        return;
    }
    $name = basename($_FILES['file']['name']);
    $dest = __DIR__ . '/uploads/' . $name;
    move_uploaded_file($_FILES['file']['tmp_name'], $dest);
    http_response_code(200);
    echo json_encode(["path" => "/uploads/" . $name]);
    return;
}

// If the request maps to a real file on disk (e.g. anything we just
// uploaded into ./uploads/), let the built-in server's default handler
// serve it — this is what actually executes an uploaded .php webshell.
$requested = __DIR__ . parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if (is_file($requested)) {
    return false;
}

http_response_code(404);
echo "Not Found";
return true;
