<?php 

    ini_set("blenc.key_file", "ext/blenc/tests/keys.txt");
    $key = blenc_encrypt(file_get_contents("input.php"), "ext/blenc/tests/output.phpe");
    file_put_contents("ext/blenc/tests/keys.txt", $key);
    include_once("ext/blenc/tests/output.phpe");

    unlink("ext/blenc/tests/keys.txt");
    unlink("ext/blenc/tests/output.phpe");

?>
