--TEST--
Check for blenc presence
--SKIPIF--
<?php if (!extension_loaded("blenc")) print "skip"; ?>
--FILE--
<?php 
echo "blenc extension is available";
?>
--EXPECT--
blenc extension is available
