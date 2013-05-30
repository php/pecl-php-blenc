<?php
/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2013 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.0 of the PHP license,       |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_0.txt.                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Giuseppe Chiesa <gchiesa@php.net>                            |
  +----------------------------------------------------------------------+
*/

/**
 * blencode.php
 * Encode a php source file with BLENC
 * 
 * This script will create an encoded version of SOURCEFILE.php with extension .phpenc
 * and link the old SOURCEFILE.php to the encoded version.
 * blencode.php also will create some other files: 
 *   blenc.key          with the unencrypted blowfish encryption key
 *   key_file.blenc     with the encrypted version of blowfish key, in order to redistribute
 *                      them with your encoded sources.
 *   ./backup           directory where original SOURCE files will be saved.
 * 
 */ 
function usage($prg)
{
    echo "Usage : php -f $prg SOURCE ";
    echo "\n".
         "It will create a encoded version of SOURCE with extension .phpenc \n".
         "and will replace the code in SOURCE with a include request for the \n".
         "new encoded file.\n".
         "$prg also will create some other files:\n".
         "  blenc.key      with the unencrypted blowfish encryption key\n".
         "  key_file.blenc with the encrypted version of blowfish key, in order to\n".
         "                 redistribute them with your encoded sources.\n".
         "  ./backup       directory where original SOURCE files will be saved\n\n";
         
}

function minify($fname)
{
    $retval = '';
    $fdata = file($fname);
    
    foreach($fdata as $row) {
    
        $retval .= ' '.trim($row).' ';
        
    }
    
    return $retval;
}



/*
  +----------------------------------------------------------------------+
  | MAIN                                                                 |
  +----------------------------------------------------------------------+
*/
ini_set("output_buffering", "16000");

if($argc < 2) {
    
    usage(basename($argv[0]));
    die();
    
}

$B1=@system('tput smso');
$B0=@system('tput rmso');

if(!file_exists($argv[1])) {

    echo "$B1 BLENC $B0 file $argv[1] not found.\n";
    die();
    
}

if(file_exists('blenc.key'))
    $key_prev = $key = file_get_contents('blenc.key');
else {
    
    $key_prev = $key = md5(time());
    file_put_contents('blenc.key', $key);
}

echo "$B1 BLENC $B0 blenc_protect starts...\n";
echo "$B1 BLENC $B0 blowfish unencrypted key: $key\n";
echo "$B1 BLENC $B0 file to encode: ".$argv[1]."\n";

if(file_exists($argv[1])) {

    if(!is_dir('backup')) {
    
        mkdir('backup');
        
    }
    
    if(!file_exists('backup/'.basename($argv[1]))) {

        $backup_file = 'backup/'.basename($argv[1]);
        
    } else {
    
        $backup_file = 'backup/'.basename($argv[1]).'.'.date('Y_m_d_H_i_s', time());

    }
        
    copy($argv[1], $backup_file);
    echo "$B1 BLENC $B0 backup file : $backup_file\n";
    
    $contents = php_strip_whitespace($argv[1]);
    file_put_contents('/tmp/blencode-txt', $contents);
    $contents = minify('/tmp/blencode-txt');
    $aS = array('<?php', '?>', '<?');
    $aR = array('', '', '');
    $contents = trim(str_replace($aS, $aR, $contents));
    echo "$B1 BLENC $B0 size of content: ".strlen($contents)."\n";
    echo "$B1 BLENC $B0 MD5: ".md5($contents)."\n";
    file_put_contents('/tmp/blencode-log', "---\nFILE: $argv[1]\nSIZE: ".strlen($contents)."\nMD5: ".md5($contents)."\n", FILE_APPEND);
    
    if($key != '')
        $key = blenc_encrypt($contents, $argv[1].'enc', $key);
    else
        $key = blenc_encrypt($contents, $argv[1].'enc');

    echo "$B1 BLENC $B0 redistributable key: $key\n";
    
    file_put_contents('key_file.blenc', $key."\n", FILE_APPEND);
    
    unlink($argv[1]);
    symlink($argv[1].'enc', $argv[1]);
    
    $result = @system('sort -k1 -u -o key_file.blenc key_file.blenc');
    echo "$B1 BLENC $B0 redistributable key file key_file.blenc updated.\n";
    echo "$B1 BLENC $B0 done.\n";
    
}
?>
